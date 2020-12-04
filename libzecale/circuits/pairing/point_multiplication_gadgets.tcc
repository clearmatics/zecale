// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_PAIRING_POINT_MULTIPLICATION_GADGETS_TCC__
#define __ZECALE_CIRCUITS_PAIRING_POINT_MULTIPLICATION_GADGETS_TCC__

#include "libzecale/circuits/pairing/point_multiplication_gadgets.hpp"

namespace libzecale
{

namespace implementation
{

// Internal class used to extract the value of a G1_variable.
template<typename wppT>
class G1_variable_with_get_element : public libsnark::G1_variable<wppT>
{
public:
    using nppT = other_curve<wppT>;
    inline libff::G1<nppT> get_element() const
    {
        return libff::G1<nppT>(
            this->pb.lc_val(this->X),
            this->pb.lc_val(this->Y),
            libff::Fq<nppT>::one());
    }
};

} // namespace implementation

template<typename wppT>
libff::G1<other_curve<wppT>> g1_variable_get_element(
    const libsnark::G1_variable<wppT> &var)
{
    return ((implementation::G1_variable_with_get_element<wppT> *)(&var))
        ->get_element();
}

template<typename wppT>
libff::G2<other_curve<wppT>> g2_variable_get_element(
    const libsnark::G2_variable<wppT> &var)
{
    using nppT = other_curve<wppT>;
    return libff::G2<nppT>(
        var.X->get_element(),
        var.Y->get_element(),
        libff::G2<nppT>::twist_field::one());
}

// G1_mul_by_const_scalar_gadget

template<typename wppT, mp_size_t scalarLimbs>
G1_mul_by_const_scalar_gadget<wppT, scalarLimbs>::G1_mul_by_const_scalar_gadget(
    libsnark::protoboard<libff::Fr<wppT>> &pb,
    const libff::bigint<scalarLimbs> &scalar,
    const libsnark::G1_variable<wppT> &P,
    const libsnark::G1_variable<wppT> &result,
    const std::string &annotation_prefix)
    : libsnark::gadget<libff::Fr<wppT>>(pb, annotation_prefix)
    , _scalar(scalar)
    , _result(result)
{
    const size_t last_bit = _scalar.num_bits() - 1;
    const libsnark::G1_variable<wppT> *last_value = &P;

    // Temporary vector of intermediate variables. Reserve the maximum number
    // of possible entries to ensure no reallocation (i.e. last_value is always
    // valid).
    std::vector<libsnark::G1_variable<wppT>> values;
    values.reserve(2 * last_bit);

    for (size_t i = last_bit - 1; i > 0; --i) {
        // Double
        values.emplace_back(pb, FMT(annotation_prefix, " value[%zu]", i));
        _dbl_gadgets.emplace_back(new dbl_gadget(
            pb,
            *last_value,
            values.back(),
            FMT(annotation_prefix, " double[%zu]", i)));
        last_value = &values.back();

        // Add
        if (_scalar.test_bit(i)) {
            values.emplace_back(pb, FMT(annotation_prefix, " value[%zu]", i));
            _add_gadgets.emplace_back(new add_gadget(
                pb,
                *last_value,
                P,
                values.back(),
                FMT(annotation_prefix, " add[%zu]", i)));
            last_value = &values.back();
        }
    }

    // Depending on the value of the final (lowest-order) bit, perform final
    // double or double-and-add into _result.

    if (_scalar.test_bit(0)) {
        // Double
        values.emplace_back(pb, FMT(annotation_prefix, " value[0]"));
        _dbl_gadgets.emplace_back(new dbl_gadget(
            pb,
            *last_value,
            values.back(),
            FMT(annotation_prefix, " double[0]")));
        last_value = &values.back();

        // Add into _result
        _add_gadgets.emplace_back(new add_gadget(
            pb, *last_value, P, _result, FMT(annotation_prefix, " add[0]")));
    } else {
        // Double
        _dbl_gadgets.emplace_back(new dbl_gadget(
            pb, *last_value, _result, FMT(annotation_prefix, " double[0]")));
    }
}

template<typename wppT, mp_size_t scalarLimbs>
void G1_mul_by_const_scalar_gadget<wppT, scalarLimbs>::
    generate_r1cs_constraints()
{
    const size_t last_bit = _scalar.num_bits() - 1;
    size_t dbl_idx = 0;
    size_t add_idx = 0;
    for (ssize_t i = last_bit - 1; i >= 0; --i) {
        // Double gadget constraints
        _dbl_gadgets[dbl_idx++]->generate_r1cs_constraints();

        // Add gadget constraints
        if (_scalar.test_bit(i)) {
            _add_gadgets[add_idx++]->generate_r1cs_constraints();
        }
    }
}

template<typename wppT, mp_size_t scalarLimbs>
void G1_mul_by_const_scalar_gadget<wppT, scalarLimbs>::generate_r1cs_witness()
{
    const size_t last_bit = _scalar.num_bits() - 1;
    size_t dbl_idx = 0;
    size_t add_idx = 0;
    for (ssize_t i = last_bit - 1; i >= 0; --i) {
        // Double gadget constraints
        _dbl_gadgets[dbl_idx++]->generate_r1cs_witness();

        // Add gadget constraints
        if (_scalar.test_bit(i)) {
            _add_gadgets[add_idx++]->generate_r1cs_witness();
        }
    }
}

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_PAIRING_POINT_MULTIPLICATION_GADGETS_TCC__
