// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_PAIRING_GROUP_VARIABLE_GADGETS_TCC__
#define __ZECALE_CIRCUITS_PAIRING_GROUP_VARIABLE_GADGETS_TCC__

#include "libzecale/circuits/pairing/group_variable_gadgets.hpp"

namespace libzecale
{

namespace internal
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

} // namespace internal

template<typename wppT>
libff::G1<other_curve<wppT>> g1_variable_get_element(
    const libsnark::G1_variable<wppT> &var)
{
    return ((internal::G1_variable_with_get_element<wppT> *)(&var))
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

template<typename wppT>
libsnark::G2_variable<wppT> g2_variable_negate(
    libsnark::protoboard<libff::Fr<wppT>> &pb,
    const libsnark::G2_variable<wppT> &g2,
    const std::string &annotation_prefix)
{
    return libsnark::G2_variable<wppT>(pb, *g2.X, -*g2.Y, annotation_prefix);
}

// point_mul_by_const_scalar_gadget

template<
    typename groupT,
    typename groupVariableT,
    typename add_gadget,
    typename dbl_gadget,
    typename scalarT>
point_mul_by_const_scalar_gadget<
    groupT,
    groupVariableT,
    add_gadget,
    dbl_gadget,
    scalarT>::
    point_mul_by_const_scalar_gadget(
        libsnark::protoboard<FieldT> &pb,
        const scalarT &scalar,
        const groupVariableT &P,
        const groupVariableT &result,
        const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , _scalar(scalar)
    , _result(result)
{
    const size_t last_bit = _scalar.num_bits() - 1;
    const groupVariableT *last_value = &P;

    // Temporary vector of intermediate variables. Reserve the maximum number
    // of possible entries to ensure no reallocation (i.e. last_value is always
    // valid).
    std::vector<groupVariableT> values;
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
    // double or double-and-add into result.

    if (_scalar.test_bit(0)) {
        // Double
        values.emplace_back(pb, FMT(annotation_prefix, " value[0]"));
        _dbl_gadgets.emplace_back(new dbl_gadget(
            pb,
            *last_value,
            values.back(),
            FMT(annotation_prefix, " double[0]")));
        last_value = &values.back();

        // Add into result
        _add_gadgets.emplace_back(new add_gadget(
            pb, *last_value, P, result, FMT(annotation_prefix, " add[0]")));
    } else {
        // Double
        _dbl_gadgets.emplace_back(new dbl_gadget(
            pb, *last_value, result, FMT(annotation_prefix, " double[0]")));
    }
}

template<
    typename groupT,
    typename groupVariableT,
    typename add_gadget,
    typename dbl_gadget,
    typename scalarT>
void point_mul_by_const_scalar_gadget<
    groupT,
    groupVariableT,
    add_gadget,
    dbl_gadget,
    scalarT>::generate_r1cs_constraints()
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

template<
    typename groupT,
    typename groupVariableT,
    typename add_gadget,
    typename dbl_gadget,
    typename scalarT>
void point_mul_by_const_scalar_gadget<
    groupT,
    groupVariableT,
    add_gadget,
    dbl_gadget,
    scalarT>::generate_r1cs_witness()
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

template<
    typename groupT,
    typename groupVariableT,
    typename add_gadget,
    typename dbl_gadget,
    typename scalarT>
const groupVariableT &point_mul_by_const_scalar_gadget<
    groupT,
    groupVariableT,
    add_gadget,
    dbl_gadget,
    scalarT>::result() const
{
    return _result;
}

// G2_add_gadget

template<typename wppT>
G2_add_gadget<wppT>::G2_add_gadget(
    libsnark::protoboard<libff::Fr<wppT>> &pb,
    const libsnark::G2_variable<wppT> &A,
    const libsnark::G2_variable<wppT> &B,
    const libsnark::G2_variable<wppT> &result,
    const std::string &annotation_prefix)
    : libsnark::gadget<libff::Fr<wppT>>(pb, annotation_prefix)
    , _A(A)
    , _B(B)
    , _result(result)
    , _lambda(pb, FMT(annotation_prefix, " lambda"))
    // lambda = (By - Ay) / (Bx - Ax)
    // <=>  lambda * (Bx - Ax) = By - Ay
    , _lambda_constraint(
          pb,
          _lambda,
          *_B.X - *_A.X,
          *_B.Y - *_A.Y,
          FMT(annotation_prefix, " _lambda_constraint"))
    // Rx = lambda^2 - Ax - Bx
    // <=> lambda^2 = Rx + Ax + Bx
    , _Rx_constraint(
          pb,
          _lambda,
          _lambda,
          *_result.X + *_A.X + *_B.X,
          FMT(annotation_prefix, " _Rx_constraint"))
    // Ry = lambda * (Ax - Rx) - Ay
    // <=> lambda * (Ax - Rx) = Ry + Ay
    , _Ry_constraint(
          pb,
          _lambda,
          (*_A.X - *_result.X),
          *_result.Y + *_A.Y,
          FMT(annotation_prefix, " _Ry_constraint"))
{
}

template<typename wppT> void G2_add_gadget<wppT>::generate_r1cs_constraints()
{
    _lambda_constraint.generate_r1cs_constraints();
    _Rx_constraint.generate_r1cs_constraints();
    _Ry_constraint.generate_r1cs_constraints();
}

template<typename wppT> void G2_add_gadget<wppT>::generate_r1cs_witness()
{
    using nppT = other_curve<wppT>;
    const libff::Fqe<nppT> Ax = _A.X->get_element();
    const libff::Fqe<nppT> Ay = _A.Y->get_element();
    const libff::Fqe<nppT> Bx = _B.X->get_element();
    const libff::Fqe<nppT> By = _B.Y->get_element();

    // lambda = (By - Ay) / (Bx - Ax)
    const libff::Fqe<nppT> lambda = (By - Ay) * (Bx - Ax).inverse();
    _lambda.generate_r1cs_witness(lambda);
    _lambda_constraint.B.evaluate();
    _lambda_constraint.result.evaluate();
    _lambda_constraint.generate_r1cs_witness();

    // Rx = lambda^2 - Ax - Bx
    // Ry = lambda * (Ax - Rx) - Ay
    const libff::Fqe<nppT> Rx = lambda.squared() - Ax - Bx;
    const libff::Fqe<nppT> Ry = lambda * (Ax - Rx) - Ay;
    _result.generate_r1cs_witness(
        libff::G2<nppT>(Rx, Ry, libff::Fqe<nppT>::one()));

    // lambda^2 = Rx + Ax + Bx
    _Rx_constraint.result.evaluate();
    _Rx_constraint.generate_r1cs_witness();

    // lambda * (Ax - Rx) = Ry + Ay
    _Ry_constraint.B.evaluate();
    _Ry_constraint.result.evaluate();
    _Ry_constraint.generate_r1cs_witness();
}

// G2_dbl_gadget

template<typename wppT>
G2_dbl_gadget<wppT>::G2_dbl_gadget(
    libsnark::protoboard<libff::Fr<wppT>> &pb,
    const libsnark::G2_variable<wppT> &A,
    const libsnark::G2_variable<wppT> &B,
    const std::string &annotation_prefix)
    : libsnark::gadget<libff::Fr<wppT>>(pb, annotation_prefix)
    , _A(A)
    , _B(B)
    , _lambda(pb, FMT(annotation_prefix, " lambda"))
    // Ax_squared = Ax * Ax
    , _Ax_squared_constraint(
          pb,
          *_A.X,
          *_A.X,
          libsnark::Fqe_variable<wppT>(pb, FMT(annotation_prefix, " Ax^2")),
          FMT(annotation_prefix, " _Ax_squared_constraint"))
    // lambda = (3 * Ax^2 + a) / 2 * Ay
    // <=> lambda * (Ay + Ay) = 3 * Ax_squared + a
    , _lambda_constraint(
          pb,
          _lambda,
          *_A.Y + *_A.Y,
          _Ax_squared_constraint.result * libff::Fr<wppT>(3) +
              libff::G2<nppT>::coeff_a,
          FMT(annotation_prefix, " _lambda_constraint"))
    // Bx = lambda^2 - 2 * Ax
    // <=> lambda * lambda = Bx + Ax + Ax
    , _Bx_constraint(
          pb,
          _lambda,
          _lambda,
          *_B.X + *_A.X + *_A.X,
          FMT(annotation_prefix, " _Bx_constraint"))
    // By = lambda * (Ax - Bx) - Ay
    // <=> lambda * (Ax - Bx) = By + Ay
    , _By_constraint(
          pb,
          _lambda,
          (*_A.X - *_B.X),
          *_B.Y + *_A.Y,
          FMT(annotation_prefix, " _By_constraint"))
{
}

template<typename wppT> void G2_dbl_gadget<wppT>::generate_r1cs_constraints()
{
    _Ax_squared_constraint.generate_r1cs_constraints();
    _lambda_constraint.generate_r1cs_constraints();
    _Bx_constraint.generate_r1cs_constraints();
    _By_constraint.generate_r1cs_constraints();
}

template<typename wppT> void G2_dbl_gadget<wppT>::generate_r1cs_witness()
{
    const libff::Fqe<nppT> Ax = _A.X->get_element();
    const libff::Fqe<nppT> Ay = _A.Y->get_element();

    // Ax_squared = Ax * Ax
    _Ax_squared_constraint.generate_r1cs_witness();
    _Ax_squared_constraint.result.evaluate();
    const libff::Fqe<nppT> Ax_squared =
        _Ax_squared_constraint.result.get_element();

    // lambda = (3 * Ax^2 + a) / 2 * Ay
    // <=> lambda * (Ay + Ay) = 3 * Ax_squared + a
    const libff::Fqe<nppT> Ax_squared_plus_a =
        Ax_squared + Ax_squared + Ax_squared + libff::G2<nppT>::coeff_a;
    const libff::Fqe<nppT> lambda = Ax_squared_plus_a * (Ay + Ay).inverse();
    _lambda.generate_r1cs_witness(lambda);
    _lambda_constraint.B.evaluate();
    _lambda_constraint.generate_r1cs_witness();

    // Bx = lambda^2 - 2 * Ax
    // By = lambda * (Ax - Bx) - Ay
    const libff::Fqe<nppT> Bx = lambda.squared() - Ax - Ax;
    const libff::Fqe<nppT> By = lambda * (Ax - Bx) - Ay;
    _B.generate_r1cs_witness(libff::G2<nppT>(Bx, By, libff::Fqe<nppT>::one()));

    // lambda * lambda = Bx + Ax + Ax
    _Bx_constraint.generate_r1cs_witness();

    // lambda * (Ax - Bx) = By + Ay
    _By_constraint.B.evaluate();
    _By_constraint.generate_r1cs_witness();
}

// G2_is_zero_gadget

template<typename wppT>
G2_equality_gadget<wppT>::G2_equality_gadget(
    libsnark::protoboard<libff::Fr<wppT>> &pb,
    const libsnark::G2_variable<wppT> &A,
    const libsnark::G2_variable<wppT> &B,
    const std::string &annotation_prefix)
    : libsnark::gadget<libff::Fr<wppT>>(pb, annotation_prefix), _A(A), _B(B)
{
}

template<typename wppT>
void G2_equality_gadget<wppT>::generate_r1cs_constraints()
{
    // A.X == B.X
    generate_fpe_equality_constraints(*_A.X, *_B.X);
    // A.Y == B.Y
    generate_fpe_equality_constraints(*_A.X, *_B.X);
}

template<typename wppT> void G2_equality_gadget<wppT>::generate_r1cs_witness()
{
    // Nothing to do
}

template<typename wppT>
void G2_equality_gadget<wppT>::generate_fpe_equality_constraints(
    const libsnark::Fp2_variable<libff::Fqe<nppT>> &a,
    const libsnark::Fp2_variable<libff::Fqe<nppT>> &b)
{
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<libff::Fr<wppT>>(a.c0, 1, b.c0),
        FMT(this->annotation_prefix, " c0"));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<libff::Fr<wppT>>(a.c1, 1, b.c1),
        FMT(this->annotation_prefix, " c1"));
}

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_PAIRING_GROUP_VARIABLE_GADGETS_TCC__
