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

// G2_add_gadget

template<typename wppT>
G2_add_gadget<wppT>::G2_add_gadget(
    libsnark::protoboard<libff::Fr<wppT>> &pb,
    const libsnark::G2_variable<wppT> &A,
    const libsnark::G2_variable<wppT> &B,
    const libsnark::G2_variable<wppT> &C,
    const std::string &annotation_prefix)
    : libsnark::gadget<libff::Fr<wppT>>(pb, annotation_prefix)
    , _A(A)
    , _B(B)
    , _C(C)
    , _lambda(pb, FMT(annotation_prefix, " lambda"))
    , _nu(pb, FMT(annotation_prefix, " nu"))
    // lambda * (Bx - Ax) = By - Ay
    , _lambda_constraint(
          pb,
          _lambda,
          *_B.X - *_A.X,
          *_B.Y - *_A.Y,
          FMT(annotation_prefix, " _lambda_constraint"))
    // lambda * Ax = Ay - nu
    , _nu_constraint(
          pb,
          _lambda,
          *_A.X,
          *_A.Y - _nu,
          FMT(annotation_prefix, " _nu_constraint"))
    // lambda^2 = Cx + Ax + Bx
    , _Cx_constraint(
          pb,
          _lambda,
          _lambda,
          *_C.X + *_A.X + *_B.X,
          FMT(annotation_prefix, " _Cx_constraint"))
    // Cx * lambda = -Cy - nu
    , _Cy_constraint(
          pb,
          *_C.X,
          _lambda,
          -*_C.Y - _nu,
          FMT(annotation_prefix, " _Cy_constraint"))
{
    // _lambda.allocate(pb, FMT(annotation_prefix, " lambda"));
    // _nu.allocate(pb, FMT(annotation_prefix, " nu"));
}

template<typename wppT> void G2_add_gadget<wppT>::generate_r1cs_constraints()
{
    _lambda_constraint.generate_r1cs_constraints();
    _nu_constraint.generate_r1cs_constraints();
    _Cx_constraint.generate_r1cs_constraints();
    _Cy_constraint.generate_r1cs_constraints();
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

    // nu = Ay - lambda * Ax
    const libff::Fqe<nppT> nu = Ay - lambda * Ax;
    _nu.generate_r1cs_witness(nu);
    _nu_constraint.result.evaluate();
    _nu_constraint.generate_r1cs_witness();

    // Cx = lambda^2 - Ax - Bx
    // Cy = -(lambda * Cx + nu)
    const libff::Fqe<nppT> Cx = lambda.squared() - Ax - Bx;
    const libff::Fqe<nppT> Cy = -(lambda * Cx + nu);
    _C.generate_r1cs_witness(libff::G2<nppT>(Cx, Cy, libff::Fqe<nppT>::one()));
    _Cx_constraint.result.evaluate();
    _Cx_constraint.generate_r1cs_witness();
    _Cy_constraint.result.evaluate();
    _Cy_constraint.generate_r1cs_witness();
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
    , _nu(pb, FMT(annotation_prefix, " nu"))
    // Ax_squared = Ax * Ax
    , _Ax_squared_constraint(
          pb,
          *_A.X,
          *_A.X,
          libsnark::Fqe_variable<wppT>(pb, FMT(annotation_prefix, " Ax^2")),
          FMT(annotation_prefix, " _Ax_squared_constraint"))
    // lambda * (Ay + Ay) = 3 * Ax_squared + a
    , _lambda_constraint(
          pb,
          _lambda,
          *_A.Y + *_A.Y,
          _Ax_squared_constraint.result * libff::Fr<wppT>(3) +
              libff::G2<nppT>::coeff_a,
          FMT(annotation_prefix, " _lambda_constraint"))
    // lambda * Ax = Ay - nu
    , _nu_constraint(
          pb,
          _lambda,
          *_A.X,
          *_A.Y - _nu,
          FMT(annotation_prefix, " _nu_constraint"))
    // lambda * lambda = Bx + Ax + Ax
    , _Bx_constraint(
          pb,
          _lambda,
          _lambda,
          *_B.X + *_A.X + *_A.X,
          FMT(annotation_prefix, " _Bx_constraint"))
    // lambda * Bx = - By - nu
    , _By_constraint(
          pb,
          _lambda,
          *_B.X,
          -*_B.Y - _nu,
          FMT(annotation_prefix, " _By_constraint"))
{
}

template<typename wppT> void G2_dbl_gadget<wppT>::generate_r1cs_constraints()
{
    _Ax_squared_constraint.generate_r1cs_constraints();
    _lambda_constraint.generate_r1cs_constraints();
    _nu_constraint.generate_r1cs_constraints();
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

    // nu = Ay - lambda * Ax
    // <=> lambda * Ax = Ay - nu
    const libff::Fqe<nppT> nu = Ay - lambda * Ax;
    _nu.generate_r1cs_witness(nu);
    _nu_constraint.generate_r1cs_witness();

    // Bx = lambda^2 - 2 * Ax
    // By = - (lambda * Ax + nu)
    const libff::Fqe<nppT> Bx = lambda.squared() - Ax - Ax;
    const libff::Fqe<nppT> By = -(lambda * Bx + nu);
    _B.generate_r1cs_witness(libff::G2<nppT>(Bx, By, libff::Fqe<nppT>::one()));

    // lambda * lambda = Bx + Ax + Ax
    _Bx_constraint.generate_r1cs_witness();

    // lambda * Bx = - By - nu
    _By_constraint.generate_r1cs_witness();
}

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_PAIRING_POINT_MULTIPLICATION_GADGETS_TCC__
