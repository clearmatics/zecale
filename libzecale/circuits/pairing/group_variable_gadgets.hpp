// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+
#ifndef __ZECALE_CIRCUITS_PAIRING_GROUP_VARIABLE_GADGETS_HPP__
#define __ZECALE_CIRCUITS_PAIRING_GROUP_VARIABLE_GADGETS_HPP__

#include "libzecale/circuits/pairing/pairing_params.hpp"

#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g1_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g2_gadget.hpp>

namespace libzecale
{

/// Utility function to get the value from a (witnessed) G1_variable.
template<typename wppT>
libff::G1<other_curve<wppT>> g1_variable_get_element(
    const libsnark::G1_variable<wppT> &g1_variable);

/// Utility function to get the value from a (witnessed) G2_variable.
template<typename wppT>
libff::G2<other_curve<wppT>> g2_variable_get_element(
    const libsnark::G2_variable<wppT> &var);

/// Negate a G2 variable and return the result. (Note that evaluate should be
/// called on the result, or its components, before using it in witness
/// generation).
template<typename wppT>
libsnark::G2_variable<wppT> g2_variable_negate(
    libsnark::protoboard<libff::Fr<wppT>> &pb,
    const libsnark::G2_variable<wppT> &g2,
    const std::string &annotation_prefix);

/// Generic gadget to perform scalar multiplication of group variables.
template<
    typename groupT,
    typename groupVariableT,
    typename add_gadget,
    typename dbl_gadget,
    typename scalarT>
class point_mul_by_const_scalar_gadget
    : libsnark::gadget<typename groupT::base_field>
{
public:
    using FieldT = typename groupT::base_field;

    const scalarT _scalar;
    const groupVariableT _result;
    std::vector<std::shared_ptr<add_gadget>> _add_gadgets;
    std::vector<std::shared_ptr<dbl_gadget>> _dbl_gadgets;

    point_mul_by_const_scalar_gadget(
        libsnark::protoboard<FieldT> &pb,
        const scalarT &scalar,
        const groupVariableT &P,
        const groupVariableT &result,
        const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
    const groupVariableT &result() const;
};

/// Gadget for scalar multiplication of G1 elements
template<typename wppT, mp_size_t scalarLimbs>
using G1_mul_by_const_scalar_gadget = point_mul_by_const_scalar_gadget<
    libff::G1<other_curve<wppT>>,
    libsnark::G1_variable<wppT>,
    libsnark::G1_add_gadget<wppT>,
    libsnark::G1_dbl_gadget<wppT>,
    libff::bigint<scalarLimbs>>;

/// Gadget to add 2 G2 points
template<typename wppT>
class G2_add_gadget : public libsnark::gadget<libff::Fr<wppT>>
{
public:
    libsnark::G2_variable<wppT> _A;
    libsnark::G2_variable<wppT> _B;
    libsnark::G2_variable<wppT> _C;

    libsnark::Fqe_variable<wppT> _lambda;
    libsnark::Fqe_variable<wppT> _nu;

    // lambda = (By - Ay) / (Bx - Ax)
    // <=>  lambda * (Bx - Ax) = By - Ay
    libsnark::Fqe_mul_gadget<wppT> _lambda_constraint;

    // nu = Ay - lambda * Ax
    // <=> lambda * Ax = Ay - nu
    libsnark::Fqe_mul_gadget<wppT> _nu_constraint;

    // Cx = lambda^2 - Ax - Bx
    // <=> lambda^2 = Cx + Ax + Bx
    libsnark::Fqe_mul_gadget<wppT> _Cx_constraint;

    // Cy = -(lambda * Cx + nu)
    // <=> Cx * lambda = -Cy - nu
    libsnark::Fqe_mul_gadget<wppT> _Cy_constraint;

    G2_add_gadget(
        libsnark::protoboard<libff::Fr<wppT>> &pb,
        const libsnark::G2_variable<wppT> &A,
        const libsnark::G2_variable<wppT> &B,
        const libsnark::G2_variable<wppT> &C,
        const std::string &annotation_prefix);
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename wppT> class G2_dbl_gadget : libsnark::gadget<libff::Fr<wppT>>
{
public:
    using nppT = other_curve<wppT>;

    libsnark::G2_variable<wppT> _A;
    libsnark::G2_variable<wppT> _B;

    libsnark::Fqe_variable<wppT> _lambda;
    libsnark::Fqe_variable<wppT> _nu;

    // Ax_squared = Ax * Ax
    libsnark::Fqe_mul_gadget<wppT> _Ax_squared_constraint;

    // lambda = (3 * Ax^2 + a) / 2 * Ay
    // <=> lambda * (Ay + Ay) = 3 * Ax_squared + a
    libsnark::Fqe_mul_gadget<wppT> _lambda_constraint;

    // nu = Ay - lambda * Ax
    // <=> lambda * Ax = Ay - nu
    libsnark::Fqe_mul_gadget<wppT> _nu_constraint;

    // Bx = lambda^2 - 2 * Ax
    // <=> lambda * lambda = Bx + Ax + Ax
    libsnark::Fqe_mul_gadget<wppT> _Bx_constraint;

    // By = - (lambda * Bx + nu)
    // <=> lambda * Bx = - By - nu
    libsnark::Fqe_mul_gadget<wppT> _By_constraint;

    G2_dbl_gadget(
        libsnark::protoboard<libff::Fr<wppT>> &pb,
        const libsnark::G2_variable<wppT> &A,
        const libsnark::G2_variable<wppT> &B,
        const std::string &annotation_prefix);
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename wppT, mp_size_t scalarLimbs>
using G2_mul_by_const_scalar_gadget = point_mul_by_const_scalar_gadget<
    libff::G2<other_curve<wppT>>,
    libsnark::G2_variable<wppT>,
    G2_add_gadget<wppT>,
    G2_dbl_gadget<wppT>,
    libff::bigint<scalarLimbs>>;

template<typename wppT>
class G2_equality_gadget : libsnark::gadget<libff::Fr<wppT>>
{
public:
    using nppT = other_curve<wppT>;

    libsnark::G2_variable<wppT> _A;
    libsnark::G2_variable<wppT> _B;

    G2_equality_gadget(
        libsnark::protoboard<libff::Fr<wppT>> &pb,
        const libsnark::G2_variable<wppT> &A,
        const libsnark::G2_variable<wppT> &B,
        const std::string &annotation_prefix);
    void generate_r1cs_constraints();
    void generate_r1cs_witness();

private:
    // There is no generic way to iterate over the components of Fp?_variable,
    // so this method must be specialized per field extension. However, the
    // version that expects 2 components may still compile on Fp3_variable,
    // say. Hence we specify Fp2_variable explicitly in the parameters to avoid
    // callers accidentally using this for other pairings and passing in
    // Fp?_variable.
    void generate_fpe_equality_constraints(
        const libsnark::Fp2_variable<libff::Fqe<nppT>> &a,
        const libsnark::Fp2_variable<libff::Fqe<nppT>> &b);
};

} // namespace libzecale

#include "libzecale/circuits/pairing/group_variable_gadgets.tcc"

#endif // __ZECALE_CIRCUITS_PAIRING_GROUP_VARIABLE_GADGETS_HPP__
