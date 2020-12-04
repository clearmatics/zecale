// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+
#ifndef __ZECALE_CIRCUITS_PAIRING_POINT_MULTIPLICATION_GADGETS_HPP__
#define __ZECALE_CIRCUITS_PAIRING_POINT_MULTIPLICATION_GADGETS_HPP__

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

template<typename wppT, mp_size_t scalarLimbs>
class G1_mul_by_const_scalar_gadget : libsnark::gadget<libff::Fr<wppT>>
{
public:
    using Field = libff::Fr<wppT>;
    using add_gadget = libsnark::G1_add_gadget<wppT>;
    using dbl_gadget = libsnark::G1_dbl_gadget<wppT>;

    const libff::bigint<scalarLimbs> _scalar;
    std::vector<std::shared_ptr<add_gadget>> _add_gadgets;
    std::vector<std::shared_ptr<dbl_gadget>> _dbl_gadgets;
    const libsnark::G1_variable<wppT> &_result;

    G1_mul_by_const_scalar_gadget(
        libsnark::protoboard<libff::Fr<wppT>> &pb,
        const libff::bigint<scalarLimbs> &scalar,
        const libsnark::G1_variable<wppT> &P,
        const libsnark::G1_variable<wppT> &result,
        const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

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

} // namespace libzecale

#include "libzecale/circuits/pairing/point_multiplication_gadgets.tcc"

#endif // __ZECALE_CIRCUITS_PAIRING_POINT_MULTIPLICATION_GADGETS_HPP__
