// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_PAIRING_BLS12_377_MEMBERSHIP_CHECK_GADGETS_HPP__
#define __ZECALE_CIRCUITS_PAIRING_BLS12_377_MEMBERSHIP_CHECK_GADGETS_HPP__

#include "libzecale/circuits/fields/fp12_2over3over2_gadgets.hpp"
#include "libzecale/circuits/pairing/group_variable_gadgets.hpp"
#include "libzecale/circuits/pairing/pairing_params.hpp"

#include <libff/algebra/curves/bls12_377/bls12_377_init.hpp>
#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g1_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g2_gadget.hpp>

namespace libzecale
{

/// Curve equation and subgroup membership check for BLS12-377 G1 variables.
template<typename wppT>
class bls12_377_G1_membership_check_gadget : libsnark::gadget<libff::Fr<wppT>>
{
public:
    using nppT = other_curve<wppT>;
    using G1_mul_by_cofactor_gadget =
        G1_mul_by_const_scalar_gadget<wppT, libff::G1<nppT>::h_limbs>;

    // Point P to check
    libsnark::G1_variable<wppT> _P;
    // P' s.t. [h]P' = P
    libsnark::G1_variable<wppT> _P_primed;
    // Check that P' \in E(Fq)
    libsnark::G1_checker_gadget<wppT> _P_primed_checker;
    // [h]P' = P condition
    G1_mul_by_cofactor_gadget _P_primed_mul_cofactor;

    bls12_377_G1_membership_check_gadget(
        libsnark::protoboard<libff::Fr<wppT>> &pb,
        const libsnark::G1_variable<wppT> &P,
        const std::string &annotation_prefix);
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

/// Untwist-Frobenius-Twist operation on BLS12-377 G2 elements. (Note that
/// evaluate should be called on the result, or its components, before using it
/// in witness generation).
template<typename wppT>
libsnark::G2_variable<wppT> bls12_377_g2_untwist_frobenius_twist(
    libsnark::protoboard<libff::Fr<wppT>> &pb,
    const libsnark::G2_variable<wppT> &g2,
    size_t exp,
    const std::string &annotation_prefix);

/// Curve equation and subgroup membership check for BLS12-377 G2 variables.
template<typename wppT>
class bls12_377_G2_membership_check_gadget : libsnark::gadget<libff::Fr<wppT>>
{
public:
    // Follows libff implementation of bls12_377_G2::is_in_safe_subgroup().
    // See: libff/algebra/curves/bls12_377/bls12_377_g2.cpp.

    // Check that[h1.r] P == 0, where
    //   [h1.r]P is P + [t](\psi(P) - P) - \psi^2(P)
    // (See bls12_377.sage).
    // Note that in this case we check that:
    //   P + [t](\psi(P) - P) = \psi^2(P)
    // since G2_variable cannot represent 0 (in G2).

    // Check P is well-formed
    libsnark::G2_checker_gadget<wppT> _P_checker;
    // \psi(P) - P
    G2_add_gadget<wppT> _psi_P_minus_P;
    // [t](\psi(P) - P)
    G2_mul_by_const_scalar_gadget<wppT, libff::bls12_377_r_limbs>
        _t_times_psi_P_minus_P;
    // P + [t](\psi(P) - P)
    G2_add_gadget<wppT> _P_plus_t_times_psi_P_minus_P;
    // P + [t](\psi(P) - P) = \psi^2(P)
    G2_equality_gadget<wppT> _h1_r_P_equals_zero;

    bls12_377_G2_membership_check_gadget(
        libsnark::protoboard<libff::Fr<wppT>> &pb,
        libsnark::G2_variable<wppT> &g2,
        const std::string &annotation_prefix);
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

} // namespace libzecale

#include "libzecale/circuits/pairing/bls12_377_membership_check_gadgets.tcc"

#endif // __ZECALE_CIRCUITS_PAIRING_BLS12_377_MEMBERSHIP_CHECK_GADGETS_HPP__
