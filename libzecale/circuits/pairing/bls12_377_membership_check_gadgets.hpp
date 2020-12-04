// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_PAIRING_BLS12_377_MEMBERSHIP_CHECK_GADGETS_HPP__
#define __ZECALE_CIRCUITS_PAIRING_BLS12_377_MEMBERSHIP_CHECK_GADGETS_HPP__

#include "libzecale/circuits/pairing/group_variable_gadgets.hpp"
#include "libzecale/circuits/pairing/pairing_params.hpp"

#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g1_gadget.hpp>

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

} // namespace libzecale

#include "libzecale/circuits/pairing/bls12_377_membership_check_gadgets.tcc"

#endif // __ZECALE_CIRCUITS_PAIRING_BLS12_377_MEMBERSHIP_CHECK_GADGETS_HPP__
