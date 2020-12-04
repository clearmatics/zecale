// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_PAIRING_BLS12_377_MEMBERSHIP_CHECK_GADGETS_TCC__
#define __ZECALE_CIRCUITS_PAIRING_BLS12_377_MEMBERSHIP_CHECK_GADGETS_TCC__

#include "libzecale/circuits/pairing/bls12_377_membership_check_gadgets.hpp"

namespace libzecale
{

// bls12_377_G2_membership_check_gadget

template<typename wppT>
bls12_377_G1_membership_check_gadget<wppT>::
    bls12_377_G1_membership_check_gadget(
        libsnark::protoboard<libff::Fr<wppT>> &pb,
        const libsnark::G1_variable<wppT> &P,
        const std::string &annotation_prefix)
    : libsnark::gadget<libff::Fr<wppT>>(pb, annotation_prefix)
    , _P(P)
    , _P_primed(pb, FMT(annotation_prefix, " P_primed"))
    , _P_primed_checker(
          pb, _P_primed, FMT(annotation_prefix, " P_primed_checker"))
    , _P_primed_mul_cofactor(
          pb,
          libff::G1<nppT>::h,
          _P_primed,
          P,
          FMT(annotation_prefix, " mul_by_cofactor"))
{
}

template<typename wppT>
void bls12_377_G1_membership_check_gadget<wppT>::generate_r1cs_constraints()
{
    _P_primed_checker.generate_r1cs_constraints();
    _P_primed_mul_cofactor.generate_r1cs_constraints();
}

template<typename wppT>
void bls12_377_G1_membership_check_gadget<wppT>::generate_r1cs_witness()
{
    // P has already been witnessed. Compute P'.
    const libff::G1<nppT> P_val(
        this->pb.lc_val(_P.X), this->pb.lc_val(_P.Y), libff::Fq<nppT>::one());
    const libff::G1<nppT> P_primed_val = P_val.proof_of_safe_subgroup();

    // Witness P_primed and the multiplication gadget. Re-witness the result P,
    // ensuring that the result is as expected.
    _P_primed.generate_r1cs_witness(P_primed_val);
    _P_primed_checker.generate_r1cs_witness();
    _P_primed_mul_cofactor.generate_r1cs_witness();
    _P.generate_r1cs_witness(P_val);
}

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_PAIRING_BLS12_377_MEMBERSHIP_CHECK_GADGETS_TCC__
