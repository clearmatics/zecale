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

template<typename wppT>
libsnark::G2_variable<wppT> bls12_377_g2_untwist_frobenius_twist(
    libsnark::protoboard<libff::Fr<wppT>> &pb,
    const libsnark::G2_variable<wppT> &g2,
    size_t exp,
    const std::string &annotation_prefix)
{
    // Follows the libff implementation of
    // bls12_377_G2::untwist_frobenius_twist(). See:
    // libff/algebra/curves/bls12_377/bls12_377_g2.cpp.

    using nppT = other_curve<wppT>;
    using FqeT = libff::Fqe<nppT>;
    using FqkT = libff::Fqk<nppT>;
    using Fq6T = typename FqkT::my_Fp6;

    // Untwist:
    //   untwist_x =
    //     (x as Fp6) * bls12_377_g2_untwist_frobenius_twist_v.coeffs[0]
    //   untwist_y =
    //     (y as Fp12) * bls12_377_g2_untwist_frobenius_twist_w_3
    Fp6_3over2_variable<Fq6T> x_as_Fp6(
        pb,
        *g2.X,
        libsnark::Fp2_variable<FqeT>(
            pb, libff::Fqe<nppT>::zero(), FMT(annotation_prefix, " Fqe(0)")),
        libsnark::Fp2_variable<FqeT>(
            pb, libff::Fqe<nppT>::zero(), FMT(annotation_prefix, " Fqe(0)")),
        FMT(annotation_prefix, " x_as_Fp6"));
    Fp6_3over2_variable<Fq6T> y_as_Fp6(
        pb,
        *g2.Y,
        libsnark::Fp2_variable<FqeT>(
            pb, FqeT::zero(), FMT(annotation_prefix, " Fqe(0)")),
        libsnark::Fp2_variable<FqeT>(
            pb, FqeT::zero(), FMT(annotation_prefix, " Fqe(0)")),
        FMT(annotation_prefix, " y_as_Fp6"));
    Fp12_2over3over2_variable<FqkT> y_as_Fp12(
        pb,
        y_as_Fp6,
        Fp6_3over2_variable<Fq6T>(
            pb, Fq6T::zero(), FMT(annotation_prefix, " Fp6(0)")),
        FMT(annotation_prefix, " y_as_Fp12"));

    Fp6_3over2_variable<Fq6T> untwist_x =
        x_as_Fp6 * libff::bls12_377_g2_untwist_frobenius_twist_v.coeffs[0];
    Fp12_2over3over2_variable<FqkT> untwist_y =
        y_as_Fp12 * libff::bls12_377_g2_untwist_frobenius_twist_w_3;

    // Frobenius:
    Fp6_3over2_variable<Fq6T> untwist_frob_x = untwist_x.frobenius_map(exp);
    Fp12_2over3over2_variable<FqkT> untwist_frob_y =
        untwist_y.frobenius_map(exp);

    // Twist:
    Fp6_3over2_variable<Fq6T> untwist_frob_twist_x =
        untwist_frob_x *
        libff::bls12_377_g2_untwist_frobenius_twist_v_inverse.coeffs[0];
    Fp12_2over3over2_variable<FqkT> untwist_frob_twist_y =
        untwist_frob_y *
        libff::bls12_377_g2_untwist_frobenius_twist_w_3_inverse;

    return libsnark::G2_variable<wppT>(
        pb,
        untwist_frob_twist_x._c0,
        untwist_frob_twist_y._c0._c0,
        annotation_prefix);
}

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_PAIRING_BLS12_377_MEMBERSHIP_CHECK_GADGETS_TCC__
