// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_PAIRING_BW6_761_PAIRING_PARAMS_HPP__
#define __ZECALE_CIRCUITS_PAIRING_BW6_761_PAIRING_PARAMS_HPP__

#include "libzecale/circuits/fields/fp12_2over3over2_gadgets.hpp"
#include "libzecale/circuits/pairing/bls12_377_pairing.hpp"
#include "libzecale/circuits/pairing/pairing_params.hpp"

#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>
#include <libff/algebra/curves/bw6_761/bw6_761_pp.hpp>
#include <libsnark/gadgetlib1/gadgets/fields/fp2_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/pairing_params.hpp>

namespace libzecale
{

template<typename ppT> class bls12_377_G1_precomputation;
template<typename ppT> class bls12_377_G1_precompute_gadget;
template<typename ppT> class bls12_377_G2_precomputation;
template<typename ppT> class bls12_377_G2_precompute_gadget;

// Parameters for creating BW6-761 proofs that include statements about
// BLS12_377 pairings.
class bw6_761_pairing_selector
{
public:
    static_assert(
        std::is_same<
            libff::Fr<libff::bw6_761_pp>,
            libff::Fq<libff::bls12_377_pp>>::value,
        "Field types do not match");

    typedef libff::Fr<libff::bw6_761_pp> FieldT;
    typedef libff::Fqe<libff::bls12_377_pp> FqeT;
    typedef libff::Fqk<libff::bls12_377_pp> FqkT;

    typedef libsnark::Fp2_variable<FqeT> Fqe_variable_type;
    typedef libsnark::Fp2_mul_gadget<FqeT> Fqe_mul_gadget_type;
    typedef libsnark::Fp2_mul_by_lc_gadget<FqeT> Fqe_mul_by_lc_gadget_type;
    typedef libsnark::Fp2_sqr_gadget<FqeT> Fqe_sqr_gadget_type;

    typedef Fp12_2over3over2_variable<FqkT> Fqk_variable_type;
    // typedef libsnark::Fp12_mul_gadget<FqkT> Fqk_mul_gadget_type;
    // typedef libsnark::Fp12_mul_by_2345_gadget<FqkT>
    typedef Fp12_2over3over2_mul_by_024_gadget<FqkT> Fqk_mul_by_024_gadget_type;
    typedef Fp12_2over3over2_square_gadget<FqkT> Fqk_sqr_gadget_type;

    typedef libff::bls12_377_pp other_curve_type;

    typedef bls12_377_G1_precomputation<libff::bw6_761_pp>
        G1_precomputation_type;
    typedef bls12_377_G1_precompute_gadget<libff::bw6_761_pp>
        G1_precompute_gadget_type;
    typedef bls12_377_G2_precomputation<libff::bw6_761_pp>
        G2_precomputation_type;
    typedef bls12_377_G2_precompute_gadget<libff::bw6_761_pp>
        G2_precompute_gadget_type;

    // typedef bls12_377_e_over_e_miller_loop_gadget
    //     bls12_377_over_e_miller_loop_gadget_type;
    // typedef bls12_377_e_times_e_over_e_miller_loop_gadget
    //     e_times_e_over_e_miller_loop_gadget_type;
    // typedef bls12_377_e_times_e_times_e_over_e_miller_loop_gadget
    //     e_times_e_times_e_over_e_miller_loop_gadget_type;
    // typedef bls12_377_final_exp_gadget final_exp_gadget_type;

    static const constexpr libff::bigint<libff::bw6_761_Fr::num_limbs>
        &pairing_loop_count = libff::bls12_377_ate_loop_count;
};

template<>
class pairing_selector<libff::bw6_761_pp>
    : public libzecale::bw6_761_pairing_selector
{
};

} // namespace libzecale

namespace libsnark
{

template<>
class pairing_selector<libff::bw6_761_pp>
    : public libzecale::bw6_761_pairing_selector
{
};

} // namespace libsnark

#endif // __ZECALE_CIRCUITS_PAIRING_BW6_761_PAIRING_PARAMS_HPP__
