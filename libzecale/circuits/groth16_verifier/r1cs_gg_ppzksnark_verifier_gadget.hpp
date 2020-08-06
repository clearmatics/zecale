// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

/// Reference
/// \[BGM17]:
///  "Scalable Multi-party Computation for zk-SNARK Parameters in the Random
///  Beacon Model" Sean Bowe and Ariel Gabizon and Ian Miers, IACR Cryptology
///  ePrint Archive 2017, <http://eprint.iacr.org/2017/1050>

#ifndef __ZECALE_CIRCUITS_GROTH16_VERIFIER_R1CS_GG_PPZKSNARK_VERIFIER_GADGET_HPP__
#define __ZECALE_CIRCUITS_GROTH16_VERIFIER_R1CS_GG_PPZKSNARK_VERIFIER_GADGET_HPP__

#include "libzecale/circuits/pairing/pairing_checks.hpp"
#include "libzecale/circuits/pairing/pairing_params.hpp"

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g1_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g2_gadget.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

namespace libzecale
{

template<typename ppT> class pairing_selector;

template<typename ppT>
class r1cs_gg_ppzksnark_proof_variable : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    typedef libff::Fr<ppT> FieldT;

    std::shared_ptr<libsnark::G1_variable<ppT>> g_A;
    std::shared_ptr<libsnark::G2_variable<ppT>> g_B;
    std::shared_ptr<libsnark::G1_variable<ppT>> g_C;

    std::vector<std::shared_ptr<libsnark::G1_variable<ppT>>> all_G1_vars;
    std::vector<std::shared_ptr<libsnark::G2_variable<ppT>>> all_G2_vars;

    std::vector<std::shared_ptr<libsnark::G1_checker_gadget<ppT>>>
        all_G1_checkers;
    std::shared_ptr<libsnark::G2_checker_gadget<ppT>> G2_checker;

    libsnark::pb_variable_array<FieldT> proof_contents;

    r1cs_gg_ppzksnark_proof_variable(
        libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix);
    void generate_r1cs_constraints();
    void generate_r1cs_witness(
        const libsnark::r1cs_gg_ppzksnark_proof<other_curve<ppT>> &proof);
    static size_t size();
};

template<typename ppT>
class r1cs_gg_ppzksnark_verification_key_variable
    : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    typedef libff::Fr<ppT> FieldT;

    std::shared_ptr<libsnark::G1_variable<ppT>> alpha_g1;
    std::shared_ptr<libsnark::G2_variable<ppT>> beta_g2;
    std::shared_ptr<libsnark::G2_variable<ppT>> delta_g2;
    std::shared_ptr<libsnark::G1_variable<ppT>> encoded_ABC_base;
    std::vector<std::shared_ptr<libsnark::G1_variable<ppT>>> ABC_g1;

    libsnark::pb_variable_array<FieldT> all_bits;
    libsnark::pb_linear_combination_array<FieldT> all_vars;
    size_t input_size;

    std::shared_ptr<libsnark::multipacking_gadget<FieldT>> packer;

    // Unfortunately, g++ 4.9 and g++ 5.0 have a bug related to
    // incorrect inlining of small functions:
    // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=65307, which
    // produces wrong assembly even at -O1. The test case at the bug
    // report is directly derived from this code here. As a temporary
    // work-around we mark the key functions noinline to hint compiler
    // that inlining should not be performed.

    // TODO: remove later, when g++ developers fix the bug.

    __attribute__((noinline)) r1cs_gg_ppzksnark_verification_key_variable(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable_array<FieldT> &all_bits,
        const size_t input_size,
        const std::string &annotation_prefix);
    void generate_r1cs_constraints(const bool enforce_bitness);
    void generate_r1cs_witness(
        const libsnark::r1cs_gg_ppzksnark_verification_key<other_curve<ppT>>
            &vk);
    void generate_r1cs_witness(const libff::bit_vector &vk_bits);
    libff::bit_vector get_bits() const;
    static size_t __attribute__((noinline))
    size_in_bits(const size_t input_size);
    static libff::bit_vector get_verification_key_bits(
        const libsnark::r1cs_gg_ppzksnark_verification_key<other_curve<ppT>>
            &r1cs_vk);
};

template<typename ppT>
class r1cs_gg_ppzksnark_preprocessed_r1cs_gg_ppzksnark_verification_key_variable
{
public:
    typedef libff::Fr<ppT> FieldT;

    std::shared_ptr<G1_precomputation<ppT>> vk_alpha_g1_precomp;
    std::shared_ptr<G2_precomputation<ppT>> vk_generator_g2_precomp;
    std::shared_ptr<G2_precomputation<ppT>> vk_beta_g2_precomp;
    std::shared_ptr<G2_precomputation<ppT>> vk_delta_g2_precomp;

    std::shared_ptr<libsnark::G1_variable<ppT>> encoded_ABC_base;
    std::vector<std::shared_ptr<libsnark::G1_variable<ppT>>> ABC_g1;

    r1cs_gg_ppzksnark_preprocessed_r1cs_gg_ppzksnark_verification_key_variable();
    r1cs_gg_ppzksnark_preprocessed_r1cs_gg_ppzksnark_verification_key_variable(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::r1cs_gg_ppzksnark_verification_key<other_curve<ppT>>
            &r1cs_vk,
        const std::string &annotation_prefix);
};

template<typename ppT>
class r1cs_gg_ppzksnark_verifier_process_vk_gadget
    : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    typedef libff::Fr<ppT> FieldT;

    std::shared_ptr<G1_precompute_gadget<ppT>> compute_vk_alpha_g1_precomp;

    std::shared_ptr<G2_precompute_gadget<ppT>> compute_vk_generator_g2_precomp;
    std::shared_ptr<G2_precompute_gadget<ppT>> compute_vk_beta_g2_precomp;
    std::shared_ptr<G2_precompute_gadget<ppT>> compute_vk_delta_g2_precomp;

    r1cs_gg_ppzksnark_verification_key_variable<ppT> vk;
    r1cs_gg_ppzksnark_preprocessed_r1cs_gg_ppzksnark_verification_key_variable<
        ppT> &pvk;

    r1cs_gg_ppzksnark_verifier_process_vk_gadget(
        libsnark::protoboard<FieldT> &pb,
        const r1cs_gg_ppzksnark_verification_key_variable<ppT> &vk,
        r1cs_gg_ppzksnark_preprocessed_r1cs_gg_ppzksnark_verification_key_variable<
            ppT> &pvk,
        const std::string &annotation_prefix);
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename ppT>
class r1cs_gg_ppzksnark_online_verifier_gadget
    : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    typedef libff::Fr<ppT> FieldT;

    r1cs_gg_ppzksnark_preprocessed_r1cs_gg_ppzksnark_verification_key_variable<
        ppT>
        pvk;

    libsnark::pb_variable_array<FieldT> input;
    size_t elt_size;
    r1cs_gg_ppzksnark_proof_variable<ppT> proof;
    // The `result` variable should be allocated outside of this circuit
    libsnark::pb_variable<FieldT> result;
    const size_t input_len;

    std::shared_ptr<libsnark::G1_variable<ppT>> acc;
    std::shared_ptr<libsnark::G1_multiscalar_mul_gadget<ppT>> accumulate_input;

    std::shared_ptr<G1_precomputation<ppT>> proof_g_A_precomp;
    std::shared_ptr<G2_precomputation<ppT>> proof_g_B_precomp;
    std::shared_ptr<G1_precomputation<ppT>> proof_g_C_precomp;
    std::shared_ptr<G1_precomputation<ppT>> acc_precomp;

    std::shared_ptr<G1_precompute_gadget<ppT>> compute_proof_g_A_precomp;
    std::shared_ptr<G2_precompute_gadget<ppT>> compute_proof_g_B_precomp;
    std::shared_ptr<G1_precompute_gadget<ppT>> compute_proof_g_C_precomp;
    std::shared_ptr<G1_precompute_gadget<ppT>> compute_acc_precomp;

    std::shared_ptr<check_e_equals_eee_gadget<ppT>> check_QAP_valid;

    r1cs_gg_ppzksnark_online_verifier_gadget(
        libsnark::protoboard<FieldT> &pb,
        const r1cs_gg_ppzksnark_preprocessed_r1cs_gg_ppzksnark_verification_key_variable<
            ppT> &pvk,
        const libsnark::pb_variable_array<FieldT> &input,
        const size_t elt_size,
        const r1cs_gg_ppzksnark_proof_variable<ppT> &proof,
        const libsnark::pb_variable<FieldT> &result_QAP_valid,
        const std::string &annotation_prefix);
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename ppT>
class r1cs_gg_ppzksnark_verifier_gadget
    : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    typedef libff::Fr<ppT> FieldT;

    std::shared_ptr<
        r1cs_gg_ppzksnark_preprocessed_r1cs_gg_ppzksnark_verification_key_variable<
            ppT>>
        pvk;
    std::shared_ptr<r1cs_gg_ppzksnark_verifier_process_vk_gadget<ppT>>
        compute_pvk;
    std::shared_ptr<r1cs_gg_ppzksnark_online_verifier_gadget<ppT>>
        online_verifier;

    r1cs_gg_ppzksnark_verifier_gadget(
        libsnark::protoboard<FieldT> &pb,
        const r1cs_gg_ppzksnark_verification_key_variable<ppT> &vk,
        const libsnark::pb_variable_array<FieldT> &input,
        const size_t elt_size,
        const r1cs_gg_ppzksnark_proof_variable<ppT> &proof,
        const libsnark::pb_variable<FieldT> &result,
        const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

} // namespace libzecale

#include "r1cs_gg_ppzksnark_verifier_gadget.tcc"

#endif // __ZECALE_CIRCUITS_GROTH16_VERIFIER_R1CS_GG_PPZKSNARK_VERIFIER_GADGET_HPP__
