// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

/// Reference
/// \[BGM17]:
///  "Scalable Multi-party Computation for zk-SNARK Parameters in the Random
///  Beacon Model" Sean Bowe and Ariel Gabizon and Ian Miers, IACR Cryptology
///  ePrint Archive 2017, <http://eprint.iacr.org/2017/1050>

#ifndef __ZECALE_CIRCUITS_GROTH16_VERIFIER_R1CS_GG_PPZKSNARK_VERIFIER_GADGET_HPP__
#define __ZECALE_CIRCUITS_GROTH16_VERIFIER_R1CS_GG_PPZKSNARK_VERIFIER_GADGET_HPP__

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g1_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g2_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/pairing_checks.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

namespace libzecale
{

template<typename ppT> class pairing_selector;

template<typename ppT>
class r1cs_gg_ppzksnark_proof_variable : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    typedef libff::Fr<ppT> FieldT;

    std::shared_ptr<libsnark::G1_variable<ppT>> _g_A;
    std::shared_ptr<libsnark::G2_variable<ppT>> _g_B;
    std::shared_ptr<libsnark::G1_variable<ppT>> _g_C;

    std::vector<std::shared_ptr<libsnark::G1_variable<ppT>>> _all_G1_vars;
    std::vector<std::shared_ptr<libsnark::G2_variable<ppT>>> _all_G2_vars;

    std::vector<std::shared_ptr<libsnark::G1_checker<ppT>>> _all_G1_checkers;
    std::shared_ptr<libsnark::G2_checker<ppT>> _G2_checker;

    libsnark::pb_variable_array<FieldT> _proof_contents;

    r1cs_gg_ppzksnark_proof_variable(
        libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix);
    void generate_r1cs_constraints();
    void generate_r1cs_witness(
        const libsnark::r1cs_gg_ppzksnark_proof<libsnark::other_curve<ppT>>
            &proof);
    static size_t size();
};

template<typename ppT>
class r1cs_gg_ppzksnark_verification_key_variable
    : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    typedef libff::Fr<ppT> FieldT;

    std::shared_ptr<libsnark::G1_variable<ppT>> _alpha_g1;
    std::shared_ptr<libsnark::G2_variable<ppT>> _beta_g2;
    std::shared_ptr<libsnark::G2_variable<ppT>> _delta_g2;
    std::shared_ptr<libsnark::G1_variable<ppT>> _encoded_ABC_base;
    std::vector<std::shared_ptr<libsnark::G1_variable<ppT>>> _ABC_g1;

    libsnark::pb_variable_array<FieldT> _all_bits;
    libsnark::pb_linear_combination_array<FieldT> _all_vars;
    const size_t _num_primary_inputs;

    std::shared_ptr<libsnark::multipacking_gadget<FieldT>> _packer;

    r1cs_gg_ppzksnark_verification_key_variable(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable_array<FieldT> &all_bits,
        const size_t num_primary_inputs,
        const std::string &annotation_prefix);
    void generate_r1cs_constraints(const bool enforce_bitness);
    void generate_r1cs_witness(
        const libsnark::r1cs_gg_ppzksnark_verification_key<
            libsnark::other_curve<ppT>> &vk);
    void generate_r1cs_witness(const libff::bit_vector &vk_bits);
    libff::bit_vector get_bits() const;
    static size_t __attribute__((noinline))
    size_in_bits(const size_t input_size);
    static libff::bit_vector get_verification_key_bits(
        const libsnark::r1cs_gg_ppzksnark_verification_key<
            libsnark::other_curve<ppT>> &r1cs_vk);
};

/// A version of r1cs_gg_ppzksnark_verification_key_variable without variables
/// for the bits. In the case where an algebraic hash of the verification key
/// is used, this type saves many unnecessary variables.
template<typename ppT>
class r1cs_gg_ppzksnark_verification_key_scalar_variable
    : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    typedef libff::Fr<ppT> FieldT;

    libsnark::G1_variable<ppT> _alpha_g1;
    libsnark::G2_variable<ppT> _beta_g2;
    libsnark::G2_variable<ppT> _delta_g2;
    std::shared_ptr<libsnark::G1_variable<ppT>> _encoded_ABC_base;
    std::vector<std::shared_ptr<libsnark::G1_variable<ppT>>> _ABC_g1;

    r1cs_gg_ppzksnark_verification_key_scalar_variable(
        libsnark::protoboard<FieldT> &pb,
        const size_t num_primary_inputs,
        const std::string &annotation_prefix);
    void generate_r1cs_constraints();
    void generate_r1cs_witness(
        const libsnark::r1cs_gg_ppzksnark_verification_key<
            libsnark::other_curve<ppT>> &vk);

    size_t num_primary_inputs() const;
    const libsnark::pb_linear_combination_array<FieldT> &get_all_vars() const;
    static std::vector<FieldT> get_verification_key_scalars(
        const libsnark::r1cs_gg_ppzksnark_verification_key<
            libsnark::other_curve<ppT>> &r1cs_vk);

protected:
    libsnark::pb_linear_combination_array<FieldT> _all_vars;
    const size_t _num_primary_inputs;
};

template<typename ppT>
class r1cs_gg_ppzksnark_preprocessed_verification_key_variable
{
public:
    typedef libff::Fr<ppT> FieldT;

    std::shared_ptr<libsnark::G1_precomputation<ppT>> _vk_alpha_g1_precomp;
    std::shared_ptr<libsnark::G2_precomputation<ppT>> _vk_generator_g2_precomp;
    std::shared_ptr<libsnark::G2_precomputation<ppT>> _vk_beta_g2_precomp;
    std::shared_ptr<libsnark::G2_precomputation<ppT>> _vk_delta_g2_precomp;

    std::shared_ptr<libsnark::G1_variable<ppT>> _encoded_ABC_base;
    std::vector<std::shared_ptr<libsnark::G1_variable<ppT>>> _ABC_g1;

    r1cs_gg_ppzksnark_preprocessed_verification_key_variable();
    r1cs_gg_ppzksnark_preprocessed_verification_key_variable(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::r1cs_gg_ppzksnark_verification_key<
            libsnark::other_curve<ppT>> &r1cs_vk,
        const std::string &annotation_prefix);
};

template<typename ppT>
class r1cs_gg_ppzksnark_verifier_process_vk_gadget
    : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    typedef libff::Fr<ppT> FieldT;

    std::shared_ptr<libsnark::precompute_G1_gadget<ppT>>
        _compute_vk_alpha_g1_precomp;

    std::shared_ptr<libsnark::precompute_G2_gadget<ppT>>
        _compute_vk_generator_g2_precomp;
    std::shared_ptr<libsnark::precompute_G2_gadget<ppT>>
        _compute_vk_beta_g2_precomp;
    std::shared_ptr<libsnark::precompute_G2_gadget<ppT>>
        _compute_vk_delta_g2_precomp;

    r1cs_gg_ppzksnark_verification_key_scalar_variable<ppT> _vk;
    r1cs_gg_ppzksnark_preprocessed_verification_key_variable<ppT> &_pvk;

    r1cs_gg_ppzksnark_verifier_process_vk_gadget(
        libsnark::protoboard<FieldT> &pb,
        const r1cs_gg_ppzksnark_verification_key_scalar_variable<ppT> &vk,
        r1cs_gg_ppzksnark_preprocessed_verification_key_variable<ppT> &pvk,
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

    r1cs_gg_ppzksnark_preprocessed_verification_key_variable<ppT> _pvk;

    libsnark::pb_variable_array<FieldT> _input;
    size_t _elt_size;
    r1cs_gg_ppzksnark_proof_variable<ppT> _proof;
    // The `result` variable should be allocated outside of this circuit
    libsnark::pb_variable<FieldT> _result;
    const size_t _input_len;

    std::shared_ptr<libsnark::G1_variable<ppT>> _acc;
    std::shared_ptr<libsnark::G1_multiscalar_mul_gadget<ppT>> _accumulate_input;

    std::shared_ptr<libsnark::G1_precomputation<ppT>> _proof_g_A_precomp;
    std::shared_ptr<libsnark::G2_precomputation<ppT>> _proof_g_B_precomp;
    std::shared_ptr<libsnark::G1_precomputation<ppT>> _proof_g_C_precomp;
    std::shared_ptr<libsnark::G1_precomputation<ppT>> _acc_precomp;

    std::shared_ptr<libsnark::precompute_G1_gadget<ppT>>
        _compute_proof_g_A_precomp;
    std::shared_ptr<libsnark::precompute_G2_gadget<ppT>>
        _compute_proof_g_B_precomp;
    std::shared_ptr<libsnark::precompute_G1_gadget<ppT>>
        _compute_proof_g_C_precomp;
    std::shared_ptr<libsnark::precompute_G1_gadget<ppT>> _compute_acc_precomp;

    std::shared_ptr<libsnark::check_e_equals_eee_gadget<ppT>> _check_QAP_valid;

    r1cs_gg_ppzksnark_online_verifier_gadget(
        libsnark::protoboard<FieldT> &pb,
        const r1cs_gg_ppzksnark_preprocessed_verification_key_variable<ppT>
            &pvk,
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
        r1cs_gg_ppzksnark_preprocessed_verification_key_variable<ppT>>
        _pvk;
    std::shared_ptr<r1cs_gg_ppzksnark_verifier_process_vk_gadget<ppT>>
        _compute_pvk;
    std::shared_ptr<r1cs_gg_ppzksnark_online_verifier_gadget<ppT>>
        _online_verifier;

    r1cs_gg_ppzksnark_verifier_gadget(
        libsnark::protoboard<FieldT> &pb,
        const r1cs_gg_ppzksnark_verification_key_scalar_variable<ppT> &vk,
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
