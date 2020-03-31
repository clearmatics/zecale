// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+


#ifndef __ZECALE_R1CS_GG_PPZKSNARK_VERIFIER_GADGET_TCC__
#define __ZECALE_R1CS_GG_PPZKSNARK_VERIFIER_GADGET_TCC__

#include <libsnark/gadgetlib1/constraint_profiling.hpp>

namespace libzecale {

template<typename ppT>
r1cs_gg_ppzksnark_proof_variable<ppT>::r1cs_gg_ppzksnark_proof_variable(libsnark::protoboard<FieldT> &pb,
                                                                  const std::string &annotation_prefix) :
    gadget<FieldT>(pb, annotation_prefix)
{
    const size_t num_G1 = 2; // g_A, g_C
    const size_t num_G2 = 1; // g_B

    g_A.reset(new libsnark::G1_variable<ppT>(pb, FMT(annotation_prefix, " g_A")));
    g_B.reset(new libsnark::G2_variable<ppT>(pb, FMT(annotation_prefix, " g_B")));
    g_C.reset(new libsnark::G1_variable<ppT>(pb, FMT(annotation_prefix, " g_C")));

    all_G1_vars = { g_A, g_C };
    all_G2_vars = { g_B };

    all_G1_checkers.resize(all_G1_vars.size());

    for (size_t i = 0; i < all_G1_vars.size(); ++i)
    {
        all_G1_checkers[i].reset(new libsnark::G1_checker_gadget<ppT>(pb, *all_G1_vars[i], FMT(annotation_prefix, " all_G1_checkers_%zu", i)));
    }
    G2_checker.reset(new libsnark::G2_checker_gadget<ppT>(pb, *g_B_g, FMT(annotation_prefix, " G2_checker")));

    assert(all_G1_vars.size() == num_G1);
    assert(all_G2_vars.size() == num_G2);
}

template<typename ppT>
void r1cs_gg_ppzksnark_proof_variable<ppT>::generate_r1cs_constraints()
{
    for (auto &G1_checker : all_G1_checkers)
    {
        G1_checker->generate_r1cs_constraints();
    }

    G2_checker->generate_r1cs_constraints();
}

template<typename ppT>
void r1cs_gg_ppzksnark_proof_variable<ppT>::generate_r1cs_witness(const r1cs_gg_ppzksnark_proof<other_curve<ppT> > &proof)
{
    std::vector<libff::G1<other_curve<ppT> > > G1_elems;
    std::vector<libff::G2<other_curve<ppT> > > G2_elems;

    G1_elems = { proof.g_A, proof.g_C };
    G2_elems = { proof.g_B };

    assert(G1_elems.size() == all_G1_vars.size());
    assert(G2_elems.size() == all_G2_vars.size());

    for (size_t i = 0; i < G1_elems.size(); ++i)
    {
        all_G1_vars[i]->generate_r1cs_witness(G1_elems[i]);
    }

    for (size_t i = 0; i < G2_elems.size(); ++i)
    {
        all_G2_vars[i]->generate_r1cs_witness(G2_elems[i]);
    }

    for (auto &G1_checker : all_G1_checkers)
    {
        G1_checker->generate_r1cs_witness();
    }

    G2_checker->generate_r1cs_witness();
}

template<typename ppT>
size_t r1cs_gg_ppzksnark_proof_variable<ppT>::size()
{
    const size_t num_G1 = 2;
    const size_t num_G2 = 1;
    return (num_G1 * libsnark::G1_variable<ppT>::num_field_elems + num_G2 * libsnark::G2_variable<ppT>::num_field_elems);
}

template<typename ppT>
r1cs_gg_ppzksnark_verification_key_variable<ppT>::r1cs_gg_ppzksnark_verification_key_variable(libsnark::protoboard<FieldT> &pb,
                                                                                        const libsnark::pb_variable_array<FieldT> &all_bits,
                                                                                        const size_t input_size,
                                                                                        const std::string &annotation_prefix) :
    gadget<FieldT>(pb, annotation_prefix),
    all_bits(all_bits),
    input_size(input_size)
{
    // alpha_g1, ABC_g1
    const size_t num_G1 = 1 + (input_size + 1);
    // beta_g2, delta_g2
    const size_t num_G2 = 2;

    assert(all_bits.size() == (libsnark::G1_variable<ppT>::size_in_bits() * num_G1 + libsnark::G2_variable<ppT>::size_in_bits() * num_G2));

    this->alpha_g1.reset(new libsnark::G1_variable<ppT>(pb, FMT(annotation_prefix, " alpha_g1")));
    this->beta_g2.reset(new libsnark::G2_variable<ppT>(pb, FMT(annotation_prefix, " beta_g2")));
    this->delta_g2.reset(new libsnark::G2_variable<ppT>(pb, FMT(annotation_prefix, " delta_g2")));

    all_G1_vars = { this->alpha_g1 };
    all_G2_vars = { this->beta_g2, this->delta_g2 };

    this->ABC_g1.resize(input_size);
    this->encoded_ABC_base.reset(new libsnark::G1_variable<ppT>(pb, FMT(annotation_prefix, " encoded_ABC_base")));
    this->all_G1_vars.emplace_back(this->encoded_ABC_base);

    for (size_t i = 0; i < input_size; ++i)
    {
        this->ABC_g1[i].reset(new libsnark::G1_variable<ppT>(pb, FMT(annotation_prefix, " ABC_g1[%zu]", i)));
        all_G1_vars.emplace_back(this->ABC_g1[i]);
    }

    for (auto &G1_var : all_G1_vars)
    {
        all_vars.insert(all_vars.end(), G1_var->all_vars.begin(), G1_var->all_vars.end());
    }

    for (auto &G2_var : all_G2_vars)
    {
        all_vars.insert(all_vars.end(), G2_var->all_vars.begin(), G2_var->all_vars.end());
    }

    assert(all_G1_vars.size() == num_G1);
    assert(all_G2_vars.size() == num_G2);
    assert(all_vars.size() == (num_G1 * libsnark::G1_variable<ppT>::num_variables() + num_G2 * libsnark::G2_variable<ppT>::num_variables()));

    packer.reset(new libsnark::multipacking_gadget<FieldT>(pb, all_bits, all_vars, FieldT::size_in_bits(), FMT(annotation_prefix, " packer")));
}

template<typename ppT>
void r1cs_gg_ppzksnark_verification_key_variable<ppT>::generate_r1cs_constraints(const bool enforce_bitness)
{
    packer->generate_r1cs_constraints(enforce_bitness);
}

template<typename ppT>
void r1cs_gg_ppzksnark_verification_key_variable<ppT>::generate_r1cs_witness(const r1cs_gg_ppzksnark_verification_key<other_curve<ppT> > &vk)
{
    std::vector<libff::G1<other_curve<ppT> > > G1_elems;
    std::vector<libff::G2<other_curve<ppT> > > G2_elems;

    G1_elems = { vk.alpha_g1 };
    G2_elems = { vk.beta_g2, vk.delta_g2 };

    assert(vk.ABC_g1.rest.indices.size() == input_size);
    G1_elems.emplace_back(vk.ABC_g1.first);
    for (size_t i = 0; i < input_size; ++i)
    {
        assert(vk.ABC_g1.rest.indices[i] == i);
        G1_elems.emplace_back(vk.ABC_g1.rest.values[i]);
    }

    assert(G1_elems.size() == all_G1_vars.size());
    assert(G2_elems.size() == all_G2_vars.size());

    for (size_t i = 0; i < G1_elems.size(); ++i)
    {
        all_G1_vars[i]->generate_r1cs_witness(G1_elems[i]);
    }

    for (size_t i = 0; i < G2_elems.size(); ++i)
    {
        all_G2_vars[i]->generate_r1cs_witness(G2_elems[i]);
    }

    packer->generate_r1cs_witness_from_packed();
}

template<typename ppT>
void r1cs_gg_ppzksnark_verification_key_variable<ppT>::generate_r1cs_witness(const libff::bit_vector &vk_bits)
{
    all_bits.fill_with_bits(this->pb, vk_bits);
    packer->generate_r1cs_witness_from_bits();
}

template<typename ppT>
libff::bit_vector r1cs_gg_ppzksnark_verification_key_variable<ppT>::get_bits() const
{
    return all_bits.get_bits(this->pb);
}

template<typename ppT>
size_t r1cs_gg_ppzksnark_verification_key_variable<ppT>::size_in_bits(const size_t input_size)
{
    const size_t num_G1 = 1 + (input_size + 1);
    const size_t num_G2 = 2;
    const size_t result = libsnark::G1_variable<ppT>::size_in_bits() * num_G1 + libsnark::G2_variable<ppT>::size_in_bits() * num_G2;
    printf("G1_size_in_bits = %zu, G2_size_in_bits = %zu\n", libsnark::G1_variable<ppT>::size_in_bits(), libsnark::G2_variable<ppT>::size_in_bits());
    printf("r1cs_gg_ppzksnark_verification_key_variable<ppT>::size_in_bits(%zu) = %zu\n", input_size, result);
    return result;
}

template<typename ppT>
libff::bit_vector r1cs_gg_ppzksnark_verification_key_variable<ppT>::get_verification_key_bits(const r1cs_gg_ppzksnark_verification_key<other_curve<ppT> > &r1cs_vk)
{
    typedef libff::Fr<ppT> FieldT;

    const size_t input_size_in_elts = r1cs_vk.ABC_g1.rest.indices.size();
    const size_t vk_size_in_bits = r1cs_gg_ppzksnark_verification_key_variable<ppT>::size_in_bits(input_size_in_elts);

    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable_array<FieldT> vk_bits;
    vk_bits.allocate(pb, vk_size_in_bits, "vk_bits");
    r1cs_gg_ppzksnark_verification_key_variable<ppT> vk(pb, vk_bits, input_size_in_elts, "translation_step_vk");
    vk.generate_r1cs_witness(r1cs_vk);

    return vk.get_bits();
}

template<typename ppT>
r1cs_gg_ppzksnark_preprocessed_r1cs_gg_ppzksnark_verification_key_variable<ppT>::r1cs_gg_ppzksnark_preprocessed_r1cs_gg_ppzksnark_verification_key_variable()
{
    // will be allocated outside
}

template<typename ppT>
r1cs_gg_ppzksnark_preprocessed_r1cs_gg_ppzksnark_verification_key_variable<ppT>::r1cs_gg_ppzksnark_preprocessed_r1cs_gg_ppzksnark_verification_key_variable(libsnark::protoboard<FieldT> &pb,
                                                                                                                                                const r1cs_gg_ppzksnark_verification_key<other_curve<ppT> > &r1cs_vk,
                                                                                                                                                const std::string &annotation_prefix)
{
    encoded_ABC_base.reset(new libsnark::G1_variable<ppT>(pb, r1cs_vk.ABC_g1.first, FMT(annotation_prefix, " encoded_ABC_base")));
    ABC_g1.resize(r1cs_vk.ABC_g1.rest.indices.size());
    for (size_t i = 0; i < r1cs_vk.ABC_g1.rest.indices.size(); ++i)
    {
        assert(r1cs_vk.ABC_g1.rest.indices[i] == i);
        ABC_g1[i].reset(new libsnark::G1_variable<ppT>(pb, r1cs_vk.ABC_g1.rest.values[i], FMT(annotation_prefix, " ABC_g1[%zu]", i)));
    }

    vk_alpha_g1_precomp.reset(new libsnark::G1_precomputation<ppT>(pb, r1cs_vk.alpha_g1, FMT(annotation_prefix, " vk_alpha_g1_precomp")));

    vk_generator_g2_precomp.reset(new libsnark::G2_precomputation<ppT>(pb, libff::G2<other_curve<ppT> >::one(), FMT(annotation_prefix, " vk_generator_g2_precomp")));
    vk_beta_g2_precomp.reset(new libsnark::G2_precomputation<ppT>(pb, r1cs_vk.beta_g2, FMT(annotation_prefix, " vk_beta_g2_precomp")));
    vk_delta_g2_precomp.reset(new libsnark::G2_precomputation<ppT>(pb, r1cs_vk.delta_g2, FMT(annotation_prefix, " vk_delta_g2_precomp")));
}

template<typename ppT>
r1cs_gg_ppzksnark_verifier_process_vk_gadget<ppT>::r1cs_gg_ppzksnark_verifier_process_vk_gadget(libsnark::protoboard<FieldT> &pb,
                                                                                          const r1cs_gg_ppzksnark_verification_key_variable<ppT> &vk,
                                                                                          r1cs_gg_ppzksnark_preprocessed_r1cs_gg_ppzksnark_verification_key_variable<ppT> &pvk,
                                                                                          const std::string &annotation_prefix) :
    gadget<FieldT>(pb, annotation_prefix),
    vk(vk),
    pvk(pvk)
{
    pvk.encoded_ABC_base = vk.encoded_IC_base;
    pvk.ABC_g1 = vk.encoded_IC_query;

    pvk.vk_alpha_g1_precomp.reset(new libsnark::G1_precomputation<ppT>());

    pvk.vk_generator_g2_precomp.reset(new libsnark::G2_precomputation<ppT>());
    pvk.vk_beta_g2_precomp.reset(new libsnark::G2_precomputation<ppT>());
    pvk.vk_delta_g2_precomp.reset(new libsnark::G2_precomputation<ppT>());

    compute_vk_alpha_g1_precomp.reset(new libsnark::precompute_G1_gadget<ppT>(pb, *vk.alpha_g1, *pvk.vk_alpha_g1_precomp, FMT(annotation_prefix, " compute_vk_alpha_g1_precomp")));

    pvk.vk_generator_g2_precomp.reset(new libsnark::G2_precomputation<ppT>(pb, libff::G2<other_curve<ppT> >::one(), FMT(annotation_prefix, " vk_generator_g2_precomp")));
    compute_vk_beta_g2_precomp.reset(new libsnark::precompute_G2_gadget<ppT>(pb, *vk.beta_g2, *pvk.vk_beta_g2_precomp, FMT(annotation_prefix, " compute_vk_beta_g2_precomp")));
    compute_vk_delta_g2_precomp.reset(new libsnark::precompute_G2_gadget<ppT>(pb, *vk.delta_g2, *pvk.vk_delta_g2_precomp, FMT(annotation_prefix, " compute_vk_delta_g2_precomp")));
}

template<typename ppT>
void r1cs_gg_ppzksnark_verifier_process_vk_gadget<ppT>::generate_r1cs_constraints()
{
    compute_vk_alpha_g1_precomp->generate_r1cs_constraints();

    compute_vk_beta_g2_precomp->generate_r1cs_constraints();
    compute_vk_delta_g2_precomp->generate_r1cs_constraints();
}

template<typename ppT>
void r1cs_gg_ppzksnark_verifier_process_vk_gadget<ppT>::generate_r1cs_witness()
{
    compute_vk_alpha_g1_precomp->generate_r1cs_witness();

    compute_vk_beta_g2_precomp->generate_r1cs_witness();
    compute_vk_delta_g2_precomp->generate_r1cs_witness();
}

template<typename ppT>
r1cs_gg_ppzksnark_online_verifier_gadget<ppT>::r1cs_gg_ppzksnark_online_verifier_gadget(libsnark::protoboard<FieldT> &pb,
                                                                                  const r1cs_gg_ppzksnark_preprocessed_r1cs_gg_ppzksnark_verification_key_variable<ppT> &pvk,
                                                                                  const libsnark::pb_variable_array<FieldT> &input,
                                                                                  const size_t elt_size,
                                                                                  const r1cs_gg_ppzksnark_proof_variable<ppT> &proof,
                                                                                  const libsnark::pb_variable<FieldT> &result,
                                                                                  const std::string &annotation_prefix) :
    gadget<FieldT>(pb, annotation_prefix),
    pvk(pvk),
    input(input),
    elt_size(elt_size),
    proof(proof),
    result(result),
    input_len(input.size())
{
    // 1. Accumulate input and store base in acc
    // See: https://github.com/clearmatics/libsnark/blob/master/libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.tcc#L568-L571
    acc.reset(new libsnark::G1_variable<ppT>(pb, FMT(annotation_prefix, " acc")));
    std::vector<libsnark::G1_variable<ppT> > IC_terms;
    for (size_t i = 0; i < pvk.ABC_g1.size(); ++i)
    {
        IC_terms.emplace_back(*(pvk.ABC_g1[i]));
    }
    accumulate_input.reset(new libsnark::G1_multiscalar_mul_gadget<ppT>(pb, *(pvk.encoded_ABC_base), input, elt_size, IC_terms, *acc, FMT(annotation_prefix, " accumulate_input")));

    // 2. Do the precomputations on the inputs of the pairings
    // See: https://github.com/clearmatics/libsnark/blob/master/libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.tcc#L588-L591
    //
    // 2.1 Allocate the results of theprecomputations
    proof_g_A_precomp.reset(new libsnark::G1_precomputation<ppT>());
    proof_g_B_precomp.reset(new libsnark::G2_precomputation<ppT>());
    proof_g_C_precomp.reset(new libsnark::G1_precomputation<ppT>());
    acc_precomp.reset(new libsnark::G1_precomputation<ppT>());
    // 2.2 Do the precomputations
    compute_proof_g_A_precomp.reset(new libsnark::precompute_G1_gadget<ppT>(pb, *(proof.g_A), *proof_g_A_precomp, FMT(annotation_prefix, " compute_proof_g_A_precomp")));
    compute_proof_g_B_precomp.reset(new libsnark::precompute_G1_gadget<ppT>(pb, *(proof.g_B), *proof_g_B_precomp, FMT(annotation_prefix, " compute_proof_g_B_precomp")));
    compute_proof_g_C_precomp.reset(new libsnark::precompute_G1_gadget<ppT>(pb, *(proof.g_C), *proof_g_C_precomp, FMT(annotation_prefix, " compute_proof_g_C_precomp")));
    compute_acc_precomp.reset(new libsnark::precompute_G1_gadget<ppT>(pb, *acc, *acc_precomp, FMT(annotation_prefix, " compute_acc_precomp")));
    
    // 3. Carry out the pairing checks to check QAP equation
    QAP_valid.allocate(pb, FMT(annotation_prefix, " QAP_valid"));
    check_QAP_valid.reset(new check_e_equals_eee_gadget<ppT>(
        pb,
        *(pvk.vk_alpha_g1_precomp),
        *(pvk.vk_beta_g1_precomp),
        *(acc_precomp),
        *(pvk.vk_generator_g2_precomp),
        *(proof_g_C_precomp),
        *(pvk.vk_delta_g2_precomp),
        *proof_g_A_precomp, // LHS
        *proof_g_B_precomp, // LHS
        QAP_valid,
        FMT(annotation_prefix, " check_QAP_valid")));
}

template<typename ppT>
void r1cs_gg_ppzksnark_online_verifier_gadget<ppT>::generate_r1cs_constraints()
{
    PROFILE_CONSTRAINTS(this->pb, "accumulate verifier input")
    {
        libff::print_indent(); printf("* Number of bits as an input to verifier gadget: %zu\n", input.size());
        accumulate_input->generate_r1cs_constraints();
    }

    PROFILE_CONSTRAINTS(this->pb, "rest of the verifier")
    {
        compute_proof_g_A_precomp->generate_r1cs_constraints();
        compute_proof_g_B_precomp->generate_r1cs_constraints();
        compute_proof_g_C_precomp->generate_r1cs_constraints();
        compute_acc_precomp->generate_r1cs_constraints();

        check_QAP_valid->generate_r1cs_constraints();
    }
}

template<typename ppT>
void r1cs_gg_ppzksnark_online_verifier_gadget<ppT>::generate_r1cs_witness()
{
    accumulate_input->generate_r1cs_witness();

    compute_proof_g_A_precomp->generate_r1cs_witness();
    compute_proof_g_B_precomp->generate_r1cs_witness();
    compute_proof_g_C_precomp->generate_r1cs_witness();
    compute_acc_precomp->generate_r1cs_witness();

    check_QAP_valid->generate_r1cs_witness();
}

template<typename ppT>
r1cs_gg_ppzksnark_verifier_gadget<ppT>::r1cs_gg_ppzksnark_verifier_gadget(libsnark::protoboard<FieldT> &pb,
                                                                    const r1cs_gg_ppzksnark_verification_key_variable<ppT> &vk,
                                                                    const libsnark::pb_variable_array<FieldT> &input,
                                                                    const size_t elt_size,
                                                                    const r1cs_gg_ppzksnark_proof_variable<ppT> &proof,
                                                                    const libsnark::pb_variable<FieldT> &result,
                                                                    const std::string &annotation_prefix) :
    gadget<FieldT>(pb, annotation_prefix)
{
    pvk.reset(new r1cs_gg_ppzksnark_preprocessed_r1cs_gg_ppzksnark_verification_key_variable<ppT>());
    compute_pvk.reset(new r1cs_gg_ppzksnark_verifier_process_vk_gadget<ppT>(pb, vk, *pvk, FMT(annotation_prefix, " compute_pvk")));
    online_verifier.reset(new r1cs_gg_ppzksnark_online_verifier_gadget<ppT>(pb, *pvk, input, elt_size, proof, result, FMT(annotation_prefix, " online_verifier")));
}

template<typename ppT>
void r1cs_gg_ppzksnark_verifier_gadget<ppT>::generate_r1cs_constraints()
{
    PROFILE_CONSTRAINTS(this->pb, "precompute pvk")
    {
        compute_pvk->generate_r1cs_constraints();
    }

    PROFILE_CONSTRAINTS(this->pb, "online verifier")
    {
        online_verifier->generate_r1cs_constraints();
    }
}

template<typename ppT>
void r1cs_gg_ppzksnark_verifier_gadget<ppT>::generate_r1cs_witness()
{
    compute_pvk->generate_r1cs_witness();
    online_verifier->generate_r1cs_witness();
}

} // libzecale

#endif // __ZECALE_R1CS_GG_PPZKSNARK_VERIFIER_GADGET_TCC__
