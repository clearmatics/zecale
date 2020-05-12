// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_TCC__
#define __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_TCC__

#include <libzeth/snarks/default/default_snark.hpp>
#include <libzeth/zeth_constants.hpp>

using namespace libzeth;

namespace libzecale
{

template<
    typename nppT,
    typename wppT,
    typename nSnarkT,
    typename wSnarkT,
    size_t NumProofs>
wSnarkT::KeypairT aggregator_circuit_wrapper<
    nppT,
    wppT,
    nSnarkT,
    wSnarkT,
    NumProofs>::generate_trusted_setup() const
{
    std::cout << "[agg_circ_wrap -- generate_trusted_setup] DEBUG1" << std::endl;
    libsnark::protoboard<libff::Fr<wppT>> pb;

    std::cout << "[agg_circ_wrap -- generate_trusted_setup] DEBUG2" << std::endl;
    aggregator_gadget<nppT, wppT, NumProofs> g(pb);

    std::cout << "[agg_circ_wrap -- generate_trusted_setup] DEBUG3" << std::endl;
    g.generate_r1cs_constraints();

    // Generate a verification and proving key (trusted setup)
    // and write them in a file
    std::cout << "[agg_circ_wrap -- generate_trusted_setup] DEBUG4" << std::endl;
    wSnarkT::KeypairT keypair = wSnarkT::generate_setup(pb);

    return keypair;
}

template<
    typename nppT,
    typename wppT,
    typename nSnarkT,
    typename wSnarkT,
    size_t NumProofs>
libsnark::protoboard<libff::Fr<wppT>> aggregator_circuit_wrapper<
    nppT,
    wppT,
    nSnarkT,
    wSnarkT,
    NumProofs>::get_constraint_system() const
{
    libsnark::protoboard<libff::Fr<wppT>> pb;
    aggregator_gadget<nppT, wppT, NumProofs> g(pb);
    g.generate_r1cs_constraints();
    return pb;
}

template<
    typename nppT,
    typename wppT,
    typename nSnarkT,
    typename wSnarkT,
    size_t NumProofs>
libzeth::extended_proof<wppT, wSnarkT> aggregator_circuit_wrapper<
    nppT,
    wppT,
    nSnarkT,
    wSnarkT,
    NumProofs>::
    prove(
        nSnarkT::VerificationKeyT nested_vk,
        std::array<libzeth::extended_proof<nppT, nSnarkT>, NumProofs> extended_proofs,
        const wSnarkT::ProvingKeyT &aggregator_proving_key)
        const
{
    libsnark::protoboard<libff::Fr<wppT>> pb;

    aggregator_gadget<nppT, wppT, NumProofs> g(pb);
    g.generate_r1cs_constraints();
    // We pass to the witness generation function the elements defined
    // over the "other curve". See:
    // https://github.com/scipr-lab/libsnark/blob/master/libsnark/gadgetlib1/gadgets/verifiers/r1cs_ppzksnark_verifier_gadget.hpp#L98
    g.generate_r1cs_witness(nested_vk, extended_proofs);

    bool is_valid_witness = pb.is_satisfied();
    std::cout << "*** [DEBUG] Satisfiability result: " << is_valid_witness << " ***" << std::endl;

    wSnarkT::ProofT proof = libzeth::gen_proof<wppT>(pb, aggregator_proving_key);
    libsnark::r1cs_primary_input<libff::Fr<wppT>> primary_input = pb.primary_input();

    // Instantiate an extended_proof from the proof we generated and the given
    // primary_input
    libzeth::extended_proof<wppT, wSnarkT> ext_proof = extended_proof<wppT, wSnarkT>(proof, primary_input);

    return ext_proof;
}

} // namespace libzecale

#endif // __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_TCC__
