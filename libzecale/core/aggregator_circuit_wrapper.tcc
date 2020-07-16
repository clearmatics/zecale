// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_TCC__
#define __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_TCC__

#include <libzeth/zeth_constants.hpp>

using namespace libzeth;

namespace libzecale
{

template<
    typename nppT,
    typename wppT,
    typename nSnarkT,
    typename wVerifierT,
    size_t NumProofs>
typename wVerifierT::SnarkT::KeypairT aggregator_circuit_wrapper<
    nppT,
    wppT,
    nSnarkT,
    wVerifierT,
    NumProofs>::generate_trusted_setup() const
{
    libsnark::protoboard<libff::Fr<wppT>> pb;
    aggregator_gadget<nppT, wppT, nSnarkT, wVerifierT, NumProofs> g(pb);
    g.generate_r1cs_constraints();

    // Generate a verification and proving key (trusted setup)
    typename wSnarkT::KeypairT keypair = wSnarkT::generate_setup(pb);

    return keypair;
}

template<
    typename nppT,
    typename wppT,
    typename nSnarkT,
    typename wVerifierT,
    size_t NumProofs>
libsnark::protoboard<libff::Fr<wppT>> aggregator_circuit_wrapper<
    nppT,
    wppT,
    nSnarkT,
    wVerifierT,
    NumProofs>::get_constraint_system() const
{
    libsnark::protoboard<libff::Fr<wppT>> pb;
    aggregator_gadget<nppT, wppT, nSnarkT, wVerifierT, NumProofs> g(pb);
    g.generate_r1cs_constraints();
    return pb;
}

template<
    typename nppT,
    typename wppT,
    typename nSnarkT,
    typename wVerifierT,
    size_t NumProofs>
libzeth::extended_proof<wppT, typename wVerifierT::SnarkT>
aggregator_circuit_wrapper<nppT, wppT, nSnarkT, wVerifierT, NumProofs>::prove(
    typename nSnarkT::VerificationKeyT nested_vk,
    const std::array<const libzeth::extended_proof<nppT, nSnarkT> *, NumProofs>
        &extended_proofs,
    const typename wSnarkT::ProvingKeyT &aggregator_proving_key) const
{
    libsnark::protoboard<libff::Fr<wppT>> pb;

    aggregator_gadget<nppT, wppT, nSnarkT, wVerifierT, NumProofs> g(pb);
    g.generate_r1cs_constraints();
    // We pass to the witness generation function the elements defined
    // over the "other curve". See:
    // https://github.com/scipr-lab/libsnark/blob/master/libsnark/gadgetlib1/gadgets/verifiers/r1cs_ppzksnark_verifier_gadget.hpp#L98
    g.generate_r1cs_witness(nested_vk, extended_proofs);

    bool is_valid_witness = pb.is_satisfied();
    std::cout << "*** [DEBUG] Satisfiability result: " << is_valid_witness
              << " ***" << std::endl;

    typename wSnarkT::ProofT proof =
        wSnarkT::generate_proof(pb, aggregator_proving_key);
    libsnark::r1cs_primary_input<libff::Fr<wppT>> primary_input =
        pb.primary_input();

    // Instantiate an extended_proof from the proof we generated and the given
    // primary_input
    libzeth::extended_proof<wppT, wSnarkT> ext_proof =
        extended_proof<wppT, wSnarkT>(
            std::move(proof), std::move(primary_input));

    return ext_proof;
}

} // namespace libzecale

#endif // __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_TCC__
