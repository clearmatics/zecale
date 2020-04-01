// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_AGGREGATOR_CIRCUIT_WRAPPER_TCC__
#define __ZECALE_AGGREGATOR_CIRCUIT_WRAPPER_TCC__

#include <libzeth/snarks_alias.hpp>
#include <libzeth/zeth.h>

using namespace libzeth;

namespace libzecale
{

template<
    typename ZethProofCurve,      // Curve over which we "prove" Zeth state
                                  // transitions => E/Fq
    typename AggregateProofCurve, // Curve over which we "prove" succesfull
                                  // verication of the nested proofs batch =>
                                  // E/Fr
    size_t NumProofs>
keyPairT<AggregateProofCurve> aggregator_circuit_wrapper<
    ZethProofCurve,
    AggregateProofCurve,
    NumProofs>::generate_trusted_setup() const
{
    std::cout << "[Aggregator_circuit_wrapper -- generate_trusted_setup] DEBUG1"
              << std::endl;
    libsnark::protoboard<ScalarFieldAggregatorT> pb;

    std::cout << "[Aggregator_circuit_wrapper -- generate_trusted_setup] DEBUG2"
              << std::endl;
    aggregator_gadget<ZethProofCurve, AggregateProofCurve, NumProofs> g(pb);
    std::cout
        << "[Aggregator_circuit_wrapper -- generate_trusted_setup] DEBUG2.1"
        << std::endl;
    g.generate_r1cs_constraints();

    // Generate a verification and proving key (trusted setup)
    // and write them in a file
    std::cout << "[Aggregator_circuit_wrapper -- generate_trusted_setup] DEBUG3"
              << std::endl;
    keyPairT<AggregateProofCurve> keypair =
        gen_trusted_setup<AggregateProofCurve>(pb);
    // TODO: the function below only works with `libff::alt_bn128_G1` so it is
    // commented out to make the build pass wiht the MNT curves
    // write_setup<AggregateProofCurve>(keypair, this->setup_path);

    return keypair;
}

#ifdef DEBUG
template<
    typename ZethProofCurve,      // Curve over which we "prove" Zeth state
                                  // transitions => E/Fq
    typename AggregateProofCurve, // Curve over which we "prove" succesfull
                                  // verication of the nested proofs batch =>
                                  // E/Fr
    size_t NumProofs>
void aggregator_circuit_wrapper<
    ZethProofCurve,
    AggregateProofCurve,
    NumProofs>::dump_constraint_system(boost::filesystem::path file_path) const
{
    libsnark::protoboard<ScalarFieldAggregatorT> pb;
    aggregator_gadget<ZethProofCurve, AggregateProofCurve, NumProofs> g(pb);
    g.generate_r1cs_constraints();

    // Write the constraint system in the default location
    r1cs_to_json<AggregateProofCurve>(pb, file_path);
}
#endif

template<
    typename ZethProofCurve,      // Curve over which we "prove" Zeth state
                                  // transitions => E/Fq
    typename AggregateProofCurve, // Curve over which we "prove" succesfull
                                  // verication of the nested proofs batch =>
                                  // E/Fr
    size_t NumProofs>
extended_proof<AggregateProofCurve> aggregator_circuit_wrapper<
    ZethProofCurve,
    AggregateProofCurve,
    NumProofs>::
    prove(
        libsnark::r1cs_ppzksnark_verification_key<ZethProofCurve> nested_vk,
        std::array<libzeth::extended_proof<ZethProofCurve>, NumProofs>
            extended_proofs,
        const provingKeyT<AggregateProofCurve> &aggregator_proving_key) const
{
    libsnark::protoboard<ScalarFieldAggregatorT> pb;

    aggregator_gadget<ZethProofCurve, AggregateProofCurve, NumProofs> g(pb);
    g.generate_r1cs_constraints();
    // We pass to the witness generation function the elements defined
    // over the "other curve"
    // see:
    // https://github.com/scipr-lab/libsnark/blob/master/libsnark/gadgetlib1/gadgets/verifiers/r1cs_ppzksnark_verifier_gadget.hpp#L98
    g.generate_r1cs_witness(nested_vk, extended_proofs);

    bool is_valid_witness = pb.is_satisfied();
    std::cout << "******* [DEBUG] Satisfiability result: " << is_valid_witness
              << " *******" << std::endl;

    proofT<AggregateProofCurve> proof =
        libzeth::gen_proof<AggregateProofCurve>(pb, aggregator_proving_key);
    libsnark::r1cs_primary_input<libff::Fr<AggregateProofCurve>> primary_input =
        pb.primary_input();

    // Instantiate an extended_proof from the proof we generated and the given
    // primary_input
    extended_proof<AggregateProofCurve> ext_proof =
        extended_proof<AggregateProofCurve>(proof, primary_input);

    // Write the extended proof in a file (Default path is taken if not
    // specified)
    // TODO: the function below only works for `libff::alt_bn128_G1` so it is
    // commented out to make the build pass with the mnt curves
    // ext_proof.write_extended_proof();

    return ext_proof;
}

} // namespace libzecale

#endif // __ZECALE_AGGREGATOR_CIRCUIT_WRAPPER_TCC__
