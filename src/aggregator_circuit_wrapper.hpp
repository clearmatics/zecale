// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_AGGREGATOR_CIRCUIT_WRAPPER_HPP__
#define __ZECALE_AGGREGATOR_CIRCUIT_WRAPPER_HPP__

#include "circuits/aggregator.tcc"

#include <libzeth/libsnark_helpers/extended_proof.hpp>
#include <libzeth/libsnark_helpers/libsnark_helpers.hpp>

// zkSNARK specific imports, and templates instantiation
#include <libzeth/snarks_core_imports.hpp>
#include <libzeth/snarks_alias.hpp>

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
class aggregator_circuit_wrapper
{
public:
    typedef libff::Fr<AggregateProofCurve> ScalarFieldAggregatorT;

    boost::filesystem::path setup_path;
    std::shared_ptr<
        aggregator_gadget<ZethProofCurve, AggregateProofCurve, NumProofs>>
        aggregator_g;

    aggregator_circuit_wrapper(const boost::filesystem::path setup_path = "")
        : setup_path(setup_path){};

    // Generate the trusted setup
    libzeth::keyPairT<AggregateProofCurve> generate_trusted_setup()
        const;

#ifdef DEBUG
    // Used to debug the constraint system
    // Exports the r1cs to json and write to debug folder
    void dump_constraint_system(boost::filesystem::path file_path) const;
#endif

    // Generate a proof and returns an extended proof
    extended_proof<AggregateProofCurve> prove(
        libzeth::verificationKeyT<ZethProofCurve> nested_vk,
        std::array<libzeth::extended_proof<ZethProofCurve>, NumProofs>
            extended_proofs,
        const libzeth::provingKeyT<AggregateProofCurve>
            &aggregator_proving_key) const;
};

} // namespace libzecale

#include "aggregator_circuit_wrapper.tcc"

#endif // __ZECALE_AGGREGATOR_CIRCUIT_WRAPPER_HPP__
