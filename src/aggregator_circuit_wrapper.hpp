#ifndef __ZECALE_AGGREGATOR_CIRCUIT_WRAPPER_HPP__
#define __ZECALE_AGGREGATOR_CIRCUIT_WRAPPER_HPP__

#include <zeth/src/circuits/aggregator.tcc>
#include <zeth/src/libsnark_helpers/libsnark_helpers.hpp>

// We directly import PGHR13 related files as we only support this SNARK for now
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
// zkSNARK specific imports
#include <zeth/snarks_core_imports.hpp>

using namespace libzeth;

namespace libzecale
{

template<
    typename ZethProofCurve, // Curve over which we "prove" Zeth state transitions => E/Fq
    typename AggregateProofCurve, // Curve over which we "prove" succesfull verication of the nested proofs batch => E/Fr
    size_t NumProofs>
class aggregator_circuit_wrapper
{
public:
    typedef libff::Fr<AggregateProofCurve> ScalarFieldAggregatorT;

    boost::filesystem::path setup_path;
    std::shared_ptr<aggregator_gadget<
        ZethProofCurve,
        AggregateProofCurve,
        NumProofs>
    > aggregator_g;

    aggregator_circuit_wrapper(const boost::filesystem::path setup_path = "")
        : setup_path(setup_path){};

    // Generate the trusted setup
    libsnark::r1cs_ppzksnark_keypair<AggregateProofCurve> generate_trusted_setup() const;

#ifdef DEBUG
    // Used to debug the constraint system
    // Exports the r1cs to json and write to debug folder
    void dump_constraint_system(boost::filesystem::path file_path) const;
#endif

    // Generate a proof and returns an extended proof
    extended_proof<AggregateProofCurve> prove(
        libsnark::r1cs_ppzksnark_verification_key<ZethProofCurve> nested_vk,
        std::array<libzeth::extended_proof<ZethProofCurve>, NumProofs> extended_proofs,
        const libsnark::r1cs_ppzksnark_proving_key<AggregateProofCurve> &aggregator_proving_key) const;
};

} // namespace libzecale

#include "aggregator_circuit_wrapper.tcc"

#endif // __ZECALE_AGGREGATOR_CIRCUIT_WRAPPER_HPP__
