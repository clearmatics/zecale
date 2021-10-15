// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CORE_AGGREGATOR_CIRCUIT_TCC__
#define __ZECALE_CORE_AGGREGATOR_CIRCUIT_TCC__

#include "libzecale/circuits/aggregator_circuit.hpp"

#include <libzeth/zeth_constants.hpp>

using namespace libzeth;

namespace libzecale
{

template<typename wppT, typename wsnarkT, typename nverifierT, size_t NumProofs>
aggregator_circuit<wppT, wsnarkT, nverifierT, NumProofs>::aggregator_circuit(
    const size_t inputs_per_nested_proof)
    : _num_inputs_per_nested_proof(inputs_per_nested_proof), _pb()
{
    // The order of allocation here is important as it determines which inputs
    // are primary.

    // Input for hash of nested verification key.
    _nested_vk_hash.allocate(_pb, FMT("", "_nested_vk_hash"));

    // Packed results (populated by the packer)
    _nested_proof_results.allocate(_pb, FMT("", "_nested_proof_results"));

    // Allocate nested primary inputs (populated by aggregator).
    for (size_t i = 0; i < NumProofs; i++) {
        _nested_primary_inputs[i].allocate(
            _pb,
            _num_inputs_per_nested_proof,
            FMT("", "_nested_primary_inputs_bits[%zu]", i));
    }

    // Set the number of primary inputs.
    const size_t total_primary_inputs = num_primary_inputs();
    _pb.set_input_sizes(total_primary_inputs);

    // Allocate the unpacked nested proof verification results (populated by
    // aggregator, consumed by results packer.
    for (size_t i = 0; i < NumProofs; i++) {
        _nested_proof_results_unpacked[i].allocate(
            _pb, FMT("", "_nested_proof_results[%zu]", i));
    }

    // Allocate vk and the intermediate bit representation
    _nested_vk.reset(new verification_key_variable_gadget(
        _pb, _num_inputs_per_nested_proof, "_nested_vk"));

    // Allocate proof variables.
    for (size_t i = 0; i < NumProofs; i++) {
        _nested_proofs[i].reset(
            new proof_variable_gadget(_pb, FMT("", "_nested_proofs[%zu]", i)));
    }

    // Nested verification key hash gadget
    _nested_vk_hash_gadget.reset(
        new verification_key_hash_gadget<wppT, nverifierT>(
            _pb,
            *_nested_vk,
            _nested_vk_hash,
            FMT("", "_nested_vk_hash_gadget")));

    // Aggregator gadget
    _aggregator_gadget.reset(new aggregator_gadget<wppT, nverifierT, NumProofs>(
        _pb,
        *_nested_vk,
        _nested_primary_inputs,
        _nested_proofs,
        _nested_proof_results_unpacked,
        "_aggregator_gadget"));

    // Results packer gadgets
    libsnark::pb_linear_combination_array<libff::Fr<wppT>>
        unpacked_results_array(NumProofs);
    for (size_t i = 0; i < NumProofs; ++i) {
        unpacked_results_array[i] = _nested_proof_results_unpacked[i];
    }

    _nested_proof_results_packer.reset(
        new libsnark::packing_gadget<libff::Fr<wppT>>(
            _pb,
            unpacked_results_array,
            _nested_proof_results,
            "_nested_proof_results_packer"));

    // Initialize all constraints in the circuit.
    for (size_t i = 0; i < NumProofs; ++i) {
        _nested_proofs[i]->generate_r1cs_constraints();
    }
    _nested_vk_hash_gadget->generate_r1cs_constraints();
    _aggregator_gadget->generate_r1cs_constraints();
    _nested_proof_results_packer->generate_r1cs_constraints(false);
}

template<typename wppT, typename wsnarkT, typename nverifierT, size_t NumProofs>
typename wsnarkT::keypair aggregator_circuit<
    wppT,
    wsnarkT,
    nverifierT,
    NumProofs>::generate_trusted_setup() const
{
    // Generate a verification and proving key (trusted setup)
    return wsnarkT::generate_setup(_pb);
}

template<typename wppT, typename wsnarkT, typename nverifierT, size_t NumProofs>
const libsnark::r1cs_constraint_system<libff::Fr<wppT>>
    &aggregator_circuit<wppT, wsnarkT, nverifierT, NumProofs>::
        get_constraint_system() const
{
    return _pb.get_constraint_system();
}

template<typename wppT, typename wsnarkT, typename nverifierT, size_t NumProofs>
libzeth::extended_proof<wppT, wsnarkT> aggregator_circuit<
    wppT,
    wsnarkT,
    nverifierT,
    NumProofs>::
    prove(
        const typename nsnark::verification_key &nested_vk,
        const std::array<
            const libzeth::extended_proof<npp, nsnark> *,
            NumProofs> &extended_proofs,
        const typename wsnarkT::proving_key &aggregator_proving_key)
{
    // Witness the proofs and construct the array of primary inputs (in npp).
    // These will be used to populate _nested_primary_inputs.
    std::array<const libsnark::r1cs_primary_input<libff::Fr<npp>> *, NumProofs>
        nested_inputs{};
    for (size_t i = 0; i < NumProofs; ++i) {
        const libzeth::extended_proof<npp, nsnark> &ep = *(extended_proofs[i]);
        if (ep.get_primary_inputs().size() != _num_inputs_per_nested_proof) {
            throw std::runtime_error(
                "attempt to aggregate proof with invalid number of inputs");
        }

        nested_inputs[i] = &ep.get_primary_inputs();
        _nested_proofs[i]->generate_r1cs_witness(ep.get_proof());
    }

    // Witness the verification key
    _nested_vk->generate_r1cs_witness(nested_vk);

    // Witness hash of verification keypair
    _nested_vk_hash_gadget->generate_r1cs_witness();

    // Pass the input values (in npp) to the aggregator gadget.
    _aggregator_gadget->generate_r1cs_witness(nested_inputs);

    // Witness the packed results
    _nested_proof_results_packer->generate_r1cs_witness_from_bits();

#ifdef DEBUG
    // Check the validity of the circuit.
    bool is_valid_witness = _pb.is_satisfied();
    std::cout << "*** [DEBUG] Satisfiability result: " << is_valid_witness
              << " ***" << std::endl;
#endif

    // Return an extended_proof for the given witness.
    return extended_proof<wppT, wsnarkT>(
        wsnarkT::generate_proof(aggregator_proving_key, _pb),
        _pb.primary_input());
}

template<typename wppT, typename wsnarkT, typename nverifierT, size_t NumProofs>
size_t aggregator_circuit<wppT, wsnarkT, nverifierT, NumProofs>::
    num_primary_inputs() const
{
    // Compute the total number of primary inputs for a circuit of this type,
    // including leading vk_hash, results and nested primary inputs (see
    // aggregator_circuit.hpp for full layout).
    return 1 + 1 + NumProofs * _num_inputs_per_nested_proof;
}

} // namespace libzecale

#endif // __ZECALE_CORE_AGGREGATOR_CIRCUIT_TCC__
