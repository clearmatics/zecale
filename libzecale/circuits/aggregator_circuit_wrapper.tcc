// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_TCC__
#define __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_TCC__

#include "libzecale/circuits/aggregator_circuit_wrapper.hpp"

#include <libzeth/zeth_constants.hpp>

using namespace libzeth;

namespace libzecale
{

template<
    typename wppT,
    typename wsnarkT,
    typename nverifierT,
    typename hashT,
    size_t NumProofs>
aggregator_circuit_wrapper<wppT, wsnarkT, nverifierT, hashT, NumProofs>::
    aggregator_circuit_wrapper(const size_t inputs_per_nested_proof)
    : _num_inputs_per_nested_proof(inputs_per_nested_proof), _pb()
{
    // The order of allocation here is important as it determines which inputs
    // are primary.

    // Input for hash of nested verification key.
    _nested_vk_hash.allocate(_pb, FMT("", "_nested_vk_hash"));

    // For each proof in a batch, allocate primary inputs and results. These
    // are the primary inputs. Note: both inputs and results will be
    // populated by the aggregator gadget.
    for (size_t i = 0; i < NumProofs; i++) {
        _nested_primary_inputs[i].allocate(
            _pb,
            _num_inputs_per_nested_proof,
            FMT("", "_nested_primary_inputs_bits[%zu]", i));

        _nested_proof_results[i].allocate(
            _pb, FMT("", "_nested_proof_results[%zu]", i));
    }

    // Set the number of primary inputs.
    const size_t total_primary_inputs =
        1 + NumProofs * (inputs_per_nested_proof + 1);
    _pb.set_input_sizes(total_primary_inputs);

    // Allocate vk and the intermediate bit representation
    const size_t vk_size_in_bits =
        verification_key_variable_gadget::size_in_bits(
            _num_inputs_per_nested_proof);
    libsnark::pb_variable_array<libff::Fr<wppT>> nested_vk_bits;
    nested_vk_bits.allocate(_pb, vk_size_in_bits, "nested_vk_bits");
    _nested_vk.reset(new verification_key_variable_gadget(
        _pb, nested_vk_bits, _num_inputs_per_nested_proof, "_nested_vk"));

    // Allocate proof variables.
    for (size_t i = 0; i < NumProofs; i++) {
        _nested_proofs[i].reset(
            new proof_variable_gadget(_pb, FMT("", "_nested_proofs[%zu]", i)));
    }

    // Nested verification key hash gadget
    _nested_vk_hash_gadget.reset(
        new verification_key_hash_gadget<wppT, nverifierT, hashT>(
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
        _nested_proof_results,
        "_aggregator_gadget"));

    // Initialize all constraints in the circuit.
    _nested_vk->generate_r1cs_constraints(true);
    for (size_t i = 0; i < NumProofs; ++i) {
        _nested_proofs[i]->generate_r1cs_constraints();
    }
    _nested_vk_hash_gadget->generate_r1cs_constraints();
    _aggregator_gadget->generate_r1cs_constraints();
}

template<
    typename wppT,
    typename wsnarkT,
    typename nverifierT,
    typename hashT,
    size_t NumProofs>
typename wsnarkT::keypair aggregator_circuit_wrapper<
    wppT,
    wsnarkT,
    nverifierT,
    hashT,
    NumProofs>::generate_trusted_setup() const
{
    // Generate a verification and proving key (trusted setup)
    return wsnarkT::generate_setup(_pb);
}

template<
    typename wppT,
    typename wsnarkT,
    typename nverifierT,
    typename hashT,
    size_t NumProofs>
const libsnark::protoboard<libff::Fr<wppT>>
    &aggregator_circuit_wrapper<wppT, wsnarkT, nverifierT, hashT, NumProofs>::
        get_constraint_system() const
{
    return _pb;
}

template<
    typename wppT,
    typename wsnarkT,
    typename nverifierT,
    typename hashT,
    size_t NumProofs>
libzeth::extended_proof<wppT, wsnarkT> aggregator_circuit_wrapper<
    wppT,
    wsnarkT,
    nverifierT,
    hashT,
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

#ifdef DEBUG
    // Check the validity of the circuit.
    bool is_valid_witness = _pb.is_satisfied();
    std::cout << "*** [DEBUG] Satisfiability result: " << is_valid_witness
              << " ***" << std::endl;
#endif

    // Return an extended_proof for the given witness.
    return extended_proof<wppT, wsnarkT>(
        wsnarkT::generate_proof(_pb, aggregator_proving_key),
        _pb.primary_input());
}

} // namespace libzecale

#endif // __ZECALE_CORE_AGGREGATOR_CIRCUIT_WRAPPER_TCC__
