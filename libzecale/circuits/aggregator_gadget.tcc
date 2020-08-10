// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_AGGREGATOR_GADGET_TCC__
#define __ZECALE_CIRCUITS_AGGREGATOR_GADGET_TCC__

#include "libzecale/circuits/aggregator_gadget.hpp"

namespace libzecale
{

template<typename wppT, typename nverifierT, size_t NumProofs>
aggregator_gadget<wppT, nverifierT, NumProofs>::aggregator_gadget(
    libsnark::protoboard<libff::Fr<wppT>> &pb,
    const size_t inputs_per_nested_proof,
    const std::string &annotation_prefix)
    : libsnark::gadget<libff::Fr<wppT>>(pb, annotation_prefix)
    , num_inputs_per_nested_proof(inputs_per_nested_proof)
{
    // Assert that a single input of a nested proof (element of
    // libff::Fr<nppT>) can be encoded in a single input of the wrapping proof
    // (element of libff::Fr<wppT>). This holds for all pairing chains we test,
    // but if it fails then nested inputs will need to be encoded over multiple
    // wrapper inputs. Unfortunately this check cannot be made statically.
    //
    // TODO: if num_bits are equal then also check that `libff::Fr<nppT>::mod`
    // <= `libff::Fr<wppT>::num_bits`.
    assert(libff::Fr<npp>::num_bits <= libff::Fr<wppT>::num_bits);

    // TODO: allocations of these "public" variables should happen outside of
    // the gadget.

    // Allocate the primary inputs and results first (these are expected to be
    // public).
    for (size_t i = 0; i < NumProofs; i++) {
        nested_primary_inputs[i].allocate(
            pb,
            num_inputs_per_nested_proof,
            FMT(this->annotation_prefix,
                " nested_primary_inputs_bits[%zu]",
                i));

        // Allocation of the results
        nested_proofs_results[i].allocate(
            pb, FMT(this->annotation_prefix, " nested_proofs_results[%zu]", i));
    }

    // TODO: Allocate (or accept) a variable to store the hash of the VK (to
    // avoid proofs generated with a malicious keypair).

    // Allocate the bit representation of the public inputs and initialize the
    // input packers.
    const size_t num_bits_per_input = libff::Fr<npp>::size_in_bits();
    const size_t num_input_bits_per_nested_proof =
        num_inputs_per_nested_proof * num_bits_per_input;
    for (size_t i = 0; i < NumProofs; i++) {
        nested_primary_inputs_bits[i].allocate(
            pb,
            num_input_bits_per_nested_proof,
            FMT(this->annotation_prefix,
                " nested_primary_inputs_bits[%zu]",
                i));

        nested_primary_input_packers.emplace_back(new input_packing_gadget(
            pb,
            nested_primary_inputs_bits[i],
            nested_primary_inputs[i],
            num_bits_per_input,
            FMT(annotation_prefix, " nested_input_packers[%zu]", i)));
    }

    // TODO: this should be done by the caller - not by a gadget.

    // Set the number of primary inputs.
    const size_t total_primary_inputs =
        NumProofs * (num_inputs_per_nested_proof + 1);
    pb.set_input_sizes(total_primary_inputs);

    // The nested VK is interpreted as an array of bits. The number of primary
    // inputs is required since it determines the size of the nested VK.
    const size_t vk_size_in_bits =
        verification_key_variable_gadget::size_in_bits(
            num_inputs_per_nested_proof);
    libsnark::pb_variable_array<libff::Fr<wppT>> nested_vk_bits;
    nested_vk_bits.allocate(
        pb, vk_size_in_bits, FMT(this->annotation_prefix, " vk_size_in_bits"));
    nested_vk.reset(new verification_key_variable_gadget(
        pb,
        nested_vk_bits,
        num_inputs_per_nested_proof,
        FMT(this->annotation_prefix, " nested_vk")));

    // Allocate proof variable gadgets
    for (size_t i = 0; i < NumProofs; i++) {
        nested_proofs[i].reset(new proof_variable_gadget(
            pb, FMT(this->annotation_prefix, " nested_proofs[%zu]", i)));
    }

    // Initialize the verifier gadgets
    for (size_t i = 0; i < NumProofs; i++) {
        verifiers[i].reset(new verifier_gadget(
            pb,
            *nested_vk,
            nested_primary_inputs_bits[i],
            libff::Fr<npp>::size_in_bits(),
            *nested_proofs[i],
            nested_proofs_results[i],
            FMT(this->annotation_prefix, " verifiers[%zu]", i)));
    }
}

template<typename wppT, typename nverifierT, size_t NumProofs>
void aggregator_gadget<wppT, nverifierT, NumProofs>::generate_r1cs_constraints()
{
    // Generate constraints for the verification key
    nested_vk->generate_r1cs_constraints(true); // ensure bitness

    // Generate constraints (including boolean-ness of the bit representations)
    // for input packers, nested proofs and the proof verifiers.
    for (size_t i = 0; i < NumProofs; i++) {
        nested_primary_input_packers[i]->generate_r1cs_constraints(true);
        nested_proofs[i]->generate_r1cs_constraints();
        verifiers[i]->generate_r1cs_constraints();
    }
}

template<typename wppT, typename nverifierT, size_t NumProofs>
void aggregator_gadget<wppT, nverifierT, NumProofs>::generate_r1cs_witness(
    const typename nsnark::verification_key &in_nested_vk,
    const std::array<const libzeth::extended_proof<npp, nsnark> *, NumProofs>
        &in_extended_proofs)
{
    // Witness the VK
    nested_vk->generate_r1cs_witness(in_nested_vk);

    for (size_t i = 0; i < NumProofs; i++) {
        // Witness the nested_proofs
        nested_proofs[i]->generate_r1cs_witness(
            in_extended_proofs[i]->get_proof());

        // Witness the nested_prinary_inputs. This is done by input values are
        // of type libff::Fr<nppT>. They are converted to bit arrays to
        // populate `nested_primary_inputs_bits`, andn then the
        // `nested_primary_input_packers` are used to convert to variables of
        // the circuit (elements of libff::Fr<wppT>).
        const libsnark::r1cs_primary_input<libff::Fr<npp>>
            &other_curve_primary_inputs =
                in_extended_proofs[i]->get_primary_inputs();
        const libff::bit_vector input_bits =
            libff::convert_field_element_vector_to_bit_vector<libff::Fr<npp>>(
                other_curve_primary_inputs);
        nested_primary_inputs_bits[i].fill_with_bits(this->pb, input_bits);
        nested_primary_input_packers[i]->generate_r1cs_witness_from_bits();

        // Witness the verifiers
        verifiers[i]->generate_r1cs_witness();
    }
}

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_AGGREGATOR_GADGET_TCC__
