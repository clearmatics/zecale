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
    const verification_key_variable_gadget &vk,
    const std::array<libsnark::pb_variable_array<libff::Fr<wppT>>, NumProofs>
        &inputs,
    const std::array<std::shared_ptr<proof_variable_gadget>, NumProofs> &proofs,
    const std::array<libsnark::pb_variable<libff::Fr<wppT>>, NumProofs>
        &proof_results,
    const std::string &annotation_prefix)
    : libsnark::gadget<libff::Fr<wppT>>(pb, annotation_prefix)
    , num_inputs_per_nested_proof(vk.input_size)
    , nested_primary_inputs(inputs)
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
            inputs[i],
            num_bits_per_input,
            FMT(annotation_prefix, " nested_input_packers[%zu]", i)));
    }

    // Initialize the verifier gadgets
    for (size_t i = 0; i < NumProofs; i++) {
        verifiers[i].reset(new verifier_gadget(
            pb,
            vk,
            nested_primary_inputs_bits[i],
            libff::Fr<npp>::size_in_bits(),
            *proofs[i],
            proof_results[i],
            FMT(this->annotation_prefix, " verifiers[%zu]", i)));
    }
}

template<typename wppT, typename nverifierT, size_t NumProofs>
void aggregator_gadget<wppT, nverifierT, NumProofs>::generate_r1cs_constraints()
{
    // Generate constraints (including boolean-ness of the bit representations)
    // for input packers, nested proofs and the proof verifiers.
    for (size_t i = 0; i < NumProofs; i++) {
        nested_primary_input_packers[i]->generate_r1cs_constraints(true);
        verifiers[i]->generate_r1cs_constraints();
    }
}

template<typename wppT, typename nverifierT, size_t NumProofs>
void aggregator_gadget<wppT, nverifierT, NumProofs>::generate_r1cs_witness(
    const std::array<
        const libsnark::r1cs_primary_input<libff::Fr<npp>> *,
        NumProofs> &nested_inputs)
{
    for (size_t i = 0; i < NumProofs; i++) {
        // Witness the nested_primary_inputs. This is done by input values are
        // of type libff::Fr<nppT>. They are converted to bit arrays to
        // populate `nested_primary_inputs_bits`, and the
        // `nested_primary_input_packers` are used to convert to variables of
        // the circuit (elements of libff::Fr<wppT>).
        const libsnark::r1cs_primary_input<libff::Fr<npp>>
            &other_curve_primary_inputs = *(nested_inputs[i]);
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
