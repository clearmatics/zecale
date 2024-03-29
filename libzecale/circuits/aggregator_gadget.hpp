// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_AGGREGATOR_GADGET_HPP_
#define __ZECALE_CIRCUITS_AGGREGATOR_GADGET_HPP_

#include <libff/algebra/fields/field_utils.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/pairing_params.hpp>
#include <libzeth/core/extended_proof.hpp>

namespace libzecale
{

/// Gadget that aggregates a batch of nested proofs, creating a single wrapping
/// proof the validity (or possible invalidity) of each proof in the batch.
///
/// A note about fields:
/// A proof (PGHR13 or GROTH16) is made of group elements
/// (G1 or G2 for some pairing) where the group elements belong to E/F_q (for
/// G1) or E/F_q^n (for G2), and `n` varies depending on the setting. As such,
/// the coordinates of the elements in the proof are defined over the field
/// F_q. This field is referred to as the "base field". Primary inputs however
/// are defined over F_r, referred to as the "scalar field".
///
/// In order to aggregate proofs, we require that the base field of the curve
/// used in the nested proof (nppT here) be the scalar field for the wrapping
/// pairing (wppT).
template<typename wppT, typename nverifierT, size_t NumProofs>
class aggregator_gadget : libsnark::gadget<libff::Fr<wppT>>
{
private:
    using npp = libsnark::other_curve<wppT>;
    using nsnark = typename nverifierT::snark;
    using process_verification_key_gadget =
        typename nverifierT::process_verification_key_gadget;
    using online_verifier_gadget = typename nverifierT::online_verifier_gadget;
    using proof_variable_gadget = typename nverifierT::proof_variable_gadget;
    using verification_key_variable_gadget =
        typename nverifierT::verification_key_variable_gadget;
    using processed_verification_key_variable_gadget =
        typename nverifierT::processed_verification_key_variable_gadget;
    using input_packing_gadget = libsnark::multipacking_gadget<libff::Fr<wppT>>;

    const size_t num_inputs_per_nested_proof;

    // TODO: Remove unused variables

    /// Processed verification key
    processed_verification_key_variable_gadget processed_vk;

    // Required in order to generate the bit strings from instance value.
    std::array<libsnark::pb_variable_array<libff::Fr<wppT>>, NumProofs>
        nested_primary_inputs;

    /// The binary representation of inputs to the nested Fr<nppT> inputs. Each
    /// entry is the concatenation of all bits of the inputs to the a single
    /// nested proof. (Expected to be an auxiliary input).
    std::array<libsnark::pb_variable_array<libff::Fr<wppT>>, NumProofs>
        nested_primary_inputs_bits;

    /// Verification key processor
    process_verification_key_gadget vk_processor;

    /// Gadgets checking the binary representation of the nested inputs.
    std::vector<std::shared_ptr<input_packing_gadget>>
        nested_primary_input_packers;

    // Gadgets that verify the proofs and inputs against nested_vk.
    std::array<std::shared_ptr<online_verifier_gadget>, NumProofs> verifiers;

public:
    aggregator_gadget(
        libsnark::protoboard<libff::Fr<wppT>> &pb,
        const verification_key_variable_gadget &vk,
        const std::array<
            libsnark::pb_variable_array<libff::Fr<wppT>>,
            NumProofs> &inputs,
        const std::array<std::shared_ptr<proof_variable_gadget>, NumProofs>
            &proofs,
        const std::array<libsnark::pb_variable<libff::Fr<wppT>>, NumProofs>
            &proof_results,
        const std::string &annotation_prefix);

    void generate_r1cs_constraints();

    /// Set the wppT scalar variables based on the nested verification key,
    /// proofs and inputs in nppT.
    void generate_r1cs_witness(
        const std::array<
            const libsnark::r1cs_primary_input<libff::Fr<npp>> *,
            NumProofs> &in_extended_proofs);
};

} // namespace libzecale

#include "libzecale/circuits/aggregator_gadget.tcc"

#endif // __ZECALE_CIRCUITS_AGGREGATOR_GADGET_HPP_
