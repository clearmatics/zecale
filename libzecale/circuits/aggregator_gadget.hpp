// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_AGGREGATOR_GADGET_HPP_
#define __ZECALE_CIRCUITS_AGGREGATOR_GADGET_HPP_

#include "libzecale/circuits/pairing/pairing_params.hpp"

#include <libff/algebra/fields/field_utils.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
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
    using npp = other_curve<wppT>;
    using nsnark = typename nverifierT::snark;
    using verifier_gadget = typename nverifierT::verifier_gadget;
    using proof_variable_gadget = typename nverifierT::proof_variable_gadget;
    using verification_key_variable_gadget =
        typename nverifierT::verification_key_variable_gadget;
    using input_packing_gadget = libsnark::multipacking_gadget<libff::Fr<wppT>>;

    const size_t num_inputs_per_nested_proof;

    /// The nested primary inputs lie in the scalar field `libff::Fr<nppT>`,
    /// and must be represented as elements of `libff::Fr<wppT>` for use in the
    /// wrapper proof. This gadget assumes that libff::Fr<nppT> can be
    /// represented as a single `libff::Fr<wppT>`, and internally asserts this.
    /// (Expected to be primary inputs to the wrapping statement).
    std::array<libsnark::pb_variable_array<libff::Fr<wppT>>, NumProofs>
        nested_primary_inputs;

    /// The array of the results of the verifiers. 1 meaning that the nested
    /// proof is valid, 0 meaning it may not be valid. (Expected to be a
    /// primary inputs to the wrapping statement).
    std::array<libsnark::pb_variable<libff::Fr<wppT>>, NumProofs>
        nested_proofs_results;

    /// The binary representation of inputs to the nested Fr<nppT> inputs. Each
    /// entry is the concatenation of all bits of the inputs to the a single
    /// nested proof. (Expected to be an auxiliary input).
    std::array<libsnark::pb_variable_array<libff::Fr<wppT>>, NumProofs>
        nested_primary_inputs_bits;

    /// Gadgets checking the binary representation of the nested inputs.
    std::vector<std::shared_ptr<input_packing_gadget>>
        nested_primary_input_packers;

    /// The nested proofs (defined over `nppT`) to verify. As above, these are
    /// verified by virtue of the fact that the base field for nppT is the
    /// scalar field of wppT. These gadgets take a witness in the form of a
    /// proof with group elements from nppT and represent them as variables in
    /// the wppT scalar field. (Variables are expected to be auxiliary inputs).
    std::array<std::shared_ptr<proof_variable_gadget>, NumProofs> nested_proofs;

    /// (Nested) verification key used to verify the nested proofs. Consists of
    /// group elements of `nppT`, which again, can be represented using
    /// elements in `libff::Fr<wppT>`.
    std::shared_ptr<verification_key_variable_gadget> nested_vk;

    /// Gadgets that verify the proofs and inputs against nested_vk.
    std::array<std::shared_ptr<verifier_gadget>, NumProofs> verifiers;

public:
    aggregator_gadget(
        libsnark::protoboard<libff::Fr<wppT>> &pb,
        const size_t inputs_per_nested_proof,
        const std::string &annotation_prefix = "aggregator_gadget");

    void generate_r1cs_constraints();

    /// Set the wppT scalar variables based on the nested verification key,
    /// proofs and inputs in nppT.
    void generate_r1cs_witness(
        const typename nsnark::verification_key &in_nested_vk,
        const std::array<
            const libzeth::extended_proof<npp, nsnark> *,
            NumProofs> &in_extended_proofs);
};

} // namespace libzecale

#include "libzecale/circuits/aggregator_gadget.tcc"

#endif // __ZECALE_CIRCUITS_AGGREGATOR_GADGET_HPP_
