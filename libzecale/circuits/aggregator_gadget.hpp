// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_AGGREGATOR_GADGET_HPP_
#define __ZECALE_CIRCUITS_AGGREGATOR_GADGET_HPP_

#include <libff/algebra/fields/field_utils.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libzeth/core/extended_proof.hpp>

namespace libzecale
{

/// We know that a proof (PGHR13 or GROTH16) is made of group elements (G1 or
/// G2) where the group elements belong to E/F_q (for G1) or E/F_q^n (for G2),
/// and `n` varies depending on the setting. As such, the coordinates of the
/// elements in the proof are defined over the field F_q. This field is
/// referred to as the "base field".
///
/// Primary inputs however are defined over F_r, referred to as the "scalar
/// field".
///
/// In the context of recursion, especially in the context of the MNT(4,6)-cycle
/// of pairing friendly elliptic curves, it is necessary to be careful with how
/// we refer to the fields. In fact, the base field used to define one curve
/// also constitutes the scalar field of the other curve, and vice-and-versa.
/// This represents a cycle.
///
/// In fact, in the context of Zeth proof "aggregation", we have the following:
/// |              |      Zeth proof      |    Aggregator proof    |
/// ----------------------------------------------------------------
/// |  Base field  |  Pi_z (over Fq)      |     Pi_a (over Fr)     |
/// | Scalar field |  PrimIn_z (over Fr)  |   PrimIn_a (over Fq)   |
template<
    typename nppT,
    typename wppT,
    typename nsnarkT,
    typename wverifierT,
    size_t NumProofs>
class aggregator_gadget : libsnark::gadget<libff::Fr<wppT>>
{
private:
    using verifier_gadget = typename wverifierT::verifier_gadget;
    using proof_variable_gadget = typename wverifierT::proof_variable_gadget;
    using verification_key_variable_gadget =
        typename wverifierT::verification_key_variable_gadget;

    const size_t num_inputs_per_nested_proof;

    std::array<std::shared_ptr<verifier_gadget>, NumProofs> verifiers;

    /// ---- Primary inputs (public) ---- //
    ///
    /// The primary inputs lie in the scalar field `libff::Fr<wppT>`
    ///
    /// The Zeth primary inputs associated with the Zeth proofs in the witness
    /// We need to convert them to `libff::Fr<wppT>` elements so that they
    /// constitute valid values for the wires of our circuit which is defined
    /// over `libff::Fr<wppT>`
    std::array<libsnark::pb_variable_array<libff::Fr<wppT>>, NumProofs>
        nested_primary_inputs;

    /// The array of the results of the verifiers
    std::array<libsnark::pb_variable<libff::Fr<wppT>>, NumProofs>
        nested_proofs_results;

    /// ---- Auxiliary inputs (private) ---- //
    ///
    /// The auxiliary inputs lie in the scalar field `libff::Fr<wppT>`
    ///
    /// A proof of computational integrity is sufficient, **we don't need ZK
    /// here** We move the proofs to verify as part of the auxiliary input
    /// though in order to keep the amount of info sent on-chain as small as
    /// possible. On-chain we only need to have access to the Zeth primary
    /// inputs in order to change the state of the Mixer accordingly. The Zeth
    /// proofs are not strictly necessary.
    ///
    /// The `NumProofs` proofs to verify
    /// 1. The Zeth proofs to verify in this circuit
    /// The Zeth proofs are defined over `nppT`
    /// This is fine because the coordinates of the proofs lie over the base
    /// field used to define nppT and this base field is the scalar
    /// field `libff::Fr<wppT>` by the property of the cycle we use. Hence
    /// the proofs are already valid wire assignments for the aggregation
    /// circuit.
    ///
    /// CAREFUL:
    /// as shown on the link below, the `r1cs_ppzksnark_proof_variable` is of
    /// type `r1cs_ppzksnark_proof_variable<curve>` BUT it takes
    /// `r1cs_ppzksnark_proof<other_curve<ppT> >` for the witness!
    /// https://github.com/scipr-lab/libsnark/blob/master/libsnark/gadgetlib1/gadgets/verifiers/r1cs_ppzksnark_verifier_gadget.hpp#L55
    ///
    std::array<std::shared_ptr<proof_variable_gadget>, NumProofs> nested_proofs;

    /// Likewise, this is not strictly necessary, but we do not need to pass the
    /// VK to the contract everytime as such we move it to the auxiliary inputs
    ///
    /// (Nested) verification key - VK used to verify Zeth proofs
    /// This verification key is made of elements of `nppT`, which
    /// again, makes sense because elements of `nppT` are defined over
    /// `E/BaseFieldZethT`, and `BaseFieldZethT` is `libff::Fr<wppT>`
    /// which is where we do arithmetic here
    std::shared_ptr<verification_key_variable_gadget> nested_vk;

public:
    // Make sure that we do not exceed the number of proofs
    // specified in zeth's configuration file (see: zeth.h file)
    // BOOST_STATIC_ASSERT(NumInputs <= ZETH_NUM_PROOFS_INPUT);

    // Primary inputs are packed to be added to the extended proof and given to
    // the verifier on-chain
    aggregator_gadget(
        libsnark::protoboard<libff::Fr<wppT>> &pb,
        const size_t inputs_per_nested_proof,
        const std::string &annotation_prefix = "aggregator_gadget");

    // Check:
    // - ZERO
    // - Generate the constraints for the VK
    // - Generate the constraints for the nested proofs
    // - Generate the constraints for the verifiers
    void generate_r1cs_constraints();

    // In the witness we manipulate elements defined over the "other curve"
    // see:
    // https://github.com/scipr-lab/libsnark/blob/master/libsnark/gadgetlib1/gadgets/verifiers/r1cs_ppzksnark_verifier_gadget.hpp#L98
    void generate_r1cs_witness(
        const typename nsnarkT::verification_key &in_nested_vk,
        const std::array<
            const libzeth::extended_proof<nppT, nsnarkT> *,
            NumProofs> &in_extended_proofs);
};

} // namespace libzecale

#include "libzecale/circuits/aggregator_gadget.tcc"

#endif // __ZECALE_CIRCUITS_AGGREGATOR_GADGET_HPP_
