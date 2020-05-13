// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_AGGREGATOR_TCC__
#define __ZECALE_CIRCUITS_AGGREGATOR_TCC__

// Contains the circuits for the notes
#include <libzeth/circuits/notes/note.hpp>
#include <libzeth/core/joinsplit_input.hpp>

// Contains the definitions of the constants we use
#include <boost/static_assert.hpp>
#include <libzeth/core/merkle_tree_field.hpp>
#include <libzeth/zeth_constants.hpp>

#include <libzeth/snarks/default/default_snark.hpp>

// Include the verifier gadgets
#include "libzecale/circuits/verifier_gagdet_imports.hpp"

#include <libff/algebra/fields/field_utils.hpp>

using namespace libzeth;

// TODO: Templatize this file, and use similar apparoach as in
// Zeth to import the good includes and set the right aliases
// and use the right gadgets for the verification key gadgets and so on.

namespace libzecale
{

/// We know that a proof (PGHR13 or GROTH16) is made of group elements (G1 or G2)
/// where the coordinates of the group elements are elements of E/F_q (for G1),
/// or elements of E/F_q^n (for G2), where `n` varies depending on the setting.
/// As such, the coordinates of the elements in the proof are defined over the
/// field Fq this field is referred to as the "base field".
///
/// Primary inputs however are defined over F_r, referred to as the "scalar
/// field".
///
/// In the context of recursion, especially in the context of the MNT(4,6)-cycle
/// of pairing friendly elliptic curves, it is necessary to be careful with how
/// we refer to the fields. In fact, the base field used to define one curve also
/// constitutes the scalar field of the other curve, and vice-and-versa. This
/// represents a cycle.
///
/// In fact, in the context of Zeth proof "aggregation", we have the following:
/// |              |      Zeth proof      |    Aggregator proof    |
/// ----------------------------------------------------------------
/// |  Base field  |  Pi_z (over Fq)      |     Pi_a (over Fr)     |
/// | Scalar field |  PrimIn_z (over Fr)  |   PrimIn_a (over Fq)   |

template<
    typename nppT,
    typename wppT,
    size_t NumProofs>
class aggregator_gadget : libsnark::gadget<libff::Fr<wppT>>
{
private:
    std::array<std::shared_ptr<VerifierGadgetT<wppT>>, NumProofs> verifiers;

    libsnark::pb_variable<libff::Fr<wppT>> wZero;

    /// ---- Primary inputs (public) ---- //
    ///
    /// The primary inputs lie in the scalar field `libff::Fr<wppT>`
    ///
    /// The Zeth primary inputs associated with the Zeth proofs in the witness
    /// We need to convert them to `libff::Fr<wppT>` elements so that they
    /// constitute valid values for the wires of our circuit which is defined
    /// over `libff::Fr<wppT>`
    std::array<libsnark::pb_variable_array<libff::Fr<wppT>>, NumProofs> nested_primary_inputs;

    /// The array of the results of the verifiers
    std::array<libsnark::pb_variable<libff::Fr<wppT>>, NumProofs> nested_proofs_results;

    /// ---- Auxiliary inputs (private) ---- //
    ///
    /// The auxiliary inputs lie in the scalar field `libff::Fr<wppT>`
    ///
    /// A proof of computational integrity is sufficient, **we don't need ZK here**
    /// We move the proofs to verify as part of the auxiliary input though in
    /// order to keep the amount of info sent on-chain as small as possible.
    /// On-chain we only need to have access to the Zeth primary inputs in order
    /// to change the state of the Mixer accordingly. The Zeth proofs are not
    /// strictly necessary.
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
    std::array<std::shared_ptr<ProofVariableGadgetT<wppT>>, NumProofs> nested_proofs;

    /// Likewise, this is not strictly necessary, but we do not need to pass the
    /// VK to the contract everytime as such we move it to the auxiliary inputs
    ///
    /// (Nested) verification key - VK used to verify Zeth proofs
    /// This verification key is made of elements of `nppT`, which
    /// again, makes sense because elements of `nppT` are defined over
    /// `E/BaseFieldZethT`, and `BaseFieldZethT` is `libff::Fr<wppT>`
    /// which is where we do arithmetic here
    std::shared_ptr<VerificationKeyVariableGadgetT<wppT>> nested_vk;

public:
    // Make sure that we do not exceed the number of proofs
    // specified in zeth's configuration file (see: zeth.h file)
    // BOOST_STATIC_ASSERT(NumInputs <= ZETH_NUM_PROOFS_INPUT);

    // Primary inputs are packed to be added to the extended proof and given to
    // the verifier on-chain
    aggregator_gadget(
        libsnark::protoboard<libff::Fr<wppT>> &pb,
        const std::string &annotation_prefix = "aggregator_gadget")
        : libsnark::gadget<libff::Fr<wppT>>(pb, annotation_prefix)
    {
        // Block dedicated to generate the verifier inputs
        // The verifier inputs, are values asociated to wires in the arithmetic
        // circuit and thus are all elements of the scalar field
        // `libff::Fr<wppT>`
        //
        // All inputs (primary and auxiliary) are in `libff::Fr<wppT>`
        //
        // Luckily:
        // mnt6_Fr::num_bits = mnt6_Fq::num_bits = mnt4_Fr::num_bits =
        // mnt4_Fq::num_bits = 298; As such, we can use the packed primary
        // inputs associated with the Zeth proofs directly as elements of
        // `libff::Fr<wppT>`
        {
            // == The # of primary inputs for Zeth proofs is 9 ==
            // since the primary inputs are:
            // [Root, NullifierS (2), CommitmentS (2), h_sig, h_iS (2), Residual
            // Field Element]
            const size_t nb_zeth_inputs = 9;
            const size_t nb_zeth_inputs_in_bits =
                nb_zeth_inputs * libff::Fr<nppT>::size_in_bits();
            for (size_t i = 0; i < NumProofs; i++) {
                nested_primary_inputs[i].allocate(
                    pb,
                    nb_zeth_inputs_in_bits,
                    FMT(this->annotation_prefix,
                        " nested_primary_inputs[%zu]-(in bits)",
                        i));

                // Allocation of the results
                nested_proofs_results[i].allocate(
                    pb,
                    FMT(this->annotation_prefix,
                        " nested_proofs_results[%zu]",
                        i));
            }

            // The primary inputs are:
            // - The Zeth PrimaryInputs associated to the Zeth proofs in the
            // auxiliary inputs
            // - Each verification result corresponding to each Zeth proofs and
            // the associated primary inputs
            //
            // TODO:
            //
            // The number of primary inputs is pretty big here
            // so we may want to hash the set of primary inputs to follow the
            // same trick as in [GGPR13] in order to save costs on the Verifier
            // side In this way, the verifier only has a single public input
            // which is the hash of the primary inputs. And for the zk-rollup
            // implementation, we will only need to send the "zeth public
            // inputs" as normal arguments to the contract. Then the contract
            // would hash them, and pass the hash to the verifier to verify the
            // proof
            // -> this doesn't minimize the # of args passed to the Mixer, but
            // minimize the number of scalar multiplications done by the
            // Verifier.
            //
            // As such the statement of the `Aggregator` is:
            //  - Verify the `N` proofs by invoking the `N` verifiers
            //  - Hash all the primary inputs values to a value H which now
            //  becomes the only primary inputs
            const size_t primary_input_size = NumProofs * (nb_zeth_inputs + 1);
            pb.set_input_sizes(primary_input_size);
            // ---------------------------------------------------------------
            //
            // Allocation of the auxiliary input after the primary inputs
            // The auxiliary inputs are:
            // - The VK to use to verify the Zeth proofs - Note, to avoid proofs
            // generated with malicious keypair (one for which the trapdoor is
            // known) we will need to add the "hash to the vk" as part of the
            // primary inputs
            // - The Zeth proofs
            wZero.allocate(
                pb,
                FMT(this->annotation_prefix, " wZero"));
            // == The nested vk ==
            // Bit size of the nested VK
            // The nested VK is interpreted as an array of bits
            // We pass `nb_zeth_inputs` to the function below as it corresponds
            // to the # of primary inputs of the zeth circuit, which is used to
            // determine the size of the zeth VK which is the one we manipulate
            // below.
            const size_t vk_size_in_bits = VerificationKeyVariableGadgetT<
                wppT>::size_in_bits(nb_zeth_inputs);
            libsnark::pb_variable_array<libff::Fr<wppT>> nested_vk_bits;
            nested_vk_bits.allocate(
                pb,
                vk_size_in_bits,
                FMT(this->annotation_prefix, " vk_size_in_bits"));
            nested_vk.reset(
                new VerificationKeyVariableGadgetT<wppT>(
                    pb,
                    nested_vk_bits,
                    nb_zeth_inputs,
                    FMT(this->annotation_prefix, " nested_vk")));

            // Initialize the proof variable gadgets. The protoboard allocation
            // is done in the constructor `r1cs_ppzksnark_proof_variable()`
            for (size_t i = 0; i < NumProofs; i++) {
                nested_proofs[i].reset(
                    new ProofVariableGadgetT<wppT>(
                        pb,
                        FMT(this->annotation_prefix,
                            " nested_proofs[%zu]",
                            i)));
            }
        }

        // Initialize the verifier gadgets
        for (size_t i = 0; i < NumProofs; i++) {
            verifiers[i].reset(new VerifierGadgetT<wppT>(
                pb,
                *nested_vk,
                nested_primary_inputs[i],
                libff::Fr<nppT>::size_in_bits(),
                *nested_proofs[i],
                nested_proofs_results[i],
                FMT(this->annotation_prefix, " verifiers[%zu]", i)));
        }
    }

    // Check:
    // - ZERO
    // - Generate the constraints for the VK
    // - Generate the constraints for the nested proofs
    // - Generate the constraints for the verifiers
    void generate_r1cs_constraints()
    {
        // Constrain `wZero`
        // Make sure that the wZero variable is the zero of
        // the field
        libsnark::generate_r1cs_equals_const_constraint<libff::Fr<wppT>>(
            this->pb,
            wZero,
            libff::Fr<wppT>::zero(),
            FMT(this->annotation_prefix, " wZero"));

        // Generate constraints for the verification key
        nested_vk->generate_r1cs_constraints(true); // ensure bitness

        // Generate constraints...
        for (size_t i = 0; i < NumProofs; i++) {
            // ... For the nested_proofs
            nested_proofs[i]->generate_r1cs_constraints();

            // ... For the verifiers
            verifiers[i]->generate_r1cs_constraints();
        }
    }

    // In the witness we manipulate elements defined over the "other curve"
    // see:
    // https://github.com/scipr-lab/libsnark/blob/master/libsnark/gadgetlib1/gadgets/verifiers/r1cs_ppzksnark_verifier_gadget.hpp#L98
    void generate_r1cs_witness(
        typename libzeth::default_snark<nppT>::VerificationKeyT in_nested_vk,
        std::array<libzeth::extended_proof<nppT, libzeth::default_snark<nppT>>, NumProofs>
            in_extended_proofs)
    {
        // Witness `zero`
        this->pb.val(wZero) =
            libff::Fr<wppT>::zero();

        // Witness the VK
        nested_vk->generate_r1cs_witness(in_nested_vk);

        // Witness...
        for (size_t i = 0; i < NumProofs; i++) {
            // ... the nested_proofs
            nested_proofs[i]->generate_r1cs_witness(
                in_extended_proofs[i].get_proof());

            // ... the nested_prinary_inputs
            // Explicit cast of the primary inputs to the other curve
            //
            // The problem is that `nested_primary_inputs` are of type
            // `libff::Fr<wppT>` but the primary inputs of the Zeth proof
            // (`in_extended_proofs[i].get_primary_input()`) are over
            // `ScalarFieldZethT` We need to explicitly and manually convert
            // from `ScalarFieldZethT` to `libff::Fr<wppT>` here
            libsnark::r1cs_primary_input<libff::Fr<nppT>>
                other_curve_primary_inputs =
                    in_extended_proofs[i].get_primary_input();
            // Convert
            // WARNING: This should be done in the circuit via the packing
            // gadgets!! This is just a dirty hack
            const libff::bit_vector input_bits =
                libff::convert_field_element_vector_to_bit_vector<
                    libff::Fr<nppT>>(other_curve_primary_inputs);
            // std::vector<libff::Fr<wppT>> this_curve_primary_inputs =
            // libff::pack_bit_vector_into_field_element_vector<libff::Fr<wppT>>(temp_bits,
            // libff::Fr<wppT>::size_in_bits());
            // nested_primary_inputs[i].fill_with_field_elements(this->pb,
            // input_bits);
            nested_primary_inputs[i].fill_with_bits(this->pb, input_bits);

            // ... the verifiers
            verifiers[i]->generate_r1cs_witness();
        }
    }
};

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_AGGREGATOR_TCC__
