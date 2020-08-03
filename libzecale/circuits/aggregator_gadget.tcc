// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_AGGREGATOR_GADGET_TCC__
#define __ZECALE_CIRCUITS_AGGREGATOR_GADGET_TCC__

namespace libzecale
{

template<
    typename nppT,
    typename wppT,
    typename nsnarkT,
    typename wverifierT,
    size_t NumProofs>
aggregator_gadget<nppT, wppT, nsnarkT, wverifierT, NumProofs>::
    aggregator_gadget(
        libsnark::protoboard<libff::Fr<wppT>> &pb,
        const size_t inputs_per_nested_proof,
        const std::string &annotation_prefix)
    : libsnark::gadget<libff::Fr<wppT>>(pb, annotation_prefix)
    , num_inputs_per_nested_proof(inputs_per_nested_proof)
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
        const size_t num_input_bits_per_nested_proof =
            num_inputs_per_nested_proof * libff::Fr<nppT>::size_in_bits();
        for (size_t i = 0; i < NumProofs; i++) {
            nested_primary_inputs[i].allocate(
                pb,
                num_input_bits_per_nested_proof,
                FMT(this->annotation_prefix,
                    " nested_primary_inputs[%zu]-(in bits)",
                    i));

            // Allocation of the results
            nested_proofs_results[i].allocate(
                pb,
                FMT(this->annotation_prefix, " nested_proofs_results[%zu]", i));
        }

        // The primary inputs are:
        // - The Zeth PrimaryInputs associated to the Zeth proofs in the
        // auxiliary inputs
        // - Each verification result corresponding to each Zeth proofs and
        // the associated primary inputs
        //
        // TODO:
        //
        // The number of primary inputs is pretty big here so we may want
        // to hash the set of primary inputs to follow the same trick as in
        // [GGPR13] in order to save costs on the Verifier side. In this
        // way, the verifier only has a single public input which is the
        // hash of the primary inputs. And for the zk-rollup
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
        const size_t total_primary_inputs =
            NumProofs * (num_inputs_per_nested_proof + 1);
        pb.set_input_sizes(total_primary_inputs);
        // ---------------------------------------------------------------
        //
        // Allocation of the auxiliary input after the primary inputs
        // The auxiliary inputs are:
        // - The VK to use to verify the Zeth proofs - Note, to avoid proofs
        // generated with malicious keypair (one for which the trapdoor is
        // known) we will need to add the "hash to the vk" as part of the
        // primary inputs
        // - The Zeth proofs

        // == The nested vk ==
        // Bit size of the nested VK
        // The nested VK is interpreted as an array of bits
        // We pass `nb_zeth_inputs` to the function below as it corresponds
        // to the # of primary inputs of the zeth circuit, which is used to
        // determine the size of the zeth VK which is the one we manipulate
        // below.
        const size_t vk_size_in_bits =
            verification_key_variable_gadget::size_in_bits(
                num_inputs_per_nested_proof);
        libsnark::pb_variable_array<libff::Fr<wppT>> nested_vk_bits;
        nested_vk_bits.allocate(
            pb,
            vk_size_in_bits,
            FMT(this->annotation_prefix, " vk_size_in_bits"));
        nested_vk.reset(new verification_key_variable_gadget(
            pb,
            nested_vk_bits,
            num_inputs_per_nested_proof,
            FMT(this->annotation_prefix, " nested_vk")));

        // Initialize the proof variable gadgets. The protoboard allocation
        // is done in the constructor `r1cs_ppzksnark_proof_variable()`
        for (size_t i = 0; i < NumProofs; i++) {
            nested_proofs[i].reset(new proof_variable_gadget(
                pb, FMT(this->annotation_prefix, " nested_proofs[%zu]", i)));
        }
    }

    // Initialize the verifier gadgets
    for (size_t i = 0; i < NumProofs; i++) {
        verifiers[i].reset(new verifier_gadget(
            pb,
            *nested_vk,
            nested_primary_inputs[i],
            libff::Fr<nppT>::size_in_bits(),
            *nested_proofs[i],
            nested_proofs_results[i],
            FMT(this->annotation_prefix, " verifiers[%zu]", i)));
    }
}

template<
    typename nppT,
    typename wppT,
    typename nsnarkT,
    typename wverifierT,
    size_t NumProofs>
void aggregator_gadget<nppT, wppT, nsnarkT, wverifierT, NumProofs>::
    generate_r1cs_constraints()
{
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

template<
    typename nppT,
    typename wppT,
    typename nsnarkT,
    typename wverifierT,
    size_t NumProofs>
void aggregator_gadget<nppT, wppT, nsnarkT, wverifierT, NumProofs>::
    generate_r1cs_witness(
        const typename nsnarkT::verification_key &in_nested_vk,
        const std::array<
            const libzeth::extended_proof<nppT, nsnarkT> *,
            NumProofs> &in_extended_proofs)
{
    // Witness the VK
    nested_vk->generate_r1cs_witness(in_nested_vk);

    // Witness...
    for (size_t i = 0; i < NumProofs; i++) {
        // ... the nested_proofs
        nested_proofs[i]->generate_r1cs_witness(
            in_extended_proofs[i]->get_proof());

        // ... the nested_prinary_inputs
        // Explicit cast of the primary inputs to the other curve
        //
        // The problem is that `nested_primary_inputs` are of type
        // `libff::Fr<wppT>` but the primary inputs of the Zeth proof
        // (`in_extended_proofs[i]->get_primary_input()`) are over
        // `ScalarFieldZethT` We need to explicitly and manually convert
        // from `ScalarFieldZethT` to `libff::Fr<wppT>` here
        const libsnark::r1cs_primary_input<libff::Fr<nppT>>
            &other_curve_primary_inputs =
                in_extended_proofs[i]->get_primary_inputs();
        // Convert
        // WARNING: This should be done in the circuit via the packing
        // gadgets!! This is just a dirty hack
        const libff::bit_vector input_bits =
            libff::convert_field_element_vector_to_bit_vector<libff::Fr<nppT>>(
                other_curve_primary_inputs);
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

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_AGGREGATOR_GADGET_TCC__
