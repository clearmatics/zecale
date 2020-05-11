// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "gtest/gtest.h"
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>
#include <libff/algebra/fields/field_utils.hpp>
#include <libff/common/default_types/ec_pp.hpp>

// Header to use the merkle tree data structure to keep a local merkle tree
#include <libsnark/common/data_structures/merkle_tree.hpp>

// Include the joinsplit gadget - generate the zeth proofs
#include <libzeth/circuit_wrapper.hpp>
#include <libzeth/circuits/blake2s/blake2s_comp.hpp>
#include <libzeth/libsnark_helpers/libsnark_helpers.hpp>
// Include the core files and template instantiations corresponding
// to the proof system used
#include <libzeth/snarks_alias.hpp>
#include <libzeth/snarks_core_imports.hpp>
#include <libzeth/util.hpp>

// Header to access the snark aliases
#include "aggregator_circuit_wrapper.hpp"

using namespace libzeth;

// Instantiation of the templates for the tests
// IMPORTANT:
// Because we now switch the curve over which we generate the Zeth proofs
// we need to be careful. In fact, the fields (base and scalar) of
// the MNT curves are BIGGER than the ones of the alt_bn128.
// As such, we need to modify the Zeth statement to remove the "residual" bits
// because now, a digest can be fully packed into a field element without
// residual bits
//
// The Field capacity of the fields associated with the MNT curves is 297bits
typedef libff::mnt4_pp ZethProofCurve;
typedef libff::mnt6_pp AggregateProofCurve;

typedef libff::Fr<ZethProofCurve> ScalarFieldZethT;
typedef libff::Fr<AggregateProofCurve> ScalarFieldAggregatorT;

// The templates below are used in the Zeth circuit, hence
// why they are instantiated from the `ScalarFieldZethT` scalar field
typedef BLAKE2s_256_comp<ScalarFieldZethT> HashT;
typedef MiMC_mp_gadget<ScalarFieldZethT> HashTreeT;

static const size_t TreeDepth = 4;
static const size_t InputsNumber = 2;
static const size_t OutputsNumber = 2;
static const size_t BatchSize = 1;

using namespace libzecale;

namespace
{

/// This function generates one valid zeth proof.
/// It returns the extended proof generated (snark + primary inputs)
libzeth::extended_proof<ZethProofCurve> generate_valid_zeth_proof(
    circuit_wrapper<
        ScalarFieldZethT,
        HashT,
        HashTreeT,
        ZethProofCurve,
        InputsNumber,
        OutputsNumber,
        TreeDepth> &zeth_prover,
    libzeth::keyPairT<ZethProofCurve> zeth_keypair)
{
    libff::print_header("Entering generate_valid_zeth_proof");

    libff::enter_block("Instantiate merkle tree for the tests", true);
    std::unique_ptr<merkle_tree_field<ScalarFieldZethT, HashTreeT>>
        test_merkle_tree =
            std::unique_ptr<merkle_tree_field<ScalarFieldZethT, HashTreeT>>(
                new merkle_tree_field<ScalarFieldZethT, HashTreeT>(TreeDepth));
    libff::leave_block("Instantiate merkle tree for the tests", true);

    // Generate a valid proof for commitment inserted at address 1
    libff::enter_block("Create joinsplit_input", true);
    // Generate note data
    bits384 trap_r_bits384 = get_bits384_from_vector(hex_to_binary_vector(
        "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00"
        "000000000000FF00000000000000FF"));
    bits64 value_bits64 =
        get_bits64_from_vector(hex_to_binary_vector("2F0000000000000F"));
    bits256 a_sk_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "FF0000000000000000000000000000000000000000000000000000000000000F"));
    bits256 rho_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "FFFF000000000000000000000000000000000000000000000000000000009009"));
    bits256 a_pk_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "f172d7299ac8ac974ea59413e4a87691826df038ba24a2b52d5c5d15c2cc8c49"));
    bits256 nf_bits256 = get_bits256_from_vector(hex_digest_to_binary_vector(
        "ff2f41920346251f6e7c67062149f98bc90c915d3d3020927ca01deab5da0fd7"));
    ScalarFieldZethT cm_field =
        ScalarFieldZethT("9047913389147464750130699723564635396506448356890"
                         "6678810249472230384841563494");
    const size_t address_commitment = 1;
    libff::bit_vector address_bits;
    for (size_t i = 0; i < TreeDepth; ++i) {
        address_bits.push_back((address_commitment >> i) & 0x1);
    }
    bits256 h_sig = get_bits256_from_vector(hex_digest_to_binary_vector(
        "6838aac4d8247655715d3dfb9b32573da2b7d3360ba89ccdaaa7923bb24c99f7"));
    bits256 phi = get_bits256_from_vector(hex_digest_to_binary_vector(
        "403794c0e20e3bf36b820d8f7aef5505e5d1c7ac265d5efbcc3030a74a3f701b"));

    // We insert the commitment to the zeth note in the merkle tree
    test_merkle_tree->set_value(address_commitment, cm_field);
    ScalarFieldZethT updated_root_value = test_merkle_tree->get_root();
    std::vector<ScalarFieldZethT> path =
        test_merkle_tree->get_path(address_commitment);

    // JS Inputs: 1 note of value > 0 to spend, and a dummy note
    zeth_note note_input(
        a_pk_bits256, value_bits64, rho_bits256, trap_r_bits384);
    zeth_note note_dummy_input(
        a_pk_bits256,
        get_bits64_from_vector(hex_to_binary_vector("0000000000000000")),
        get_bits256_from_vector(
            hex_digest_to_binary_vector("AAAA0000000000000000000000000000000000"
                                        "0000000000000000000000EEEE")),
        trap_r_bits384);
    joinsplit_input<ScalarFieldZethT, TreeDepth> input(
        path,
        get_bits_addr_from_vector<TreeDepth>(address_bits),
        note_input,
        a_sk_bits256,
        nf_bits256);
    // We keep the same path and address as the previous commitment
    // We don't care since this note is zero-valued and the merkle auth path
    // check is rendered dummy in such case
    joinsplit_input<ScalarFieldZethT, TreeDepth> input_dummy(
        path,
        get_bits_addr_from_vector<TreeDepth>(address_bits),
        note_dummy_input,
        a_sk_bits256,
        nf_bits256);
    std::array<joinsplit_input<ScalarFieldZethT, TreeDepth>, InputsNumber>
        inputs;
    inputs[0] = input;
    inputs[1] = input_dummy;
    libff::leave_block("Create joinsplit_input", true);

    libff::enter_block("Create JSOutput/zeth_note", true);
    bits64 value_out_bits64 =
        get_bits64_from_vector(hex_to_binary_vector("1800000000000008"));
    bits256 a_pk_out_bits256 = get_bits256_from_vector(
        hex_digest_to_binary_vector("7777f753bfe21ba2219ced74875b8dbd8c114c3c79"
                                    "d7e41306dd82118de1895b"));
    bits256 rho_out_bits256;
    bits384 trap_r_out_bits384 = get_bits384_from_vector(hex_to_binary_vector(
        "11000000000000990000000000000099000000000000007700000000000000FF00"
        "000000000000FF0000000000000777"));

    zeth_note note_output(
        a_pk_out_bits256,
        value_out_bits64,
        rho_out_bits256,
        trap_r_out_bits384);
    zeth_note note_dummy_output(
        a_pk_out_bits256,
        get_bits64_from_vector(hex_to_binary_vector("0000000000000000")),
        rho_out_bits256,
        trap_r_out_bits384);
    bits64 value_pub_out_bits64 =
        get_bits64_from_vector(hex_to_binary_vector("1700000000000007"));
    std::array<zeth_note, OutputsNumber> outputs;
    outputs[0] = note_output;
    outputs[1] = note_dummy_output;
    libff::leave_block("Create JSOutput/zeth_note", true);

    libff::enter_block("Generate Zeth proof", true);
    libzeth::extended_proof<ZethProofCurve> ext_proof = zeth_prover.prove(
        updated_root_value,
        inputs,
        outputs,
        // vpub_in = 0
        get_bits64_from_vector(hex_to_binary_vector("0000000000000000")),
        value_pub_out_bits64,
        h_sig,
        phi,
        zeth_keypair.pk);
    libff::leave_block("Generate Zeth proof", true);

    libff::enter_block("Verify Zeth proof", true);
    libzeth::verificationKeyT<ZethProofCurve> vk = zeth_keypair.vk;
    bool bit = libzeth::verify(ext_proof, vk);

    /*
     * // The proof should be valid, so we assert it
     * //ASSERT_EQ(bit, true);
     **/
    libff::leave_block("Verify Zeth proof", true);

    /*
     * std::cout << "[DEBUG] Displaying the Zeth extended proof" << std::endl;
     * // The formatting functions to display the proof/primary inputs
     * // only work for `libff::alt_bn128_G1`
     * ext_proof.dump_proof();
     * std::cout << "[DEBUG] Displaying the Zeth primary inputs" << std::endl;
     * ext_proof.dump_primary_inputs();
     **/

    // Return the extended proof to build the inputs of the aggregator circuit
    return ext_proof;
}

/// Test aggregation of a batch of proofs
///
/// Here we use the same proof system to generate the "zeth proofs"
/// and the Zecale proofs, but we could use different proofs systems.
/// We use the same SNARK for simplicity.
bool test_valid_aggregation_batch_proofs(
    aggregator_circuit_wrapper<ZethProofCurve, AggregateProofCurve, BatchSize>
        &aggregator_prover,
    libzeth::keyPairT<AggregateProofCurve> aggregator_keypair,
    libzeth::keyPairT<ZethProofCurve> zeth_keypair,
    std::array<libzeth::extended_proof<ZethProofCurve>, BatchSize>
        nested_proofs)
{
    libff::enter_block("Generate Aggregate proof", true);
    extended_proof<AggregateProofCurve> ext_proof = aggregator_prover.prove(
        // This should cause a crash because the primary inputs are
        // packed in Zeth and are processed as unpacked here.
        zeth_keypair.vk,
        nested_proofs,
        aggregator_keypair.pk);
    libff::leave_block("Generate Aggregate proof", true);

    libff::enter_block("Verify Aggregate proof", true);
    libzeth::verificationKeyT<AggregateProofCurve> vk = aggregator_keypair.vk;
    bool res = libzeth::verify(ext_proof, vk);
    std::cout << "Does the proof verify? " << res << std::endl;
    libff::leave_block("Verify Aggregate proof", true);

    /*
     * std::cout << "[DEBUG] Displaying the Aggregate extended proof" <<
     *std::endl; ext_proof.dump_proof(); std::cout << "[DEBUG] Displaying the
     *Aggregate primary inputs" << std::endl; ext_proof.dump_primary_inputs();
     **/

    return res;
}

TEST(MainTests, AggregatorTest)
{
    std::cout << "[DEBUG] Capacity of ScalarFieldZethT: "
              << ScalarFieldZethT::capacity() << std::endl;
    std::cout << "[DEBUG] Capacity of ScalarFieldAggregatorT: "
              << ScalarFieldAggregatorT::capacity() << std::endl;
    std::cout << "[DEBUG] Entering test for the aggregator" << std::endl;

    // Run the trusted setup once for all tests, and keep the keypair in memory
    // for the duration of the tests

    circuit_wrapper<
        ScalarFieldZethT,
        HashT,
        HashTreeT,
        ZethProofCurve,
        InputsNumber,
        OutputsNumber,
        TreeDepth>
        zeth_prover;
    std::cout << "[DEBUG] Before Zeth trusted setup" << std::endl;
    libzeth::keyPairT<ZethProofCurve> zeth_keypair =
        zeth_prover.generate_trusted_setup();

    // Test to aggregate a single proof (i.e. generate a proof for the
    // verification of the proof)
    std::cout << "[DEBUG] Before gen Zeth proof" << std::endl;
    libzeth::extended_proof<ZethProofCurve> valid_proof =
        generate_valid_zeth_proof(zeth_prover, zeth_keypair);

    /*
     * // Generate an invalid proof
     * libzeth::extended_proof<ZethProofCurve> invalid_proof = valid_proof;
     * invalid_proof.get_primary_input
     **/

    std::array<libzeth::extended_proof<ZethProofCurve>, BatchSize> batch = {
        valid_proof};
    // Make sure that the number of primary inputs matches the one we set in the
    // `aggregator_prover` circuit
    std::cout << "[DEBUG] nested_proofs[0].get_primary_input().size(): "
              << batch[0].get_primary_input().size() << std::endl;
    // Make sure that we have the right amount of primary inputs
    ASSERT_EQ(batch[0].get_primary_input().size(), 9);

    std::cout << "[DEBUG] Before creation of the Aggregator prover"
              << std::endl;
    aggregator_circuit_wrapper<ZethProofCurve, AggregateProofCurve, BatchSize>
        aggregator_prover;
    std::cout << "[DEBUG] Before gen Aggregator setup" << std::endl;
    libzeth::keyPairT<AggregateProofCurve> aggregator_keypair =
        aggregator_prover.generate_trusted_setup();

    std::cout << "[DEBUG] Before first test" << std::endl;
    bool res = false;
    res = test_valid_aggregation_batch_proofs(
        aggregator_prover, aggregator_keypair, zeth_keypair, batch);
    ASSERT_TRUE(res);
}

} // namespace

int main(int argc, char **argv)
{
    libff::start_profiling();

    // Initialize the curve parameters before running the tests
    ZethProofCurve::init_public_params();
    AggregateProofCurve::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}