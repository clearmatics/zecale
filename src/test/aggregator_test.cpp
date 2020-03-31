#include "gtest/gtest.h"
#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>
#include <libff/algebra/fields/field_utils.hpp>


#include <libff/algebra/curves/alt_bn128/alt_bn128_init.hpp>

// Header to use the merkle tree data structure to keep a local merkle tree
#include <libsnark/common/data_structures/merkle_tree.hpp>

// include the joinsplit gadget - generate the zeth proofs
#include <libzeth/circuit_wrapper.hpp>
#include <libzeth/circuits/blake2s/blake2s_comp.hpp>
#include <libzeth/libsnark_helpers/libsnark_helpers.hpp>
#include <libzeth/snarks_core_imports.hpp>
#include <libzeth/util.hpp>

// Header to access the snark aliases
#include <libzeth/snarks_alias.hpp>

#include "aggregator_circuit_wrapper.hpp"

using namespace libzeth;

// Instantiation of the templates for the tests
// IMPORTANT:
// Because we now switch the curve over which we generate the Zeth proofs
// we need to be careful. In fact, the fields (base and scalar) of
// the MNT curves are BIGGER than the ones of the alt_bn128.
// As such, we need to modify the Zeth statement to remove the "residual" bits
// because now, a digest can be fully packed into a field element without residual bits
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

using namespace libzecale;

namespace
{

// This function generates one zeth proof, with the associated primary inputs.
// It also returns the nested verification key which will be used by the aggregator
// to verify the nested proof
std::array<libzeth::extended_proof<ZethProofCurve>, 2> GenerateTwoZethProofs(
    circuit_wrapper<
        ScalarFieldZethT,
        HashT,
        HashTreeT,
        ZethProofCurve,
        2,
        2,
        TreeDepth> &zeth_prover,
    libsnark::r1cs_ppzksnark_keypair<ZethProofCurve> zeth_keypair)
{
    // --- General setup for the tests --- //
    libff::print_header("Entering GenerateOneZethProof");

    libff::enter_block("Instantiate merkle tree for the tests", true);
    std::unique_ptr<merkle_tree_field<ScalarFieldZethT, HashTreeT>> test_merkle_tree =
        std::unique_ptr<merkle_tree_field<ScalarFieldZethT, HashTreeT>>(
            new merkle_tree_field<ScalarFieldZethT, HashTreeT>(TreeDepth));
    libff::leave_block("Instantiate merkle tree for the tests", true);

    // --- Test 1: Generate a valid proof for commitment inserted at address 1
    libff::enter_block("Create joinsplit_input", true);
        // Generate note data
        bits384 trap_r_bits384 = get_bits384_from_vector(
            hex_to_binary_vector(
                "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00"
                "000000000000FF00000000000000FF"
            )
        );
        bits64 value_bits64 = get_bits64_from_vector(
            hex_to_binary_vector(
                "2F0000000000000F"
            )
        );
        bits256 a_sk_bits256 = get_bits256_from_vector(
            hex_digest_to_binary_vector(
                "FF0000000000000000000000000000000000000000000000000000000000000F"
            )
        );
        bits256 rho_bits256 = get_bits256_from_vector(
            hex_digest_to_binary_vector(
                "FFFF000000000000000000000000000000000000000000000000000000009009"
            )
        );
        bits256 a_pk_bits256 = get_bits256_from_vector(
            hex_digest_to_binary_vector(
                "f172d7299ac8ac974ea59413e4a87691826df038ba24a2b52d5c5d15c2cc8c49"
            )
        );
        bits256 nf_bits256 = get_bits256_from_vector(
            hex_digest_to_binary_vector(
                "ff2f41920346251f6e7c67062149f98bc90c915d3d3020927ca01deab5da0fd7"
            )
        );
        ScalarFieldZethT cm_field = ScalarFieldZethT("9047913389147464750130699723564635396506448356890"
                                "6678810249472230384841563494");
        const size_t address_commitment = 1;
        libff::bit_vector address_bits;
        for (size_t i = 0; i < TreeDepth; ++i) {
            address_bits.push_back((address_commitment >> i) & 0x1);
        }
        bits256 h_sig = get_bits256_from_vector(
            hex_digest_to_binary_vector(
                "6838aac4d8247655715d3dfb9b32573da2b7d3360ba89ccdaaa7923bb24c99f7"
            )
        );
        bits256 phi = get_bits256_from_vector(
            hex_digest_to_binary_vector(
                "403794c0e20e3bf36b820d8f7aef5505e5d1c7ac265d5efbcc3030a74a3f701b"
            )
        );

        // We insert the commitment to the zeth note in the merkle tree
        test_merkle_tree->set_value(address_commitment, cm_field);
        ScalarFieldZethT updated_root_value = test_merkle_tree->get_root();
        std::vector<ScalarFieldZethT> path = test_merkle_tree->get_path(address_commitment);

        // JS Inputs: 1 note of value > 0 to spend, and a dummy note
        zeth_note note_input(
            a_pk_bits256,
            value_bits64,
            rho_bits256,
            trap_r_bits384
        );
        zeth_note note_dummy_input(
            a_pk_bits256,
            get_bits64_from_vector(
                hex_to_binary_vector("0000000000000000")
            ),
            get_bits256_from_vector(
                hex_digest_to_binary_vector(
                    "AAAA00000000000000000000000000000000000000000000000000000000EEEE"
                )
            ),
            trap_r_bits384
        );
        joinsplit_input<ScalarFieldZethT, TreeDepth> input(
            path,
            get_bits_addr_from_vector<TreeDepth>(address_bits),
            note_input,
            a_sk_bits256,
            nf_bits256
        );
        // We keep the same path and address as the previous commitment
        // We don't care since this coin is zero-valued and the merkle auth path
        // check Doesn't count in such case
        joinsplit_input<ScalarFieldZethT, TreeDepth> input_dummy(
            path,
            get_bits_addr_from_vector<TreeDepth>(address_bits),
            note_dummy_input,
            a_sk_bits256,
            nf_bits256
        );
        std::array<joinsplit_input<ScalarFieldZethT, TreeDepth>, 2> inputs;
        inputs[0] = input;
        inputs[1] = input_dummy;
    libff::leave_block("Create joinsplit_input", true);

    libff::enter_block("Create JSOutput/zeth_note", true);
        bits64 value_out_bits64 = get_bits64_from_vector(
            hex_to_binary_vector("1800000000000008")
        );
        bits256 a_pk_out_bits256 = get_bits256_from_vector(
            hex_digest_to_binary_vector(
                "7777f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
            )
        );
        bits256 rho_out_bits256;
        bits384 trap_r_out_bits384 = get_bits384_from_vector(
            hex_to_binary_vector(
                "11000000000000990000000000000099000000000000007700000000000000FF00"
                "000000000000FF0000000000000777"
            )
        );

        zeth_note note_output(
            a_pk_out_bits256,
            value_out_bits64,
            rho_out_bits256,
            trap_r_out_bits384
        );
        zeth_note note_dummy_output(
            a_pk_out_bits256,
            get_bits64_from_vector(hex_to_binary_vector("0000000000000000")),
            rho_out_bits256,
            trap_r_out_bits384
        );
        bits64 value_pub_out_bits64 =
            get_bits64_from_vector(hex_to_binary_vector("1700000000000007"));
        std::array<zeth_note, 2> outputs;
        outputs[0] = note_output;
        outputs[1] = note_dummy_output;
    libff::leave_block("Create JSOutput/zeth_note", true);

    libff::enter_block("Generate Zeth proof", true);
        extended_proof<ZethProofCurve> ext_proof = zeth_prover.prove(
            updated_root_value,
            inputs,
            outputs,
            get_bits64_from_vector(
                hex_to_binary_vector("0000000000000000")
            ), // vpub_in = 0
            value_pub_out_bits64,
            h_sig,
            phi,
            zeth_keypair.pk
        );
    libff::leave_block("Generate Zeth proof", true);

    libff::enter_block("Verify Zeth proof", true);
        libsnark::r1cs_ppzksnark_verification_key<ZethProofCurve> vk = zeth_keypair.vk;
        bool res = libzeth::verify(ext_proof, vk);
        std::cout << "Does the proof verify? " << res << std::endl;
    libff::leave_block("Verify Zeth proof", true);

    std::cout << "[DEBUG] Displaying the Zeth extended proof" << std::endl;
    // The formatting functions to display the proof/primary inputs
    // only work for `libff::alt_bn128_G1`
    //ext_proof.dump_proof();
    std::cout << "[DEBUG] Displaying the Zeth primary inputs" << std::endl;
    //ext_proof.dump_primary_inputs();

    std::cout << "Zeth Res value: " << res << std::endl;

    // Return the extended proof to build the inputs of the aggregator circuit
    std::array<libzeth::extended_proof<ZethProofCurve>, 2> result = {ext_proof, ext_proof};
    return result;
}

// Test aggregation of a single Zeth proof
bool TestValidAggregationTwoZethProofs(
    aggregator_circuit_wrapper<
        ZethProofCurve,
        AggregateProofCurve,
        2
    > &aggregator_prover,
    libsnark::r1cs_ppzksnark_keypair<AggregateProofCurve> aggregator_keypair,
    libsnark::r1cs_ppzksnark_keypair<ZethProofCurve> zeth_keypair,
    std::array<libzeth::extended_proof<ZethProofCurve>, 2> nested_proofs
) {
    libff::enter_block("Generate Aggregate proof", true);
        extended_proof<AggregateProofCurve> ext_proof = aggregator_prover.prove(
            zeth_keypair.vk, // This should cause a crash because the primary inputs are packed in Zeth and are processed as unpacked here.
            nested_proofs,
            aggregator_keypair.pk
        );
    libff::leave_block("Generate Aggregate proof", true);

    libff::enter_block("Verify Aggregate proof", true);
        libsnark::r1cs_ppzksnark_verification_key<AggregateProofCurve> vk = aggregator_keypair.vk;
        bool res = libzeth::verify(ext_proof, vk);
        std::cout << "Does the proof verify? " << res << std::endl;
    libff::leave_block("Verify Aggregate proof", true);

    std::cout << "[DEBUG] Displaying the Aggregate extended proof" << std::endl;
    ext_proof.dump_proof();
    std::cout << "[DEBUG] Displaying the Aggregate primary inputs" << std::endl;
    ext_proof.dump_primary_inputs();

    return res;
}

TEST(MainTests, AggregatorTest)
{
    std::cout << "Capacity of ScalarFieldZethT: " << ScalarFieldZethT::capacity() << std::endl;
    std::cout << "Capacity of ScalarFieldAggregatorT: " << ScalarFieldAggregatorT::capacity() << std::endl;
    std::cout << "Entering test for the aggregator" << std::endl;

    // Run the trusted setup once for all tests, and keep the keypair in memory
    // for the duration of the tests

    circuit_wrapper<
        ScalarFieldZethT,
        HashT,
        HashTreeT,
        ZethProofCurve,
        2,
        2,
        TreeDepth
    > zeth_prover;
    std::cout << "Before Zeth trusted setup" << std::endl;
    libsnark::r1cs_ppzksnark_keypair<ZethProofCurve> zeth_keypair = zeth_prover.generate_trusted_setup();

    // Test to aggregate a single proof (i.e. generate a proof for the verification of the proof)
    std::cout << "Before gen Zeth proof" << std::endl;
    std::array<libzeth::extended_proof<ZethProofCurve>, 2> nested_proofs = GenerateTwoZethProofs(zeth_prover, zeth_keypair);
    // Make sure that the number of primary inputs matches the one we set in the `aggregator_prover` circuit
    std::cout << "[DEBUG ] nested_proofs[0].get_primary_input().size(): " << nested_proofs[0].get_primary_input().size() << std::endl;
    // Make sure that we have the right amount of primary inputs
    assert(nested_proofs[0].get_primary_input().size() == 9);

    std::cout << "[DEBUG - 1] Before creation of the Aggregator prover" << std::endl;
    aggregator_circuit_wrapper<ZethProofCurve, AggregateProofCurve, 2> aggregator_prover;
    std::cout << "[DEBUG - 2] Before gen Aggregator setup" << std::endl;
    libsnark::r1cs_ppzksnark_keypair<AggregateProofCurve> aggregator_keypair = aggregator_prover.generate_trusted_setup();

    std::cout << "Before first test" << std::endl;
    bool res = false;
    res = TestValidAggregationTwoZethProofs(
        aggregator_prover,
        aggregator_keypair,
        zeth_keypair,
        nested_proofs
    );
    std::cout << "Res: " << res << std::endl;
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

/*
template<
    typename ZethProofCurve,
    typename AggregateProofCurve,
    size_t NumProofs>
void test_verifier_single_proof(const std::string &annotation_A, const std::string &annotation_B)
{
    typedef libff::Fr<ZethProofCurve> ScalarFieldZethT;
    using BaseFieldAggregatorT = ScalarFieldZethT;

    typedef libff::Fr<AggregateProofCurve> ScalarFieldAggregatorT;
    using BaseFieldZethT = ScalarFieldAggregatorT;

    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " == In the test_verifier function == " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;

    const size_t num_constraints = 50;
    const size_t primary_input_size = 3;

    // Proof generated over F_r from an arithmetic circuit defined over F_q -> \pi_A
    r1cs_example<FieldT_A> example = generate_r1cs_example_with_field_input<FieldT_A>(num_constraints, primary_input_size);
    assert(example.primary_input.size() == primary_input_size);

    assert(example.constraint_system.is_satisfied(example.primary_input, example.auxiliary_input));

    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " == Generating the keypair == " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;
    const r1cs_ppzksnark_keypair<ppT_A> keypair = r1cs_ppzksnark_generator<ppT_A>(example.constraint_system);

    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " == Generating the nested proof == " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;
    const r1cs_ppzksnark_proof<ppT_A> pi = r1cs_ppzksnark_prover<ppT_A>(keypair.pk, example.primary_input, example.auxiliary_input);

    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " == Verifying the nested proof (outside a circuit) == " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;
    bool bit = r1cs_ppzksnark_verifier_strong_IC<ppT_A>(keypair.vk, example.primary_input, pi);
    assert(bit);

    // ====================================================== //
    // This block kind of corresponds to what needs to be put
    // in the constructor of the aggregator
    // ====================================================== // 
    // Verification of the proof generated over F_r, and production of a proof over F_q -> \pi_B
    // Note: The primary inputs corresponding to the nested proof are defined over the scalar field of the first circuit,
    // and we know that all variables (i.e. wires value) lie in the scalar field, as such, when verifying a proof P_A
    // as part of the proof generation P_B, we need to convert the primary inputs of P_A into valid wire value
    // of the arithmetic circuit used to generate P_B. We need to convert the elements of Fr (scalar field of circuit C_A)
    // into elements of the scalar field of circuit C_B, i.e. elements of Fq.
    const size_t elt_size = FieldT_A::size_in_bits();
    // Bit size of the nested primary inputs
    const size_t primary_input_size_in_bits = elt_size * primary_input_size;
    // Bit size of the nested VK
    const size_t vk_size_in_bits = r1cs_ppzksnark_verification_key_variable<ppT_B>::size_in_bits(primary_input_size);

    protoboard<FieldT_B> pb;
    pb_variable_array<FieldT_B> vk_bits;
    vk_bits.allocate(pb, vk_size_in_bits, "vk_bits");

    pb_variable_array<FieldT_B> primary_input_bits;
    primary_input_bits.allocate(pb, primary_input_size_in_bits, "primary_input_bits");

    // The nested proof to verify
    r1cs_ppzksnark_proof_variable<ppT_B> proof(pb, "proof");
    // The nested VK to verify the nested proof
    r1cs_ppzksnark_verification_key_variable<ppT_B> vk(pb, vk_bits, primary_input_size, "vk");

    pb_variable<FieldT_B> result;
    result.allocate(pb, "result");

    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " == Instantiate the `r1cs_ppzksnark_verifier_gadget` == " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;
    r1cs_ppzksnark_verifier_gadget<ppT_B> verifier(pb, vk, primary_input_bits, elt_size, proof, result, "verifier");
    // ====================================================== // 

    // ====================================================== //
    // This block kind of corresponds to what needs to be put
    // in the constructor of the `generate_r1cs_constraints`
    // function of the aggregator
    // ====================================================== // 

    PROFILE_CONSTRAINTS(pb, "check that proofs lies on the curve")
    {
        proof.generate_r1cs_constraints();
    }
    verifier.generate_r1cs_constraints();

    // ====================================================== //

    // ====================================================== //
    // This block kind of corresponds to what needs to be put
    // in the constructor of the `generate_r1cs_witness`
    // function of the aggregator
    // ====================================================== // 

    libff::bit_vector input_as_bits;
    for (const FieldT_A &el : example.primary_input)
    {
        libff::bit_vector v = libff::convert_field_element_to_bit_vector<FieldT_A>(el, elt_size);
        input_as_bits.insert(input_as_bits.end(), v.begin(), v.end());
    }

    primary_input_bits.fill_with_bits(pb, input_as_bits);

    vk.generate_r1cs_witness(keypair.vk);
    proof.generate_r1cs_witness(pi);
    verifier.generate_r1cs_witness();
    pb.val(result) = FieldT_B::one();

    printf("positive test:\n");
    assert(pb.is_satisfied());

    // ====================================================== //

    // ====================================================== //
    // This block kind of corresponds to what needs to be put
    // in the `aggregator_circuit_wrapper`
    // ====================================================== // 

    // Generate a proof of verification of the nested proof, i.e. generate the aggregation/wrapping proof
    // 1. Generate a verification and proving key (trusted setup)
    libsnark::r1cs_ppzksnark_keypair<ppT_B> wrap_keypair = libzeth::gen_trusted_setup<ppT_B>(pb);
    // 2. Generate the wrapping proof
    libsnark::r1cs_ppzksnark_proof<ppT_B> wrap_proof = libzeth::gen_proof<ppT_B>(pb, wrap_keypair.pk);
    libsnark::r1cs_ppzksnark_primary_input<ppT_B> wrap_primary_inputs = libsnark::r1cs_ppzksnark_primary_input<ppT_B>();
    const libzeth::extended_proof<ppT_B> ext_proof = libzeth::extended_proof<ppT_B>(wrap_proof, wrap_primary_inputs);
    bool res = libzeth::verify<ppT_B>(ext_proof, wrap_keypair.vk);
    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " == Result of the verification: " << res << "  == " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;

    // ====================================================== //

    pb.val(primary_input_bits[0]) = FieldT_B::one() - pb.val(primary_input_bits[0]);
    verifier.generate_r1cs_witness();
    pb.val(result) = FieldT_B::one();

    printf("negative test:\n");
    assert(!pb.is_satisfied());
    PRINT_CONSTRAINT_PROFILING();
    printf("number of constraints for verifier: %zu (verifier is implemented in %s constraints and verifies %s proofs))\n",
           pb.num_constraints(), annotation_B.c_str(), annotation_A.c_str());
}

template<typename ppT_A, typename ppT_B>
void test_verifier_batch_proofs(const std::string &annotation_A, const std::string &annotation_B)
{
    typedef libff::Fr<ppT_A> FieldT_A;
    typedef libff::Fr<ppT_B> FieldT_B;

    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " == In the test_verifier function == " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;

    const size_t num_constraints = 50;
    const size_t primary_input_size = 3;

    // Proof generated over F_r from an arithmetic circuit defined over F_q -> \pi_A
    r1cs_example<FieldT_A> example = generate_r1cs_example_with_field_input<FieldT_A>(num_constraints, primary_input_size);
    assert(example.primary_input.size() == primary_input_size);

    assert(example.constraint_system.is_satisfied(example.primary_input, example.auxiliary_input));

    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " == Generating the keypair == " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;
    const r1cs_ppzksnark_keypair<ppT_A> keypair = r1cs_ppzksnark_generator<ppT_A>(example.constraint_system);

    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " == Generating the nested proof == " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;
    const r1cs_ppzksnark_proof<ppT_A> pi = r1cs_ppzksnark_prover<ppT_A>(keypair.pk, example.primary_input, example.auxiliary_input);

    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " == Verifying the nested proof (outside a circuit) == " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;
    bool bit = r1cs_ppzksnark_verifier_strong_IC<ppT_A>(keypair.vk, example.primary_input, pi);
    assert(bit);

    // Verification of the proof generated over F_r, and production of a proof over F_q -> \pi_B
    const size_t elt_size = FieldT_A::size_in_bits();
    const size_t primary_input_size_in_bits = elt_size * primary_input_size;
    const size_t vk_size_in_bits = r1cs_ppzksnark_verification_key_variable<ppT_B>::size_in_bits(primary_input_size);

    protoboard<FieldT_B> pb;
    pb_variable_array<FieldT_B> vk_bits;
    vk_bits.allocate(pb, vk_size_in_bits, "vk_bits");

    pb_variable_array<FieldT_B> primary_input_bits;
    primary_input_bits.allocate(pb, primary_input_size_in_bits, "primary_input_bits");

    r1cs_ppzksnark_proof_variable<ppT_B> proof(pb, "proof");

    r1cs_ppzksnark_verification_key_variable<ppT_B> vk(pb, vk_bits, primary_input_size, "vk");

    pb_variable<FieldT_B> result;
    result.allocate(pb, "result");

    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " == Instantiate the `r1cs_ppzksnark_verifier_gadget` == " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;
    r1cs_ppzksnark_verifier_gadget<ppT_B> verifier(pb, vk, primary_input_bits, elt_size, proof, result, "verifier");

    PROFILE_CONSTRAINTS(pb, "check that proofs lies on the curve")
    {
        proof.generate_r1cs_constraints();
    }
    verifier.generate_r1cs_constraints();

    libff::bit_vector input_as_bits;
    for (const FieldT_A &el : example.primary_input)
    {
        libff::bit_vector v = libff::convert_field_element_to_bit_vector<FieldT_A>(el, elt_size);
        input_as_bits.insert(input_as_bits.end(), v.begin(), v.end());
    }

    primary_input_bits.fill_with_bits(pb, input_as_bits);

    vk.generate_r1cs_witness(keypair.vk);
    proof.generate_r1cs_witness(pi);
    verifier.generate_r1cs_witness();
    pb.val(result) = FieldT_B::one();

    printf("positive test:\n");
    assert(pb.is_satisfied());

    // Generate a proof of verification of the nested proof, i.e. generate the aggregation/wrapping proof
    // 1. Generate a verification and proving key (trusted setup)
    libsnark::r1cs_ppzksnark_keypair<ppT_B> wrap_keypair = libzeth::gen_trusted_setup<ppT_B>(pb);
    // 2. Generate the wrapping proof
    libsnark::r1cs_ppzksnark_proof<ppT_B> wrap_proof = libzeth::gen_proof<ppT_B>(pb, wrap_keypair.pk);
    libsnark::r1cs_ppzksnark_primary_input<ppT_B> wrap_primary_inputs = libsnark::r1cs_ppzksnark_primary_input<ppT_B>();
    const libzeth::extended_proof<ppT_B> ext_proof = libzeth::extended_proof<ppT_B>(wrap_proof, wrap_primary_inputs);
    bool res = libzeth::verify<ppT_B>(ext_proof, wrap_keypair.vk);
    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " == Result of the verification: " << res << "  == " << std::endl;
    std::cout << " =================================== " << std::endl;
    std::cout << " =================================== " << std::endl;

    pb.val(primary_input_bits[0]) = FieldT_B::one() - pb.val(primary_input_bits[0]);
    verifier.generate_r1cs_witness();
    pb.val(result) = FieldT_B::one();

    printf("negative test:\n");
    assert(!pb.is_satisfied());
    PRINT_CONSTRAINT_PROFILING();
    printf("number of constraints for verifier: %zu (verifier is implemented in %s constraints and verifies %s proofs))\n",
           pb.num_constraints(), annotation_B.c_str(), annotation_A.c_str());
}
*/