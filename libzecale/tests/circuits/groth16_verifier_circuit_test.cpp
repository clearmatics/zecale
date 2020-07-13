// DISCLAIMER:
// File adapated from:
// https://github.com/scipr-lab/libsnark/blob/master/libsnark/gadgetlib1/gadgets/verifiers/tests/test_r1cs_ppzksnark_verifier_gadget.cpp

#include "libzecale/circuits/groth16_verifier/r1cs_gg_ppzksnark_verifier_gadget.hpp"
#include "libzecale/circuits/pairing/bw6_761_pairing_params.hpp"
#include "libzecale/circuits/pairing/mnt_pairing_params.hpp"
#include "libzecale/circuits/pairing/pairing_params.hpp"

#include <gtest/gtest.h>
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

using namespace libzecale;
using namespace libsnark;

namespace
{

/// This test generates a valid proof and checks that this valid proof
/// is succesfully verified by the groth16 verifier gadget
template<typename ppT_A, typename ppT_B>
void test_verifier(
    const std::string &annotation_A, const std::string &annotation_B)
{
    typedef libff::Fr<ppT_A> FieldT_A;
    typedef libff::Fr<ppT_B> FieldT_B;

    const size_t num_constraints = 50;
    const size_t primary_input_size = 3;

    libsnark::r1cs_example<FieldT_A> example =
        libsnark::generate_r1cs_example_with_field_input<FieldT_A>(
            num_constraints, primary_input_size);
    ASSERT_EQ(example.primary_input.size(), primary_input_size);
    ASSERT_TRUE(example.constraint_system.is_satisfied(
        example.primary_input, example.auxiliary_input));

    const libsnark::r1cs_gg_ppzksnark_keypair<ppT_A> keypair =
        libsnark::r1cs_gg_ppzksnark_generator<ppT_A>(example.constraint_system);
    const libsnark::r1cs_gg_ppzksnark_proof<ppT_A> pi =
        libsnark::r1cs_gg_ppzksnark_prover<ppT_A>(
            keypair.pk, example.primary_input, example.auxiliary_input);
    bool bit = libsnark::r1cs_gg_ppzksnark_verifier_strong_IC<ppT_A>(
        keypair.vk, example.primary_input, pi);
    ASSERT_TRUE(bit);

    const size_t elt_size = FieldT_A::size_in_bits();
    const size_t primary_input_size_in_bits = elt_size * primary_input_size;
    const size_t vk_size_in_bits =
        r1cs_gg_ppzksnark_verification_key_variable<ppT_B>::size_in_bits(
            primary_input_size);

    libsnark::protoboard<FieldT_B> pb;
    libsnark::pb_variable_array<FieldT_B> vk_bits;
    vk_bits.allocate(pb, vk_size_in_bits, "vk_bits");

    libsnark::pb_variable_array<FieldT_B> primary_input_bits;
    primary_input_bits.allocate(
        pb, primary_input_size_in_bits, "primary_input_bits");

    r1cs_gg_ppzksnark_proof_variable<ppT_B> proof(pb, "proof");
    r1cs_gg_ppzksnark_verification_key_variable<ppT_B> vk(
        pb, vk_bits, primary_input_size, "vk");

    libsnark::pb_variable<FieldT_B> result;
    result.allocate(pb, "result");

    r1cs_gg_ppzksnark_verifier_gadget<ppT_B> verifier(
        pb, vk, primary_input_bits, elt_size, proof, result, "verifier");

    PROFILE_CONSTRAINTS(pb, "check that proofs lies on the curve")
    {
        proof.generate_r1cs_constraints();
    }
    verifier.generate_r1cs_constraints();

    libff::bit_vector input_as_bits;
    for (const FieldT_A &el : example.primary_input) {
        libff::bit_vector v =
            libff::convert_field_element_to_bit_vector<FieldT_A>(el, elt_size);
        input_as_bits.insert(input_as_bits.end(), v.begin(), v.end());
    }

    primary_input_bits.fill_with_bits(pb, input_as_bits);

    // Check valid proof with good verification key and primary inputs
    // The result should be ONE
    vk.generate_r1cs_witness(keypair.vk);
    proof.generate_r1cs_witness(pi);
    verifier.generate_r1cs_witness();
    pb.val(result) = FieldT_B::one();

    std::cout << "Positive test case" << std::endl;
    ASSERT_TRUE(pb.is_satisfied());

    // Change the primary inputs to make the proof verification fail
    pb.val(primary_input_bits[0]) =
        FieldT_B::one() - pb.val(primary_input_bits[0]);
    verifier.generate_r1cs_witness();
    pb.val(result) = FieldT_B::one();

    std::cout << "Negative test case" << std::endl;
    ASSERT_FALSE(pb.is_satisfied());
    PRINT_CONSTRAINT_PROFILING();
    printf(
        "number of constraints for verifier: %zu (verifier is implemented in "
        "%s constraints and verifies %s proofs))\n",
        pb.num_constraints(),
        annotation_B.c_str(),
        annotation_A.c_str());
}

template<typename ppT_A, typename ppT_B>
void test_hardcoded_verifier(
    const std::string &annotation_A, const std::string &annotation_B)
{
    typedef libff::Fr<ppT_A> FieldT_A;
    typedef libff::Fr<ppT_B> FieldT_B;

    const size_t num_constraints = 50;
    const size_t primary_input_size = 3;

    libsnark::r1cs_example<FieldT_A> example =
        libsnark::generate_r1cs_example_with_field_input<FieldT_A>(
            num_constraints, primary_input_size);
    ASSERT_EQ(example.primary_input.size(), primary_input_size);

    ASSERT_TRUE(example.constraint_system.is_satisfied(
        example.primary_input, example.auxiliary_input));
    const libsnark::r1cs_gg_ppzksnark_keypair<ppT_A> keypair =
        libsnark::r1cs_gg_ppzksnark_generator<ppT_A>(example.constraint_system);
    const libsnark::r1cs_gg_ppzksnark_proof<ppT_A> pi =
        libsnark::r1cs_gg_ppzksnark_prover<ppT_A>(
            keypair.pk, example.primary_input, example.auxiliary_input);
    bool bit = libsnark::r1cs_gg_ppzksnark_verifier_strong_IC<ppT_A>(
        keypair.vk, example.primary_input, pi);
    ASSERT_TRUE(bit);

    const size_t elt_size = FieldT_A::size_in_bits();
    const size_t primary_input_size_in_bits = elt_size * primary_input_size;

    protoboard<FieldT_B> pb;
    r1cs_gg_ppzksnark_preprocessed_r1cs_gg_ppzksnark_verification_key_variable<
        ppT_B>
        hardcoded_vk(pb, keypair.vk, "hardcoded_vk");
    pb_variable_array<FieldT_B> primary_input_bits;
    primary_input_bits.allocate(
        pb, primary_input_size_in_bits, "primary_input_bits");

    r1cs_gg_ppzksnark_proof_variable<ppT_B> proof(pb, "proof");

    pb_variable<FieldT_B> result;
    result.allocate(pb, "result");

    r1cs_gg_ppzksnark_online_verifier_gadget<ppT_B> online_verifier(
        pb,
        hardcoded_vk,
        primary_input_bits,
        elt_size,
        proof,
        result,
        "online_verifier");

    PROFILE_CONSTRAINTS(pb, "check that proofs lies on the curve")
    {
        proof.generate_r1cs_constraints();
    }
    online_verifier.generate_r1cs_constraints();

    libff::bit_vector input_as_bits;
    for (const FieldT_A &el : example.primary_input) {
        libff::bit_vector v =
            libff::convert_field_element_to_bit_vector<FieldT_A>(el, elt_size);
        input_as_bits.insert(input_as_bits.end(), v.begin(), v.end());
    }

    primary_input_bits.fill_with_bits(pb, input_as_bits);

    proof.generate_r1cs_witness(pi);
    online_verifier.generate_r1cs_witness();
    pb.val(result) = FieldT_B::one();

    printf("Positive test:\n");
    ASSERT_TRUE(pb.is_satisfied());

    // Modify the primary inputs to make the proof verification fail
    pb.val(primary_input_bits[0]) =
        FieldT_B::one() - pb.val(primary_input_bits[0]);
    online_verifier.generate_r1cs_witness();
    pb.val(result) = FieldT_B::one();

    printf("Negative test:\n");
    ASSERT_FALSE(pb.is_satisfied());
    PRINT_CONSTRAINT_PROFILING();
    printf(
        "number of constraints for verifier: %zu (verifier is implemented in "
        "%s constraints and verifies %s proofs))\n",
        pb.num_constraints(),
        annotation_B.c_str(),
        annotation_A.c_str());
}

TEST(Groth16VerifierGadgetTests, MntGroth16VerifierGadget)
{
    test_verifier<libff::mnt4_pp, libff::mnt6_pp>("mnt4", "mnt6");
    test_verifier<libff::mnt6_pp, libff::mnt4_pp>("mnt6", "mnt4");

    test_hardcoded_verifier<libff::mnt4_pp, libff::mnt6_pp>("mnt4", "mnt6");
    test_hardcoded_verifier<libff::mnt6_pp, libff::mnt4_pp>("mnt6", "mnt4");
}

TEST(Groth16VerifierGadgetTests, BlsGroth16VerifierGadget)
{
    test_verifier<libff::bls12_377_pp, libff::bw6_761_pp>(
        "bls12-377", "bw6-761");

    test_hardcoded_verifier<libff::bls12_377_pp, libff::bw6_761_pp>(
        "bls12-377", "bw6-761");
}

} // namespace

int main(int argc, char **argv)
{
    libff::start_profiling();

    libff::mnt4_pp::init_public_params();
    libff::mnt6_pp::init_public_params();
    libff::bls12_377_pp::init_public_params();
    libff::bw6_761_pp::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
