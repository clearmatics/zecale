/**
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>
#include <libff/algebra/fields/field_utils.hpp>

#include <libsnark/gadgetlib1/gadgets/fields/fp2_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/fields/fp3_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/fields/fp4_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/fields/fp6_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/verifiers/r1cs_ppzksnark_verifier_gadget.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include "libsnark_helpers/libsnark_helpers.hpp"

using namespace libsnark;

template<typename FieldT>
void dump_constraints(const protoboard<FieldT> &pb)
{
#ifdef DEBUG
    for (auto s : pb.constraint_system.constraint_annotations)
    {
        printf("constraint: %s\n", s.second.c_str());
    }
#endif
}

template<typename ppT_A, typename ppT_B>
void test_verifier_single_proof(const std::string &annotation_A, const std::string &annotation_B)
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

int main(void)
{
    libff::start_profiling();
    libff::mnt4_pp::init_public_params();
    libff::mnt6_pp::init_public_params();

    // Generate a proof over mnt4, and verify it's validity over mnt6
    test_verifier_single_proof<libff::mnt4_pp, libff::mnt6_pp>("mnt4", "mnt6");
    // Generate a set of proofs over mnt4, and verify their validity over mnt6
    test_verifier_batch_proofs<libff::mnt4_pp, libff::mnt6_pp>("mnt4", "mnt6");
}