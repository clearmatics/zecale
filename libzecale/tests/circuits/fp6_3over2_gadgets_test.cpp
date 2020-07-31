// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzecale/circuits/fields/fp6_3over2_gadgets.hpp"
// #include "libzecale/circuits/pairing/bw6_761_pairing_params.hpp"

#include <gtest/gtest.h>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>
#include <libff/algebra/curves/bw6_761/bw6_761_pp.hpp>
#include <libzeth/snarks/groth16/groth16_snark.hpp>

using ppp = libff::bw6_761_pp;
using snark = libzeth::groth16_snark<ppp>;

namespace
{

TEST(Fp6_3over2_Test, ConstantOperations)
{
    using Fp6T = libff::bls12_377_Fq6;
    using Fp2T = typename Fp6T::my_Fp2;
    using FieldT = typename Fp6T::my_Fp;
    using Fp6_variable = libzecale::Fp6_3over2_variable<Fp6T>;

    // Native operations
    const Fp6T a(
        Fp2T(FieldT("1"), FieldT("2")),
        Fp2T(FieldT("3"), FieldT("4")),
        Fp2T(FieldT("5"), FieldT("6")));
    const Fp6T b(
        Fp2T(FieldT("21"), FieldT("22")),
        Fp2T(FieldT("23"), FieldT("24")),
        Fp2T(FieldT("25"), FieldT("26")));
    const Fp2T fp2(FieldT("7"), FieldT("8"));
    const Fp6T a_frob_1 = a.Frobenius_map(1);
    const Fp6T a_frob_2 = a.Frobenius_map(2);
    const Fp6T a_frob_3 = a.Frobenius_map(3);
    const Fp6T a_frob_6 = a.Frobenius_map(6);
    const Fp6T a_frob_12 = a.Frobenius_map(12);
    const Fp6T a_times_b = a * b;
    const Fp6T a_times_fp2 = fp2 * a;
    const Fp6T negative_a = -a;

    // Frobenius map in a circuit
    libsnark::protoboard<FieldT> pb;
    Fp6_variable a_var(pb, "a");
    Fp6_variable a_frob_1_var = a_var.frobenius_map(1);
    Fp6_variable a_frob_2_var = a_var.frobenius_map(2);
    Fp6_variable a_frob_3_var = a_var.frobenius_map(3);
    Fp6_variable a_frob_6_var = a_var.frobenius_map(6);
    Fp6_variable a_frob_12_var = a_var.frobenius_map(12);
    Fp6_variable a_times_b_var = a_var * b;
    Fp6_variable a_times_fp2_var = a_var * fp2;
    Fp6_variable negative_a_var = -a_var;
    const size_t num_primary_inputs = pb.num_inputs();
    pb.set_input_sizes(num_primary_inputs);

    // Values
    a_var.generate_r1cs_witness(a);
    a_frob_1_var.evaluate();
    a_frob_2_var.evaluate();
    a_frob_3_var.evaluate();
    a_frob_6_var.evaluate();
    a_frob_12_var.evaluate();
    a_times_b_var.evaluate();
    a_times_fp2_var.evaluate();
    negative_a_var.evaluate();

    ASSERT_EQ(a_frob_1, a_frob_1_var.get_element());
    ASSERT_EQ(a_frob_2, a_frob_2_var.get_element());
    ASSERT_EQ(a_frob_3, a_frob_3_var.get_element());
    ASSERT_EQ(a_frob_6, a_frob_6_var.get_element());
    ASSERT_EQ(a_frob_12, a_frob_12_var.get_element());
    ASSERT_EQ(a, a_frob_12);
    ASSERT_EQ(a_times_b, a_times_b_var.get_element());
    ASSERT_EQ(a_times_fp2, a_times_fp2_var.get_element());
    ASSERT_EQ(negative_a, negative_a_var.get_element());
}

TEST(Fp6_3over2_Test, MulGadgetTest)
{
    using Fp6T = libff::bls12_377_Fq6;
    using Fp2T = typename Fp6T::my_Fp2;
    using FieldT = typename Fp6T::my_Fp;

    // Native multiplication
    const Fp6T a(
        Fp2T(FieldT("5"), FieldT("6")),
        Fp2T(FieldT("7"), FieldT("8")),
        Fp2T(FieldT("9"), FieldT("10")));
    const Fp6T b(
        Fp2T(FieldT("21"), FieldT("22")),
        Fp2T(FieldT("23"), FieldT("24")),
        Fp2T(FieldT("25"), FieldT("26")));
    const Fp6T c = a * b;

    // Multiplication in circuit
    libsnark::protoboard<FieldT> pb;
    libzecale::Fp6_3over2_variable<Fp6T> a_var(pb, "a");
    libzecale::Fp6_3over2_variable<Fp6T> b_var(pb, "b");
    libzecale::Fp6_3over2_variable<Fp6T> c_var(pb, "c");
    const size_t num_primary_inputs = pb.num_inputs();
    pb.set_input_sizes(num_primary_inputs);

    libzecale::Fp6_3over2_mul_gadget<Fp6T> mul_a_b(
        pb, a_var, b_var, c_var, "a*b");

    // Constraints
    mul_a_b.generate_r1cs_constraints();

    // values
    a_var.generate_r1cs_witness(a);
    b_var.generate_r1cs_witness(b);
    mul_a_b.generate_r1cs_witness();

    // Check values
    const Fp6T a_val = a_var.get_element();
    const Fp6T b_val = b_var.get_element();
    const Fp2T v1 = mul_a_b._compute_v1.result.get_element();
    const Fp2T v2 = mul_a_b._compute_v2.result.get_element();
    const Fp2T a1a2_times_b1b2 =
        mul_a_b._compute_a1a2_times_b1b2.result.get_element();
    const Fp2T v0 = mul_a_b._compute_v0.result.get_element();
    const Fp2T a0a1_times_b0b1 =
        mul_a_b._compute_a0a1_times_b0b1.result.get_element();
    const Fp2T a0a2_times_b0b2 =
        mul_a_b._compute_a0a2_times_b0b2.result.get_element();
    const Fp6T c_val = c_var.get_element();

    ASSERT_EQ(a, a_val);
    ASSERT_EQ(b, b_val);
    ASSERT_EQ(a.coeffs[1] * b.coeffs[1], v1);
    ASSERT_EQ(a.coeffs[2] * b.coeffs[2], v2);
    ASSERT_EQ(
        (a.coeffs[1] + a.coeffs[2]) * (b.coeffs[1] + b.coeffs[2]),
        a1a2_times_b1b2);
    ASSERT_EQ(a.coeffs[0] * b.coeffs[0], v0);
    ASSERT_EQ(
        (a.coeffs[0] + a.coeffs[1]) * (b.coeffs[0] + b.coeffs[1]),
        a0a1_times_b0b1);
    ASSERT_EQ(
        (a.coeffs[0] + a.coeffs[2]) * (b.coeffs[0] + b.coeffs[2]),
        a0a2_times_b0b2);
    ASSERT_EQ(c.coeffs[1], c_val.coeffs[1]);
    ASSERT_EQ(c.coeffs[2], c_val.coeffs[2]);
    ASSERT_EQ(c, c_val);

    // Generate and check the proof
    const typename snark::keypair keypair = snark::generate_setup(pb);
    libsnark::r1cs_primary_input<libff::Fr<ppp>> primary_input =
        pb.primary_input();
    libsnark::r1cs_auxiliary_input<libff::Fr<ppp>> auxiliary_input =
        pb.auxiliary_input();
    typename snark::proof proof = snark::generate_proof(pb, keypair.pk);
    ASSERT_TRUE(snark::verify(primary_input, proof, keypair.vk));
}

} // namespace

int main(int argc, char **argv)
{
    libff::bls12_377_pp::init_public_params();
    libff::bw6_761_pp::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
