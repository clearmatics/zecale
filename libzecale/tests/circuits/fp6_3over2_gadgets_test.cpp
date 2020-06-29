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
    const Fp2T a1b1 = mul_a_b._a1b1.result.get_element();
    const Fp2T a2b2 = mul_a_b._a2b2.result.get_element();
    const Fp2T a1a2_times_b1b2 = mul_a_b._a1a2_times_b1b2.result.get_element();
    const Fp2T a0b0 = mul_a_b._a0b0.result.get_element();
    const Fp2T a0a1_times_b0b1 = mul_a_b._a0a1_times_b0b1.result.get_element();
    const Fp2T a0a2_times_b0b2 = mul_a_b._a0a2_times_b0b2.result.get_element();
    const Fp6T c_val = c_var.get_element();

    ASSERT_EQ(a, a_val);
    ASSERT_EQ(b, b_val);
    ASSERT_EQ(a.c1 * b.c1, a1b1);
    ASSERT_EQ(a.c2 * b.c2, a2b2);
    ASSERT_EQ((a.c1 + a.c2) * (b.c1 + b.c2), a1a2_times_b1b2);
    ASSERT_EQ(a.c0 * b.c0, a0b0);
    ASSERT_EQ((a.c0 + a.c1) * (b.c0 + b.c1), a0a1_times_b0b1);
    ASSERT_EQ((a.c0 + a.c2) * (b.c0 + b.c2), a0a2_times_b0b2);
    // ASSERT_EQ(c.c0, c_val.c0);
    ASSERT_EQ(c.c1, c_val.c1);
    ASSERT_EQ(c.c2, c_val.c2);
    ASSERT_EQ(c, c_val);

    // Generate and check the proof
    const typename snark::KeypairT keypair = snark::generate_setup(pb);
    libsnark::r1cs_primary_input<libff::Fr<ppp>> primary_input =
        pb.primary_input();
    libsnark::r1cs_auxiliary_input<libff::Fr<ppp>> auxiliary_input =
        pb.auxiliary_input();
    typename snark::ProofT proof = snark::generate_proof(pb, keypair.pk);
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
