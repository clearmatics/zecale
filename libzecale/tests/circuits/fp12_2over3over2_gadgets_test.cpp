// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzecale/circuits/fields/fp12_2over3over2_gadgets.hpp"
#include "libzecale/circuits/pairing/bls12_377_pairing.hpp"
#include "libzecale/circuits/pairing/bw6_761_pairing_params.hpp"

#include <gtest/gtest.h>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>
#include <libff/algebra/curves/bw6_761/bw6_761_pp.hpp>
#include <libzeth/snarks/groth16/groth16_snark.hpp>

using ppp = libff::bw6_761_pp;
using snark = libzeth::groth16_snark<ppp>;

namespace
{

TEST(Fp12_2over3over2_Test, SquareGadgetTest)
{
    using Fp12T = libff::bls12_377_Fq12;
    using FieldT = typename Fp12T::my_Fp;
    using Fp2T = typename Fp12T::my_Fp2;
    using Fp6T = typename Fp12T::my_Fp6;

    // Native squaring
    const Fp12T z(
        Fp6T(
            Fp2T(FieldT("5"), FieldT("6")),
            Fp2T(FieldT("7"), FieldT("8")),
            Fp2T(FieldT("9"), FieldT("10"))),
        Fp6T(
            Fp2T(FieldT("21"), FieldT("22")),
            Fp2T(FieldT("23"), FieldT("24")),
            Fp2T(FieldT("25"), FieldT("26"))));
    const Fp12T z_squared = z.squared();

    // Squaring in a circuit
    libsnark::protoboard<FieldT> pb;
    libzecale::Fp12_2over3over2_variable<Fp12T> z_var(pb, "z");
    libzecale::Fp12_2over3over2_variable<Fp12T> z_squared_var(pb, "z_squared");
    const size_t num_primary_inputs = pb.num_inputs();
    pb.set_input_sizes(num_primary_inputs);

    libzecale::Fp12_2over3over2_square_gadget<Fp12T> square_gadget(
        pb, z_var, z_squared_var, " square_z");

    // Constraints
    square_gadget.generate_r1cs_constraints();

    // Values
    z_var.generate_r1cs_witness(z);
    square_gadget.generate_r1cs_witness();

    const Fp12T z_squared_val = z_squared_var.get_element();
    ASSERT_EQ(z_squared, z_squared_val);

    // Generate and check the proof
    const typename snark::KeypairT keypair = snark::generate_setup(pb);
    libsnark::r1cs_primary_input<libff::Fr<ppp>> primary_input =
        pb.primary_input();
    libsnark::r1cs_auxiliary_input<libff::Fr<ppp>> auxiliary_input =
        pb.auxiliary_input();
    typename snark::ProofT proof = snark::generate_proof(pb, keypair.pk);
    ASSERT_TRUE(snark::verify(primary_input, proof, keypair.vk));
}

TEST(Fp12_2over3over2_Test, MulBy024GadgetTest)
{
    using Fp12T = libff::bls12_377_Fq12;
    using FieldT = typename Fp12T::my_Fp;
    using Fp2T = typename Fp12T::my_Fp2;
    using Fp6T = typename Fp12T::my_Fp6;

    // Native multiplication, using values from the libff tests.
    const Fp12T z(
        Fp6T(
            Fp2T(FieldT("5"), FieldT("6")),
            Fp2T(FieldT("7"), FieldT("8")),
            Fp2T(FieldT("9"), FieldT("10"))),
        Fp6T(
            Fp2T(FieldT("21"), FieldT("22")),
            Fp2T(FieldT("23"), FieldT("24")),
            Fp2T(FieldT("25"), FieldT("26"))));
    const Fp2T x0(FieldT("11"), FieldT("12"));
    const Fp2T x2(FieldT("15"), FieldT("16"));
    const Fp2T x4(FieldT("3"), FieldT("4"));
    const Fp12T z_times_x = z.mul_by_024(x0, x4, x2);

    // Multiplication in a circuit
    libsnark::protoboard<FieldT> pb;
    libzecale::Fp12_2over3over2_variable<Fp12T> z_var(pb, "z");
    libsnark::Fp2_variable<Fp2T> x0_var(pb, " x0");
    libsnark::Fp2_variable<Fp2T> x2_var(pb, " x2");
    libsnark::Fp2_variable<Fp2T> x4_var(pb, " x4");
    libzecale::Fp12_2over3over2_variable<Fp12T> z_times_x_var(pb, "z_times_x");
    const size_t num_primary_inputs = pb.num_inputs();
    pb.set_input_sizes(num_primary_inputs);

    libzecale::Fp12_2over3over2_mul_by_024_gadget<Fp12T> mul_024(
        pb, z_var, x0_var, x2_var, x4_var, z_times_x_var, "mul_024");

    // Constraints
    mul_024.generate_r1cs_constraints();

    // Values
    z_var.generate_r1cs_witness(z);
    x0_var.generate_r1cs_witness(x0);
    x2_var.generate_r1cs_witness(x2);
    x4_var.generate_r1cs_witness(x4);
    mul_024.generate_r1cs_witness();

    const Fp2T &z0 = z.c0.c0;
    const Fp2T &z1 = z.c0.c1;
    const Fp2T &z2 = z.c0.c2;
    const Fp2T &z3 = z.c1.c0;
    const Fp2T &z4 = z.c1.c1;
    const Fp2T &z5 = z.c1.c2;
    ASSERT_EQ(z, mul_024._Z.get_element());
    ASSERT_EQ(x0, mul_024._X_0.get_element());
    ASSERT_EQ(x2, mul_024._X_2.get_element());
    ASSERT_EQ(x4, mul_024._X_4.get_element());

    const Fp12T z_times_x_val = z_times_x_var.get_element();
    ASSERT_EQ(z_times_x_val, mul_024._result.get_element());

    // result.c0.c0
    ASSERT_EQ(z1 * x2, mul_024._z1_x2.result.get_element());
    ASSERT_EQ(z4 * x4, mul_024._z4_x4.result.get_element());
    ASSERT_EQ(z0 * x0, mul_024._z0_x0.result.get_element());
    ASSERT_EQ(z_times_x.c0.c0, z_times_x_val.c0.c0);

    // result.c0.c1
    ASSERT_EQ(z2 * x2, mul_024._z2_x2.result.get_element());
    ASSERT_EQ(z5 * x4, mul_024._z5_x4.result.get_element());
    ASSERT_EQ(z_times_x.c0.c1, z_times_x_val.c0.c1);

    // result.c0.c2
    ASSERT_EQ(z3 * x4, mul_024._z3_x4.result.get_element());
    ASSERT_EQ(z_times_x.c0.c2, z_times_x_val.c0.c2);

    // result.c1.c0
    ASSERT_EQ(z3 * x0, mul_024._z3_x0.result.get_element());
    ASSERT_EQ(z_times_x.c1.c0, z_times_x_val.c1.c0);

    // result.c1.c1
    ASSERT_EQ(z5 * x2, mul_024._z5_x2.result.get_element());
    ASSERT_EQ(z_times_x.c1.c1, z_times_x_val.c1.c1);

    // result.c1.c2
    ASSERT_EQ(z1 * x0, mul_024._z1_x0.result.get_element());
    const Fp2T S =
        (z1 * x2) + (z1 * x0) + (z5 * x4) + (z3 * x4) + (z3 * x0) + (z5 * x2);
    ASSERT_EQ(S, mul_024._S.get_element());
    ASSERT_EQ((z1 + z3 + z5) * (x0 + x2 + x4) - S, z_times_x_val.c1.c2);
    ASSERT_EQ(z_times_x.c1.c2, z_times_x_val.c1.c2);

    // result
    ASSERT_EQ(z_times_x, z_times_x_var.get_element());

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
