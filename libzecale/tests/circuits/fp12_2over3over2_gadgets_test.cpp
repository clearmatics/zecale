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

TEST(Fp12_2over3over2_Test, ConstantOperations)
{
    using Fp12T = libff::bls12_377_Fq12;
    using FieldT = typename Fp12T::my_Fp;
    using Fp2T = typename Fp12T::my_Fp2;
    using Fp6T = typename Fp12T::my_Fp6;
    using Fp12_variable = libzecale::Fp12_2over3over2_variable<Fp12T>;

    // Native Frobenius calculation (check 1, 2, 6, and 12)
    const Fp12T a(
        Fp6T(
            Fp2T(FieldT("1"), FieldT("2")),
            Fp2T(FieldT("3"), FieldT("4")),
            Fp2T(FieldT("5"), FieldT("6"))),
        Fp6T(
            Fp2T(FieldT("21"), FieldT("22")),
            Fp2T(FieldT("23"), FieldT("24")),
            Fp2T(FieldT("25"), FieldT("26"))));
    const Fp2T fp2(FieldT("7"), FieldT("8"));
    const Fp12T unitary = libff::bls12_377_final_exponentiation_first_chunk(a);

    const Fp12T a_frob_1 = a.Frobenius_map(1);
    const Fp12T a_frob_2 = a.Frobenius_map(2);
    const Fp12T a_frob_3 = a.Frobenius_map(3);
    const Fp12T a_frob_6 = a.Frobenius_map(6);
    const Fp12T a_frob_12 = a.Frobenius_map(12);
    const Fp12T a_times_fp2 = fp2 * a;
    const Fp12T unitary_inv = unitary.unitary_inverse();

    // Operations in a circuit
    libsnark::protoboard<FieldT> pb;
    Fp12_variable a_var(pb, "a");
    Fp12_variable unitary_var(pb, "unitary");
    Fp12_variable a_frob_1_var = a_var.frobenius_map(1);
    Fp12_variable a_frob_2_var = a_var.frobenius_map(2);
    Fp12_variable a_frob_3_var = a_var.frobenius_map(3);
    Fp12_variable a_frob_6_var = a_var.frobenius_map(6);
    Fp12_variable a_frob_12_var = a_var.frobenius_map(12);
    Fp12_variable a_times_fp2_var = a_var * fp2;
    Fp12_variable unitary_inv_var = unitary_var.unitary_inverse();

    const size_t num_primary_inputs = pb.num_inputs();
    pb.set_input_sizes(num_primary_inputs);

    // Values
    a_var.generate_r1cs_witness(a);
    unitary_var.generate_r1cs_witness(unitary);
    a_frob_1_var.evaluate();
    a_frob_2_var.evaluate();
    a_frob_3_var.evaluate();
    a_frob_6_var.evaluate();
    a_frob_12_var.evaluate();
    a_times_fp2_var.evaluate();
    unitary_inv_var.evaluate();

    ASSERT_EQ(a_frob_1, a_frob_1_var.get_element());
    ASSERT_EQ(a_frob_2, a_frob_2_var.get_element());
    ASSERT_EQ(a_frob_3, a_frob_3_var.get_element());
    ASSERT_EQ(a_frob_6, a_frob_6_var.get_element());
    ASSERT_EQ(a_frob_12, a_frob_12_var.get_element());
    ASSERT_EQ(a, a_frob_12);
    ASSERT_EQ(a_times_fp2, a_times_fp2_var.get_element());
    ASSERT_EQ(unitary_inv, unitary_inv_var.get_element());
}

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
    const typename snark::keypair keypair = snark::generate_setup(pb);
    libsnark::r1cs_primary_input<libff::Fr<ppp>> primary_input =
        pb.primary_input();
    libsnark::r1cs_auxiliary_input<libff::Fr<ppp>> auxiliary_input =
        pb.auxiliary_input();
    typename snark::proof proof = snark::generate_proof(pb, keypair.pk);
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

    const Fp2T &z0 = z.coeffs[0].coeffs[0];
    const Fp2T &z1 = z.coeffs[0].coeffs[1];
    const Fp2T &z2 = z.coeffs[0].coeffs[2];
    const Fp2T &z3 = z.coeffs[1].coeffs[0];
    const Fp2T &z4 = z.coeffs[1].coeffs[1];
    const Fp2T &z5 = z.coeffs[1].coeffs[2];
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
    ASSERT_EQ(z_times_x.coeffs[0].coeffs[0], z_times_x_val.coeffs[0].coeffs[0]);

    // result.c0.c1
    ASSERT_EQ(z2 * x2, mul_024._z2_x2.result.get_element());
    ASSERT_EQ(z5 * x4, mul_024._z5_x4.result.get_element());
    ASSERT_EQ(z_times_x.coeffs[0].coeffs[1], z_times_x_val.coeffs[0].coeffs[1]);

    // result.c0.c2
    ASSERT_EQ(z3 * x4, mul_024._z3_x4.result.get_element());
    ASSERT_EQ(z_times_x.coeffs[0].coeffs[2], z_times_x_val.coeffs[0].coeffs[2]);

    // result.c1.c0
    ASSERT_EQ(z3 * x0, mul_024._z3_x0.result.get_element());
    ASSERT_EQ(z_times_x.coeffs[1].coeffs[0], z_times_x_val.coeffs[1].coeffs[0]);

    // result.c1.c1
    ASSERT_EQ(z5 * x2, mul_024._z5_x2.result.get_element());
    ASSERT_EQ(z_times_x.coeffs[1].coeffs[1], z_times_x_val.coeffs[1].coeffs[1]);

    // result.c1.c2
    ASSERT_EQ(z1 * x0, mul_024._z1_x0.result.get_element());
    const Fp2T S =
        (z1 * x2) + (z1 * x0) + (z5 * x4) + (z3 * x4) + (z3 * x0) + (z5 * x2);
    ASSERT_EQ(S, mul_024._S.get_element());
    ASSERT_EQ(
        (z1 + z3 + z5) * (x0 + x2 + x4) - S, z_times_x_val.coeffs[1].coeffs[2]);
    ASSERT_EQ(z_times_x.coeffs[1].coeffs[2], z_times_x_val.coeffs[1].coeffs[2]);

    // result
    ASSERT_EQ(z_times_x, z_times_x_var.get_element());

    // Generate and check the proof
    const typename snark::keypair keypair = snark::generate_setup(pb);
    libsnark::r1cs_primary_input<libff::Fr<ppp>> primary_input =
        pb.primary_input();
    libsnark::r1cs_auxiliary_input<libff::Fr<ppp>> auxiliary_input =
        pb.auxiliary_input();
    typename snark::proof proof = snark::generate_proof(pb, keypair.pk);
    ASSERT_TRUE(snark::verify(primary_input, proof, keypair.vk));
}

TEST(Fp12_2over3over2_Test, MulGadgetTest)
{
    using Fp12T = libff::bls12_377_Fq12;
    using FieldT = typename Fp12T::my_Fp;
    using Fp2T = typename Fp12T::my_Fp2;
    using Fp6T = typename Fp12T::my_Fp6;

    // Native multiplication
    const Fp12T a(
        Fp6T(
            Fp2T(FieldT("1"), FieldT("2")),
            Fp2T(FieldT("3"), FieldT("4")),
            Fp2T(FieldT("5"), FieldT("6"))),
        Fp6T(
            Fp2T(FieldT("21"), FieldT("22")),
            Fp2T(FieldT("23"), FieldT("24")),
            Fp2T(FieldT("25"), FieldT("26"))));
    const Fp12T b(
        Fp6T(
            Fp2T(FieldT("7"), FieldT("8")),
            Fp2T(FieldT("9"), FieldT("10")),
            Fp2T(FieldT("11"), FieldT("12"))),
        Fp6T(
            Fp2T(FieldT("27"), FieldT("28")),
            Fp2T(FieldT("39"), FieldT("30")),
            Fp2T(FieldT("31"), FieldT("32"))));
    const Fp12T c = a * b;

    // Multiplication in a circuit
    libsnark::protoboard<FieldT> pb;
    libzecale::Fp12_2over3over2_variable<Fp12T> a_var(pb, "a");
    libzecale::Fp12_2over3over2_variable<Fp12T> b_var(pb, "b");
    libzecale::Fp12_2over3over2_variable<Fp12T> c_var(pb, "c");
    const size_t num_primary_inputs = pb.num_inputs();
    pb.set_input_sizes(num_primary_inputs);
    libzecale::Fp12_2over3over2_mul_gadget<Fp12T> a_times_b(
        pb, a_var, b_var, c_var, "a*b=c");

    // Constraints
    a_times_b.generate_r1cs_constraints();

    // Values
    a_var.generate_r1cs_witness(a);
    b_var.generate_r1cs_witness(b);
    a_times_b.generate_r1cs_witness();

    const Fp6T a0b0 = a_times_b._v0._result.get_element();
    const Fp6T a1b1 = a_times_b._v1._result.get_element();
    const Fp12T c_value = c_var.get_element();
    const Fp6T expect_a1b1_result = a.coeffs[1] * b.coeffs[1];

    ASSERT_EQ(a.coeffs[0] * b.coeffs[0], a0b0);
    ASSERT_EQ(a.coeffs[1], a_times_b._v1._A.get_element());
    ASSERT_EQ(b.coeffs[1], a_times_b._v1._B.get_element());
    ASSERT_EQ(expect_a1b1_result, a1b1);

    const Fp6T expect_a0a1_times_b0b1_A = a.coeffs[0] + a.coeffs[1];
    const Fp6T expect_a0a1_times_b0b1_B = b.coeffs[0] + b.coeffs[1];
    const Fp6T expect_a0a1_times_b0b1_result = c.coeffs[1] + a0b0 + a1b1;

    ASSERT_EQ(
        expect_a0a1_times_b0b1_A,
        a_times_b._a0_plus_a1_times_b0_plus_b1._A.get_element());
    ASSERT_EQ(
        expect_a0a1_times_b0b1_B,
        a_times_b._a0_plus_a1_times_b0_plus_b1._B.get_element());
    ASSERT_EQ(
        expect_a0a1_times_b0b1_result,
        a_times_b._a0_plus_a1_times_b0_plus_b1._result.get_element());

    ASSERT_EQ(c.coeffs[0], c_value.coeffs[0]);
    ASSERT_EQ(c.coeffs[1], c_value.coeffs[1]);

    // Generate and check the proof
    const typename snark::keypair keypair = snark::generate_setup(pb);
    libsnark::r1cs_primary_input<libff::Fr<ppp>> primary_input =
        pb.primary_input();
    libsnark::r1cs_auxiliary_input<libff::Fr<ppp>> auxiliary_input =
        pb.auxiliary_input();
    typename snark::proof proof = snark::generate_proof(pb, keypair.pk);
    ASSERT_TRUE(snark::verify(primary_input, proof, keypair.vk));
}

TEST(Fp12_2over3over2_Test, InvGadgetTest)
{
    using Fp12T = libff::bls12_377_Fq12;
    using FieldT = typename Fp12T::my_Fp;
    using Fp2T = typename Fp12T::my_Fp2;
    using Fp6T = typename Fp12T::my_Fp6;

    // Native inversion
    const Fp12T a(
        Fp6T(
            Fp2T(FieldT("1"), FieldT("2")),
            Fp2T(FieldT("3"), FieldT("4")),
            Fp2T(FieldT("5"), FieldT("6"))),
        Fp6T(
            Fp2T(FieldT("21"), FieldT("22")),
            Fp2T(FieldT("23"), FieldT("24")),
            Fp2T(FieldT("25"), FieldT("26"))));
    const Fp12T a_inv = a.inverse();

    // Inversion in a circuit
    libsnark::protoboard<FieldT> pb;
    libzecale::Fp12_2over3over2_variable<Fp12T> a_var(pb, "a");
    libzecale::Fp12_2over3over2_variable<Fp12T> a_inv_var(pb, "a.inverse");
    const size_t num_primary_inputs = pb.num_inputs();
    pb.set_input_sizes(num_primary_inputs);
    libzecale::Fp12_2over3over2_inv_gadget<Fp12T> invert(
        pb, a_var, a_inv_var, "check a.inverse");

    // Constraints
    invert.generate_r1cs_constraints();

    // Values
    a_var.generate_r1cs_witness(a);
    invert.generate_r1cs_witness();

    const Fp12T a_inv_value = a_inv_var.get_element();
    ASSERT_EQ(a_inv, a_inv_value);

    // Generate and check the proof
    const typename snark::keypair keypair = snark::generate_setup(pb);
    libsnark::r1cs_primary_input<libff::Fr<ppp>> primary_input =
        pb.primary_input();
    libsnark::r1cs_auxiliary_input<libff::Fr<ppp>> auxiliary_input =
        pb.auxiliary_input();
    typename snark::proof proof = snark::generate_proof(pb, keypair.pk);
    ASSERT_TRUE(snark::verify(primary_input, proof, keypair.vk));
}

TEST(Fp12_2over3over2_Test, CyclotomicSquareGadget)
{
    using Fp12T = libff::bls12_377_Fq12;
    using FieldT = typename Fp12T::my_Fp;
    using Fp2T = typename Fp12T::my_Fp2;
    using Fp6T = typename Fp12T::my_Fp6;

    // Native Frobenius calculation (check 1, 2, 6, and 12)
    const Fp12T a(
        Fp6T(
            Fp2T(FieldT("1"), FieldT("2")),
            Fp2T(FieldT("3"), FieldT("4")),
            Fp2T(FieldT("5"), FieldT("6"))),
        Fp6T(
            Fp2T(FieldT("21"), FieldT("22")),
            Fp2T(FieldT("23"), FieldT("24")),
            Fp2T(FieldT("25"), FieldT("26"))));
    const Fp12T u = libff::bls12_377_final_exponentiation_first_chunk(a);
    const Fp12T u_squared = u.cyclotomic_squared();

    // Inversion in a circuit
    libsnark::protoboard<FieldT> pb;
    libzecale::Fp12_2over3over2_variable<Fp12T> u_var(pb, "u");
    libzecale::Fp12_2over3over2_variable<Fp12T> u_squared_var(pb, "u_squared");
    const size_t num_primary_inputs = pb.num_inputs();
    pb.set_input_sizes(num_primary_inputs);
    libzecale::Fp12_2over3over2_cyclotomic_square_gadget<Fp12T>
        cyclotomic_square_gadget(
            pb, u_var, u_squared_var, "compute_cyclotomic_square");

    // Constraints
    cyclotomic_square_gadget.generate_r1cs_constraints();

    // Values
    u_var.generate_r1cs_witness(u);
    cyclotomic_square_gadget.generate_r1cs_witness();

    const Fp2T z0 = cyclotomic_square_gadget._A._c0._c0.get_element();
    const Fp2T z1 = cyclotomic_square_gadget._A._c0._c1.get_element();
    const Fp2T z2 = cyclotomic_square_gadget._A._c0._c2.get_element();
    const Fp2T z3 = cyclotomic_square_gadget._A._c1._c0.get_element();
    const Fp2T z4 = cyclotomic_square_gadget._A._c1._c1.get_element();
    const Fp2T z5 = cyclotomic_square_gadget._A._c1._c2.get_element();

    ASSERT_EQ(u.coeffs[0].coeffs[0], z0);
    ASSERT_EQ(u.coeffs[0].coeffs[1], z1);
    ASSERT_EQ(u.coeffs[0].coeffs[2], z2);
    ASSERT_EQ(u.coeffs[1].coeffs[0], z3);
    ASSERT_EQ(u.coeffs[1].coeffs[1], z4);
    ASSERT_EQ(u.coeffs[1].coeffs[2], z5);

    ASSERT_EQ(z0, cyclotomic_square_gadget._z0z4.A.get_element());
    ASSERT_EQ(z4, cyclotomic_square_gadget._z0z4.B.get_element());
    ASSERT_EQ(z0 * z4, cyclotomic_square_gadget._z0z4.result.get_element());
    ASSERT_EQ(
        FieldT(6).inverse() * (u_squared.coeffs[1].coeffs[1] - z4 - z4),
        z0 * z4);

    ASSERT_EQ(
        FieldT(3) * (z0 + z4),
        cyclotomic_square_gadget._check_result_0.A.get_element());
    ASSERT_EQ(
        z0 + Fp6T::non_residue * z4,
        cyclotomic_square_gadget._check_result_0.B.get_element());
    ASSERT_EQ(
        FieldT(3) * (z0 + z4) * (z0 + Fp6T::non_residue * z4),
        cyclotomic_square_gadget._check_result_0.result.get_element());
    ASSERT_EQ(
        FieldT(3) * (z0 + z4) * (z0 + Fp6T::non_residue * z4),
        u_squared.coeffs[0].coeffs[0] + u.coeffs[0].coeffs[0] +
            u.coeffs[0].coeffs[0] +
            FieldT(3) * z0 * z4 * (Fp2T::one() + Fp6T::non_residue));

    ASSERT_EQ(
        u_squared.coeffs[0].coeffs[0], u_squared_var._c0._c0.get_element());
    ASSERT_EQ(
        u_squared.coeffs[0].coeffs[1], u_squared_var._c0._c1.get_element());
    ASSERT_EQ(
        u_squared.coeffs[0].coeffs[2], u_squared_var._c0._c2.get_element());
    ASSERT_EQ(
        u_squared.coeffs[1].coeffs[0], u_squared_var._c1._c0.get_element());
    ASSERT_EQ(
        u_squared.coeffs[1].coeffs[1], u_squared_var._c1._c1.get_element());
    ASSERT_EQ(
        u_squared.coeffs[1].coeffs[2], u_squared_var._c1._c2.get_element());
    ASSERT_EQ(u_squared, u_squared_var.get_element());

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
