// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzecale/circuits/pairing/bw6_761_pairing_params.hpp"
#include "libzecale/circuits/pairing/group_variable_gadgets.hpp"

#include <gtest/gtest.h>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>
#include <libff/algebra/curves/bw6_761/bw6_761_pp.hpp>

using wpp = libff::bw6_761_pp;
using npp = libsnark::other_curve<wpp>;

namespace
{

TEST(PointMultiplicationGadgetsTest, G1MulByConstScalar)
{
    // Compute inputs and results
    const libff::G1<npp> P_val = libff::Fr<npp>(13) * libff::G1<npp>::one();
    const libff::Fr<npp> scalar_val_a = libff::Fr<npp>(127);
    const libff::G1<npp> expect_result_val_a = scalar_val_a * P_val;
    const libff::Fr<npp> scalar_val_b = libff::Fr<npp>(122);
    const libff::G1<npp> expect_result_val_b = scalar_val_b * P_val;
    // Circuit
    libsnark::protoboard<libff::Fr<wpp>> pb;
    libsnark::G1_variable<wpp> P(pb, "P");
    libsnark::G1_variable<wpp> result_a(pb, "result");
    libzecale::G1_mul_by_const_scalar_gadget<wpp, libff::Fr<npp>::num_limbs>
        mul_gadget_a(pb, scalar_val_a.as_bigint(), P, result_a, "mul_gadget_a");
    libsnark::G1_variable<wpp> result_b(pb, "result");
    libzecale::G1_mul_by_const_scalar_gadget<wpp, libff::Fr<npp>::num_limbs>
        mul_gadget_b(pb, scalar_val_b.as_bigint(), P, result_b, "mul_gadget_b");

    mul_gadget_a.generate_r1cs_constraints();
    mul_gadget_b.generate_r1cs_constraints();

    P.generate_r1cs_witness(P_val);
    mul_gadget_a.generate_r1cs_witness();
    mul_gadget_b.generate_r1cs_witness();

    ASSERT_TRUE(pb.is_satisfied());

    const libff::G1<npp> result_a_val =
        libzecale::g1_variable_get_element(result_a);
    ASSERT_EQ(expect_result_val_a, result_a_val);
    const libff::G1<npp> result_b_val =
        libzecale::g1_variable_get_element(result_b);
    ASSERT_EQ(expect_result_val_b, result_b_val);
}

TEST(PointMultiplicationGadgetsTest, G1MulByConstScalarWithKnownResult)
{
    // Compute inputs and results
    const libff::G1<npp> P_val = libff::Fr<npp>(13) * libff::G1<npp>::one();
    const libff::G1<npp> Q_val = libff::Fr<npp>(12) * libff::G1<npp>::one();
    const libff::Fr<npp> scalar_val = libff::Fr<npp>(127);
    const libff::G1<npp> result_val = scalar_val * P_val;

    // Valid case
    {
        // Circuit
        libsnark::protoboard<libff::Fr<wpp>> pb;
        libsnark::G1_variable<wpp> P(pb, "P");
        libsnark::G1_variable<wpp> result(pb, "result");
        libzecale::G1_mul_by_const_scalar_gadget<wpp, libff::Fr<npp>::num_limbs>
            mul_gadget(pb, scalar_val.as_bigint(), P, result, "mul_gadget");

        mul_gadget.generate_r1cs_constraints();

        // Witness the input, gadget AND output
        P.generate_r1cs_witness(P_val);
        mul_gadget.generate_r1cs_witness();
        result.generate_r1cs_witness(result_val);
        ASSERT_TRUE(pb.is_satisfied());
    }

    // Invalid case. Use the gadget to ensure a specific value in the result,
    // by assigning the expected value after the gadget.
    {
        // Circuit
        libsnark::protoboard<libff::Fr<wpp>> pb;
        libsnark::G1_variable<wpp> P(pb, "P");
        libsnark::G1_variable<wpp> result(pb, "result");
        libzecale::G1_mul_by_const_scalar_gadget<wpp, libff::Fr<npp>::num_limbs>
            mul_gadget(pb, scalar_val.as_bigint(), P, result, "mul_gadget");

        mul_gadget.generate_r1cs_constraints();

        // Witness the input, gadget AND (invalid) output
        P.generate_r1cs_witness(Q_val);
        mul_gadget.generate_r1cs_witness();
        result.generate_r1cs_witness(result_val);
        ASSERT_FALSE(pb.is_satisfied());
    }
}

TEST(PointMultiplicationGadgetsTest, G2AddGadget)
{
    // Compute inputs and results
    const libff::G2<npp> A_val = libff::Fr<npp>(13) * libff::G2<npp>::one();
    const libff::G2<npp> B_val = libff::Fr<npp>(12) * libff::G2<npp>::one();
    const libff::G2<npp> expect_C_val =
        libff::Fr<npp>(12 + 13) * libff::G2<npp>::one();
    ASSERT_EQ(expect_C_val, A_val + B_val);

    libsnark::protoboard<libff::Fr<wpp>> pb;
    libsnark::G2_variable<wpp> A(pb, "A");
    libsnark::G2_variable<wpp> B(pb, "B");
    libsnark::G2_variable<wpp> C(pb, "C");
    libzecale::G2_add_gadget<wpp> add_gadget(pb, A, B, C, "add_gadget");

    add_gadget.generate_r1cs_constraints();

    A.generate_r1cs_witness(A_val);
    B.generate_r1cs_witness(B_val);
    add_gadget.generate_r1cs_witness();

    const libff::G2<npp> C_val = libzecale::g2_variable_get_element(C);
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_EQ(expect_C_val, C_val);
}

TEST(PointMultiplicationGadgetsTest, G2DblGadget)
{
    // Compute inputs and results
    const libff::G2<npp> A_val = libff::Fr<npp>(13) * libff::G2<npp>::one();
    const libff::G2<npp> expect_B_val =
        libff::Fr<npp>(13 + 13) * libff::G2<npp>::one();
    ASSERT_EQ(A_val.dbl(), expect_B_val);

    libsnark::protoboard<libff::Fr<wpp>> pb;
    libsnark::G2_variable<wpp> A(pb, "A");
    libsnark::G2_variable<wpp> B(pb, "B");
    libzecale::G2_dbl_gadget<wpp> dbl_gadget(pb, A, B, "dbl_gadget");

    dbl_gadget.generate_r1cs_constraints();

    A.generate_r1cs_witness(A_val);
    dbl_gadget.generate_r1cs_witness();

    const libff::G2<npp> B_val = libzecale::g2_variable_get_element(B);
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_EQ(expect_B_val, B_val);
}

TEST(PointMultiplicationGadgetsTest, G2MulByConstScalar)
{
    // Compute inputs and results
    const libff::G2<npp> P_val = libff::Fr<npp>(13) * libff::G2<npp>::one();
    const libff::Fr<npp> scalar_val = libff::Fr<npp>(127);
    const libff::G2<npp> expect_result_val = scalar_val * P_val;

    // Circuit
    libsnark::protoboard<libff::Fr<wpp>> pb;
    libsnark::G2_variable<wpp> P(pb, "P");
    libsnark::G2_variable<wpp> result(pb, "result");
    libzecale::G2_mul_by_const_scalar_gadget<wpp, libff::Fr<npp>::num_limbs>
        mul_gadget(pb, scalar_val.as_bigint(), P, result, "mul_gadget");

    mul_gadget.generate_r1cs_constraints();

    P.generate_r1cs_witness(P_val);
    mul_gadget.generate_r1cs_witness();

    ASSERT_TRUE(pb.is_satisfied());

    const libff::G2<npp> result_val =
        libzecale::g2_variable_get_element(result);
    ASSERT_EQ(expect_result_val, result_val);
}

TEST(PointMultiplicationGadgetsTest, G2MulByConstScalarWithKnownResult)
{
    // Compute inputs and results
    const libff::G2<npp> P_val = libff::Fr<npp>(13) * libff::G2<npp>::one();
    const libff::G2<npp> Q_val = libff::Fr<npp>(12) * libff::G2<npp>::one();
    const libff::Fr<npp> scalar_val = libff::Fr<npp>(127);
    const libff::G2<npp> result_val = scalar_val * P_val;

    // Valid case
    {
        // Circuit
        libsnark::protoboard<libff::Fr<wpp>> pb;
        libsnark::G2_variable<wpp> P(pb, "P");
        libsnark::G2_variable<wpp> result(pb, "result");
        libzecale::G2_mul_by_const_scalar_gadget<wpp, libff::Fr<npp>::num_limbs>
            mul_gadget(pb, scalar_val.as_bigint(), P, result, "mul_gadget");

        mul_gadget.generate_r1cs_constraints();

        // Witness the input and output
        result.generate_r1cs_witness(result_val);
        P.generate_r1cs_witness(P_val);
        mul_gadget.generate_r1cs_witness();
        result.generate_r1cs_witness(result_val);
        ASSERT_TRUE(pb.is_satisfied());
    }

    // Invalid case
    {
        // Circuit
        libsnark::protoboard<libff::Fr<wpp>> pb;
        libsnark::G2_variable<wpp> P(pb, "P");
        libsnark::G2_variable<wpp> result(pb, "result");
        libzecale::G2_mul_by_const_scalar_gadget<wpp, libff::Fr<npp>::num_limbs>
            mul_gadget(pb, scalar_val.as_bigint(), P, result, "mul_gadget");

        mul_gadget.generate_r1cs_constraints();

        // Witness the input and output
        result.generate_r1cs_witness(result_val);
        P.generate_r1cs_witness(Q_val);
        mul_gadget.generate_r1cs_witness();
        result.generate_r1cs_witness(result_val);
        ASSERT_FALSE(pb.is_satisfied());
    }
}

} // namespace

int main(int argc, char **argv)
{
    libff::bls12_377_pp::init_public_params();
    libff::bw6_761_pp::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
