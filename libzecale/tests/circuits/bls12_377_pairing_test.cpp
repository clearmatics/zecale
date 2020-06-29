// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzecale/circuits/pairing/bls12_377_pairing.hpp"
#include "libzecale/circuits/pairing/bw6_761_pairing_params.hpp"

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <gtest/gtest.h>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>
#include <libff/algebra/curves/bw6_761/bw6_761_pp.hpp>
#include <libsnark/gadgetlib1/gadgets/fields/fp2_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/pairing_params.hpp>
#include <libzeth/snarks/groth16/groth16_snark.hpp>

using ppp = libff::bw6_761_pp; // Parent pairing
using ps = libsnark::pairing_selector<ppp>;
using cpp = ps::other_curve_type; // Child pairing

using snark = libzeth::groth16_snark<ppp>;

namespace
{

TEST(BLS12_377_PairingTest, PrecomputeDoubleGadgetTest)
{
    // Fqe element in bls12-377.  Perform a single double step natively.
    const libff::bls12_377_G2 R0 =
        libff::bls12_377_Fr("13") * libff::bls12_377_G2::one();
    const libff::bls12_377_Fq two_inv = libff::bls12_377_Fq("2").inverse();

    libff::bls12_377_ate_ell_coeffs R1_coeffs;
    libff::bls12_377_G2 R1;
    {
        R1 = R0;
        libff::bls12_377_doubling_step_for_miller_loop(two_inv, R1, R1_coeffs);
    }

    // Create and populate protoboard

    libsnark::protoboard<libff::Fr<ppp>> pb;

    libzecale::bls12_377_G2_proj<ppp> R0_var(pb, "R0");

    const size_t num_primary_inputs = pb.num_inputs();
    pb.set_input_sizes(num_primary_inputs);
    std::cout << "num_primary_inputs: " << std::to_string(num_primary_inputs)
              << "\n";

    libzecale::bls12_377_ate_dbl_gadget<ppp> check_double_R0(
        pb, R0_var, "check R1");

    check_double_R0.generate_r1cs_constraints();

    // Populate the values

    R0_var.generate_r1cs_witness(R0);
    check_double_R0.generate_r1cs_witness(two_inv);

    // Check values

    const libzecale::bls12_377_G2_proj<ppp> &R1_var = check_double_R0.out_R;
    const libzecale::bls12_377_ate_ell_coeffs<ppp> &R1_coeffs_var =
        check_double_R0.out_coeffs;

    const libff::Fqe<cpp> A = check_double_R0.A.get_element();
    const libff::Fqe<cpp> B = check_double_R0.B.get_element();
    const libff::Fqe<cpp> C = check_double_R0.C.get_element();
    const libff::Fqe<cpp> E = check_double_R0.E.get_element();
    const libff::Fqe<cpp> F = check_double_R0.F.get_element();
    const libff::Fqe<cpp> G = check_double_R0.G.get_element();
    const libff::Fqe<cpp> H = check_double_R0.H.get_element();
    const libff::Fqe<cpp> I = check_double_R0.I.get_element();
    const libff::Fqe<cpp> J = check_double_R0.J.get_element();
    const libff::Fqe<cpp> E_squared = check_double_R0.E_squared.get_element();
    const libff::Fqe<cpp> G_squared = check_double_R0.G_squared.get_element();
    const libff::Fqe<cpp> B_minus_F = check_double_R0.B_minus_F.get_element();
    const libff::Fqe<cpp> G_squared_minus_3_E_squared =
        check_double_R0.G_squared_minus_3_E_squared.get_element();

    ASSERT_EQ(R0.X * R0.Y, libff::Fr<ppp>(2) * A);

    ASSERT_EQ(R0.Y.squared(), B);

    ASSERT_EQ(R0.Z.squared(), C);

    ASSERT_EQ(libff::Fr<ppp>(3) * libff::bls12_377_twist_coeff_b * C, E);

    ASSERT_EQ(libff::Fr<ppp>(3) * E, F);

    ASSERT_EQ(two_inv * (B + F), G);

    const libff::Fqe<cpp> Y_plus_Z_squared = (R0.Y + R0.Z).squared();
    ASSERT_EQ(Y_plus_Z_squared - B - C, H);

    ASSERT_EQ(E - B, I);

    ASSERT_EQ(R0.X.squared(), J);

    ASSERT_EQ(E.squared(), E_squared);
    ASSERT_EQ(G.squared(), G_squared);
    ASSERT_EQ(B - F, B_minus_F);

    ASSERT_EQ(A * (B - F), R1_var.X.get_element());
    ASSERT_EQ(R1.X, R1_var.X.get_element());

    ASSERT_EQ(
        G_squared - (libff::Fr<ppp>(3) * E_squared),
        G_squared_minus_3_E_squared);
    ASSERT_EQ(G_squared_minus_3_E_squared, R1_var.Y.get_element());
    ASSERT_EQ(R1.Y, R1_var.Y.get_element());

    ASSERT_EQ(R1.Z, R1_var.Z.get_element());

    ASSERT_EQ(R1_coeffs.ell_0, R1_coeffs_var.ell_0.get_element());

    ASSERT_EQ(R1_coeffs.ell_VW, R1_coeffs_var.ell_vw.get_element());

    ASSERT_EQ(R1_coeffs.ell_VV, R1_coeffs_var.ell_vv.get_element());

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
