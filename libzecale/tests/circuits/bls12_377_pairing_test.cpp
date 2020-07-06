// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzecale/circuits/fields/fp12_2over3over2_gadgets.hpp"
#include "libzecale/circuits/pairing/bls12_377_pairing.hpp"
#include "libzecale/circuits/pairing/bw6_761_pairing_params.hpp"
#include "libzecale/circuits/pairing/pairing_params.hpp"

#include <gtest/gtest.h>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>
#include <libff/algebra/curves/bw6_761/bw6_761_pp.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/pairing_params.hpp>
#include <libzeth/snarks/groth16/groth16_snark.hpp>

using wpp = libff::bw6_761_pp;
using npp = libsnark::other_curve<wpp>;
using snark = libzeth::groth16_snark<wpp>;

namespace
{

TEST(BLS12_377_PairingTest, G1PrecomputeGadgetTest)
{
    // Native precompute
    libff::bls12_377_G1 P =
        libff::bls12_377_Fr("13") * libff::bls12_377_G1::one();
    libff::bls12_377_G1_precomp P_prec = bls12_377_precompute_G1(P);

    // Circuit with precompute gadget
    libsnark::protoboard<libff::Fr<wpp>> pb;
    libsnark::G1_variable<wpp> P_var(pb, "P");
    libzecale::bls12_377_ate_G1_precomputation<wpp> P_prec_var(pb, "P_prec");
    const size_t num_primary_inputs = pb.num_inputs();
    pb.set_input_sizes(num_primary_inputs);
    libzecale::bls12_377_ate_G1_precompute_gadget<wpp> precompute_gadget(
        pb, P_var, P_prec_var, "bls12_317 G1 precompute gadget");

    precompute_gadget.generate_r1cs_constraints();

    P_var.generate_r1cs_witness(P);
    precompute_gadget.generate_r1cs_witness();

    // Check that the correct values have been propagated
    const libff::Fr<wpp> P_prec_X = pb.lc_val(*(P_prec_var._Px));
    const libff::Fr<wpp> P_prec_Y = pb.lc_val(*(P_prec_var._Py));

    ASSERT_EQ(P_prec.PX, P_prec_X);
    ASSERT_EQ(P_prec.PY, P_prec_Y);
}

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

    libsnark::protoboard<libff::Fr<wpp>> pb;

    libzecale::bls12_377_G2_proj<wpp> R0_var(pb, "R0");

    const size_t num_primary_inputs = pb.num_inputs();
    pb.set_input_sizes(num_primary_inputs);
    std::cout << "num_primary_inputs: " << std::to_string(num_primary_inputs)
              << "\n";

    libzecale::bls12_377_ate_dbl_gadget<wpp> check_double_R0(
        pb, R0_var, "check R1");

    check_double_R0.generate_r1cs_constraints();

    // Populate the values

    R0_var.generate_r1cs_witness(R0);
    check_double_R0.generate_r1cs_witness(two_inv);

    // Check values

    const libzecale::bls12_377_G2_proj<wpp> &R1_var = check_double_R0.out_R;
    const libzecale::bls12_377_ate_ell_coeffs<wpp> &R1_coeffs_var =
        check_double_R0.out_coeffs;

    const libff::Fqe<npp> A = check_double_R0.A.get_element();
    const libff::Fqe<npp> B = check_double_R0.B.get_element();
    const libff::Fqe<npp> C = check_double_R0.C.get_element();
    const libff::Fqe<npp> E = check_double_R0.E.get_element();
    const libff::Fqe<npp> F = check_double_R0.F.get_element();
    const libff::Fqe<npp> G = check_double_R0.G.get_element();
    const libff::Fqe<npp> H = check_double_R0.H.get_element();
    const libff::Fqe<npp> I = check_double_R0.I.get_element();
    const libff::Fqe<npp> J = check_double_R0.J.get_element();
    const libff::Fqe<npp> E_squared = check_double_R0.E_squared.get_element();
    const libff::Fqe<npp> G_squared = check_double_R0.G_squared.get_element();
    const libff::Fqe<npp> B_minus_F = check_double_R0.B_minus_F.get_element();
    const libff::Fqe<npp> G_squared_minus_3_E_squared =
        check_double_R0.G_squared_minus_3_E_squared.get_element();

    ASSERT_EQ(R0.X * R0.Y, libff::Fr<wpp>(2) * A);

    ASSERT_EQ(R0.Y.squared(), B);

    ASSERT_EQ(R0.Z.squared(), C);

    ASSERT_EQ(libff::Fr<wpp>(3) * libff::bls12_377_twist_coeff_b * C, E);

    ASSERT_EQ(libff::Fr<wpp>(3) * E, F);

    ASSERT_EQ(two_inv * (B + F), G);

    const libff::Fqe<npp> Y_plus_Z_squared = (R0.Y + R0.Z).squared();
    ASSERT_EQ(Y_plus_Z_squared - B - C, H);

    ASSERT_EQ(E - B, I);

    ASSERT_EQ(R0.X.squared(), J);

    ASSERT_EQ(E.squared(), E_squared);
    ASSERT_EQ(G.squared(), G_squared);
    ASSERT_EQ(B - F, B_minus_F);

    ASSERT_EQ(A * (B - F), R1_var.X.get_element());
    ASSERT_EQ(R1.X, R1_var.X.get_element());

    ASSERT_EQ(
        G_squared - (libff::Fr<wpp>(3) * E_squared),
        G_squared_minus_3_E_squared);
    ASSERT_EQ(G_squared_minus_3_E_squared, R1_var.Y.get_element());
    ASSERT_EQ(R1.Y, R1_var.Y.get_element());

    ASSERT_EQ(R1.Z, R1_var.Z.get_element());

    ASSERT_EQ(R1_coeffs.ell_0, R1_coeffs_var.ell_0.get_element());

    ASSERT_EQ(R1_coeffs.ell_VW, R1_coeffs_var.ell_vw.get_element());

    ASSERT_EQ(R1_coeffs.ell_VV, R1_coeffs_var.ell_vv.get_element());

    // Generate and check the proof
    const typename snark::KeypairT keypair = snark::generate_setup(pb);
    libsnark::r1cs_primary_input<libff::Fr<wpp>> primary_input =
        pb.primary_input();
    libsnark::r1cs_auxiliary_input<libff::Fr<wpp>> auxiliary_input =
        pb.auxiliary_input();
    typename snark::ProofT proof = snark::generate_proof(pb, keypair.pk);
    ASSERT_TRUE(snark::verify(primary_input, proof, keypair.vk));
}

TEST(BLS12_377_PairingTest, PrecomputeAddGadgetTest)
{
    // Fqe element in bls12-377.  Perform a single add step natively.

    const libff::bls12_377_G2 Q =
        libff::bls12_377_Fr("7") * libff::bls12_377_G2::one();
    const libff::bls12_377_G2 R0 =
        libff::bls12_377_Fr("13") * libff::bls12_377_G2::one();

    libff::bls12_377_ate_ell_coeffs R1_coeffs;
    libff::bls12_377_G2 R1;
    {
        R1 = R0;
        libff::bls12_377_mixed_addition_step_for_miller_loop(Q, R1, R1_coeffs);
    }

    // Create and populate protoboard with a simple circuit containing the ate
    // add gadget.

    libsnark::protoboard<libff::Fr<wpp>> pb;
    libzecale::Fqe_variable<wpp> Q_X(pb, " Q_X");
    libzecale::Fqe_variable<wpp> Q_Y(pb, " Q_Y");
    const size_t num_primary_inputs = pb.num_inputs();
    libzecale::bls12_377_G2_proj<wpp> R0_var(pb, " R0");

    pb.set_input_sizes(num_primary_inputs);
    std::cout << "num_primary_inputs: " << std::to_string(num_primary_inputs)
              << "\n";

    libzecale::bls12_377_ate_add_gadget<wpp> check_add_R0(
        pb, Q_X, Q_Y, R0_var, "check R1");

    check_add_R0.generate_r1cs_constraints();

    // Populate R0 and Q, and generate values via the gadget

    Q_X.generate_r1cs_witness(Q.X);
    Q_Y.generate_r1cs_witness(Q.Y);
    R0_var.generate_r1cs_witness(R0);

    check_add_R0.generate_r1cs_witness();

    // Check values

    const libff::Fqe<npp> A = check_add_R0.A.get_element();
    const libff::Fqe<npp> B = check_add_R0.B.get_element();
    const libff::Fqe<npp> theta = check_add_R0.theta.get_element();
    const libff::Fqe<npp> lambda = check_add_R0.lambda.get_element();
    const libff::Fqe<npp> C = check_add_R0.C.get_element();
    const libff::Fqe<npp> D = check_add_R0.D.get_element();
    const libff::Fqe<npp> E = check_add_R0.E.get_element();
    const libff::Fqe<npp> F = check_add_R0.F.get_element();
    const libff::Fqe<npp> G = check_add_R0.G.get_element();
    const libff::Fqe<npp> H = check_add_R0.H.get_element();
    const libff::Fqe<npp> I = check_add_R0.I.get_element();
    const libff::Fqe<npp> J = check_add_R0.J.get_element();
    const libff::Fqe<npp> out_Rx = check_add_R0.out_Rx.get_element();
    const libff::Fqe<npp> out_Rz = check_add_R0.out_Rz.get_element();

    // A = Qy * Rz
    ASSERT_EQ(Q.Y * R0.Z, A);
    // B = Qx * Rz;
    ASSERT_EQ(Q.X * R0.Z, B);
    // theta = Ry - A;
    ASSERT_EQ(R0.Y - A, theta);
    // lambda = Rx - B;
    ASSERT_EQ(R0.X - B, lambda);
    // C = theta.squared();
    ASSERT_EQ(theta * theta, C);
    // D = lambda.squared();
    ASSERT_EQ(lambda * lambda, D);
    // E = lambda * D;
    ASSERT_EQ(lambda * D, E);
    // F = Rz * C;
    ASSERT_EQ(R0.Z * C, F);
    // G = Rx * D;
    ASSERT_EQ(R0.X * D, G);
    // H = E + F - (G + G);
    ASSERT_EQ(E + F - G - G, H);
    // I = Ry * E;
    ASSERT_EQ(R0.Y * E, I);
    // J = theta * Qx - lambda * Qy;
    ASSERT_EQ(theta * Q.X - lambda * Q.Y, J);

    // out_Rx = lambda * H;
    ASSERT_EQ(lambda * H, out_Rx);

    ASSERT_EQ(R1.X, out_Rx);
    ASSERT_EQ(R1.Z, out_Rz);

    ASSERT_EQ(R1.X, check_add_R0.out_R.X.get_element());
    ASSERT_EQ(R1.Y, check_add_R0.out_R.Y.get_element());
    ASSERT_EQ(R1.Z, check_add_R0.out_R.Z.get_element());
    ASSERT_EQ(R1_coeffs.ell_0, check_add_R0.out_coeffs.ell_0.get_element());
    ASSERT_EQ(R1_coeffs.ell_VW, check_add_R0.out_coeffs.ell_vw.get_element());
    ASSERT_EQ(R1_coeffs.ell_VV, check_add_R0.out_coeffs.ell_vv.get_element());

    // Generate and check the proof

    const typename snark::KeypairT keypair = snark::generate_setup(pb);
    libsnark::r1cs_primary_input<libff::Fr<wpp>> primary_input =
        pb.primary_input();
    libsnark::r1cs_auxiliary_input<libff::Fr<wpp>> auxiliary_input =
        pb.auxiliary_input();
    typename snark::ProofT proof = snark::generate_proof(pb, keypair.pk);
    ASSERT_TRUE(snark::verify(primary_input, proof, keypair.vk));
}

template<typename ppT>
static void assert_ate_coeffs_eq(
    const libff::bls12_377_ate_ell_coeffs &native,
    const libzecale::bls12_377_ate_ell_coeffs<ppT> &circuit,
    const std::string &type,
    size_t idx)
{
    ASSERT_EQ(native.ell_0, circuit.ell_0.get_element())
        << type << " ell_0 " << std::to_string(idx) << "\n";
    ASSERT_EQ(native.ell_VW, circuit.ell_vw.get_element())
        << type << " ell_vw " << std::to_string(idx) << "\n";
    ASSERT_EQ(native.ell_VV, circuit.ell_vv.get_element())
        << type << " ell_vv " << std::to_string(idx) << "\n";
}

TEST(BLS12_377_PairingTest, G2PrecomputeGadgetTest)
{
    // Native precompute
    libff::bls12_377_G2 Q =
        libff::bls12_377_Fr("7") * libff::bls12_377_G2::one();
    Q.to_affine_coordinates();

    const libff::bls12_377_ate_G2_precomp native_precomp =
        libff::bls12_377_ate_precompute_G2(Q);

    // Circuit with precompute gadget
    libsnark::protoboard<libff::Fr<wpp>> pb;
    libzecale::Fqe_variable<wpp> Qx(pb, " Qx");
    libzecale::Fqe_variable<wpp> Qy(pb, " Qy");
    const size_t num_primary_inputs = pb.num_inputs();
    pb.set_input_sizes(num_primary_inputs);
    libzecale::bls12_377_ate_precompute_gadget<wpp> precompute_gadget(
        pb, Qx, Qy, "bls12_317 precompute gadget");

    precompute_gadget.generate_r1cs_constraints();

    Qx.generate_r1cs_witness(Q.X);
    Qy.generate_r1cs_witness(Q.Y);
    precompute_gadget.generate_r1cs_witness();

    // Iterate through non-zero bits of loop_count, highest order first,
    // skipping the first.
    size_t native_coeffs_idx = 0;
    size_t dbl_idx = 0;
    size_t add_idx = 0;
    libzecale::bls12_377_miller_loop_bits bits;
    while (bits.next()) {
        const bool bit = bits.current();

        // Check the coeffs from the double
        assert_ate_coeffs_eq(
            native_precomp.coeffs[native_coeffs_idx++],
            precompute_gadget._ate_dbls[dbl_idx]->out_coeffs,
            "dbl",
            dbl_idx);
        dbl_idx++;

        if (bit) {
            assert_ate_coeffs_eq(
                native_precomp.coeffs[native_coeffs_idx++],
                precompute_gadget._ate_adds[add_idx]->out_coeffs,
                "add",
                add_idx);
            add_idx++;
        }
    }

    // Generate and check the proof
    const typename snark::KeypairT keypair = snark::generate_setup(pb);
    libsnark::r1cs_primary_input<libff::Fr<wpp>> primary_input =
        pb.primary_input();
    libsnark::r1cs_auxiliary_input<libff::Fr<wpp>> auxiliary_input =
        pb.auxiliary_input();
    typename snark::ProofT proof = snark::generate_proof(pb, keypair.pk);
    ASSERT_TRUE(snark::verify(primary_input, proof, keypair.vk));
}

TEST(BLS12_377_PairingTest, MillerLoopGadgetTest)
{
    // Native calculation
    libff::bls12_377_G1 P =
        libff::bls12_377_Fr("13") * libff::bls12_377_G1::one();
    libff::bls12_377_G2 Q =
        libff::bls12_377_Fr("7") * libff::bls12_377_G2::one();

    libff::bls12_377_Fq12 miller;
    {
        libff::bls12_377_G1_precomp G1_precomp =
            libff::bls12_377_ate_precompute_G1(P);
        libff::bls12_377_G2_precomp G2_precomp =
            libff::bls12_377_ate_precompute_G2(Q);
        miller = libff::bls12_377_ate_miller_loop(G1_precomp, G2_precomp);
    }

    // Circuit with Miller loop gadget
    libsnark::protoboard<libff::Fr<wpp>> pb;
    libsnark::pb_variable<libff::Fr<wpp>> Px;
    Px.allocate(pb, "Px");
    libsnark::pb_variable<libff::Fr<wpp>> Py;
    Py.allocate(pb, "Py");
    libzecale::Fqe_variable<wpp> Qx(pb, " Qx");
    libzecale::Fqe_variable<wpp> Qy(pb, " Qy");
    const size_t num_primary_inputs = pb.num_inputs();
    pb.set_input_sizes(num_primary_inputs);

    libzecale::bls12_377_ate_miller_loop_gadget<wpp> miller_loop_gadget(
        pb, Px, Py, Qx, Qy, "miller loop");

    miller_loop_gadget.generate_r1cs_constraints();

    // Set affine values
    P.to_affine_coordinates();
    Q.to_affine_coordinates();

    pb.val(Px) = P.X;
    pb.val(Py) = P.Y;
    Qx.generate_r1cs_witness(Q.X);
    Qy.generate_r1cs_witness(Q.Y);
    miller_loop_gadget.generate_r1cs_witness();

    // Check values
    libff::bls12_377_Fq12 circuit_miller =
        miller_loop_gadget.result().get_element();
    ASSERT_EQ(miller, circuit_miller);

    // Generate and check the proof
    const typename snark::KeypairT keypair = snark::generate_setup(pb);
    libsnark::r1cs_primary_input<libff::Fr<wpp>> primary_input =
        pb.primary_input();
    libsnark::r1cs_auxiliary_input<libff::Fr<wpp>> auxiliary_input =
        pb.auxiliary_input();
    typename snark::ProofT proof = snark::generate_proof(pb, keypair.pk);
    ASSERT_TRUE(snark::verify(primary_input, proof, keypair.vk));
}

TEST(BLS12_377_PairingTest, FinalExpFirstPart)
{
    using FieldT = libff::Fr<wpp>;
    using FqkT = libff::Fqk<npp>;
    using Fq2T = typename FqkT::my_Fp2;
    using Fq6T = typename FqkT::my_Fp6;

    // Native calculation
    const FqkT a(
        Fq6T(
            Fq2T(FieldT("1"), FieldT("2")),
            Fq2T(FieldT("3"), FieldT("4")),
            Fq2T(FieldT("5"), FieldT("6"))),
        Fq6T(
            Fq2T(FieldT("21"), FieldT("22")),
            Fq2T(FieldT("23"), FieldT("24")),
            Fq2T(FieldT("25"), FieldT("26"))));
    const FqkT final_exp_first_part =
        bls12_377_final_exponentiation_first_chunk(a);

    // Circuit with final exponentiation first part gadget
    libsnark::protoboard<FieldT> pb;
    libzecale::Fp12_2over3over2_variable<FqkT> a_var(pb, "a");
    libzecale::Fp12_2over3over2_variable<FqkT> final_exp_first_part_var(
        pb, "final_exp_first_part");
    const size_t num_primary_inputs = pb.num_inputs();
    pb.set_input_sizes(num_primary_inputs);
    libzecale::bls12_377_final_exp_first_part_gadget<wpp>
        final_exp_first_part_gadget(
            pb,
            a_var,
            final_exp_first_part_var,
            "compute_final_exp_first_part");

    final_exp_first_part_gadget.generate_r1cs_constraints();

    a_var.generate_r1cs_witness(a);
    final_exp_first_part_gadget.generate_r1cs_witness();

    ASSERT_EQ(final_exp_first_part, final_exp_first_part_var.get_element());

    // Generate and check the proof
    const typename snark::KeypairT keypair = snark::generate_setup(pb);
    libsnark::r1cs_primary_input<FieldT> primary_input = pb.primary_input();
    libsnark::r1cs_auxiliary_input<FieldT> auxiliary_input =
        pb.auxiliary_input();
    typename snark::ProofT proof = snark::generate_proof(pb, keypair.pk);
    ASSERT_TRUE(snark::verify(primary_input, proof, keypair.vk));
}

TEST(BLS12_377_PairingTest, ExpByZ)
{
    using FieldT = libff::Fr<wpp>;
    using FqkT = libff::Fqk<npp>;
    using Fq2T = typename FqkT::my_Fp2;
    using Fq6T = typename FqkT::my_Fp6;

    // Native calculation
    const FqkT a(
        Fq6T(
            Fq2T(FieldT("1"), FieldT("2")),
            Fq2T(FieldT("3"), FieldT("4")),
            Fq2T(FieldT("5"), FieldT("6"))),
        Fq6T(
            Fq2T(FieldT("21"), FieldT("22")),
            Fq2T(FieldT("23"), FieldT("24")),
            Fq2T(FieldT("25"), FieldT("26"))));
    const FqkT final_exp_first_part =
        bls12_377_final_exponentiation_first_chunk(a);
    const FqkT exp_z = bls12_377_exp_by_z(final_exp_first_part);

    // Circuit calculation
    libsnark::protoboard<FieldT> pb;
    libzecale::Fp12_2over3over2_variable<FqkT> final_exp_first_part_var(
        pb, "final_exp_first_part");
    libzecale::Fp12_2over3over2_variable<FqkT> exp_z_var(pb, "exp_z");
    const size_t num_primary_inputs = pb.num_inputs();
    pb.set_input_sizes(num_primary_inputs);

    libzecale::bls12_377_exp_by_z_gadget<wpp> exp_by_z_gadget(
        pb, final_exp_first_part_var, exp_z_var, "exp_by_z");

    exp_by_z_gadget.generate_r1cs_constraints();

    final_exp_first_part_var.generate_r1cs_witness(final_exp_first_part);
    exp_by_z_gadget.generate_r1cs_witness();

    ASSERT_EQ(exp_z, exp_z_var.get_element());

    // Generate and check the proof
    const typename snark::KeypairT keypair = snark::generate_setup(pb);
    libsnark::r1cs_primary_input<FieldT> primary_input = pb.primary_input();
    libsnark::r1cs_auxiliary_input<FieldT> auxiliary_input =
        pb.auxiliary_input();
    typename snark::ProofT proof = snark::generate_proof(pb, keypair.pk);
    ASSERT_TRUE(snark::verify(primary_input, proof, keypair.vk));
}

TEST(BLS12_377_PairingTest, FinalExpLastPart)
{
    using FieldT = libff::Fr<wpp>;
    using FqkT = libff::Fqk<npp>;
    using Fq2T = typename FqkT::my_Fp2;
    using Fq6T = typename FqkT::my_Fp6;

    // Native calculation
    const FqkT a(
        Fq6T(
            Fq2T(FieldT("1"), FieldT("2")),
            Fq2T(FieldT("3"), FieldT("4")),
            Fq2T(FieldT("5"), FieldT("6"))),
        Fq6T(
            Fq2T(FieldT("21"), FieldT("22")),
            Fq2T(FieldT("23"), FieldT("24")),
            Fq2T(FieldT("25"), FieldT("26"))));
    const FqkT final_exp_first_part =
        bls12_377_final_exponentiation_first_chunk(a);
    const FqkT final_exp_last_part =
        bls12_377_final_exponentiation_last_chunk(final_exp_first_part);

    // Circuit with final exponentiation last part gadget
    libsnark::protoboard<FieldT> pb;
    libzecale::Fp12_2over3over2_variable<FqkT> a_var(pb, "a");
    libzecale::Fp12_2over3over2_variable<FqkT> final_exp_last_part_var(
        pb, "final_exp_last_part");
    const size_t num_primary_inputs = pb.num_inputs();
    pb.set_input_sizes(num_primary_inputs);
    libzecale::bls12_377_final_exp_last_part_gadget<wpp>
        final_exp_last_part_gadget(
            pb, a_var, final_exp_last_part_var, "compute_final_exp_last_part");

    final_exp_last_part_gadget.generate_r1cs_constraints();

    a_var.generate_r1cs_witness(final_exp_first_part);
    final_exp_last_part_gadget.generate_r1cs_witness();

    ASSERT_EQ(final_exp_last_part, final_exp_last_part_var.get_element());

    // Generate and check the proof
    const typename snark::KeypairT keypair = snark::generate_setup(pb);
    libsnark::r1cs_primary_input<FieldT> primary_input = pb.primary_input();
    libsnark::r1cs_auxiliary_input<FieldT> auxiliary_input =
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
