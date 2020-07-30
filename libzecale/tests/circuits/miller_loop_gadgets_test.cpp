// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzecale/circuits/pairing/bw6_761_pairing_params.hpp"
#include "libzecale/circuits/pairing/mnt_pairing_params.hpp"

#include <gtest/gtest.h>

using namespace libzecale;

namespace
{

/// Generic test code to check the miller loop against an expected result.
template<typename ppT>
bool test_e_times_e_times_e_over_e_miller_loop(
    const libff::G1<other_curve<ppT>> &P1_val,
    const libff::G2<other_curve<ppT>> &Q1_val,
    const libff::G1<other_curve<ppT>> &P2_val,
    const libff::G2<other_curve<ppT>> &Q2_val,
    const libff::G1<other_curve<ppT>> &P3_val,
    const libff::G2<other_curve<ppT>> &Q3_val,
    const libff::G1<other_curve<ppT>> &P4_val,
    const libff::G2<other_curve<ppT>> &Q4_val,
    const FqkT<ppT> &expect_result,
    const std::string &annotation)
{
    libsnark::protoboard<libff::Fr<ppT>> pb;

    libsnark::G1_variable<ppT> P1(pb, "P1");
    libsnark::G2_variable<ppT> Q1(pb, "Q1");
    libsnark::G1_variable<ppT> P2(pb, "P2");
    libsnark::G2_variable<ppT> Q2(pb, "Q2");
    libsnark::G1_variable<ppT> P3(pb, "P3");
    libsnark::G2_variable<ppT> Q3(pb, "Q3");
    libsnark::G1_variable<ppT> P4(pb, "P4");
    libsnark::G2_variable<ppT> Q4(pb, "Q4");

    G1_precomputation<ppT> prec_P1;
    G1_precompute_gadget<ppT> compute_prec_P1(
        pb, P1, prec_P1, "compute_prec_P1");
    G1_precomputation<ppT> prec_P2;
    G1_precompute_gadget<ppT> compute_prec_P2(
        pb, P2, prec_P2, "compute_prec_P2");
    G1_precomputation<ppT> prec_P3;
    G1_precompute_gadget<ppT> compute_prec_P3(
        pb, P3, prec_P3, "compute_prec_P3");
    G1_precomputation<ppT> prec_P4;
    G1_precompute_gadget<ppT> compute_prec_P4(
        pb, P4, prec_P4, "compute_prec_P4");
    G2_precomputation<ppT> prec_Q1;
    G2_precompute_gadget<ppT> compute_prec_Q1(
        pb, Q1, prec_Q1, "compute_prec_Q1");
    G2_precomputation<ppT> prec_Q2;
    G2_precompute_gadget<ppT> compute_prec_Q2(
        pb, Q2, prec_Q2, "compute_prec_Q2");
    G2_precomputation<ppT> prec_Q3;
    G2_precompute_gadget<ppT> compute_prec_Q3(
        pb, Q3, prec_Q3, "compute_prec_Q3");
    G2_precomputation<ppT> prec_Q4;
    G2_precompute_gadget<ppT> compute_prec_Q4(
        pb, Q4, prec_Q4, "compute_prec_Q4");

    Fqk_variable<ppT> result(pb, "result");

    e_times_e_times_e_over_e_miller_loop_gadget<ppT> miller(
        pb,
        prec_P1,
        prec_Q1,
        prec_P2,
        prec_Q2,
        prec_P3,
        prec_Q3,
        prec_P4,
        prec_Q4,
        result,
        "miller");

    PROFILE_CONSTRAINTS(pb, "precompute P")
    {
        compute_prec_P1.generate_r1cs_constraints();
        compute_prec_P2.generate_r1cs_constraints();
        compute_prec_P3.generate_r1cs_constraints();
        compute_prec_P4.generate_r1cs_constraints();
    }
    PROFILE_CONSTRAINTS(pb, "precompute Q")
    {
        compute_prec_Q1.generate_r1cs_constraints();
        compute_prec_Q2.generate_r1cs_constraints();
        compute_prec_Q3.generate_r1cs_constraints();
        compute_prec_Q4.generate_r1cs_constraints();
    }
    PROFILE_CONSTRAINTS(pb, "Miller loop")
    {
        miller.generate_r1cs_constraints();
    }
    libsnark::PRINT_CONSTRAINT_PROFILING();

    P1.generate_r1cs_witness(P1_val);
    compute_prec_P1.generate_r1cs_witness();
    Q1.generate_r1cs_witness(Q1_val);
    compute_prec_Q1.generate_r1cs_witness();
    P2.generate_r1cs_witness(P2_val);
    compute_prec_P2.generate_r1cs_witness();
    Q2.generate_r1cs_witness(Q2_val);
    compute_prec_Q2.generate_r1cs_witness();
    P3.generate_r1cs_witness(P3_val);
    compute_prec_P3.generate_r1cs_witness();
    Q3.generate_r1cs_witness(Q3_val);
    compute_prec_Q3.generate_r1cs_witness();
    P4.generate_r1cs_witness(P4_val);
    compute_prec_P4.generate_r1cs_witness();
    Q4.generate_r1cs_witness(Q4_val);
    compute_prec_Q4.generate_r1cs_witness();
    miller.generate_r1cs_witness();

    assert(pb.is_satisfied());

    printf(
        "number of constraints for e times e times e over e Miller loop (Fr is "
        "%s)  = %zu\n",
        annotation.c_str(),
        pb.num_constraints());

    return result.get_element() == expect_result;
}

/// Generate expected test data and expected miller loop output for an MNT
/// pairing, and call the generic test_e_times_e_times_e_over_e_miller_loop
/// function above. (To be specialized to mnt4 or mnt6).
template<typename ppT>
void test_mnt_e_times_e_times_e_over_e_miller_loop(
    const std::string &annotation)
{
    libff::G1<other_curve<ppT>> P1_val =
        libff::Fr<other_curve<ppT>>::random_element() *
        libff::G1<other_curve<ppT>>::one();
    libff::G2<other_curve<ppT>> Q1_val =
        libff::Fr<other_curve<ppT>>::random_element() *
        libff::G2<other_curve<ppT>>::one();

    libff::G1<other_curve<ppT>> P2_val =
        libff::Fr<other_curve<ppT>>::random_element() *
        libff::G1<other_curve<ppT>>::one();
    libff::G2<other_curve<ppT>> Q2_val =
        libff::Fr<other_curve<ppT>>::random_element() *
        libff::G2<other_curve<ppT>>::one();

    libff::G1<other_curve<ppT>> P3_val =
        libff::Fr<other_curve<ppT>>::random_element() *
        libff::G1<other_curve<ppT>>::one();
    libff::G2<other_curve<ppT>> Q3_val =
        libff::Fr<other_curve<ppT>>::random_element() *
        libff::G2<other_curve<ppT>>::one();

    libff::G1<other_curve<ppT>> P4_val =
        libff::Fr<other_curve<ppT>>::random_element() *
        libff::G1<other_curve<ppT>>::one();
    libff::G2<other_curve<ppT>> Q4_val =
        libff::Fr<other_curve<ppT>>::random_element() *
        libff::G2<other_curve<ppT>>::one();

    libff::affine_ate_G1_precomp<other_curve<ppT>> native_prec_P1 =
        other_curve<ppT>::affine_ate_precompute_G1(P1_val);
    libff::affine_ate_G2_precomp<other_curve<ppT>> native_prec_Q1 =
        other_curve<ppT>::affine_ate_precompute_G2(Q1_val);
    libff::affine_ate_G1_precomp<other_curve<ppT>> native_prec_P2 =
        other_curve<ppT>::affine_ate_precompute_G1(P2_val);
    libff::affine_ate_G2_precomp<other_curve<ppT>> native_prec_Q2 =
        other_curve<ppT>::affine_ate_precompute_G2(Q2_val);
    libff::affine_ate_G1_precomp<other_curve<ppT>> native_prec_P3 =
        other_curve<ppT>::affine_ate_precompute_G1(P3_val);
    libff::affine_ate_G2_precomp<other_curve<ppT>> native_prec_Q3 =
        other_curve<ppT>::affine_ate_precompute_G2(Q3_val);
    libff::affine_ate_G1_precomp<other_curve<ppT>> native_prec_P4 =
        other_curve<ppT>::affine_ate_precompute_G1(P4_val);
    libff::affine_ate_G2_precomp<other_curve<ppT>> native_prec_Q4 =
        other_curve<ppT>::affine_ate_precompute_G2(Q4_val);
    libff::Fqk<other_curve<ppT>> native_result =
        (other_curve<ppT>::affine_ate_miller_loop(
             native_prec_P1, native_prec_Q1) *
         other_curve<ppT>::affine_ate_miller_loop(
             native_prec_P2, native_prec_Q2) *
         other_curve<ppT>::affine_ate_miller_loop(
             native_prec_P3, native_prec_Q3) *
         other_curve<ppT>::affine_ate_miller_loop(
             native_prec_P4, native_prec_Q4)
             .inverse());
    ASSERT_TRUE(test_e_times_e_times_e_over_e_miller_loop<ppT>(
        P1_val,
        Q1_val,
        P2_val,
        Q2_val,
        P3_val,
        Q3_val,
        P4_val,
        Q4_val,
        native_result,
        annotation));
}

TEST(MillerLoopGadgets, TestMntEEEoverEmillerLoop)
{
    test_mnt_e_times_e_times_e_over_e_miller_loop<libff::mnt4_pp>(
        " test_eee_over_e_miller_loop_mnt4");
    test_mnt_e_times_e_times_e_over_e_miller_loop<libff::mnt6_pp>(
        " test_eee_over_e_miller_loop_mnt6");
}

TEST(MillerLoopGadgets, TestBlsEEEoverEmillerLoop)
{
    using wpp = libff::bw6_761_pp;
    using npp = libff::bls12_377_pp;

    libff::G1<npp> P1_val =
        libff::Fr<npp>::random_element() * libff::G1<npp>::one();
    libff::G2<npp> Q1_val =
        libff::Fr<npp>::random_element() * libff::G2<npp>::one();

    libff::G1<npp> P2_val =
        libff::Fr<npp>::random_element() * libff::G1<npp>::one();
    libff::G2<npp> Q2_val =
        libff::Fr<npp>::random_element() * libff::G2<npp>::one();

    libff::G1<npp> P3_val =
        libff::Fr<npp>::random_element() * libff::G1<npp>::one();
    libff::G2<npp> Q3_val =
        libff::Fr<npp>::random_element() * libff::G2<npp>::one();

    libff::G1<npp> P4_val =
        libff::Fr<npp>::random_element() * libff::G1<npp>::one();
    libff::G2<npp> Q4_val =
        libff::Fr<npp>::random_element() * libff::G2<npp>::one();

    libff::G1_precomp<npp> native_prec_P1 = npp::precompute_G1(P1_val);
    libff::G2_precomp<npp> native_prec_Q1 = npp::precompute_G2(Q1_val);
    libff::G1_precomp<npp> native_prec_P2 = npp::precompute_G1(P2_val);
    libff::G2_precomp<npp> native_prec_Q2 = npp::precompute_G2(Q2_val);
    libff::G1_precomp<npp> native_prec_P3 = npp::precompute_G1(P3_val);
    libff::G2_precomp<npp> native_prec_Q3 = npp::precompute_G2(Q3_val);
    libff::G1_precomp<npp> native_prec_minus_P4 = npp::precompute_G1(-P4_val);
    libff::G2_precomp<npp> native_prec_Q4 = npp::precompute_G2(Q4_val);

    libff::Fqk<npp> miller_P1_Q1 =
        npp::miller_loop(native_prec_P1, native_prec_Q1);
    libff::Fqk<npp> miller_P2_Q2 =
        npp::miller_loop(native_prec_P2, native_prec_Q2);
    libff::Fqk<npp> miller_P3_Q3 =
        npp::miller_loop(native_prec_P3, native_prec_Q3);
    libff::Fqk<npp> miller_P4_Q4_inv =
        npp::miller_loop(native_prec_minus_P4, native_prec_Q4);
    libff::Fqk<npp> native_result =
        miller_P1_Q1 * miller_P2_Q2 * miller_P3_Q3 * miller_P4_Q4_inv;

    // Ensure that miller_P4_Q4_inv is indeed equivalent to
    // miller_P4_Q4.inverse()
    libff::G1_precomp<npp> native_prec_P4 = npp::precompute_G1(P4_val);
    libff::Fqk<npp> miller_P4_Q4 =
        npp::miller_loop(native_prec_P4, native_prec_Q4);
    ASSERT_EQ(
        npp::final_exponentiation(miller_P4_Q4.inverse()),
        npp::final_exponentiation(miller_P4_Q4_inv));

    ASSERT_TRUE(test_e_times_e_times_e_over_e_miller_loop<wpp>(
        P1_val,
        Q1_val,
        P2_val,
        Q2_val,
        P3_val,
        Q3_val,
        P4_val,
        Q4_val,
        native_result,
        " test_eee_over_e_miller_loop_bls12_377"));
}

} // namespace

int main(int argc, char **argv)
{
    libff::start_profiling();
    libff::bw6_761_pp::init_public_params();
    libff::bls12_377_pp::init_public_params();
    libff::mnt4_pp::init_public_params();
    libff::mnt6_pp::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
