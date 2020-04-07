// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "src/circuits/pairing/pairing_checks.hpp"
#include "src/circuits/pairing/weierstrass_miller_loop.hpp"

#include "gtest/gtest.h"

// Instantiation of the templates for the tests
typedef libff::mnt4_pp curve_mnt4;
typedef libff::mnt6_pp curve_mnt6;

using namespace libzecale;

namespace
{

TEST(MainTests, TestMntEEEoverEmillerLoop)
{
    bool res = false;
    res = test_mnt_e_times_e_times_e_over_e_miller_loop<curve_mnt4>(
        " test_eee_over_e_miller_loop_mnt4");
    ASSERT_TRUE(res);

    res = false;
    res = test_mnt_e_times_e_times_e_over_e_miller_loop<curve_mnt6>(
        " test_eee_over_e_miller_loop_mnt6");
    ASSERT_TRUE(res);
}

/// Create VALID test case by instantiating points from G1 and G2
/// (over `other_curve<ppT>`) that will be fed into the pairing check
/// carried out inside the circuit, and so, over Fr<ppT>
///
/// As such, `ppT` represents the curve we use to encode the arithmetic
/// circuit wire. In other words, the pairing check gadget called here
/// will be instantiated from `libff::Fr<ppT>`.
template<typename ppT> void test_valid_pairing_check_e_equals_eee_gadget()
{
    const libff::G1<other_curve<ppT>> G1_base =
        libff::G1<other_curve<ppT>>::one();
    const libff::G2<other_curve<ppT>> G2_base =
        libff::G2<other_curve<ppT>>::one();

    const libff::Fr<other_curve<ppT>> rhs_scalar1 =
        libff::Fr<other_curve<ppT>>::random_element();
    const libff::Fr<other_curve<ppT>> rhs_scalar2 =
        libff::Fr<other_curve<ppT>>::random_element();
    const libff::Fr<other_curve<ppT>> rhs_scalar3 =
        libff::Fr<other_curve<ppT>>::random_element();
    const libff::Fr<other_curve<ppT>> rhs_scalar4 =
        libff::Fr<other_curve<ppT>>::random_element();
    const libff::Fr<other_curve<ppT>> rhs_scalar5 =
        libff::Fr<other_curve<ppT>>::random_element();
    const libff::Fr<other_curve<ppT>> rhs_scalar6 =
        libff::Fr<other_curve<ppT>>::random_element();

    const libff::G1<other_curve<ppT>> rhs_pairing1_P = rhs_scalar1 * G1_base;
    const libff::G2<other_curve<ppT>> rhs_pairing1_Q = rhs_scalar2 * G2_base;
    const libff::G1<other_curve<ppT>> rhs_pairing2_P = rhs_scalar3 * G1_base;
    const libff::G2<other_curve<ppT>> rhs_pairing2_Q = rhs_scalar4 * G2_base;
    const libff::G1<other_curve<ppT>> rhs_pairing3_P = rhs_scalar5 * G1_base;
    const libff::G2<other_curve<ppT>> rhs_pairing3_Q = rhs_scalar6 * G2_base;

    // Set the LHS group elements such that the pairing check passes
    const libff::G1<other_curve<ppT>> lhs_pairing_P =
        (rhs_scalar1 * rhs_scalar2 + rhs_scalar3 * rhs_scalar4 +
         rhs_scalar5 * rhs_scalar6) *
        G1_base;
    const libff::G2<other_curve<ppT>> lhs_pairing_Q = G2_base;

    // Compute pairings "outside the circuit" to check the value of the LHS
    // against the value of the RHS, and see if the pairing check
    // is succesfull
    libff::GT<other_curve<ppT>> expected_pairing_lhs =
        other_curve<ppT>::final_exponentiation(other_curve<ppT>::miller_loop(
            other_curve<ppT>::precompute_G1(lhs_pairing_P),
            other_curve<ppT>::precompute_G2(lhs_pairing_Q)));

    libff::GT<other_curve<ppT>> expected_pairing_rhs1 =
        other_curve<ppT>::final_exponentiation(other_curve<ppT>::miller_loop(
            other_curve<ppT>::precompute_G1(rhs_pairing1_P),
            other_curve<ppT>::precompute_G2(rhs_pairing1_Q)));

    libff::GT<other_curve<ppT>> expected_pairing_rhs2 =
        other_curve<ppT>::final_exponentiation(other_curve<ppT>::miller_loop(
            other_curve<ppT>::precompute_G1(rhs_pairing2_P),
            other_curve<ppT>::precompute_G2(rhs_pairing2_Q)));

    libff::GT<other_curve<ppT>> expected_pairing_rhs3 =
        other_curve<ppT>::final_exponentiation(other_curve<ppT>::miller_loop(
            other_curve<ppT>::precompute_G1(rhs_pairing3_P),
            other_curve<ppT>::precompute_G2(rhs_pairing3_Q)));

    bool check_result =
        (expected_pairing_lhs ==
         expected_pairing_rhs1 * expected_pairing_rhs2 * expected_pairing_rhs3);

    // Set the value of the expected value of the "output wire"
    // of the pairing check gadget.
    libff::Fr<ppT> expected_result =
        check_result ? libff::Fr<ppT>::one() : libff::Fr<ppT>::zero();

    // Make sure that the pairing check succeeds and the gadget is tested
    // with the right expected value
    ASSERT_TRUE(check_result);
    ASSERT_EQ(expected_result, libff::Fr<ppT>::one());

    bool res = test_check_e_equals_eee_gadget<ppT>(
        lhs_pairing_P,
        lhs_pairing_Q,
        rhs_pairing1_P,
        rhs_pairing1_Q,
        rhs_pairing2_P,
        rhs_pairing2_Q,
        rhs_pairing3_P,
        rhs_pairing3_Q,
        expected_result,
        " test_check_e_equals_eee_gadget");

    // Check that the pairing check circuit returns the same result as
    // the one carried out "outside" the circuit (see above)
    ASSERT_TRUE(res);
}

/// Create INVALID test case by instantiating points from G1 and G2
/// (over `other_curve<ppT>`) that will be fed into the pairing check
/// carried out inside the circuit, and so, over Fr<ppT>
///
/// As such, `ppT` represents the curve we use to encode the arithmetic
/// circuit wire. In other words, the pairing check gadget called here
/// will be instantiated from `libff::Fr<ppT>`.
template<typename ppT> void test_invalid_pairing_check_e_equals_eee_gadget()
{
    const libff::G1<other_curve<ppT>> G1_base =
        libff::G1<other_curve<ppT>>::one();
    const libff::G2<other_curve<ppT>> G2_base =
        libff::G2<other_curve<ppT>>::one();

    const libff::G1<other_curve<ppT>> rhs_pairing1_P =
        libff::Fr<other_curve<ppT>>(2l) * G1_base;
    const libff::G2<other_curve<ppT>> rhs_pairing1_Q =
        libff::Fr<other_curve<ppT>>(3l) * G2_base;
    const libff::G1<other_curve<ppT>> rhs_pairing2_P =
        libff::Fr<other_curve<ppT>>(4l) * G1_base;
    const libff::G2<other_curve<ppT>> rhs_pairing2_Q =
        libff::Fr<other_curve<ppT>>(5l) * G2_base;
    const libff::G1<other_curve<ppT>> rhs_pairing3_P =
        libff::Fr<other_curve<ppT>>(6l) * G1_base;
    const libff::G2<other_curve<ppT>> rhs_pairing3_Q =
        libff::Fr<other_curve<ppT>>(7l) * G2_base;

    // Set the LHS group elements such that the pairing check should not pass
    // On the RHS, we have: e(g1, g2)^(2*3) * e(g1, g2)^(4*5) * e(g1, g2)^(6*7)
    // which gives: e(g1, g2)^(6+20+42) = e(g1, g2)^(68) = gt^(68)
    // where g1, g2 and gt represent the generators in G1, G2 and GT
    // respectively
    //
    // Here we set the LHS to e(g1, g2)^(35*27) where the scalars are choosen
    // arbritarily at the only condition that their product is =/= 68
    const libff::G1<other_curve<ppT>> lhs_pairing_P =
        libff::Fr<other_curve<ppT>>(35l) * G1_base;
    const libff::G2<other_curve<ppT>> lhs_pairing_Q =
        libff::Fr<other_curve<ppT>>(27l) * G2_base;

    // Compute pairings "outside the circuit" to check the value of the LHS
    // against the value of the RHS, and see if the pairing check
    // is succesfull
    libff::GT<other_curve<ppT>> expected_pairing_lhs =
        other_curve<ppT>::final_exponentiation(other_curve<ppT>::miller_loop(
            other_curve<ppT>::precompute_G1(lhs_pairing_P),
            other_curve<ppT>::precompute_G2(lhs_pairing_Q)));

    libff::GT<other_curve<ppT>> expected_pairing_rhs1 =
        other_curve<ppT>::final_exponentiation(other_curve<ppT>::miller_loop(
            other_curve<ppT>::precompute_G1(rhs_pairing1_P),
            other_curve<ppT>::precompute_G2(rhs_pairing1_Q)));

    libff::GT<other_curve<ppT>> expected_pairing_rhs2 =
        other_curve<ppT>::final_exponentiation(other_curve<ppT>::miller_loop(
            other_curve<ppT>::precompute_G1(rhs_pairing2_P),
            other_curve<ppT>::precompute_G2(rhs_pairing2_Q)));

    libff::GT<other_curve<ppT>> expected_pairing_rhs3 =
        other_curve<ppT>::final_exponentiation(other_curve<ppT>::miller_loop(
            other_curve<ppT>::precompute_G1(rhs_pairing3_P),
            other_curve<ppT>::precompute_G2(rhs_pairing3_Q)));

    bool check_result =
        (expected_pairing_lhs ==
         expected_pairing_rhs1 * expected_pairing_rhs2 * expected_pairing_rhs3);

    // Set the value of the expected value of the "output wire"
    // of the pairing check gadget.
    libff::Fr<ppT> expected_result =
        check_result ? libff::Fr<ppT>::one() : libff::Fr<ppT>::zero();

    // Make sure that the pairing check fails
    ASSERT_FALSE(check_result);
    ASSERT_EQ(expected_result, libff::Fr<ppT>::zero());

    bool res = test_check_e_equals_eee_gadget<ppT>(
        lhs_pairing_P,
        lhs_pairing_Q,
        rhs_pairing1_P,
        rhs_pairing1_Q,
        rhs_pairing2_P,
        rhs_pairing2_Q,
        rhs_pairing3_P,
        rhs_pairing3_Q,
        expected_result,
        " test_check_e_equals_eee_gadget");

    // Check that the pairing check circuit returns the same result as
    // the one carried out "outside" the circuit (see above)
    ASSERT_TRUE(res);
}

TEST(MainTests, TestValidCheckEequalsEEEgadget)
{
    test_valid_pairing_check_e_equals_eee_gadget<curve_mnt4>();
    test_valid_pairing_check_e_equals_eee_gadget<curve_mnt6>();
}

TEST(MainTests, TestInvalidCheckEequalsEEEgadget)
{
    test_invalid_pairing_check_e_equals_eee_gadget<curve_mnt4>();
    test_invalid_pairing_check_e_equals_eee_gadget<curve_mnt6>();
}

} // namespace

int main(int argc, char **argv)
{
    libff::start_profiling();

    // Initialize the curve parameters before running the tests
    curve_mnt4::init_public_params();
    curve_mnt6::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}