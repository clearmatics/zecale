// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "gtest/gtest.h"

#include "src/circuits/pairing/weierstrass_miller_loop.hpp"
#include "src/circuits/pairing/pairing_checks.hpp"
//#include <libsnark/gadgetlib1/gadgets/pairing/weierstrass_miller_loop.hpp>

#include <libsnark/gadgetlib1/gadgets/pairing/pairing_checks.tcc>

// Instantiation of the templates for the tests
typedef libff::mnt4_pp curve_mnt4;
typedef libff::mnt6_pp curve_mnt6;

using namespace libzecale;
//using namespace libsnark;

namespace
{

/*
 * This test passes:
 * TODO:
 * Uncomment when test below is fixed
 * 
TEST(MainTests, TestMntEEEoverEmillerLoop)
{
    bool res = false;
    res = test_mnt_e_times_e_times_e_over_e_miller_loop<curve_mnt4>(" test_eee_over_e_miller_loop_mnt4");
    ASSERT_TRUE(res);

    res = false;
    res = test_mnt_e_times_e_times_e_over_e_miller_loop<curve_mnt6>(" test_eee_over_e_miller_loop_mnt6");
    ASSERT_TRUE(res);
}
*/

TEST(MainTests, TestValidCheckEequalsEEEgadget)
{
    // Valid test
    const libff::G1<curve_mnt4> G1_base = libff::G1<curve_mnt4>::one();
    const libff::G2<curve_mnt4> G2_base = libff::G2<curve_mnt4>::one();

    const libff::Fr<curve_mnt4> rhs_scalar1 = libff::Fr<curve_mnt4>::random_element();
    const libff::Fr<curve_mnt4> rhs_scalar2 = libff::Fr<curve_mnt4>::random_element();
    const libff::Fr<curve_mnt4> rhs_scalar3 = libff::Fr<curve_mnt4>::random_element();
    const libff::Fr<curve_mnt4> rhs_scalar4 = libff::Fr<curve_mnt4>::random_element();
    const libff::Fr<curve_mnt4> rhs_scalar5 = libff::Fr<curve_mnt4>::random_element();
    const libff::Fr<curve_mnt4> rhs_scalar6 = libff::Fr<curve_mnt4>::random_element();

    const libff::G1<curve_mnt4> rhs_pairing1_P = rhs_scalar1 * G1_base;
    const libff::G2<curve_mnt4> rhs_pairing1_Q = rhs_scalar2 * G2_base;
    const libff::G1<curve_mnt4> rhs_pairing2_P = rhs_scalar3 * G1_base;
    const libff::G2<curve_mnt4> rhs_pairing2_Q = rhs_scalar4 * G2_base;
    const libff::G1<curve_mnt4> rhs_pairing3_P = rhs_scalar5 * G1_base;
    const libff::G2<curve_mnt4> rhs_pairing3_Q = rhs_scalar6 * G2_base;

    // Set the LHS group elements such that the pairing check passes
    const libff::G1<curve_mnt4> lhs_pairing_P = (rhs_scalar1 * rhs_scalar2 + rhs_scalar3 * rhs_scalar4 + rhs_scalar5 * rhs_scalar6) * G1_base;
    const libff::G2<curve_mnt4> lhs_pairing_Q = G2_base;

    // Compute pairings "outside the circuit" to check the value of the LHS
    // against the value of the RHS, and see if the pairing check
    // is succesfull
    libff::mnt4_GT expected_pairing_lhs = libff::mnt4_pp::final_exponentiation(
        libff::mnt4_pp::miller_loop(
        libff::mnt4_pp::precompute_G1(lhs_pairing_P),
        libff::mnt4_pp::precompute_G2(lhs_pairing_Q)));

    libff::mnt4_GT expected_pairing_rhs1 = libff::mnt4_pp::final_exponentiation(
        libff::mnt4_pp::miller_loop(
            libff::mnt4_pp::precompute_G1(rhs_pairing1_P),
            libff::mnt4_pp::precompute_G2(rhs_pairing1_Q)));

    libff::mnt4_GT expected_pairing_rhs2 = libff::mnt4_pp::final_exponentiation(
        libff::mnt4_pp::miller_loop(
            libff::mnt4_pp::precompute_G1(rhs_pairing2_P),
            libff::mnt4_pp::precompute_G2(rhs_pairing2_Q)));

    libff::mnt4_GT expected_pairing_rhs3 = libff::mnt4_pp::final_exponentiation(
        libff::mnt4_pp::miller_loop(
            libff::mnt4_pp::precompute_G1(rhs_pairing3_P),
            libff::mnt4_pp::precompute_G2(rhs_pairing3_Q)));

    bool check_result = (expected_pairing_lhs == expected_pairing_rhs1 * expected_pairing_rhs2 * expected_pairing_rhs3);
    libff::Fr<curve_mnt6> expected_result = check_result ? libff::Fr<curve_mnt6>::one() : libff::Fr<curve_mnt6>::zero();

    // Make sure that the pairing check succeeds
    ASSERT_TRUE(check_result);
    ASSERT_EQ(expected_result, libff::Fr<curve_mnt6>::one());

    bool res = test_check_e_equals_eee_gadget<curve_mnt6>(
        lhs_pairing_P, lhs_pairing_Q,
        rhs_pairing1_P, rhs_pairing1_Q,
        rhs_pairing2_P, rhs_pairing2_Q,
        rhs_pairing3_P, rhs_pairing3_Q,
        expected_result,
        " test_check_e_equals_eee_gadget");
    
    // Check that the pairing check circuit returns the same result as
    // the one carried out "outside" the circuit (see above)
    ASSERT_TRUE(res);
}

TEST(MainTests, TestInvalidCheckEequalsEEEgadget)
{
    // Valid test
    const libff::G1<curve_mnt4> G1_base = libff::G1<curve_mnt4>::one();
    const libff::G2<curve_mnt4> G2_base = libff::G2<curve_mnt4>::one();

    const libff::G1<curve_mnt4> rhs_pairing1_P = libff::Fr<curve_mnt4>(2l) * G1_base;
    const libff::G2<curve_mnt4> rhs_pairing1_Q = libff::Fr<curve_mnt4>(3l) * G2_base;
    const libff::G1<curve_mnt4> rhs_pairing2_P = libff::Fr<curve_mnt4>(4l) * G1_base;
    const libff::G2<curve_mnt4> rhs_pairing2_Q = libff::Fr<curve_mnt4>(5l) * G2_base;
    const libff::G1<curve_mnt4> rhs_pairing3_P = libff::Fr<curve_mnt4>(6l) * G1_base;
    const libff::G2<curve_mnt4> rhs_pairing3_Q = libff::Fr<curve_mnt4>(7l) * G2_base;

    // Set the LHS group elements such that the pairing check should not pass
    // On the RHS, we have: e(g1, g2)^(2*3) * e(g1, g2)^(4*5) * e(g1, g2)^(6*7)
    // which gives: e(g1, g2)^(6+20+42) = e(g1, g2)^(68) = gt^(68)
    // where g1, g2 and gt represent the generators in G1, G2 and GT respectively
    //
    // Here we set the LHS to e(g1, g2)^(35*27) where the scalars are choosen
    // arbritarily at the only condition that their product is =/= 68
    const libff::G1<curve_mnt4> lhs_pairing_P = libff::Fr<curve_mnt4>(35l) * G1_base;
    const libff::G2<curve_mnt4> lhs_pairing_Q = libff::Fr<curve_mnt4>(27l) * G2_base;

    // Compute pairings "outside the circuit" to check the value of the LHS
    // against the value of the RHS, and see if the pairing check
    // is succesfull
    libff::mnt4_GT expected_pairing_lhs = libff::mnt4_pp::final_exponentiation(
        libff::mnt4_pp::miller_loop(
        libff::mnt4_pp::precompute_G1(lhs_pairing_P),
        libff::mnt4_pp::precompute_G2(lhs_pairing_Q)));

    libff::mnt4_GT expected_pairing_rhs1 = libff::mnt4_pp::final_exponentiation(
        libff::mnt4_pp::miller_loop(
            libff::mnt4_pp::precompute_G1(rhs_pairing1_P),
            libff::mnt4_pp::precompute_G2(rhs_pairing1_Q)));

    libff::mnt4_GT expected_pairing_rhs2 = libff::mnt4_pp::final_exponentiation(
        libff::mnt4_pp::miller_loop(
            libff::mnt4_pp::precompute_G1(rhs_pairing2_P),
            libff::mnt4_pp::precompute_G2(rhs_pairing2_Q)));

    libff::mnt4_GT expected_pairing_rhs3 = libff::mnt4_pp::final_exponentiation(
        libff::mnt4_pp::miller_loop(
            libff::mnt4_pp::precompute_G1(rhs_pairing3_P),
            libff::mnt4_pp::precompute_G2(rhs_pairing3_Q)));

    bool check_result = (expected_pairing_lhs == expected_pairing_rhs1 * expected_pairing_rhs2 * expected_pairing_rhs3);
    libff::Fr<curve_mnt6> expected_result = check_result ? libff::Fr<curve_mnt6>::one() : libff::Fr<curve_mnt6>::zero();

    // Make sure that the pairing check fails
    ASSERT_FALSE(check_result);
    ASSERT_EQ(expected_result, libff::Fr<curve_mnt6>::zero());

    bool res = test_check_e_equals_eee_gadget<curve_mnt6>(
        lhs_pairing_P, lhs_pairing_Q,
        rhs_pairing1_P, rhs_pairing1_Q,
        rhs_pairing2_P, rhs_pairing2_Q,
        rhs_pairing3_P, rhs_pairing3_Q,
        expected_result,
        " test_check_e_equals_eee_gadget");
    
    // Check that the pairing check circuit returns the same result as
    // the one carried out "outside" the circuit (see above)
    ASSERT_TRUE(res);
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