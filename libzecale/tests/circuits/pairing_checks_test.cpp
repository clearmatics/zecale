// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzecale/circuits/pairing/mnt_pairing_params.hpp"
#include "libzecale/circuits/pairing/pairing_checks.hpp"
#include "libzecale/circuits/pairing/pairing_params.hpp"

#include <gtest/gtest.h>

using namespace libzecale;

namespace
{

/// In this test we carry out - via a circuit defined over Fr<ppT> - a pairing
/// check between elements of G1 and G2 defined over other_curve<ppT>
template<typename ppT>
bool test_check_e_equals_eee_gadget(
    // Points of the "other curve" that are fed in the pairing check
    libff::G1<other_curve<ppT>> lhs_pairing_P,
    libff::G2<other_curve<ppT>> lhs_pairing_Q,
    libff::G1<other_curve<ppT>> rhs_pairing1_P,
    libff::G2<other_curve<ppT>> rhs_pairing1_Q,
    libff::G1<other_curve<ppT>> rhs_pairing2_P,
    libff::G2<other_curve<ppT>> rhs_pairing2_Q,
    libff::G1<other_curve<ppT>> rhs_pairing3_P,
    libff::G2<other_curve<ppT>> rhs_pairing3_Q,
    // Result of the pairing check (in Fr<ppT> which is the scalar field
    // over which we define the circuit)
    libff::Fr<ppT> expected_result,
    const std::string &annotation_prefix)
{
    // We verify the pairing check over Fr<ppT> a pairing check
    // of group elements defined over libff::Fr<other_curve<ppT>>
    // i.e. we use one curve to verify a pairing check defined over the
    // "other curve"
    libsnark::protoboard<libff::Fr<ppT>> pb;

    // bool scalar_check = (scalar7 * scalar8 == scalar1 * scalar2 + scalar3 *
    // scalar4 + scalar5 * scalar6); std::cout << "[DEBUG] =======
    // scalar_check:
    // " << scalar_check << std::endl;

    libsnark::G1_variable<ppT> lhs_P(pb, FMT(annotation_prefix, " lhs_P"));
    libsnark::G2_variable<ppT> lhs_Q(pb, FMT(annotation_prefix, " lhs_Q"));
    libsnark::G1_variable<ppT> rhs_P1(pb, FMT(annotation_prefix, " rhs_P1"));
    libsnark::G2_variable<ppT> rhs_Q1(pb, FMT(annotation_prefix, " rhs_Q1"));
    libsnark::G1_variable<ppT> rhs_P2(pb, FMT(annotation_prefix, " rhs_P2"));
    libsnark::G2_variable<ppT> rhs_Q2(pb, FMT(annotation_prefix, " rhs_Q2"));
    libsnark::G1_variable<ppT> rhs_P3(pb, FMT(annotation_prefix, " rhs_P3"));
    libsnark::G2_variable<ppT> rhs_Q3(pb, FMT(annotation_prefix, " rhs_Q3"));

    G1_precomputation<ppT> lhs_prec_P;
    G1_precompute_gadget<ppT> compute_lhs_prec_P(
        pb, lhs_P, lhs_prec_P, FMT(annotation_prefix, "compute_lhs_prec_P"));
    G2_precomputation<ppT> lhs_prec_Q;
    G2_precompute_gadget<ppT> compute_lhs_prec_Q(
        pb, lhs_Q, lhs_prec_Q, FMT(annotation_prefix, "compute_lhs_prec_Q"));

    G1_precomputation<ppT> rhs_prec1_P;
    G1_precompute_gadget<ppT> compute_rhs_prec1_P(
        pb,
        rhs_P1,
        rhs_prec1_P,
        FMT(annotation_prefix, " compute_rhs_prec1_P"));
    G2_precomputation<ppT> rhs_prec1_Q;
    G2_precompute_gadget<ppT> compute_rhs_prec1_Q(
        pb,
        rhs_Q1,
        rhs_prec1_Q,
        FMT(annotation_prefix, " compute_rhs_prec1_Q"));

    G1_precomputation<ppT> rhs_prec2_P;
    G1_precompute_gadget<ppT> compute_rhs_prec2_P(
        pb,
        rhs_P2,
        rhs_prec2_P,
        FMT(annotation_prefix, " compute_rhs_prec2_P"));
    G2_precomputation<ppT> rhs_prec2_Q;
    G2_precompute_gadget<ppT> compute_rhs_prec2_Q(
        pb,
        rhs_Q2,
        rhs_prec2_Q,
        FMT(annotation_prefix, " compute_rhs_prec2_Q"));

    G1_precomputation<ppT> rhs_prec3_P;
    G1_precompute_gadget<ppT> compute_rhs_prec3_P(
        pb,
        rhs_P3,
        rhs_prec3_P,
        FMT(annotation_prefix, " compute_rhs_prec3_P"));
    G2_precomputation<ppT> rhs_prec3_Q;
    G2_precompute_gadget<ppT> compute_rhs_prec3_Q(
        pb,
        rhs_Q3,
        rhs_prec3_Q,
        FMT(annotation_prefix, " compute_rhs_prec3_Q"));

    libsnark::pb_variable<libff::Fr<ppT>> result;
    result.allocate(pb, FMT(annotation_prefix, " result"));

    check_e_equals_eee_gadget<ppT> pairing_check(
        pb,
        lhs_prec_P,
        lhs_prec_Q,
        rhs_prec1_P,
        rhs_prec1_Q,
        rhs_prec2_P,
        rhs_prec2_Q,
        rhs_prec3_P,
        rhs_prec3_Q,
        result,
        FMT(annotation_prefix, " pairing_check"));

    PROFILE_CONSTRAINTS(pb, "precompute P")
    {
        compute_lhs_prec_P.generate_r1cs_constraints();

        compute_rhs_prec1_P.generate_r1cs_constraints();
        compute_rhs_prec2_P.generate_r1cs_constraints();
        compute_rhs_prec3_P.generate_r1cs_constraints();
    }
    PROFILE_CONSTRAINTS(pb, "precompute Q")
    {
        compute_lhs_prec_Q.generate_r1cs_constraints();

        compute_rhs_prec1_Q.generate_r1cs_constraints();
        compute_rhs_prec2_Q.generate_r1cs_constraints();
        compute_rhs_prec3_Q.generate_r1cs_constraints();
    }
    PROFILE_CONSTRAINTS(pb, "Pairing check")
    {
        pairing_check.generate_r1cs_constraints();
    }
    libsnark::PRINT_CONSTRAINT_PROFILING();

    libsnark::generate_r1cs_equals_const_constraint<libff::Fr<ppT>>(
        pb, result, expected_result, FMT(annotation_prefix, " result"));

    lhs_P.generate_r1cs_witness(lhs_pairing_P);
    compute_lhs_prec_P.generate_r1cs_witness();
    lhs_Q.generate_r1cs_witness(lhs_pairing_Q);
    compute_lhs_prec_Q.generate_r1cs_witness();

    rhs_P1.generate_r1cs_witness(rhs_pairing1_P);
    compute_rhs_prec1_P.generate_r1cs_witness();
    rhs_Q1.generate_r1cs_witness(rhs_pairing1_Q);
    compute_rhs_prec1_Q.generate_r1cs_witness();

    rhs_P2.generate_r1cs_witness(rhs_pairing2_P);
    compute_rhs_prec2_P.generate_r1cs_witness();
    rhs_Q2.generate_r1cs_witness(rhs_pairing2_Q);
    compute_rhs_prec2_Q.generate_r1cs_witness();

    rhs_P3.generate_r1cs_witness(rhs_pairing3_P);
    compute_rhs_prec3_P.generate_r1cs_witness();
    rhs_Q3.generate_r1cs_witness(rhs_pairing3_Q);
    compute_rhs_prec3_Q.generate_r1cs_witness();

    pairing_check.generate_r1cs_witness();

    assert(pb.is_satisfied());
    printf(
        "number of constraints for check_e_equals_eee_gadget (Fr is "
        "%s)  = %zu\n",
        annotation_prefix.c_str(),
        pb.num_constraints());

    bool test_success = (pb.val(result) == expected_result);
    return test_success;
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

TEST(MainTests, TestMntValidCheckEequalsEEEgadget)
{
    test_valid_pairing_check_e_equals_eee_gadget<libff::mnt4_pp>();
    test_valid_pairing_check_e_equals_eee_gadget<libff::mnt6_pp>();
}

TEST(MainTests, TestMntInvalidCheckEequalsEEEgadget)
{
    test_invalid_pairing_check_e_equals_eee_gadget<libff::mnt4_pp>();
    test_invalid_pairing_check_e_equals_eee_gadget<libff::mnt6_pp>();
}

} // namespace

int main(int argc, char **argv)
{
    libff::start_profiling();

    // Initialize the curve parameters before running the tests
    libff::mnt4_pp::init_public_params();
    libff::mnt6_pp::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
