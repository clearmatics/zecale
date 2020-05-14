// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_PAIRING_PAIRING_CHECKS_TCC__
#define __ZECALE_CIRCUITS_PAIRING_PAIRING_CHECKS_TCC__

#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>

namespace libzecale
{

template<typename ppT>
check_e_equals_eee_gadget<ppT>::check_e_equals_eee_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::G1_precomputation<ppT> &lhs_G1,
    const libsnark::G2_precomputation<ppT> &lhs_G2,
    const libsnark::G1_precomputation<ppT> &rhs1_G1,
    const libsnark::G2_precomputation<ppT> &rhs1_G2,
    const libsnark::G1_precomputation<ppT> &rhs2_G1,
    const libsnark::G2_precomputation<ppT> &rhs2_G2,
    const libsnark::G1_precomputation<ppT> &rhs3_G1,
    const libsnark::G2_precomputation<ppT> &rhs3_G2,
    const libsnark::pb_variable<FieldT> &result,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , lhs_G1(lhs_G1)
    , lhs_G2(lhs_G2)
    , rhs1_G1(rhs1_G1)
    , rhs1_G2(rhs1_G2)
    , rhs2_G1(rhs2_G1)
    , rhs2_G2(rhs2_G2)
    , rhs3_G1(rhs3_G1)
    , rhs3_G2(rhs3_G2)
    , result(result)
{
    ratio.reset(new Fqk_variable<ppT>(pb, FMT(annotation_prefix, " ratio")));
    compute_ratio.reset(new e_times_e_times_e_over_e_miller_loop_gadget<ppT>(
        pb,
        rhs1_G1,
        rhs1_G2,
        rhs2_G1,
        rhs2_G2,
        rhs3_G1,
        rhs3_G2,
        lhs_G1,
        lhs_G2,
        *ratio,
        FMT(annotation_prefix, " compute_ratio")));
    check_finexp.reset(new libsnark::final_exp_gadget<ppT>(
        pb, *ratio, result, FMT(annotation_prefix, " check_finexp")));
}

template<typename ppT>
void check_e_equals_eee_gadget<ppT>::generate_r1cs_constraints()
{
    compute_ratio->generate_r1cs_constraints();
    check_finexp->generate_r1cs_constraints();
}

template<typename ppT>
void check_e_equals_eee_gadget<ppT>::generate_r1cs_witness()
{
    compute_ratio->generate_r1cs_witness();
    check_finexp->generate_r1cs_witness();
}

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
    // Result of the pairing check (in Fr<ppT> which is the scalar field over
    // which we define the circuit)
    libff::Fr<ppT> expected_result,
    const std::string &annotation_prefix)
{
    // For the macros
    using namespace libsnark;

    // We verify the pairing check over Fr<ppT> a pairing check
    // of group elements defined over libff::Fr<other_curve<ppT>>
    // i.e. we use one curve to verify a pairing check defined over the "other
    // curve"
    libsnark::protoboard<libff::Fr<ppT>> pb;

    // bool scalar_check = (scalar7 * scalar8 == scalar1 * scalar2 + scalar3 *
    // scalar4 + scalar5 * scalar6); std::cout << "[DEBUG] ======= scalar_check:
    // " << scalar_check << std::endl;

    libsnark::G1_variable<ppT> lhs_P(pb, FMT(annotation_prefix, " lhs_P"));
    libsnark::G2_variable<ppT> lhs_Q(pb, FMT(annotation_prefix, " lhs_Q"));
    libsnark::G1_variable<ppT> rhs_P1(pb, FMT(annotation_prefix, " rhs_P1"));
    libsnark::G2_variable<ppT> rhs_Q1(pb, FMT(annotation_prefix, " rhs_Q1"));
    libsnark::G1_variable<ppT> rhs_P2(pb, FMT(annotation_prefix, " rhs_P2"));
    libsnark::G2_variable<ppT> rhs_Q2(pb, FMT(annotation_prefix, " rhs_Q2"));
    libsnark::G1_variable<ppT> rhs_P3(pb, FMT(annotation_prefix, " rhs_P3"));
    libsnark::G2_variable<ppT> rhs_Q3(pb, FMT(annotation_prefix, " rhs_Q3"));

    libsnark::G1_precomputation<ppT> lhs_prec_P;
    libsnark::precompute_G1_gadget<ppT> compute_lhs_prec_P(
        pb, lhs_P, lhs_prec_P, FMT(annotation_prefix, " compute_lhs_prec_P"));
    libsnark::G2_precomputation<ppT> lhs_prec_Q;
    libsnark::precompute_G2_gadget<ppT> compute_lhs_prec_Q(
        pb, lhs_Q, lhs_prec_Q, FMT(annotation_prefix, " compute_lhs_prec_Q"));

    libsnark::G1_precomputation<ppT> rhs_prec1_P;
    libsnark::precompute_G1_gadget<ppT> compute_rhs_prec1_P(
        pb,
        rhs_P1,
        rhs_prec1_P,
        FMT(annotation_prefix, " compute_rhs_prec1_P"));
    libsnark::G2_precomputation<ppT> rhs_prec1_Q;
    libsnark::precompute_G2_gadget<ppT> compute_rhs_prec1_Q(
        pb,
        rhs_Q1,
        rhs_prec1_Q,
        FMT(annotation_prefix, " compute_rhs_prec1_Q"));

    libsnark::G1_precomputation<ppT> rhs_prec2_P;
    libsnark::precompute_G1_gadget<ppT> compute_rhs_prec2_P(
        pb,
        rhs_P2,
        rhs_prec2_P,
        FMT(annotation_prefix, " compute_rhs_prec2_P"));
    libsnark::G2_precomputation<ppT> rhs_prec2_Q;
    libsnark::precompute_G2_gadget<ppT> compute_rhs_prec2_Q(
        pb,
        rhs_Q2,
        rhs_prec2_Q,
        FMT(annotation_prefix, " compute_rhs_prec2_Q"));

    libsnark::G1_precomputation<ppT> rhs_prec3_P;
    libsnark::precompute_G1_gadget<ppT> compute_rhs_prec3_P(
        pb,
        rhs_P3,
        rhs_prec3_P,
        FMT(annotation_prefix, " compute_rhs_prec3_P"));
    libsnark::G2_precomputation<ppT> rhs_prec3_Q;
    libsnark::precompute_G2_gadget<ppT> compute_rhs_prec3_Q(
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
    PRINT_CONSTRAINT_PROFILING();

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

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_PAIRING_PAIRING_CHECKS_TCC__
