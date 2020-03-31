// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_PAIRING_CHECKS_CIRCUIT_TCC__
#define __ZECALE_PAIRING_CHECKS_CIRCUIT_TCC__

namespace libzecale {

template<typename ppT>
check_e_equals_eee_gadget<ppT>::check_e_equals_eee_gadget(libsnark::protoboard<FieldT> &pb,
                                                        const libsnark::G1_precomputation<ppT> &lhs_G1,
                                                        const libsnark::G2_precomputation<ppT> &lhs_G2,
                                                        const libsnark::G1_precomputation<ppT> &rhs1_G1,
                                                        const libsnark::G2_precomputation<ppT> &rhs1_G2,
                                                        const libsnark::G1_precomputation<ppT> &rhs2_G1,
                                                        const libsnark::G2_precomputation<ppT> &rhs2_G2,
                                                        const libsnark::G1_precomputation<ppT> &rhs3_G1,
                                                        const libsnark::G2_precomputation<ppT> &rhs3_G2,
                                                        const libsnark::pb_variable<FieldT> &result,
                                                        const std::string &annotation_prefix) :
    gadget<FieldT>(pb, annotation_prefix),
    lhs_G1(lhs_G1),
    lhs_G2(lhs_G2),
    rhs1_G1(rhs1_G1),
    rhs1_G2(rhs1_G2),
    rhs2_G1(rhs2_G1),
    rhs2_G2(rhs2_G2),
    rhs3_G1(rhs3_G1),
    rhs3_G2(rhs3_G2),
    result(result)
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
    check_finexp.reset(new final_exp_gadget<ppT>(pb, *ratio, result, FMT(annotation_prefix, " check_finexp")));
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

} // libzecale

#endif // __ZECALE_PAIRING_CHECKS_CIRCUIT_TCC__
