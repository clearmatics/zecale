// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_PAIRING_PAIRING_CHECKS_HPP__
#define __ZECALE_CIRCUITS_PAIRING_PAIRING_CHECKS_HPP__

#include "libzecale/circuits/pairing/pairing_params.hpp"
#include "libzecale/circuits/pairing/weierstrass_miller_loop.hpp"

#include <libsnark/gadgetlib1/gadgets/pairing/pairing_checks.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/weierstrass_final_exponentiation.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/weierstrass_miller_loop.hpp>
#include <memory>

namespace libzecale
{

/// This gadget is necessary to implement the Groth16 verifier
/// as per the [BGM17] paper, where we need to do:
/// e(\pi.A, \pi.B) = e([\alpha]_1, [\beta]_2) * e(acc, g2) * e(\pi.C,
/// [\delta]_2)
template<typename ppT>
class check_e_equals_eee_gadget : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    typedef libff::Fr<ppT> FieldT;

    std::shared_ptr<libsnark::Fqk_variable<ppT>> ratio;
    std::shared_ptr<e_times_e_times_e_over_e_miller_loop_gadget<ppT>>
        compute_ratio;
    std::shared_ptr<libsnark::final_exp_gadget<ppT>> check_finexp;

    libsnark::G1_precomputation<ppT> lhs_G1;
    libsnark::G2_precomputation<ppT> lhs_G2;
    libsnark::G1_precomputation<ppT> rhs1_G1;
    libsnark::G2_precomputation<ppT> rhs1_G2;
    libsnark::G1_precomputation<ppT> rhs2_G1;
    libsnark::G2_precomputation<ppT> rhs2_G2;
    libsnark::G1_precomputation<ppT> rhs3_G1;
    libsnark::G2_precomputation<ppT> rhs3_G2;

    libsnark::pb_variable<FieldT> result;

    check_e_equals_eee_gadget(
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
        const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename ppT>
bool test_check_e_equals_eee_gadget(
    libff::G1<other_curve<ppT>> scalar1,
    libff::G2<other_curve<ppT>> scalar2,
    libff::G1<other_curve<ppT>> scalar3,
    libff::G2<other_curve<ppT>> scalar4,
    libff::G1<other_curve<ppT>> scalar5,
    libff::G2<other_curve<ppT>> scalar6,
    libff::G1<other_curve<ppT>> scalar7,
    libff::G2<other_curve<ppT>> scalar8,
    libff::Fr<ppT> expected_result,
    const std::string &annotation_prefix);

} // namespace libzecale

#include "libzecale/circuits/pairing/pairing_checks.tcc"

#endif // __ZECALE_CIRCUITS_PAIRING_PAIRING_CHECKS_HPP__
