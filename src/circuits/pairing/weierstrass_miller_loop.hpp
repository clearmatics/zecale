// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_WEIERSTRASS_MILLER_LOOP_CIRCUIT_HPP__
#define __ZECALE_WEIERSTRASS_MILLER_LOOP_CIRCUIT_HPP__

#include <memory>

#include <libsnark/gadgetlib1/gadgets/pairing/pairing_params.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/weierstrass_precomputation.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/weierstrass_miller_loop.hpp>

namespace libzecale {

/// Gadget for verifying a quadruple Miller loop (where the fourth is inverted).
/// This gadget is necessary to implement the Groth16 verifier, and carry out the check:
/// e(\pi.A, \pi.B) = e(vk.\alpha, vk.\beta) * e (acc, g2) * e(\pi.C, vk.\delta)
/// where, g2 is the generator we use for encoding in G2, and where * denotes the group
/// operation in GT.
template<typename ppT>
class mnt_e_times_e_times_e_over_e_miller_loop_gadget : public gadget<libff::Fr<ppT> > {
public:
    typedef libff::Fr<ppT> FieldT;
    typedef libff::Fqe<other_curve<ppT> > FqeT;
    typedef libff::Fqk<other_curve<ppT> > FqkT;

    std::vector<std::shared_ptr<libsnark::Fqk_variable<ppT> > > g_RR_at_P1s;
    std::vector<std::shared_ptr<libsnark::Fqk_variable<ppT> > > g_RQ_at_P1s;
    std::vector<std::shared_ptr<libsnark::Fqk_variable<ppT> > > g_RR_at_P2s;
    std::vector<std::shared_ptr<libsnark::Fqk_variable<ppT> > > g_RQ_at_P2s;
    std::vector<std::shared_ptr<libsnark::Fqk_variable<ppT> > > g_RR_at_P3s;
    std::vector<std::shared_ptr<libsnark::Fqk_variable<ppT> > > g_RQ_at_P3s;
    std::vector<std::shared_ptr<libsnark::Fqk_variable<ppT> > > g_RR_at_P4s;
    std::vector<std::shared_ptr<libsnark::Fqk_variable<ppT> > > g_RQ_at_P4s;
    std::vector<std::shared_ptr<libsnark::Fqk_variable<ppT> > > fs;

    std::vector<std::shared_ptr<libsnark::mnt_miller_loop_add_line_eval<ppT> > > addition_steps1;
    std::vector<std::shared_ptr<libsnark::mnt_miller_loop_dbl_line_eval<ppT> > > doubling_steps1;
    std::vector<std::shared_ptr<libsnark::mnt_miller_loop_add_line_eval<ppT> > > addition_steps2;
    std::vector<std::shared_ptr<libsnark::mnt_miller_loop_dbl_line_eval<ppT> > > doubling_steps2;
    std::vector<std::shared_ptr<libsnark::mnt_miller_loop_add_line_eval<ppT> > > addition_steps3;
    std::vector<std::shared_ptr<libsnark::mnt_miller_loop_dbl_line_eval<ppT> > > doubling_steps3;
    std::vector<std::shared_ptr<libsnark::mnt_miller_loop_add_line_eval<ppT> > > addition_steps4;
    std::vector<std::shared_ptr<libsnark::mnt_miller_loop_dbl_line_eval<ppT> > > doubling_steps4;

    std::vector<std::shared_ptr<libsnark::Fqk_sqr_gadget<ppT> > > dbl_sqrs;
    std::vector<std::shared_ptr<libsnark::Fqk_special_mul_gadget<ppT> > > dbl_muls1;
    std::vector<std::shared_ptr<libsnark::Fqk_special_mul_gadget<ppT> > > add_muls1;
    std::vector<std::shared_ptr<libsnark::Fqk_special_mul_gadget<ppT> > > dbl_muls2;
    std::vector<std::shared_ptr<libsnark::Fqk_special_mul_gadget<ppT> > > add_muls2;
    std::vector<std::shared_ptr<libsnark::Fqk_special_mul_gadget<ppT> > > dbl_muls3;
    std::vector<std::shared_ptr<libsnark::Fqk_special_mul_gadget<ppT> > > add_muls3;
    std::vector<std::shared_ptr<libsnark::Fqk_special_mul_gadget<ppT> > > dbl_muls4;
    std::vector<std::shared_ptr<libsnark::Fqk_special_mul_gadget<ppT> > > add_muls4;

    size_t f_count;
    size_t add_count;
    size_t dbl_count;

    libsnark::G1_precomputation<ppT> prec_P1;
    libsnark::G2_precomputation<ppT> prec_Q1;
    libsnark::G1_precomputation<ppT> prec_P2;
    libsnark::G2_precomputation<ppT> prec_Q2;
    libsnark::G1_precomputation<ppT> prec_P3;
    libsnark::G2_precomputation<ppT> prec_Q3;
    libsnark::G1_precomputation<ppT> prec_P4;
    libsnark::G2_precomputation<ppT> prec_Q4;
    libsnark::Fqk_variable<ppT> result;

    mnt_e_times_e_times_e_over_e_miller_loop_gadget(protoboard<FieldT> &pb,
                                            const libsnark::G1_precomputation<ppT> &prec_P1,
                                            const libsnark::G2_precomputation<ppT> &prec_Q1,
                                            const libsnark::G1_precomputation<ppT> &prec_P2,
                                            const libsnark::G2_precomputation<ppT> &prec_Q2,
                                            const libsnark::G1_precomputation<ppT> &prec_P3,
                                            const libsnark::G2_precomputation<ppT> &prec_Q3,
                                            const libsnark::G1_precomputation<ppT> &prec_P4,
                                            const libsnark::G2_precomputation<ppT> &prec_Q4,
                                            const libsnark::Fqk_variable<ppT> &result,
                                            const std::string &annotation_prefix);
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename ppT>
void test_mnt_e_times_e_times_e_over_e_miller_loop(const std::string &annotation);

} // libzecale

#include "weierstrass_miller_loop.tcc"

#endif // __ZECALE_WEIERSTRASS_MILLER_LOOP_CIRCUIT_HPP__
