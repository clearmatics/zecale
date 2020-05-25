// DISCLAIMER:
// Content taken and modified from libsnark, developed by SCIPR Lab
// https://github.com/scipr-lab/libsnark/tree/master/libsnark/gadgetlib1/gadgets/pairing

#ifndef __ZECALE_CIRCUITS_PAIRING_MNT_PAIRING_PARAMS_HPP__
#define __ZECALE_CIRCUITS_PAIRING_MNT_PAIRING_PARAMS_HPP__

#include "libzecale/circuits/pairing/pairing_params.hpp"
#include "libzecale/circuits/pairing/weierstrass_miller_loop.hpp"

#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>
#include <libsnark/gadgetlib1/gadgets/fields/fp2_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/fields/fp3_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/fields/fp4_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/fields/fp6_gadgets.hpp>

namespace libzecale
{

template<typename ppT> class mnt_e_over_e_miller_loop_gadget;

template<typename ppT> class mnt_e_times_e_over_e_miller_loop_gadget;

template<typename ppT> class mnt_e_times_e_times_e_over_e_miller_loop_gadget;

template<typename ppT> class mnt4_final_exp_gadget;

template<typename ppT> class mnt6_final_exp_gadget;

// Specialization for MNT4.
//
template<> class pairing_selector<libff::mnt4_pp>
{
public:
    typedef libff::Fr<libff::mnt4_pp> FieldT;
    typedef libff::Fqe<libff::mnt6_pp> FqeT;
    typedef libff::Fqk<libff::mnt6_pp> FqkT;

    typedef libsnark::Fp3_variable<FqeT> Fqe_variable_type;
    typedef libsnark::Fp3_mul_gadget<FqeT> Fqe_mul_gadget_type;
    typedef libsnark::Fp3_mul_by_lc_gadget<FqeT> Fqe_mul_by_lc_gadget_type;
    typedef libsnark::Fp3_sqr_gadget<FqeT> Fqe_sqr_gadget_type;

    typedef libsnark::Fp6_variable<FqkT> Fqk_variable_type;
    typedef libsnark::Fp6_mul_gadget<FqkT> Fqk_mul_gadget_type;
    typedef libsnark::Fp6_mul_by_2345_gadget<FqkT> Fqk_special_mul_gadget_type;
    typedef libsnark::Fp6_sqr_gadget<FqkT> Fqk_sqr_gadget_type;

    typedef libff::mnt6_pp other_curve_type;

    typedef mnt_e_over_e_miller_loop_gadget<libff::mnt4_pp>
        e_over_e_miller_loop_gadget_type;
    typedef mnt_e_times_e_over_e_miller_loop_gadget<libff::mnt4_pp>
        e_times_e_over_e_miller_loop_gadget_type;
    // Add typedef for the `e_times_e_times_e_over_e_miller_loop_gadget` gadget
    typedef mnt_e_times_e_times_e_over_e_miller_loop_gadget<libff::mnt4_pp>
        e_times_e_times_e_over_e_miller_loop_gadget_type;
    typedef mnt4_final_exp_gadget<libff::mnt4_pp> final_exp_gadget_type;

    static const constexpr libff::bigint<libff::mnt6_Fr::num_limbs>
        &pairing_loop_count = libff::mnt6_ate_loop_count;
};

// Specialization for MNT6.
//
template<> class pairing_selector<libff::mnt6_pp>
{
public:
    typedef libff::Fr<libff::mnt6_pp> FieldT;

    typedef libff::Fqe<libff::mnt4_pp> FqeT;
    typedef libff::Fqk<libff::mnt4_pp> FqkT;

    typedef libsnark::Fp2_variable<FqeT> Fqe_variable_type;
    typedef libsnark::Fp2_mul_gadget<FqeT> Fqe_mul_gadget_type;
    typedef libsnark::Fp2_mul_by_lc_gadget<FqeT> Fqe_mul_by_lc_gadget_type;
    typedef libsnark::Fp2_sqr_gadget<FqeT> Fqe_sqr_gadget_type;

    typedef libsnark::Fp4_variable<FqkT> Fqk_variable_type;
    typedef libsnark::Fp4_mul_gadget<FqkT> Fqk_mul_gadget_type;
    typedef libsnark::Fp4_mul_gadget<FqkT> Fqk_special_mul_gadget_type;
    typedef libsnark::Fp4_sqr_gadget<FqkT> Fqk_sqr_gadget_type;

    typedef libff::mnt4_pp other_curve_type;

    typedef mnt_e_over_e_miller_loop_gadget<libff::mnt6_pp>
        e_over_e_miller_loop_gadget_type;
    typedef mnt_e_times_e_over_e_miller_loop_gadget<libff::mnt6_pp>
        e_times_e_over_e_miller_loop_gadget_type;
    // Add typedef for the `e_times_e_times_e_over_e_miller_loop_gadget` gadget
    typedef mnt_e_times_e_times_e_over_e_miller_loop_gadget<libff::mnt6_pp>
        e_times_e_times_e_over_e_miller_loop_gadget_type;
    typedef mnt6_final_exp_gadget<libff::mnt6_pp> final_exp_gadget_type;

    static const constexpr libff::bigint<libff::mnt4_Fr::num_limbs>
        &pairing_loop_count = libff::mnt4_ate_loop_count;
};

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_PAIRING_MNT_PAIRING_PARAMS_HPP__
