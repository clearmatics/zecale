// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_PAIRING_BLS12_377_PAIRING_HPP__
#define __ZECALE_CIRCUITS_PAIRING_BLS12_377_PAIRING_HPP__

#include "libzecale/circuits/fields/fp12_2over3over2_gadgets.hpp"
#include "libzecale/circuits/pairing/bw6_761_pairing_params.hpp"
#include "libzecale/circuits/pairing/pairing_params.hpp"

#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>
#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g1_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g2_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/fields/fp2_gadgets.hpp>

namespace libzecale
{

template<typename ppT> class bls12_377_G1_precomputation
{
public:
    using FieldT = libff::Fr<ppT>;

    std::shared_ptr<libsnark::pb_linear_combination<FieldT>> _Px;
    std::shared_ptr<libsnark::pb_linear_combination<FieldT>> _Py;

    bls12_377_G1_precomputation();

    // Construct a populated G1_precomputation from a value. All terms are
    // created as constants, requiring no new gates in the circuit.
    bls12_377_G1_precomputation(
        libsnark::protoboard<FieldT> &pb,
        const libff::G1<other_curve<ppT>> &P_val,
        const std::string &annotation_prefix);
};

/// Holds an element of G2 in homogeneous projective form. Used for
/// intermediate values of R in the miller loop.
template<typename ppT> class bls12_377_G2_proj
{
public:
    Fqe_variable<ppT> X;
    Fqe_variable<ppT> Y;
    Fqe_variable<ppT> Z;

    bls12_377_G2_proj(
        libsnark::protoboard<libff::Fr<ppT>> &pb,
        const std::string &annotation_prefix);

    bls12_377_G2_proj(
        const Fqe_variable<ppT> &X_var,
        const Fqe_variable<ppT> &Y_var,
        const Fqe_variable<ppT> &Z_var);

    void generate_r1cs_witness(const libff::bls12_377_G2 &element);
};

/// Not a gadget - holds the variables for the Fq2 coefficients of the tangent
/// line at some R, used during the doubling step.
template<typename ppT> class bls12_377_ate_ell_coeffs
{
public:
    using FqT = libff::Fq<other_curve<ppT>>;

    Fqe_variable<ppT> ell_0;
    Fqe_variable<ppT> ell_vw;
    Fqe_variable<ppT> ell_vv;

    bls12_377_ate_ell_coeffs(
        libsnark::protoboard<FqT> &pb, const std::string &annotation_prefix);

    // Create from constants
    bls12_377_ate_ell_coeffs(
        libsnark::protoboard<FqT> &pb,
        const libff::Fqe<other_curve<ppT>> ell_0_val,
        const libff::Fqe<other_curve<ppT>> ell_vw_val,
        const libff::Fqe<other_curve<ppT>> ell_vv_val,
        const std::string &annotation_prefix);
};

template<typename ppT> class bls12_377_G2_precomputation
{
public:
    using FieldT = libff::Fr<ppT>;

    std::vector<std::shared_ptr<bls12_377_ate_ell_coeffs<ppT>>> _coeffs;

    bls12_377_G2_precomputation();

    // Construct a populated G2_precomputation from a value. All terms are
    // created as constants, requiring no new gates in the circuit.
    bls12_377_G2_precomputation(
        libsnark::protoboard<FieldT> &pb,
        const libff::G2<other_curve<ppT>> &Q_val,
        const std::string &annotation_prefix);
};

template<typename ppT>
class bls12_377_G1_precompute_gadget : libsnark::gadget<libff::Fr<ppT>>
{
public:
    using FieldT = libff::Fr<ppT>;

    std::shared_ptr<libsnark::pb_linear_combination<FieldT>> _Px;
    std::shared_ptr<libsnark::pb_linear_combination<FieldT>> _Py;

    bls12_377_G1_precompute_gadget(
        libsnark::protoboard<libff::Fr<ppT>> &pb,
        const libsnark::G1_variable<ppT> &P,
        bls12_377_G1_precomputation<ppT> &P_prec,
        const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

/// Gadget that relates some "current" bls12_377_G2_proj value in_R with the
/// result of the doubling step, that is some bls12_377_G2_proj out_R and the
/// bls12_377_ate_ell_coeffs holding the coefficients of the tangent at in_R.
/// Note that the output variables are allocated by this gadget.
template<typename ppT>
class bls12_377_ate_dbl_gadget : libsnark::gadget<libff::Fr<ppT>>
{
public:
    typedef libff::Fq<other_curve<ppT>> FqT;
    typedef libff::Fqe<other_curve<ppT>> FqeT;

    bls12_377_G2_proj<ppT> _in_R;
    bls12_377_G2_proj<ppT> _out_R;
    bls12_377_ate_ell_coeffs<ppT> _out_coeffs;

    // TODO: Many of these intermediate Fqe_variables are only for clarity and
    // replicate the references held by other gadgets (e.g. `A` refers to the
    // same variable as `check_A.result`. Do an optimization pass and remove
    // some of the redundancy.

    // A = R.X * R.Y / 2
    Fqe_mul_gadget<ppT> _A;

    // B = R.Y^2
    Fqe_sqr_gadget<ppT> _B;

    // C = R.Z^2
    Fqe_sqr_gadget<ppT> _C;

    // D = 3 * C
    Fqe_variable<ppT> _D;

    // E = b' * D
    Fqe_variable<ppT> _E;

    // F = 3 * E
    Fqe_variable<ppT> _F;

    // G = (B + F) / 2

    // ell_vw = -H
    //   where
    //     H = (Y + 2) ^ 2 - (B + C)
    // ell_vw = (B+C) - (Y+2)^2
    // <=> (Y+2)^2 [H] = ell_vw - B - C
    Fqe_sqr_gadget<ppT> _Y_plus_Z_squared;

    // I = E - B

    // ell_vv = 3 * J
    //   where
    //     J = Rx^2
    // ell_vv = 3 * Rx^2
    // <=> Rx^2 [J] = ell_vv * 3^{-1}
    Fqe_sqr_gadget<ppT> _J; // Rx^2 == J

    // out_R.X = A * (B - F)
    Fqe_mul_gadget<ppT> _check_out_Rx;

    // out_R.Y = G^2 - 3 * E^2
    // <=> G^2 = outRy + 3*E^2
    Fqe_sqr_gadget<ppT> _E_squared;
    Fqe_sqr_gadget<ppT> _G_squared;

    // out_R.Z = B * H
    Fqe_mul_gadget<ppT> _check_out_Rz;

    bls12_377_ate_dbl_gadget(
        libsnark::protoboard<FqT> &pb,
        const bls12_377_G2_proj<ppT> &R,
        const bls12_377_G2_proj<ppT> &out_R,
        const bls12_377_ate_ell_coeffs<ppT> &coeffs,
        const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename ppT>
class bls12_377_ate_add_gadget : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    typedef libff::Fq<other_curve<ppT>> FqT;
    typedef libff::Fqe<other_curve<ppT>> FqeT;

    Fqe_variable<ppT> _Q_X;
    Fqe_variable<ppT> _Q_Y;
    bls12_377_G2_proj<ppT> _in_R;
    bls12_377_G2_proj<ppT> _out_R;
    bls12_377_ate_ell_coeffs<ppT> _out_coeffs;

    // ell_vv = -theta
    //   where
    //     theta = R.Y - A
    //     A = Q_Y * R.Z;
    // <=> A = Q_Y * R.Z = ell_vv + Ry
    Fqe_mul_gadget<ppT> _A;
    // ell_vw = lambda
    //   where
    //     lambda = R.X - B
    //     B = Q_X * R.Z
    // <=> B = Q_X * R.Z = R.X - ell_vw
    Fqe_mul_gadget<ppT> _B;
    // theta = R.Y - A = -ell_vv
    // Fqe_variable<ppT> _theta
    // lambda = R.X - B = ell_vw
    // Fqe_variable<ppT> lambda
    // C = theta.squared() = ell_vv^2
    Fqe_sqr_gadget<ppT> _C;
    // D = lambda.squared() = ell_vw^2
    Fqe_sqr_gadget<ppT> _D;
    // E = lambda * D;
    Fqe_mul_gadget<ppT> _E;
    // F = R.Z * C;
    Fqe_mul_gadget<ppT> _F;
    // G = R.X * D;
    Fqe_mul_gadget<ppT> _G;
    // H = E + F - (G + G);
    Fqe_variable<ppT> _H;
    // I = R.Y * E;
    Fqe_mul_gadget<ppT> _I;
    // out_coeffs.ell_0 = xi * J
    //   where
    //     J = theta * Q_X - lambda * Q_Y
    // <=> lambda * Q_Y = theta * Q_X - ell_0 * xi^{-1}
    Fqe_mul_gadget<ppT> _theta_times_Qx;
    Fqe_mul_gadget<ppT> _lambda_times_Qy;

    // out_R.X = lambda * H = ell_vw * H
    Fqe_mul_gadget<ppT> _check_out_Rx;
    // out_R.Y = theta * (G - H) - I = -ell_vv * (G-H) - I
    // <=> ell_vv * (H-G) = out_R.Y + I
    Fqe_mul_gadget<ppT> _check_out_Ry;
    // out_R.Z = Z1 * E;
    Fqe_mul_gadget<ppT> _check_out_Rz;

    bls12_377_ate_add_gadget(
        libsnark::protoboard<libff::Fr<ppT>> &pb,
        const Fqe_variable<ppT> &Q_X,
        const Fqe_variable<ppT> &Q_Y,
        const bls12_377_G2_proj<ppT> &R,
        const bls12_377_G2_proj<ppT> &out_R,
        const bls12_377_ate_ell_coeffs<ppT> &coeffs,
        const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

/// Holds the relationship between an (affine) pairing parameter Q in G2, and
/// the precomputed double and add gadgets.
template<typename ppT>
class bls12_377_G2_precompute_gadget : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    using FqeT = libff::Fqe<other_curve<ppT>>;

    bls12_377_G2_proj<ppT> _R0;
    std::vector<std::shared_ptr<bls12_377_G2_proj<ppT>>> _R;
    std::vector<std::shared_ptr<bls12_377_ate_dbl_gadget<ppT>>> _ate_dbls;
    std::vector<std::shared_ptr<bls12_377_ate_add_gadget<ppT>>> _ate_adds;

    bls12_377_G2_precompute_gadget(
        libsnark::protoboard<libff::Fr<ppT>> &pb,
        const libsnark::G2_variable<ppT> &Q,
        bls12_377_G2_precomputation<ppT> &Q_prec,
        const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

/// Given some current f in Fqk, the pairing parameter P in G1, and the
/// precomputed coefficients for the function of some line function ell(),
/// compute:
///   f * ell(P)
/// Note that this gadget allocates the variable to hold the resulting value of
/// f.
template<typename ppT>
class bls12_377_ate_compute_f_ell_P : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    using FieldT = libff::Fr<ppT>;
    using FqkT = libff::Fqk<other_curve<ppT>>;

    Fqe_mul_by_lc_gadget<ppT> _ell_vv_times_Px;
    Fqe_mul_by_lc_gadget<ppT> _ell_vw_times_Py;
    Fp12_2over3over2_mul_by_024_gadget<FqkT> _f_mul_ell_P;

    bls12_377_ate_compute_f_ell_P(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_linear_combination<FieldT> &Px,
        const libsnark::pb_linear_combination<FieldT> &Py,
        const bls12_377_ate_ell_coeffs<ppT> &ell_coeffs,
        const Fp12_2over3over2_variable<FqkT> &f,
        const Fp12_2over3over2_variable<FqkT> &f_out,
        const std::string &annotation_prefix);

    const Fp12_2over3over2_variable<FqkT> &result() const;
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename ppT>
class bls12_377_miller_loop_gadget : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    using FieldT = libff::Fr<ppT>;
    using FqeT = libff::Fqe<other_curve<ppT>>;
    using FqkT = libff::Fqk<other_curve<ppT>>;
    using Fq6T = typename FqkT::my_Fp6;

    Fp12_2over3over2_variable<FqkT> _f0;

    // Squaring of f
    std::vector<std::shared_ptr<Fp12_2over3over2_square_gadget<FqkT>>>
        _f_squared;

    // f * ell(P) (for both double and add steps)
    std::vector<std::shared_ptr<bls12_377_ate_compute_f_ell_P<ppT>>> _f_ell_P;

    bls12_377_miller_loop_gadget(
        libsnark::protoboard<FieldT> &pb,
        const bls12_377_G1_precomputation<ppT> &prec_P,
        const bls12_377_G2_precomputation<ppT> &prec_Q,
        const Fqk_variable<ppT> &result,
        const std::string &annotation_prefix);

    const Fp12_2over3over2_variable<FqkT> &result() const;
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename ppT>
class bls12_377_final_exp_first_part_gadget
    : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    using FieldT = libff::Fr<ppT>;
    using FqkT = libff::Fqk<other_curve<ppT>>;

    // Follows the implementation used in
    // libff::bls12_377_final_exponentiation_first_chunk() (see
    // clearmatics/libff/libff/algebra/curves/bls12_377/bls12_377_pairing.cpp),
    // which in turn follows:
    //   https://eprint.iacr.org/2016/130.pdf

    Fp12_2over3over2_variable<FqkT> _in;
    Fp12_2over3over2_variable<FqkT> _result;

    // A = elt^(q^6)
    // B = elt^(-1)
    Fp12_2over3over2_inv_gadget<FqkT> _B;
    // C = A * B = elt^(q^6 - 1)
    Fp12_2over3over2_mul_gadget<FqkT> _C;
    // D = C^(q^2) = elt^((q^6 - 1) * (q^2))
    // result = D * C = elt^((q^6 - 1) * (q^2 + 1))
    Fp12_2over3over2_mul_gadget<FqkT> _D_times_C;

    bls12_377_final_exp_first_part_gadget(
        libsnark::protoboard<FieldT> &pb,
        const Fp12_2over3over2_variable<FqkT> &in,
        const Fp12_2over3over2_variable<FqkT> &result,
        const std::string &annotation_prefix);

    const Fp12_2over3over2_variable<FqkT> &result() const;
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename ppT>
class bls12_377_exp_by_z_gadget : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    using FieldT = libff::Fr<ppT>;
    using FqkT = libff::Fqk<other_curve<ppT>>;
    using cyclotomic_square = Fp12_2over3over2_cyclotomic_square_gadget<FqkT>;
    using multiply = Fp12_2over3over2_mul_gadget<FqkT>;
    using unitary_inverse = Fp12_2over3over2_cyclotomic_square_gadget<FqkT>;

    Fp12_2over3over2_variable<FqkT> _in;
    Fp12_2over3over2_variable<FqkT> _result;
    std::vector<std::shared_ptr<cyclotomic_square>> _squares;
    std::vector<std::shared_ptr<multiply>> _multiplies;
    std::shared_ptr<unitary_inverse> _inverse;

    bls12_377_exp_by_z_gadget(
        libsnark::protoboard<FieldT> &pb,
        const Fp12_2over3over2_variable<FqkT> &in,
        const Fp12_2over3over2_variable<FqkT> &result,
        const std::string &annotation_prefix);

    const Fp12_2over3over2_variable<FqkT> &result() const;
    void generate_r1cs_constraints();
    void generate_r1cs_witness();

private:
    void initialize_z_neg(
        libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix);
    void initialize_z_pos(
        libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix);
};

template<typename ppT>
class bls12_377_final_exp_last_part_gadget
    : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    using FieldT = libff::Fr<ppT>;
    using FqkT = libff::Fqk<other_curve<ppT>>;

    // Based on the implementation of
    // libff::bls12_377_final_exponentiation_last_chunk() (see
    // clearmatics/libff/libff/algebra/curves/bls12_377/bls12_377_pairing.cpp),
    // which follows Algorithm 1 described in Table 1 of
    // https://eprint.iacr.org/2016/130.pdf

    Fp12_2over3over2_variable<FqkT> _in;
    Fp12_2over3over2_variable<FqkT> _result;

    Fp12_2over3over2_cyclotomic_square_gadget<FqkT> _in_squared;
    bls12_377_exp_by_z_gadget<ppT> _B;
    Fp12_2over3over2_square_gadget<FqkT> _C;
    Fp12_2over3over2_mul_gadget<FqkT> _D;
    bls12_377_exp_by_z_gadget<ppT> _E;
    bls12_377_exp_by_z_gadget<ppT> _F;
    bls12_377_exp_by_z_gadget<ppT> _G;
    Fp12_2over3over2_mul_gadget<FqkT> _H;
    bls12_377_exp_by_z_gadget<ppT> _I;
    Fp12_2over3over2_mul_gadget<FqkT> _K;
    Fp12_2over3over2_mul_gadget<FqkT> _L;
    Fp12_2over3over2_mul_gadget<FqkT> _N;
    Fp12_2over3over2_mul_gadget<FqkT> _P;
    Fp12_2over3over2_mul_gadget<FqkT> _R;
    Fp12_2over3over2_mul_gadget<FqkT> _T;
    Fp12_2over3over2_mul_gadget<FqkT> _U;
    Fp12_2over3over2_mul_gadget<FqkT> _U_times_L;

    bls12_377_final_exp_last_part_gadget(
        libsnark::protoboard<FieldT> &pb,
        const Fp12_2over3over2_variable<FqkT> &in,
        const Fp12_2over3over2_variable<FqkT> &result,
        const std::string &annotation_prefix);

    const Fp12_2over3over2_variable<FqkT> &result() const;
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

// Wrapper around final_exp gadgets with interface expected by the groth16
// gadgets. `result_is_one` is constrained to a boolean (0 or 1), and set in
// 'generate_r1cs_witness' based on the output value of the final
// exponentiation (if final exp == 1, `result_is_one` is set to 1, otherwise
// `result_is_one` is set to 0).
//
// Note that the constraints on the final exp output are ONLY enforced when
// `result_is_one` == 1. In otherwords, it is infeasible to generate valid
// inputs such that the final exp output is not equal to 1 and result_is_one ==
// 1. However, it IS possible to generate inputs such that final_exp == 1 but
// `result_is_one` == 0.
template<typename ppT>
class bls12_377_final_exp_gadget : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    using FieldT = libff::Fr<ppT>;
    using FqkT = libff::Fqk<other_curve<ppT>>;

    bls12_377_final_exp_first_part_gadget<ppT> _first_part;
    bls12_377_final_exp_last_part_gadget<ppT> _last_part;
    libsnark::pb_variable<FieldT> _result_is_one;

    bls12_377_final_exp_gadget(
        libsnark::protoboard<libff::Fr<ppT>> &pb,
        const Fp12_2over3over2_variable<FqkT> &el,
        const libsnark::pb_variable<FieldT> &result_is_one,
        const std::string &annotation_prefix);
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename ppT>
class bls12_377_e_times_e_times_e_over_e_miller_loop_gadget
    : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    using FieldT = libff::Fr<ppT>;
    using FqkT = libff::Fqk<other_curve<ppT>>;

    Fp12_2over3over2_variable<FqkT> _f0;
    libsnark::pb_linear_combination<FieldT> _minus_P4_Y;

    // Squaring of f
    std::vector<std::shared_ptr<Fp12_2over3over2_square_gadget<FqkT>>>
        _f_squared;

    // f * ell(P) (for both double and add steps)
    std::vector<std::shared_ptr<bls12_377_ate_compute_f_ell_P<ppT>>> _f_ell_P;

    bls12_377_e_times_e_times_e_over_e_miller_loop_gadget(
        libsnark::protoboard<libff::Fr<ppT>> &pb,
        const bls12_377_G1_precomputation<ppT> &P1_prec,
        const bls12_377_G2_precomputation<ppT> &Q1_prec,
        const bls12_377_G1_precomputation<ppT> &P2_prec,
        const bls12_377_G2_precomputation<ppT> &Q2_prec,
        const bls12_377_G1_precomputation<ppT> &P3_prec,
        const bls12_377_G2_precomputation<ppT> &Q3_prec,
        const bls12_377_G1_precomputation<ppT> &P4_prec,
        const bls12_377_G2_precomputation<ppT> &Q4_prec,
        const Fp12_2over3over2_variable<FqkT> &result,
        const std::string &annotation_prefix);
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

} // namespace libzecale

#include "libzecale/circuits/pairing/bls12_377_pairing.tcc"

#endif // __ZECALE_CIRCUITS_PAIRING_BLS12_377_PAIRING_HPP__
