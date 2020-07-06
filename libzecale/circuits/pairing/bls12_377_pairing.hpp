// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_PAIRING_BLS12_377_PAIRING_HPP__
#define __ZECALE_CIRCUITS_PAIRING_BLS12_377_PAIRING_HPP__

#include "libzecale/circuits/fields/fp12_2over3over2_gadgets.hpp"
#include "libzecale/circuits/pairing/bw6_761_pairing_params.hpp"

#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>
#include <libsnark/gadgetlib1/gadgets/fields/fp2_gadgets.hpp>

namespace libzecale
{

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

    void evaluate() const;

    void generate_r1cs_witness(const libff::bls12_377_G2 &element);
};

/// Not a gadget - holds the variables for the Fq2 coefficients of the tangent
/// line at some R, used during the doubling step.
template<typename ppT> class bls12_377_ate_ell_coeffs
{
public:
    const Fqe_variable<ppT> ell_0;
    const Fqe_variable<ppT> ell_vw;
    const Fqe_variable<ppT> ell_vv;

    bls12_377_ate_ell_coeffs(
        const Fqe_variable<ppT> &ell_0,
        const Fqe_variable<ppT> &ell_vw,
        const Fqe_variable<ppT> &ell_vv);

    void evaluate() const;
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

    bls12_377_G2_proj<ppT> in_R;
    bls12_377_G2_proj<ppT> out_R;

    // TODO: Many of these intermediate Fqe_variables are only for clarity and
    // replicate the references held by other gadgets (e.g. `A` refers to the
    // same variable as `check_A.result`. Do an optimization pass and remove
    // some of the redundancy.

    // A = R.X * R.Y / 2
    Fqe_variable<ppT> A;
    Fqe_mul_gadget<ppT> check_A; // R.X * R.Y = 2_times_A

    // B = R.Y^2
    Fqe_variable<ppT> B;
    Fqe_sqr_gadget<ppT> check_B; // R.Y^2 == B

    // C = R.Z^2
    Fqe_variable<ppT> C;
    Fqe_sqr_gadget<ppT> check_C; // R.Z^2 == C

    // D = 3 * C
    // Fqe_variable<ppT> D;

    // E = b' * D
    Fqe_variable<ppT> E;

    // F = 3 * E
    Fqe_variable<ppT> F;

    // G = (B + F) / 2
    Fqe_variable<ppT> G;
    // Fqe_mul_by_lc_gadget<ppT> check_G; // 2 * G == B + F

    // H = (Y + 2) ^ 2 - (B + C)
    Fqe_variable<ppT> H;
    Fqe_variable<ppT> Y_plus_Z;
    Fqe_variable<ppT> H_plus_B_plus_C;
    Fqe_sqr_gadget<ppT> check_H; // Y_plus_Z^2 == H + B + C

    // I = E - B
    Fqe_variable<ppT> I;

    // J = R.X^2
    Fqe_variable<ppT> J;
    Fqe_sqr_gadget<ppT> check_J; // R.X^2 == J

    // E^2
    Fqe_variable<ppT> E_squared;
    Fqe_sqr_gadget<ppT> check_E_squared;

    // G^2
    Fqe_variable<ppT> G_squared;
    Fqe_sqr_gadget<ppT> check_G_squared;

    // B - F
    Fqe_variable<ppT> B_minus_F;

    // out_R.X = A * (B - F)
    Fqe_mul_gadget<ppT> check_out_Rx;

    // out_R.Y = G^2 - 3 * E^2
    // check: 1 * G_squared_minus_3_E_squared == outRy
    Fqe_variable<ppT> G_squared_minus_3_E_squared;
    Fqe_mul_by_lc_gadget<ppT> check_out_Ry;

    // out_R.Z = B * H
    Fqe_mul_gadget<ppT> check_out_Rz;

    // ell_0 = xi * I
    // ell_vw = -H
    // ell_vv = 3 * J
    bls12_377_ate_ell_coeffs<ppT> out_coeffs;

    bls12_377_ate_dbl_gadget(
        libsnark::protoboard<FqT> &pb,
        const bls12_377_G2_proj<ppT> &R,
        const std::string &annotation_prefix);

    void generate_r1cs_constraints();

    // R should already be assigned. Computes all internal values and
    // outResult.
    void generate_r1cs_witness(const libff::Fr<ppT> &two_inv);
};

template<typename ppT>
class bls12_377_ate_add_gadget : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    typedef libff::Fq<other_curve<ppT>> FqT;
    typedef libff::Fqe<other_curve<ppT>> FqeT;

    Fqe_variable<ppT> Q_X;
    Fqe_variable<ppT> Q_Y;
    bls12_377_G2_proj<ppT> in_R;

    // A = Q_Y * R.Z;
    Fqe_variable<ppT> A;
    Fqe_mul_gadget<ppT> check_A;
    // B = Q_X * R.Z;
    Fqe_variable<ppT> B;
    Fqe_mul_gadget<ppT> check_B;
    // theta = R.Y - A;
    Fqe_variable<ppT> theta;
    // lambda = R.X - B;
    Fqe_variable<ppT> lambda;
    // C = theta.squared();
    Fqe_variable<ppT> C;
    Fqe_sqr_gadget<ppT> check_C;
    // D = lambda.squared();
    Fqe_variable<ppT> D;
    Fqe_sqr_gadget<ppT> check_D;
    // E = lambda * D;
    Fqe_variable<ppT> E;
    Fqe_mul_gadget<ppT> check_E;
    // F = R.Z * C;
    Fqe_variable<ppT> F;
    Fqe_mul_gadget<ppT> check_F;
    // G = R.X * D;
    Fqe_variable<ppT> G;
    Fqe_mul_gadget<ppT> check_G;
    // H = E + F - (G + G);
    Fqe_variable<ppT> H;
    // I = R.Y * E;
    Fqe_variable<ppT> I;
    Fqe_mul_gadget<ppT> check_I;
    // J = theta * Q_X - lambda * Q_Y;
    Fqe_variable<ppT> theta_times_Qx;
    Fqe_mul_gadget<ppT> check_theta_times_Qx;
    Fqe_variable<ppT> lambda_times_Qy;
    Fqe_mul_gadget<ppT> check_lambda_times_Qy;
    Fqe_variable<ppT> J;

    // out_R.X = lambda * H;
    Fqe_variable<ppT> out_Rx;
    Fqe_mul_gadget<ppT> check_out_Rx;
    // out_R.Y = theta * (G - H) - I;
    Fqe_variable<ppT> G_minus_H;
    Fqe_variable<ppT> theta_times_G_minus_H;
    Fqe_mul_gadget<ppT> check_theta_times_G_minus_H;
    // out_R.Z = Z1 * E;
    Fqe_variable<ppT> out_Rz;
    Fqe_mul_gadget<ppT> check_out_Rz;

    bls12_377_G2_proj<ppT> out_R;

    // out_coeffs.ell_0 = xi * J;
    // out_coeffs.ell_vw = lambda;
    // out_coeffs.ell_vv = -theta;
    bls12_377_ate_ell_coeffs<ppT> out_coeffs;

    bls12_377_ate_add_gadget(
        libsnark::protoboard<libff::Fr<ppT>> &pb,
        const Fqe_variable<ppT> &Q_X,
        const Fqe_variable<ppT> &Q_Y,
        const bls12_377_G2_proj<ppT> &R,
        const std::string &annotation_prefix);

    void generate_r1cs_constraints();

    void generate_r1cs_witness();
};

/// Holds the relationship between an (affine) pairing parameter Q in G2, and
/// the precomputed double and add gadgets.
template<typename ppT>
class bls12_377_ate_precompute_gadget : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    using FqeT = libff::Fqe<other_curve<ppT>>;

    Fqe_variable<ppT> _Qx;
    Fqe_variable<ppT> _Qy;
    bls12_377_G2_proj<ppT> _R0;

    std::vector<std::shared_ptr<bls12_377_ate_dbl_gadget<ppT>>> _ate_dbls;
    std::vector<std::shared_ptr<bls12_377_ate_add_gadget<ppT>>> _ate_adds;

    bls12_377_ate_precompute_gadget(
        libsnark::protoboard<libff::Fr<ppT>> &pb,
        const Fqe_variable<ppT> &Qx,
        const Fqe_variable<ppT> &Qy,
        const std::string &annotation_prefix);

    void generate_r1cs_constraints();

    /// The Qx and Qy variables passed to the constructor must have been
    /// assigned.
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
        const libsnark::pb_variable<FieldT> &Px,
        const libsnark::pb_variable<FieldT> &Py,
        const bls12_377_ate_ell_coeffs<ppT> &ell_coeffs,
        const Fp12_2over3over2_variable<FqkT> &f,
        const std::string &annotation_prefix);

    const Fp12_2over3over2_variable<FqkT> &result() const;
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename ppT>
class bls12_377_ate_miller_loop_gadget : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    using FieldT = libff::Fr<ppT>;
    using FqeT = libff::Fqe<other_curve<ppT>>;
    using FqkT = libff::Fqk<other_curve<ppT>>;
    using Fq6T = typename FqkT::my_Fp6;

    libsnark::pb_variable<FieldT> _Px;
    libsnark::pb_variable<FieldT> _Py;
    Fqe_variable<ppT> _Qx;
    Fqe_variable<ppT> _Qy;

    bls12_377_ate_precompute_gadget<ppT> _Q_precomp;
    Fp12_2over3over2_variable<FqkT> _f0;

    // Squaring of f
    std::vector<std::shared_ptr<Fp12_2over3over2_square_gadget<FqkT>>>
        _f_squared;

    // f * ell(P) (for both double and add steps)
    std::vector<std::shared_ptr<bls12_377_ate_compute_f_ell_P<ppT>>> _f_ell_P;

    bls12_377_ate_miller_loop_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable<FieldT> &PX,
        const libsnark::pb_variable<FieldT> &PY,
        const Fqe_variable<ppT> &QX,
        const Fqe_variable<ppT> &QY,
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
    // clearmatics/libff/algebra/curves/bls12_377/bls12_377_pairing.cpp), which
    // in turn follows:
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
    // clearmatics/libff/algebra/curves/bls12_377/bls12_377_pairing.cpp), which
    // follows Algorithm 1 described in Table 1 of
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

} // namespace libzecale

#include "libzecale/circuits/pairing/bls12_377_pairing.tcc"

#endif // __ZECALE_CIRCUITS_PAIRING_BLS12_377_PAIRING_HPP__
