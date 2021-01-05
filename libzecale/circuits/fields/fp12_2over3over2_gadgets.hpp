// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

/// Reference
/// \[DOSD06]
///  "Multiplication and Squaring on Pairing-Friendly Fields"
///  Devegili, OhEig, Scott and Dahab,
///  IACR Cryptology ePrint Archive 2006, <https://eprint.iacr.org/2006/471.pdf>

#ifndef __ZECALE_CIRCUITS_FIELDS_FP12_2OVER3OVER2_GADGETS_HPP__
#define __ZECALE_CIRCUITS_FIELDS_FP12_2OVER3OVER2_GADGETS_HPP__

#include "libzecale/circuits/fields/fp6_3over2_gadgets.hpp"

namespace libzecale
{

template<typename Fp12T>
class Fp12_2over3over2_variable : public libsnark::gadget<typename Fp12T::my_Fp>
{
public:
    using FieldT = typename Fp12T::my_Fp;
    using Fp6T = typename Fp12T::my_Fp6;
    using Fp2T = typename Fp12T::my_Fp2;

    Fp6_3over2_variable<Fp6T> _c0;
    Fp6_3over2_variable<Fp6T> _c1;

    Fp12_2over3over2_variable(
        libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix);
    Fp12_2over3over2_variable(
        libsnark::protoboard<FieldT> &pb,
        const Fp12T &el,
        const std::string &annotation_prefix);
    Fp12_2over3over2_variable(
        libsnark::protoboard<FieldT> &pb,
        const Fp6_3over2_variable<Fp6T> &c0,
        const Fp6_3over2_variable<Fp6T> &c1,
        const std::string &annotation_prefix);

    Fp12_2over3over2_variable<Fp12T> operator*(const Fp2T &fp2_const) const;
    Fp12_2over3over2_variable<Fp12T> frobenius_map(size_t power) const;
    Fp12_2over3over2_variable<Fp12T> unitary_inverse() const;
    void evaluate() const;
    void generate_r1cs_witness(const Fp12T &el);
    Fp12T get_element() const;
};

/// Multiply an element in Fq6 by Fq12::non_residue. Let c = c0 + c1 * v +
/// c2 * v^2 be an element of Fq6T, where v is a root of:
///   v^3 - Fq6::non_residue
/// Return c * v.
///
/// Note, this simplification does not save any complexity in the final
/// circuit since Fp6_3over2_variable::operator*(const Fp6T &)
/// (multiplication by a constant) can be implemented as linear
/// combinations.
template<typename Fp12T>
Fp6_3over2_variable<typename Fp12T::my_Fp6> fp6_mul_by_non_residue(
    libsnark::protoboard<typename Fp12T::my_Fp> &pb,
    const Fp6_3over2_variable<typename Fp12T::my_Fp6> &c,
    const std::string &annotation_prefix);

/// Let c = c0 + c1 * v + c2 * v^2 be an element of Fq6T, where v is a root of:
///   v^3 - Fq6::non_residue
/// and v is used as Fp12::non_residue.
/// Return c * v^{-1} (= c * Fp12::non_residue^{-1})
template<typename Fp12T>
Fp6_3over2_variable<typename Fp12T::my_Fp6> fp6_mul_by_non_residue_inverse(
    libsnark::protoboard<typename Fp12T::my_Fp> &pb,
    const Fp6_3over2_variable<typename Fp12T::my_Fp6> &c,
    const std::string &annotation_prefix);

/// Follows implementation in libff::Fp12_2over3over2_model, which is based on
/// Section 3 of [DOSD06].
///
/// Let (a0, a1) = a0 + a1 * w be an element of Fp12, where a0, a1 in Fp6 and
/// w = v^2 for v in Fp6. By simple expansion of terms:
///   (a0, a1)^2 = (a0^2 + a1^2 * v, 2 * a0 * a1)
/// However, since
///   a0^2 + a1^2 * v = (a0 + a1)*(a0 + a1 * v) - (a0 * a1) * v - a0 * a1,
/// it follows that (a0, a1)^2 can be computed with just 2 full multiplications
/// in Fp6. (Note that multiplications by v are free in an arithmetic circuit -
/// see mul_by_non_residue).
template<typename Fp12T>
class Fp12_2over3over2_square_gadget
    : public libsnark::gadget<typename Fp12T::my_Fp>
{
public:
    using FieldT = typename Fp12T::my_Fp;
    using Fp6T = typename Fp12T::my_Fp6;

    // Let
    //
    //     \alpha = _A.c0 * _A.c1, and
    //     \beta = (_A.c0 + _A.c1)*(_A.c0 + v*_A.c1)
    //
    // then (by the above optimization), we have
    //
    //     _result.c1 = 2 * \alpha
    //       <=>  _alpha = _result.c1 * 2.inverse()
    //
    //     _result.c0 = \beta - \alpha * v - \alpha
    //       <=>  \beta = _result.c0 + \alpha * v - \alpha
    Fp12_2over3over2_variable<Fp12T> _A;
    Fp12_2over3over2_variable<Fp12T> _result;
    Fp6_3over2_mul_gadget<Fp6T> _compute_alpha;
    Fp6_3over2_mul_gadget<Fp6T> _compute_beta;

    Fp12_2over3over2_square_gadget(
        libsnark::protoboard<FieldT> &pb,
        const Fp12_2over3over2_variable<Fp12T> &A,
        const Fp12_2over3over2_variable<Fp12T> &result,
        const std::string &annotation_prefix);

    const Fp12_2over3over2_variable<Fp12T> &result() const;
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

/// Optimal multiplication in Fp12 of z = ((z0, z1, z2), (z3, z4, z5)), by some
/// sparse x = ((x0, 0, x2), (0, x4, 0)). Follows the structure of
/// libff::Fp12_2over3over2<Fp12T>::mul_by_024 (See
/// libff/algebra/fields/fp12_2over3over2.tcc).
template<typename Fp12T>
class Fp12_2over3over2_mul_by_024_gadget
    : public libsnark::gadget<typename Fp12T::my_Fp>
{
public:
    using FieldT = typename Fp12T::my_Fp;
    using Fp6T = typename Fp12T::my_Fp6;
    using Fp2T = typename Fp12T::my_Fp2;

    Fp12_2over3over2_variable<Fp12T> _Z;
    libsnark::Fp2_variable<Fp2T> _X_0;
    libsnark::Fp2_variable<Fp2T> _X_2;
    libsnark::Fp2_variable<Fp2T> _X_4;

    // out_z0 = z0*x0 + non_residue * (z1*x2 + z4*x4)
    libsnark::Fp2_mul_gadget<Fp2T> _compute_z1_x2;
    libsnark::Fp2_mul_gadget<Fp2T> _compute_z4_x4;
    libsnark::Fp2_mul_gadget<Fp2T> _compute_z0_x0;

    // out_z1 = z1*x0 + non_residue * (z2*x2 + z5*x4)
    libsnark::Fp2_mul_gadget<Fp2T> _compute_z2_x2;
    libsnark::Fp2_mul_gadget<Fp2T> _compute_z5_x4;
    libsnark::Fp2_mul_gadget<Fp2T> _compute_z1_x0;

    // out_z2 = z0*x2 + z2*x0 + z3*x4
    libsnark::Fp2_mul_gadget<Fp2T> _compute_z3_x4;
    libsnark::Fp2_mul_gadget<Fp2T> _compute_z02_x02;

    // out_z3 = z3*x0 + non_residue * (z2*x4 + z4*x2)
    libsnark::Fp2_mul_gadget<Fp2T> _compute_z3_x0;
    libsnark::Fp2_mul_gadget<Fp2T> _compute_z24_x24;

    // out_z4 = z0*x4 + z4*x0 + non_residue * z5*x2
    libsnark::Fp2_mul_gadget<Fp2T> _compute_z5_x2;
    libsnark::Fp2_mul_gadget<Fp2T> _compute_z04_x04;

    // S = z1_x0 - z1_x2 - z3_x0 - z3*x4 - z5_x2 - z5*x4
    // out_z5 = z1*x4 + z3*x2 + z5*x0
    //        = (z1 + z3 + z5)*(x0 + x2 + x4) - S
    // => (z1 + z3 + z5)*(x0 + x2 + x4) = out_z5 + S
    libsnark::Fp2_variable<Fp2T> _S;
    libsnark::Fp2_mul_gadget<Fp2T> _compute_out_z5_plus_S;

    Fp12_2over3over2_variable<Fp12T> _result;

    Fp12_2over3over2_mul_by_024_gadget(
        libsnark::protoboard<FieldT> &pb,
        const Fp12_2over3over2_variable<Fp12T> &A,
        const libsnark::Fp2_variable<Fp2T> &B_ell_0,
        const libsnark::Fp2_variable<Fp2T> &B_ell_vv,
        const libsnark::Fp2_variable<Fp2T> &B_ell_vw,
        const Fp12_2over3over2_variable<Fp12T> &result,
        const std::string &annotation_prefix);

    const Fp12_2over3over2_variable<Fp12T> &result() const;
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

/// Full multiplication of Fp12 variables.
template<typename Fp12T>
class Fp12_2over3over2_mul_gadget
    : public libsnark::gadget<typename Fp12T::my_Fp>
{
public:
    using FieldT = typename Fp12T::my_Fp;
    using Fp6T = typename Fp12T::my_Fp6;

    Fp12_2over3over2_variable<Fp12T> _A;
    Fp12_2over3over2_variable<Fp12T> _B;
    Fp12_2over3over2_variable<Fp12T> _result;
    Fp6_3over2_mul_gadget<Fp6T> _compute_v0;
    Fp6_3over2_mul_gadget<Fp6T> _compute_v1;
    Fp6_3over2_mul_gadget<Fp6T> _compute_a0_plus_a1_times_b0_plus_b1;

    Fp12_2over3over2_mul_gadget(
        libsnark::protoboard<FieldT> &pb,
        const Fp12_2over3over2_variable<Fp12T> &A,
        const Fp12_2over3over2_variable<Fp12T> &B,
        const Fp12_2over3over2_variable<Fp12T> &result,
        const std::string &annotation_prefix);
    const Fp12_2over3over2_variable<Fp12T> &result() const;
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

/// Inverse of Fp12 variable
template<typename Fp12T>
class Fp12_2over3over2_inv_gadget
    : public libsnark::gadget<typename Fp12T::my_Fp>
{
public:
    using FieldT = typename Fp12T::my_Fp;
    using Fp2T = typename Fp12T::my_Fp2;
    using Fp6T = typename Fp12T::my_Fp6;

    Fp12_2over3over2_variable<Fp12T> _A;
    Fp12_2over3over2_variable<Fp12T> _result;
    Fp12_2over3over2_mul_gadget<Fp12T> _compute_A_times_result;

    Fp12_2over3over2_inv_gadget(
        libsnark::protoboard<FieldT> &pb,
        const Fp12_2over3over2_variable<Fp12T> &A,
        const Fp12_2over3over2_variable<Fp12T> &result,
        const std::string &annotation_prefix);
    const Fp12_2over3over2_variable<Fp12T> &result() const;
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename Fp12T>
class Fp12_2over3over2_cyclotomic_square_gadget
    : public libsnark::gadget<typename Fp12T::my_Fp>
{
public:
    using FieldT = typename Fp12T::my_Fp;
    using Fp2T = typename Fp12T::my_Fp2;
    using Fp6T = typename Fp12T::my_Fp6;

    Fp12_2over3over2_variable<Fp12T> _A;
    Fp12_2over3over2_variable<Fp12T> _result;

    // Follows the implementation of
    // libff::Fp12_2over3over2::cyclotomic_squared(), see
    // libff/algebra/fields/fp12_2over3over2.tcc

    // result4 = 6 * z0z4 + 2 * z4
    // <=> z0z4 = 6^{-1} * (result4 - 2*z4)
    libsnark::Fp2_mul_gadget<Fp2T> _compute_z0z4;

    // result0 = 3*t0_L - 3*t0_R - 2*z0
    //   where
    //     t0_L = (z0 + z4) * (z0 + non_residue * z4)
    //     t0_R = z0z4 * (my_Fp2::one() + my_Fp6::non_residue)
    // <=> 3*(z0 + z4) * (z0 + non_residue * z4)
    //       = result0 + 3*(1 + non_residue)*z0z4 + 2*z0
    libsnark::Fp2_mul_gadget<Fp2T> _check_result_0;

    // result5 = 6 * z3z2 + 2 * z5
    // <=> z3z2 = 6^{-1} * (result5 - 2*z5)
    libsnark::Fp2_mul_gadget<Fp2T> _compute_z3z2;

    // result1 = 3*t2_L - 3*t2_R - 2*z1
    //   where
    //     t2_L = (z3 + z2) * (z3 + non_residue * z2)
    //     t2_R = z3z2 * (1 + non_residue)
    // <=> 3*(z3 + z2)*(z3 + non_residue * z2)
    //       = result1 + 3*(1 + non_residue)*_z3z2 + 2*z1
    libsnark::Fp2_mul_gadget<Fp2T> _check_result_1;

    // result3 = 6 * non_residue * z1z5 + 2*z3
    // <=> z1z5 = 6^{-1} * non_residue^{-1} * (out3 - 2*z3)
    libsnark::Fp2_mul_gadget<Fp2T> _compute_z1z5;

    // result2 = 3*t4_L - 3*t4_R - 2*z2
    //   where
    //     t4_L = (z1 + z5) * (z1 + non_residue * z5)
    //     t4_R = z1z5 * (1 + non_residue);
    // <=> 3*(z1 + z5)*(z1 + non_residue * z5)
    //       = result2 + 3*(1 + non_residue)*z1z5 + 2*z2
    libsnark::Fp2_mul_gadget<Fp2T> _check_result_2;

    Fp12_2over3over2_cyclotomic_square_gadget(
        libsnark::protoboard<FieldT> &pb,
        const Fp12_2over3over2_variable<Fp12T> &A,
        const Fp12_2over3over2_variable<Fp12T> &result,
        const std::string &annotation_prefix);

    const Fp12_2over3over2_variable<Fp12T> &result() const;
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

} // namespace libzecale

#include "libzecale/circuits/fields/fp12_2over3over2_gadgets.tcc"

#endif // __ZECALE_CIRCUITS_FIELDS_FP12_2OVER3OVER2_GADGETS_HPP__
