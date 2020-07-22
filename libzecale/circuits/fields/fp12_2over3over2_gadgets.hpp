// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
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

    Fp12T get_element() const;
    void generate_r1cs_witness(const Fp12T &el);
};

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
    Fp6_3over2_mul_gadget<Fp6T> _alpha;
    Fp6_3over2_mul_gadget<Fp6T> _beta;

    Fp12_2over3over2_square_gadget(
        libsnark::protoboard<FieldT> &pb,
        const Fp12_2over3over2_variable<Fp12T> &A,
        const Fp12_2over3over2_variable<Fp12T> &result,
        const std::string &annotation_prefix);

    const Fp12_2over3over2_variable<Fp12T> &result() const;
    void generate_r1cs_constraints();
    void generate_r1cs_witness();

    /// Multiply an element in Fq6 by Fq12::non_residue. Let c = c0 + c1 * v +
    /// c2 * v^2 be an element of Fq6T, where v is a root of:
    ///   v^3 - Fq6::non_residue
    /// Return c * v.
    ///
    /// Note, this simplification does not save any complexity in the final
    /// circuit since Fp6_3over2_variable::operator*(const Fp6T &)
    /// (multiplication by a constant) can be implemented as linear
    /// combinations.
    static Fp6_3over2_variable<Fp6T> mul_by_non_residue(
        libsnark::protoboard<FieldT> &pb,
        const Fp6_3over2_variable<Fp6T> &c,
        const std::string &annotation_prefix);
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

    // out_z0 = z0*x0 + non_residue * ( z1*x2 + z4*x4 )
    libsnark::Fp2_mul_gadget<Fp2T> _z1_x2;
    libsnark::Fp2_mul_gadget<Fp2T> _z4_x4;
    libsnark::Fp2_mul_gadget<Fp2T> _z0_x0;

    // out_z1 = z1*x0 + non_residue * ( z2*x2 + z5*x4 )
    libsnark::Fp2_mul_gadget<Fp2T> _z2_x2;
    libsnark::Fp2_mul_gadget<Fp2T> _z5_x4;
    libsnark::Fp2_mul_gadget<Fp2T> _z1_x0;

    // out_z2 = z0*x2 + z2*x0 + z3*x4
    libsnark::Fp2_mul_gadget<Fp2T> _z3_x4;
    libsnark::Fp2_mul_gadget<Fp2T> _z02_x02;

    // out_z3 = z3*x0 + non_residue * (z2*x4 + z4*x2)
    libsnark::Fp2_mul_gadget<Fp2T> _z3_x0;
    libsnark::Fp2_mul_gadget<Fp2T> _z24_x24;

    // out_z4 = z0*x4 + z4*x0 + non_residue * z5*x2
    libsnark::Fp2_mul_gadget<Fp2T> _z5_x2;
    libsnark::Fp2_mul_gadget<Fp2T> _z04_x04;

    // S = z1_x0 - z1_x2 - z3_x0 - z3*x4 - z5_x2 - z5*x4
    // out_z5 = z1*x4 + z3*x2 + z5*x0
    //        = (z1 + z3 + z5)*(x0 + x2 + x4) - S
    libsnark::Fp2_variable<Fp2T> _S;
    libsnark::Fp2_mul_gadget<Fp2T> _z1z3z5_times_x0x2x4;

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

} // namespace libzecale

#include "libzecale/circuits/fields/fp12_2over3over2_gadgets.tcc"

#endif // __ZECALE_CIRCUITS_FIELDS_FP12_2OVER3OVER2_GADGETS_HPP__
