// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_FIELDS_FP6_3OVER2_GADGETS_HPP__
#define __ZECALE_CIRCUITS_FIELDS_FP6_3OVER2_GADGETS_HPP__

#include <libff/algebra/curves/public_params.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/fields/fp2_gadgets.hpp>

namespace libzecale
{

template<typename Fp6T>
class Fp6_3over2_variable : public libsnark::gadget<typename Fp6T::my_Fp>
{
public:
    using FieldT = typename Fp6T::my_Fp;
    using Fp2T = typename Fp6T::my_Fp2;

    libsnark::Fp2_variable<Fp2T> _c0;
    libsnark::Fp2_variable<Fp2T> _c1;
    libsnark::Fp2_variable<Fp2T> _c2;

    Fp6_3over2_variable(
        libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix);

    Fp6_3over2_variable(
        libsnark::protoboard<FieldT> &pb,
        const Fp6_3over2_variable<Fp6T> &el,
        const std::string &annotation_prefix);

    Fp6_3over2_variable(
        libsnark::protoboard<FieldT> &pb,
        const Fp6T &el,
        const std::string &annotation_prefix);

    Fp6_3over2_variable(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::Fp2_variable<Fp2T> &c0,
        const libsnark::Fp2_variable<Fp2T> &c1,
        const libsnark::Fp2_variable<Fp2T> &c2,
        const std::string &annotation_prefix);

    Fp6_3over2_variable<Fp6T> operator*(const FieldT &scalar) const;
    Fp6_3over2_variable<Fp6T> operator*(const Fp2T &fp2_constant) const;
    Fp6_3over2_variable<Fp6T> operator*(const Fp6T &fp6_constant) const;
    Fp6_3over2_variable<Fp6T> operator+(
        const Fp6_3over2_variable<Fp6T> &other) const;
    Fp6_3over2_variable<Fp6T> operator-(
        const Fp6_3over2_variable<Fp6T> &other) const;
    Fp6_3over2_variable<Fp6T> operator-() const;
    Fp6_3over2_variable<Fp6T> frobenius_map(size_t power) const;

    void evaluate() const;
    void generate_r1cs_witness(const Fp6T &el);
    Fp6T get_element() const;
};

// Follows implementation in libff::Fp6_3over2_model, based on Devegili OhEig
// Scott Dahab "Multiplication and Squaring on Pairing-Friendly Fields";
// Section 4 (Karatsuba).
//
// For elements a=(a0, a1, a2) and b=(b0, b1, b2) in Fp6, c=a*b can be written
// as:
//
//   c = (
//     v0 + non_residue*((a1 + a2)(b1 + b2) - v1 - v2),
//     (a0 + a1)(b0 + b1) - v0 - v1 + non_residue * v2,
//     (a0 + a2)(b0 + b2) - v0 - v2 + v1)
//
// where
//   v0 = a0*b0
//   v1 = a1*b1
//   v2 = a2*b2
// and non_residue is the element in Fp2 in the function v^3 - non_residue used
// to define Fp6.
template<typename Fp6T>
class Fp6_3over2_mul_gadget : public libsnark::gadget<typename Fp6T::my_Fp>
{
public:
    using FieldT = typename Fp6T::my_Fp;
    using Fp2T = typename Fp6T::my_Fp2;

    Fp6_3over2_variable<Fp6T> _A;
    Fp6_3over2_variable<Fp6T> _B;
    Fp6_3over2_variable<Fp6T> _result;

    // These conditions follow from the above expressions for c0, c1, c2:
    //  v0 = c0 - non_residue*((a1 + a2)(b1 + b2) - v1 - v2)
    //  (a0 + a1)(b0 + b1) = c1 + v0 + v1 - non_residue * v2
    //  (a0 + a2)(b0 + b2) = c2 + v0 + v2 - v1

    libsnark::Fp2_mul_gadget<Fp2T> _compute_v1;
    libsnark::Fp2_mul_gadget<Fp2T> _compute_v2;
    libsnark::Fp2_mul_gadget<Fp2T> _compute_a1a2_times_b1b2;
    libsnark::Fp2_mul_gadget<Fp2T> _compute_v0;
    libsnark::Fp2_mul_gadget<Fp2T> _compute_a0a1_times_b0b1;
    libsnark::Fp2_mul_gadget<Fp2T> _compute_a0a2_times_b0b2;

    Fp6_3over2_mul_gadget(
        libsnark::protoboard<FieldT> &pb,
        const Fp6_3over2_variable<Fp6T> &A,
        const Fp6_3over2_variable<Fp6T> &B,
        const Fp6_3over2_variable<Fp6T> &result,
        const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

} // namespace libzecale

#include "libzecale/circuits/fields/fp6_3over2_gadgets.tcc"

#endif // __ZECALE_CIRCUITS_FIELDS_FP6_3OVER2_GADGETS_HPP__
