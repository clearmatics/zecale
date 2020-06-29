// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
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
        const Fp6_3over2_variable<Fp6T> &v,
        const std::string &annotation_prefix);

    Fp6_3over2_variable(
        libsnark::protoboard<FieldT> &pb,
        const Fp6T &v,
        const std::string &annotation_prefix);

    Fp6_3over2_variable(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::Fp2_variable<Fp2T> &c0,
        const libsnark::Fp2_variable<Fp2T> &c1,
        const libsnark::Fp2_variable<Fp2T> &c2,
        const std::string &annotation_prefix);

    Fp6_3over2_variable<Fp6T> operator*(const FieldT &);
    Fp6_3over2_variable<Fp6T> operator+(const Fp6_3over2_variable<Fp6T> &);

    void evaluate() const;
    void generate_r1cs_witness(const Fp6T &v);
    Fp6T get_element() const;
};

// Follows implementation in libff::Fp6_3over2_model, based on Devegili OhEig
// Scott Dahab "Multiplication and Squaring on Pairing-Friendly Fields";
// Section 4 (Karatsuba).
//
// For (a0, a1, a2) and (b0, b1, b2) elements in Fp6, the components of c=a*b
// can be written:
//   c = (a0*b0 + non_residue*((a1 + a2)(b1 + b2) - a1*b1 - a2*b2),
//        (a0 + a1)(b0 + b1) - a0*b0 - a1*b1 + non_residue * a2*b2,
//        (a0 + a2)(b0 + b2) - a0*b0 - a2*b2 + a1*b1)
//
// Here non-residue is the element in Fp2 in the function v^3 - non_residue
// used to define Fp6.
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
    //  a0*b0 = c0 - non_residue*((a1 + a2)(b1 + b2) - a1*b1 - a2*b2)
    //  (a0 + a1)(b0 + b1) = c1 + a0*b0 + a1*b1 - non_residue * a2*b2
    //  (a0 + a2)(b0 + b2) = c2 + a0*b0 + a2*b2 - a1*b1

    libsnark::Fp2_mul_gadget<Fp2T> _a1b1;
    libsnark::Fp2_mul_gadget<Fp2T> _a2b2;
    libsnark::Fp2_mul_gadget<Fp2T> _a1a2_times_b1b2;
    libsnark::Fp2_mul_gadget<Fp2T> _a0b0;
    libsnark::Fp2_mul_gadget<Fp2T> _a0a1_times_b0b1;
    libsnark::Fp2_mul_gadget<Fp2T> _a0a2_times_b0b2;

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