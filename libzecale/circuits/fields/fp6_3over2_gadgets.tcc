// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_FIELDS_FP6_3OVER2_GADGETS_TCC__
#define __ZECALE_CIRCUITS_FIELDS_FP6_3OVER2_GADGETS_TCC__

#include "libzecale/circuits/fields/fp6_3over2_gadgets.hpp"

namespace libzecale
{

// Fp6_3over2_variable methods

template<typename Fp6T>
Fp6_3over2_variable<Fp6T>::Fp6_3over2_variable(
    libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , _c0(pb, FMT(annotation_prefix, " c0"))
    , _c1(pb, FMT(annotation_prefix, " c1"))
    , _c2(pb, FMT(annotation_prefix, " c2"))
{
}

template<typename Fp6T>
Fp6_3over2_variable<Fp6T>::Fp6_3over2_variable(
    libsnark::protoboard<FieldT> &pb,
    const Fp6_3over2_variable<Fp6T> &el,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , _c0(el._c0)
    , _c1(el._c1)
    , _c2(el._c2)
{
}

template<typename Fp6T>
Fp6_3over2_variable<Fp6T>::Fp6_3over2_variable(
    libsnark::protoboard<FieldT> &pb,
    const Fp6T &el,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , _c0(pb, el.c0, FMT(annotation_prefix, " c0"))
    , _c1(pb, el.c1, FMT(annotation_prefix, " c1"))
    , _c2(pb, el.c2, FMT(annotation_prefix, " c2"))
{
}

template<typename Fp6T>
Fp6_3over2_variable<Fp6T>::Fp6_3over2_variable(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::Fp2_variable<Fp2T> &c0,
    const libsnark::Fp2_variable<Fp2T> &c1,
    const libsnark::Fp2_variable<Fp2T> &c2,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix), _c0(c0), _c1(c1), _c2(c2)
{
}

template<typename Fp6T>
Fp6_3over2_variable<Fp6T> Fp6_3over2_variable<Fp6T>::operator*(
    const FieldT &scalar)
{
    return Fp6_3over2_variable<Fp6T>(
        this->pb,
        _c0 * scalar,
        _c1 * scalar,
        _c2 * scalar,
        FMT(this->annotation_prefix, " *Fp"));
}

template<typename Fp6T>
Fp6_3over2_variable<Fp6T> Fp6_3over2_variable<Fp6T>::operator+(
    const Fp6_3over2_variable<Fp6T> &other)
{
    return Fp6_3over2_variable<Fp6T>(
        this->pb,
        _c0 + other._c0,
        _c1 + other._c1,
        _c2 + other._c2,
        FMT(this->annotation_prefix.c_str(),
            " + %s",
            other.annotation_prefix.c_str()));
}

template<typename Fp6T> void Fp6_3over2_variable<Fp6T>::evaluate() const
{
    _c0.evaluate();
    _c1.evaluate();
    _c2.evaluate();
}

template<typename Fp6T>
void Fp6_3over2_variable<Fp6T>::generate_r1cs_witness(const Fp6T &el)
{
    _c0.generate_r1cs_witness(el.c0);
    _c1.generate_r1cs_witness(el.c1);
    _c2.generate_r1cs_witness(el.c2);
}

template<typename Fp6T> Fp6T Fp6_3over2_variable<Fp6T>::get_element() const
{
    return Fp6T(_c0.get_element(), _c1.get_element(), _c2.get_element());
}

// Fp6_3over2_mul_gadget methods

template<typename Fp6T>
Fp6_3over2_mul_gadget<Fp6T>::Fp6_3over2_mul_gadget(
    libsnark::protoboard<FieldT> &pb,
    const Fp6_3over2_variable<Fp6T> &A,
    const Fp6_3over2_variable<Fp6T> &B,
    const Fp6_3over2_variable<Fp6T> &result,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , _A(A)
    , _B(B)
    , _result(result)
    , _a1_times_b1(
          pb,
          A._c1,
          B._c1,
          libsnark::Fp2_variable<Fp2T>(pb, FMT(annotation_prefix, " v1")),
          FMT(annotation_prefix, " _a1_times_b1"))
    , _a2_times_b2(
          pb,
          A._c2,
          B._c2,
          libsnark::Fp2_variable<Fp2T>(pb, FMT(annotation_prefix, " v2")),
          FMT(annotation_prefix, " _a2_times_b2"))
    , _a1a2_times_b1b2(
          pb,
          A._c1 + A._c2,
          B._c1 + B._c2,
          libsnark::Fp2_variable<Fp2T>(
              pb, FMT(annotation_prefix, " (a1+a2)*(b1+b2)")),
          FMT(annotation_prefix, " _a1a2_times_b1b2"))
    // c0 = a0*b0 + non_residue*((a1 + a2)(b1 + b2) - a1*b1 - a2*b2)
    , _a0_times_b0(
          pb,
          A._c0,
          B._c0,
          _result._c0 - (_a1a2_times_b1b2.result - _a1_times_b1.result -
                         _a2_times_b2.result) *
                            Fp6T::non_residue,
          FMT(annotation_prefix, " _a0_times_b0"))
    // c1 = (a0 + a1)(b0 + b1) - a0*b0 - a1*b1 + non_residue * a2*b2
    , _a0a1_times_b0b1(
          pb,
          A._c0 + A._c1,
          B._c0 + B._c1,
          _result._c1 + _a0_times_b0.result + _a1_times_b1.result -
              _a2_times_b2.result * Fp6T::non_residue,
          FMT(annotation_prefix, " _a0a1_times_b0b1"))
    // c2 = (a0 + a2)(b0 + b2) - a0*b0 - a2*b2 + a1*b1
    , _a0a2_times_b0b2(
          pb,
          A._c0 + A._c2,
          B._c0 + B._c2,
          _result._c2 + _a0_times_b0.result + _a2_times_b2.result -
              _a1_times_b1.result,
          FMT(annotation_prefix, " _a0a2_times_b0b2"))
{
}

template<typename Fp6T>
void Fp6_3over2_mul_gadget<Fp6T>::generate_r1cs_constraints()
{
    _a1_times_b1.generate_r1cs_constraints();
    _a2_times_b2.generate_r1cs_constraints();
    _a1a2_times_b1b2.generate_r1cs_constraints();
    _a0_times_b0.generate_r1cs_constraints();
    _a0a1_times_b0b1.generate_r1cs_constraints();
    _a0a2_times_b0b2.generate_r1cs_constraints();
}

template<typename Fp6T>
void Fp6_3over2_mul_gadget<Fp6T>::generate_r1cs_witness()
{
    const Fp2T a0 = _A._c0.get_element();
    const Fp2T a1 = _A._c1.get_element();
    const Fp2T a2 = _A._c2.get_element();
    const Fp2T b0 = _B._c0.get_element();
    const Fp2T b1 = _B._c1.get_element();
    const Fp2T b2 = _B._c2.get_element();

    // c0 = v1 + non_residue*((a1 + a2)(b1 + b2) - v1 - v2)
    _a1_times_b1.generate_r1cs_witness();
    const Fp2T v1 = _a1_times_b1.result.get_element();
    _a2_times_b2.generate_r1cs_witness();
    const Fp2T v2 = _a2_times_b2.result.get_element();
    _a1a2_times_b1b2.A.evaluate();
    _a1a2_times_b1b2.B.evaluate();
    _a1a2_times_b1b2.generate_r1cs_witness();
    const Fp2T a1a2_times_b1b2 = _a1a2_times_b1b2.result.get_element();
    const Fp2T v0 = a0 * b0;
    _result._c0.generate_r1cs_witness(
        v0 + Fp6T::mul_by_non_residue(a1a2_times_b1b2 - v1 - v2));
    _a0_times_b0.generate_r1cs_witness();

    // c1 = (a0 + a1)(b0 + b1) - v1 - v1 + non_residue * v2
    const Fp2T a0a1_times_b0b1 = (a0 + a1) * (b0 + b1);
    _result._c1.generate_r1cs_witness(
        a0a1_times_b0b1 - v0 - v1 + Fp6T::mul_by_non_residue(v2));
    _a0a1_times_b0b1.A.evaluate();
    _a0a1_times_b0b1.B.evaluate();
    _a0a1_times_b0b1.generate_r1cs_witness();

    // c2 = (a0 + a2)(b0 + b2) - v1 - v2 + v1
    const Fp2T a0a2_times_b0b2 = (a0 + a2) * (b0 + b2);
    _result._c2.generate_r1cs_witness(a0a2_times_b0b2 - v0 - v2 + v1);
    _a0a2_times_b0b2.A.evaluate();
    _a0a2_times_b0b2.B.evaluate();
    _a0a2_times_b0b2.generate_r1cs_witness();
}

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_FIELDS_FP6_3OVER2_GADGETS_TCC__
