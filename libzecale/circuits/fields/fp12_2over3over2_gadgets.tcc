// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_FIELDS_FP12_2OVER3OVER2_GADGETS_TCC__
#define __ZECALE_CIRCUITS_FIELDS_FP12_2OVER3OVER2_GADGETS_TCC__

#include "libzecale/circuits/fields/fp12_2over3over2_gadgets.hpp"

namespace libzecale
{

// Fp12_2over3over2_variable methods

template<typename Fp12T>
Fp12_2over3over2_variable<Fp12T>::Fp12_2over3over2_variable(
    libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , _c0(pb, FMT(annotation_prefix, " c0"))
    , _c1(pb, FMT(annotation_prefix, " c1"))
{
}

template<typename Fp12T>
Fp12_2over3over2_variable<Fp12T>::Fp12_2over3over2_variable(
    libsnark::protoboard<FieldT> &pb,
    const Fp12T &v,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , _c0(pb, v.c0, FMT(annotation_prefix, " c0"))
    , _c1(pb, v.c1, FMT(annotation_prefix, " c1"))
{
}

template<typename Fp12T>
Fp12_2over3over2_variable<Fp12T>::Fp12_2over3over2_variable(
    libsnark::protoboard<FieldT> &pb,
    const Fp6_3over2_variable<Fp6T> &c0,
    const Fp6_3over2_variable<Fp6T> &c1,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix), _c0(c0), _c1(c1)
{
}

template<typename Fp12T>
Fp12T Fp12_2over3over2_variable<Fp12T>::get_element() const
{
    return Fp12T(_c0.get_element(), _c1.get_element());
}

template<typename Fp12T>
void Fp12_2over3over2_variable<Fp12T>::generate_r1cs_witness(const Fp12T &v)
{
    _c0.generate_r1cs_witness(v.c0);
    _c1.generate_r1cs_witness(v.c1);
}

// Fp12_2over3over2_square_gadget methods

template<typename Fp12T>
Fp12_2over3over2_square_gadget<Fp12T>::Fp12_2over3over2_square_gadget(
    libsnark::protoboard<FieldT> &pb,
    const Fp12_2over3over2_variable<Fp12T> &A,
    const Fp12_2over3over2_variable<Fp12T> &result,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , _A(A)
    , _result(result)
    , _alpha(
          pb,
          _A._c0,
          _A._c1,
          _result._c1 * (FieldT("2").inverse()),
          FMT(annotation_prefix, " _alpha"))
    , _beta(
          pb,
          _A._c0 + _A._c1,
          _A._c0 +
              mul_by_non_residue(pb, _A._c1, FMT(annotation_prefix, " a1*v")),
          _result._c0 +
              mul_by_non_residue(
                  pb, _alpha._result, FMT(annotation_prefix, " alpha*v")) +
              _alpha._result,
          FMT(annotation_prefix, " _beta"))
{
}

template<typename Fp12T>
const Fp12_2over3over2_variable<Fp12T>
    &Fp12_2over3over2_square_gadget<Fp12T>::result() const
{
    return _result;
}

template<typename Fp12T>
void Fp12_2over3over2_square_gadget<Fp12T>::generate_r1cs_constraints()
{
    _alpha.generate_r1cs_constraints();
    _beta.generate_r1cs_constraints();
}

template<typename Fp12T>
void Fp12_2over3over2_square_gadget<Fp12T>::generate_r1cs_witness()
{
    const Fp6T a0 = _A._c0.get_element();
    const Fp6T a1 = _A._c1.get_element();
    const Fp6T alpha = a0 * a1;
    _result._c1.generate_r1cs_witness(alpha + alpha);
    _alpha.generate_r1cs_witness();

    const Fp6T beta = (a0 + a1) * (a0 + Fp12T::mul_by_non_residue(a1));
    _result._c0.generate_r1cs_witness(
        beta - Fp12T::mul_by_non_residue(alpha) - alpha);
    _beta._A.evaluate();
    _beta._B.evaluate();
    _beta.generate_r1cs_witness();
}

template<typename Fp12T>
Fp6_3over2_variable<typename Fp12T::my_Fp6> Fp12_2over3over2_square_gadget<
    Fp12T>::
    mul_by_non_residue(
        libsnark::protoboard<FieldT> &pb,
        const Fp6_3over2_variable<typename Fp12T::my_Fp6> &c,
        const std::string &annotation_prefix)
{
    return Fp6_3over2_variable<Fp6T>(
        pb, c._c2 * Fp12T::non_residue, c._c0, c._c1, annotation_prefix);
}

// Fp12_2over3over2_mul_by_024_gadget methods

template<typename Fp12T>
Fp12_2over3over2_mul_by_024_gadget<Fp12T>::Fp12_2over3over2_mul_by_024_gadget(
    libsnark::protoboard<FieldT> &pb,
    const Fp12_2over3over2_variable<Fp12T> &Z,
    const libsnark::Fp2_variable<Fp2T> &X_0,
    const libsnark::Fp2_variable<Fp2T> &X_2,
    const libsnark::Fp2_variable<Fp2T> &X_4,
    const Fp12_2over3over2_variable<Fp12T> &result,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , _Z(Z)
    , _X_0(X_0)
    , _X_2(X_2)
    , _X_4(X_4)
    // out_z0 = z0*x0 + non_residue * ( z1*x2 + z4*x4 )
    // => z0 * x0 = out_z0 - non_residue * ( z1*x2 + z4*x4 )
    , _z1_x2(
          pb,
          Z._c0._c1,
          X_2,
          libsnark::Fp2_variable<Fp2T>(pb, FMT(annotation_prefix, " z1*x2")),
          FMT(annotation_prefix, "_z1_x2"))
    , _z4_x4(
          pb,
          Z._c1._c1,
          X_4,
          libsnark::Fp2_variable<Fp2T>(pb, FMT(annotation_prefix, " z4*x4")),
          FMT(annotation_prefix, " _z4_x4"))
    , _z0_x0(
          pb,
          Z._c0._c0,
          X_0,
          result._c0._c0 +
              ((_z1_x2.result + _z4_x4.result) * -Fp6T::non_residue),
          FMT(annotation_prefix, " _z0_x0"))
    // out_z1 = z1*x0 + non_residue * ( z2*x2 + z5*x4 )
    // => z1 * z0 = out_z1 - non_residue * ( z2*x2 + z5*x4 )
    , _z2_x2(
          pb,
          Z._c0._c2,
          X_2,
          libsnark::Fp2_variable<Fp2T>(pb, FMT(annotation_prefix, " z2*x2")),
          FMT(annotation_prefix, " _z2_x2"))
    , _z5_x4(
          pb,
          Z._c1._c2,
          X_4,
          libsnark::Fp2_variable<Fp2T>(pb, FMT(annotation_prefix, " z5*x4")),
          FMT(annotation_prefix, " _z5_x4"))
    , _z1_x0(
          pb,
          Z._c0._c1,
          X_0,
          result._c0._c1 +
              ((_z2_x2.result + _z5_x4.result) * -Fp6T::non_residue),
          FMT(annotation_prefix, " _z1_x0"))
    // z0*x2 + z2*x0 = (z0 + z2)*(x0 + x2) - z0*x0 - z2*x2
    // out_z2 = z0*x2 + z2*x0 + z3*x4
    //        = (z0 + z2)*(x0 + x2) - z0*x0 - z2*x2 + z3*x4
    // => (z0 + z2)*(x0 + x2) = out_z2 + z0*x0 + z2*x2 - z3*x4
    , _z3_x4(
          pb,
          Z._c1._c0,
          X_4,
          libsnark::Fp2_variable<Fp2T>(pb, FMT(annotation_prefix, " z3*x4")),
          FMT(annotation_prefix, " _z3_x4"))
    , _z02_x02(
          pb,
          Z._c0._c0 + Z._c0._c2,
          X_0 + X_2,
          result._c0._c2 + _z0_x0.result + _z2_x2.result +
              (_z3_x4.result * -FieldT::one()),
          FMT(annotation_prefix, " _z02_x02"))
    // z2*x4 + z4*x2 = (z2 + z4)*(x2 + x4) - z2*x2 - z4*x4
    // out_z3 = z3*x0 + non_residue * (z2*x4 + z4*x2)
    //        = z3*x0 + non_residue * ((z2 + z4)*(x2 + x4) - z2*x2 - z4*x4)
    // => (z2 + z4)*(x2 + x4) = (out_z3 - z3*x0) / non_residue + z2*x2 + z4_x4
    , _z3_x0(
          pb,
          Z._c1._c0,
          X_0,
          libsnark::Fp2_variable<Fp2T>(pb, FMT(annotation_prefix, " z3*x0")),
          FMT(annotation_prefix, " _z3_x0"))
    , _z24_x24(
          pb,
          Z._c0._c2 + Z._c1._c1,
          X_2 + X_4,
          _z2_x2.result + _z4_x4.result +
              (result._c1._c0 + _z3_x0.result * -FieldT::one()) *
                  Fp6T::non_residue.inverse(),
          FMT(annotation_prefix, " _z24_x24"))
    // z0*x4 + z4*x0 = (z0 + z4)*(x0 + x4) - z0*x0 - z4*x4
    // out_z4 = z0*x4 + z4*x0 + non_residue * z5*x2
    //        = (z0 + z4)*(x0 + x4) - z0*x0 - z4*x4 + non_residue * z5*x2
    // => (z0 + z4)*(x0 + x4) = out_z4 + z0*x0 + z4*x4 - non_residue * z5*x2
    , _z5_x2(
          pb,
          Z._c1._c2,
          X_2,
          libsnark::Fp2_variable<Fp2T>(pb, FMT(annotation_prefix, " z5*x2")),
          FMT(annotation_prefix, " _z5_x2"))
    , _z04_x04(
          pb,
          Z._c0._c0 + Z._c1._c1,
          X_0 + X_4,
          result._c1._c1 + _z0_x0.result + _z4_x4.result +
              _z5_x2.result * -Fp6T::non_residue,
          FMT(annotation_prefix, " _z04_x04"))
    // S = z1_x0 + z1_x2 + z3_x0 + z3*x4 + z5_x2 + z5*x4
    // out_z5 = z1*x4 + z3*x2 + z5*x0
    //        = (z1 + z3 + z5)*(x0 + x2 + x4) - S
    // => (z1 + z3 + z5)*(x0 + x2 + x4) = out_z5 + S
    , _S(_z1_x2.result + _z1_x0.result + _z5_x4.result + _z3_x4.result +
         _z3_x0.result + _z5_x2.result)
    , _z1z3z5_times_x0x2x4(
          pb,
          Z._c0._c1 + Z._c1._c0 + Z._c1._c2,
          X_0 + X_2 + X_4,
          result._c1._c2 + _S,
          FMT(annotation_prefix, " _z1z3z5_times_x0x2x4"))
    , _result(result)
{
}

template<typename Fp12T>
const Fp12_2over3over2_variable<Fp12T>
    &Fp12_2over3over2_mul_by_024_gadget<Fp12T>::result() const
{
    return _result;
}

template<typename Fp12T>
void Fp12_2over3over2_mul_by_024_gadget<Fp12T>::generate_r1cs_constraints()
{
    _z1_x2.generate_r1cs_constraints();
    _z4_x4.generate_r1cs_constraints();
    _z0_x0.generate_r1cs_constraints();
    _z2_x2.generate_r1cs_constraints();
    _z5_x4.generate_r1cs_constraints();
    _z1_x0.generate_r1cs_constraints();
    _z3_x4.generate_r1cs_constraints();
    _z02_x02.generate_r1cs_constraints();
    _z3_x0.generate_r1cs_constraints();
    _z24_x24.generate_r1cs_constraints();
    _z5_x2.generate_r1cs_constraints();
    _z04_x04.generate_r1cs_constraints();
    _z1z3z5_times_x0x2x4.generate_r1cs_constraints();
}

template<typename Fp12T>
void Fp12_2over3over2_mul_by_024_gadget<Fp12T>::generate_r1cs_witness()
{
    const Fp2T z0 = _Z._c0._c0.get_element();
    const Fp2T z1 = _Z._c0._c1.get_element();
    const Fp2T z2 = _Z._c0._c2.get_element();
    const Fp2T z3 = _Z._c1._c0.get_element();
    const Fp2T z4 = _Z._c1._c1.get_element();
    const Fp2T z5 = _Z._c1._c2.get_element();

    const Fp2T x0 = _X_0.get_element();
    const Fp2T x2 = _X_2.get_element();
    const Fp2T x4 = _X_4.get_element();

    // out_z0 = z0*x0 + non_residue * ( z1*x2 + z4*x4 )
    // => z0 * x0 = out_z0 - non_residue * ( z1*x2 + z4*x4 )
    _z1_x2.generate_r1cs_witness();
    _z4_x4.generate_r1cs_witness();
    const Fp2T z0_x0 = z0 * x0;
    const Fp2T z4_x4 = _z4_x4.result.get_element();
    _result._c0._c0.generate_r1cs_witness(
        z0_x0 + Fp6T::non_residue * (_z1_x2.result.get_element() + z4_x4));
    _z0_x0.generate_r1cs_witness();

    // out_z1 = z1*x0 + non_residue * ( z2*x2 + z5*x4 )
    // => z1 * z0 = out_z1 - non_residue * ( z2*x2 + z5*x4 )
    _z2_x2.generate_r1cs_witness();
    _z5_x4.generate_r1cs_witness();
    const Fp2T z2_x2 = _z2_x2.result.get_element();
    const Fp2T z1_x0 = z1 * x0;
    _result._c0._c1.generate_r1cs_witness(
        z1_x0 + Fp6T::non_residue * (z2_x2 + _z5_x4.result.get_element()));
    _z1_x0.generate_r1cs_witness();

    // z0*x2 + z2*x0 = (z0 + z2)*(x0 + x2) - z0*x0 - z2*x2
    // out_z2 = z0*x2 + z2*x0 + z3*x4
    //        = (z0 + z2)*(x0 + x2) - z0*x0 - z2*x2 + z3*x4
    // => (z0 + z2)*(x0 + x2) = out_z2 + z0*x0 + z2*x2 - z3*x4
    _z3_x4.generate_r1cs_witness();
    const Fp2T z3_x4 = _z3_x4.result.get_element();
    _result._c0._c2.generate_r1cs_witness(
        (z0 + z2) * (x0 + x2) - z0_x0 - z2_x2 + z3_x4);
    _z02_x02.A.evaluate();
    _z02_x02.B.evaluate();
    _z02_x02.generate_r1cs_witness();

    // z2*x4 + z4*x2 = (z2 + z4)*(x2 + x4) - z2*x2 - z4*x4
    // out_z3 = z3*x0 + non_residue * (z2*x4 + z4*x2)
    //        = z3*x0 + non_residue * ((z2 + z4)*(x2 + x4) - z2*x2 - z4*x4)
    // => (z2 + z4)*(x2 + x4) = (out_z3 - z3*x0) / non_residue + z2*x2 + z4_x4
    _z3_x0.generate_r1cs_witness();
    const Fp2T z3_x0 = _z3_x0.result.get_element();
    _result._c1._c0.generate_r1cs_witness(
        z3_x0 + Fp6T::non_residue * ((z2 + z4) * (x2 + x4) - z2_x2 - z4_x4));
    _z24_x24.A.evaluate();
    _z24_x24.B.evaluate();
    _z24_x24.generate_r1cs_witness();

    // z0*x4 + z4*x0 = (z0 + z4)*(x0 + x4) - z0*x0 - z4*x4
    // out_z4 = z0*x4 + z4*x0 + non_residue * z5*x2
    //        = (z0 + z4)*(x0 + x4) - z0*x0 - z4*x4 + non_residue * z5*x2
    // => (z0 + z4)*(x0 + x4) = out_z4 + z0*x0 + z4*x4 - non_residue * z5*x2
    _z5_x2.generate_r1cs_witness();
    const Fp2T z5_x2 = _z5_x2.result.get_element();
    _result._c1._c1.generate_r1cs_witness(
        (z0 + z4) * (x0 + x4) - z0_x0 - z4_x4 + Fp6T::non_residue * z5_x2);
    _z04_x04.A.evaluate();
    _z04_x04.B.evaluate();
    _z04_x04.generate_r1cs_witness();

    // S = z1_x0 - z1_x2 - z3_x0 - z3*x4 - z5_x2 - z5*x4
    // out_z5 = z1*x4 + z3*x2 + z5*x0
    //        = (z1 + z3 + z5)*(x0 + x2 + x4) - S
    // => (z1 + z3 + z5)*(x0 + x2 + x4) = out_z5 + S
    _S.evaluate();
    const Fp2T S = _S.get_element();
    _result._c1._c2.generate_r1cs_witness((z1 + z3 + z5) * (x0 + x2 + x4) - S);
    _z1z3z5_times_x0x2x4.A.evaluate();
    _z1z3z5_times_x0x2x4.B.evaluate();
    _z1z3z5_times_x0x2x4.generate_r1cs_witness();
}

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_FIELDS_FP12_2OVER3OVER2_GADGETS_TCC__
