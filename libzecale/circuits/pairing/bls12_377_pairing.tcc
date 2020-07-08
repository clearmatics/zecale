// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_PAIRING_BLS12_377_PAIRING_TCC__
#define __ZECALE_CIRCUITS_PAIRING_BLS12_377_PAIRING_TCC__

#include "libzecale/circuits/pairing/bls12_377_pairing.hpp"

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

namespace libzecale
{

// Iterate through bits of loop_count, skipping the highest order bit.
class bls12_377_miller_loop_bits
{
public:
    inline bls12_377_miller_loop_bits()
    {
        // TODO: should not need to do this dynamically
        ssize_t start_i = libff::bls12_377_ate_loop_count.max_bits();
        while (!libff::bls12_377_ate_loop_count.test_bit(start_i--)) {
        }
        _i = start_i + 1;
    }

    inline bool next()
    {
        if (_i > 0) {
            --_i;
            return true;
        }

        return false;
    }

    inline bool current() const
    {
        return libff::bls12_377_ate_loop_count.test_bit(_i);
    }

    inline size_t index() const { return (size_t)_i; }

    inline bool last() const { return 0 == index(); }

private:
    ssize_t _i;
};

// bls12_377_G1_precomputation methods

template<typename ppT>
bls12_377_G1_precomputation<ppT>::bls12_377_G1_precomputation() : _Px(), _Py()
{
}

// bls12_377_G2_proj methods

template<typename ppT>
bls12_377_G2_proj<ppT>::bls12_377_G2_proj(
    libsnark::protoboard<libff::Fr<ppT>> &pb,
    const std::string &annotation_prefix)
    : X(pb, FMT(annotation_prefix, " X"))
    , Y(pb, FMT(annotation_prefix, " Y"))
    , Z(pb, FMT(annotation_prefix, " Z"))
{
}

template<typename ppT>
bls12_377_G2_proj<ppT>::bls12_377_G2_proj(
    const Fqe_variable<ppT> &X_var,
    const Fqe_variable<ppT> &Y_var,
    const Fqe_variable<ppT> &Z_var)
    : X(X_var), Y(Y_var), Z(Z_var)
{
}

template<typename ppT>
void bls12_377_G2_proj<ppT>::generate_r1cs_witness(
    const libff::bls12_377_G2 &element)
{
    X.generate_r1cs_witness(element.X);
    Y.generate_r1cs_witness(element.Y);
    Z.generate_r1cs_witness(element.Z);
}

// bls12_377_ate_ell_coeffs methods

template<typename ppT>
bls12_377_ate_ell_coeffs<ppT>::bls12_377_ate_ell_coeffs(
    libsnark::protoboard<FqT> &pb, const std::string &annotation_prefix)
    : ell_0(pb, FMT(annotation_prefix, " ell_0"))
    , ell_vw(pb, FMT(annotation_prefix, " ell_vw"))
    , ell_vv(pb, FMT(annotation_prefix, " ell_vv"))
{
}

// bls12_377_G2_precomputation methods

template<typename ppT>
bls12_377_G2_precomputation<ppT>::bls12_377_G2_precomputation()
{
}

// bls12_377_G1_precompute_gadget methods

template<typename ppT>
bls12_377_G1_precompute_gadget<ppT>::bls12_377_G1_precompute_gadget(
    libsnark::protoboard<libff::Fr<ppT>> &pb,
    const libsnark::G1_variable<ppT> &P,
    bls12_377_G1_precomputation<ppT> &P_prec,
    const std::string &annotation_prefix)
    : libsnark::gadget<libff::Fr<ppT>>(pb, annotation_prefix)
    , _Px(new libsnark::pb_linear_combination<libff::Fr<ppT>>())
    , _Py(new libsnark::pb_linear_combination<libff::Fr<ppT>>())
{
    // Ensure that we don't overwrite an existing precomputation.
    assert(!P_prec._Px);
    assert(!P_prec._Py);
    _Px->assign(pb, P.X);
    _Py->assign(pb, P.Y);
    P_prec._Px = _Px;
    P_prec._Py = _Py;
}

template<typename ppT>
void bls12_377_G1_precompute_gadget<ppT>::generate_r1cs_constraints()
{
}

template<typename ppT>
void bls12_377_G1_precompute_gadget<ppT>::generate_r1cs_witness()
{
    _Px->evaluate(this->pb);
    _Py->evaluate(this->pb);
}

// bls12_377_ate_dbl_gadget methods

template<typename ppT>
bls12_377_ate_dbl_gadget<ppT>::bls12_377_ate_dbl_gadget(
    libsnark::protoboard<FqT> &pb,
    const bls12_377_G2_proj<ppT> &R,
    const bls12_377_G2_proj<ppT> &out_R,
    const bls12_377_ate_ell_coeffs<ppT> &coeffs,
    const std::string &annotation_prefix)
    : libsnark::gadget<libff::Fr<ppT>>(pb, annotation_prefix)
    , _in_R(R)
    , _out_R(out_R)
    , _out_coeffs(coeffs)

    // A = Rx * Ry / 2
    , _A(pb,
         _in_R.X,
         _in_R.Y * FqT(2).inverse(),
         Fqe_variable<ppT>(pb, FMT(annotation_prefix, " Rx*Ry/2")),
         FMT(annotation_prefix, " _A"))

    // B = Ry^2
    , _B(pb,
         _in_R.Y,
         Fqe_variable<ppT>(pb, FMT(annotation_prefix, " Ry^2")),
         FMT(annotation_prefix, " _B"))

    // ell_0 = xi * I
    //   where
    //     C = Rz^2
    //     D = 3 * C
    //     E = b' * D
    //     I = (E - B)
    // ell_0 = xi * I
    //       = xi * (E - B)
    //       = xi * (3*b'*C  - B)
    //       = xi * (3*b'*Rz^2 - Ry^2)
    // <=> Rz^2 [C] = (ell_0 + xi.Ry^2) / 3*b'*xi
    //              = (3*b')^{-1}(ell_0*xi^{-1} + B)
    , _C(pb,
         _in_R.Z,
         (_out_coeffs.ell_0 * libff::bls12_377_twist.inverse() + _B.result) *
             (FqT(3) * libff::bls12_377_twist_coeff_b).inverse(),
         FMT(annotation_prefix, " _C"))

    // D = 3 * C
    , _D(_C.result * FqT(3))

    // E = b' * D
    , _E(_D * libff::bls12_377_twist_coeff_b)

    // F = 3 * E
    , _F(_E + _E + _E)

    // H = (Y + Z) ^ 2 - (B + C)
    // ell_vw = -H
    //        = (B+C) - (Y+2)^2
    // <=> (Y+2)^2 [H] = B + C - ell_vw
    , _Y_plus_Z_squared(
          pb,
          _in_R.Y + _in_R.Z,
          _B.result + _C.result - _out_coeffs.ell_vw,
          FMT(annotation_prefix, " _Y_plus_Z_squared"))

    // I = (E - B)
    // J = Rx^2
    // ell_vv = 3 * J
    //        = 3 * Rx^2
    // <=> Rx^2 [J] = ell_vv * 3^{-1}
    , _J(pb,
         _in_R.X,
         _out_coeffs.ell_vv * FqT(3).inverse(),
         FMT(annotation_prefix, " _J"))

    // outRx = A * (B-F)
    , _check_out_Rx(
          pb,
          _A.result,
          _B.result - _F,
          _out_R.X,
          FMT(annotation_prefix, " _check_out_Rx"))

    // outRy = G^2 - 3E^2
    //   where  G = (B + F) / 2
    // <=> G^2 = outRy + 3 * E^2
    , _E_squared(
          pb,
          _E,
          Fqe_variable<ppT>(pb, FMT(annotation_prefix, " E^2")),
          FMT(annotation_prefix, " _E_squared"))
    , _G_squared(
          pb,
          (_B.result + _F) * FqT(2).inverse(),
          _out_R.Y + _E_squared.result + _E_squared.result + _E_squared.result,
          FMT(annotation_prefix, " _G_squared"))

    // outRz = B * H
    //   where
    //     H = (Y + Z) ^ 2 - (B + C)
    , _check_out_Rz(
          pb,
          _B.result,
          _Y_plus_Z_squared.result - _B.result - _C.result,
          _out_R.Z,
          FMT(annotation_prefix, " _check_out_Rz"))
{
}

template<typename ppT>
void bls12_377_ate_dbl_gadget<ppT>::generate_r1cs_constraints()
{
    _A.generate_r1cs_constraints();
    _B.generate_r1cs_constraints();
    _C.generate_r1cs_constraints();
    _Y_plus_Z_squared.generate_r1cs_constraints();
    _J.generate_r1cs_constraints();
    _check_out_Rx.generate_r1cs_constraints();
    _E_squared.generate_r1cs_constraints();
    _G_squared.generate_r1cs_constraints();
    _check_out_Rz.generate_r1cs_constraints();
}

template<typename ppT>
void bls12_377_ate_dbl_gadget<ppT>::generate_r1cs_witness()
{
    const FqeT Rx = _in_R.X.get_element();
    const FqeT Ry = _in_R.Y.get_element();
    const FqeT Rz = _in_R.Z.get_element();

    // A = Rx * Ry / 2
    _A.B.evaluate();
    _A.generate_r1cs_witness();

    // B = Ry^2
    _B.generate_r1cs_witness();

    // ell_0 = xi * I
    //   where
    //     C = Rz^2
    //     D = 3 * C
    //     E = b' * D
    //     I = (E - B)
    // <=> Rz^2 [C] = (ell_0.xi^{-1} + Ry^2) * (3*b')^{-1}
    const FqeT B = _B.result.get_element();
    const FqeT C = Rz * Rz;
    const FqeT D = FqT(3) * C;
    const FqeT E = libff::bls12_377_twist_coeff_b * D;
    const FqeT I = E - B;
    _out_coeffs.ell_0.generate_r1cs_witness(libff::bls12_377_twist * I);
    _C.result.evaluate();
    _C.generate_r1cs_witness();
    assert(C == _C.result.get_element());
    assert(
        (_out_coeffs.ell_0.get_element() * libff::bls12_377_twist.inverse() +
         B) *
            (FqT(3) * libff::bls12_377_twist_coeff_b).inverse() ==
        _C.result.get_element());

    _D.evaluate();
    assert(FqT(3) * C == _D.get_element());

    _E.evaluate();
    assert(
        _E.get_element() == libff::Fr<ppT>(3) * _C.result.get_element() *
                                libff::bls12_377_twist_coeff_b);

    // F = 3 * E (linear comb)
    _F.evaluate();
    assert(_F.get_element() == libff::Fr<ppT>(3) * _E.get_element());

    // G = (B + F) / 2
    // ell_vw = -H
    //   where
    //     H = (Y + 2) ^ 2 - (B + C)
    // ell_vw = (B+C) - (Y+2)^2
    // <=> (Y+2)^2 [H] = ell_vw - B - C
    const FqeT Ry_plus_Rz_squared = (Ry + Rz) * (Ry + Rz);
    _out_coeffs.ell_vw.generate_r1cs_witness(B + C - Ry_plus_Rz_squared);
    _Y_plus_Z_squared.A.evaluate();
    _Y_plus_Z_squared.result.evaluate();
    _Y_plus_Z_squared.generate_r1cs_witness();
    assert(_Y_plus_Z_squared.result.get_element() == Ry_plus_Rz_squared);

    // I = E - B

    // ell_vv = 3 * J
    // J = Rx^2
    const FqeT J = Rx * Rx;
    _out_coeffs.ell_vv.generate_r1cs_witness(FqT(3) * J);
    _J.result.evaluate();
    _J.generate_r1cs_witness();

    // outRx = A * (B - F)
    _check_out_Rx.B.evaluate();
    _check_out_Rx.result.evaluate();
    _check_out_Rx.generate_r1cs_witness();

    // outRy = G^2 - 3E^2
    //   where  G = (B + F) / 2
    // <=> G^2 = outRy + 3 * E^2
    _E_squared.generate_r1cs_witness();
    const FqeT E_squared = _E_squared.result.get_element();
    const FqeT F = _F.get_element();
    const FqeT G = FqT(2).inverse() * (B + F);
    const FqeT G_squared = G * G;
    _out_R.Y.generate_r1cs_witness(G_squared - FqT(3) * E_squared);
    _G_squared.A.evaluate();
    _G_squared.result.evaluate();
    _G_squared.generate_r1cs_witness();

    // out_Rz = B * H (assigned by check_outRz)
    _check_out_Rz.B.evaluate();
    assert(B == _check_out_Rz.A.get_element());
    assert(Ry_plus_Rz_squared - B - C == _check_out_Rz.B.get_element());
    _check_out_Rz.generate_r1cs_witness();
    assert(
        B * (Ry_plus_Rz_squared - B - C) == _check_out_Rz.result.get_element());
}

// bls12_377_ate_add_gadget methods

template<typename ppT>
bls12_377_ate_add_gadget<ppT>::bls12_377_ate_add_gadget(
    libsnark::protoboard<libff::Fr<ppT>> &pb,
    const Fqe_variable<ppT> &Q_X,
    const Fqe_variable<ppT> &Q_Y,
    const bls12_377_G2_proj<ppT> &in_R,
    const bls12_377_G2_proj<ppT> &out_R,
    const bls12_377_ate_ell_coeffs<ppT> &out_coeffs,
    const std::string &annotation_prefix)
    : libsnark::gadget<libff::Fr<ppT>>(pb, annotation_prefix)
    , _Q_X(Q_X)
    , _Q_Y(Q_Y)
    , _in_R(in_R)
    , _out_R(out_R)
    , _out_coeffs(out_coeffs)
    // ell_vv = -theta
    //   where
    //     theta = Ry - A
    //     A = Qy * Rz;
    // <=> A = Qy * Rz = ell_vv + Ry
    , _A(pb,
         _Q_Y,
         _in_R.Z,
         _out_coeffs.ell_vv + _in_R.Y,
         FMT(annotation_prefix, " _A"))
    // ell_vw = lambda
    //   where
    //     lambda = Rx - B
    //     B = Qx * Rz
    // <=> B = Qx * Rz = Rx - ell_vw
    , _B(pb,
         _Q_X,
         _in_R.Z,
         _in_R.X - _out_coeffs.ell_vw,
         FMT(annotation_prefix, " _B"))
    // theta = Ry - A;
    // , theta(in_R.Y + (A * -libff::Fr<ppT>::one()))
    // lambda = Rx - B;
    // , lambda(in_R.X + (B * -libff::Fr<ppT>::one()))
    // C = theta.squared() = ell_vv^2
    , _C(pb,
         _out_coeffs.ell_vv,
         Fqe_variable<ppT>(pb, FMT(annotation_prefix, " ell_vv^2")),
         FMT(annotation_prefix, " _C"))
    // D = lambda.squared() = ell_vw^2
    , _D(pb,
         _out_coeffs.ell_vw,
         Fqe_variable<ppT>(pb, FMT(annotation_prefix, " ell_vw^2")),
         FMT(annotation_prefix, " _D"))
    // E = lambda * D = D * ell_vw;
    , _E(pb,
         _D.result,
         _out_coeffs.ell_vw,
         Fqe_variable<ppT>(pb, FMT(annotation_prefix, " D*ell_vw")),
         FMT(annotation_prefix, " _E"))
    // F = Rz * C;
    , _F(pb,
         _in_R.Z,
         _C.result,
         Fqe_variable<ppT>(pb, FMT(annotation_prefix, " Rz*C")),
         FMT(annotation_prefix, " _F"))
    // G = Rx * D;
    , _G(pb,
         _in_R.X,
         _D.result,
         Fqe_variable<ppT>(pb, FMT(annotation_prefix, " Rx*D")),
         FMT(annotation_prefix, " _G"))
    // H = E + F - (G + G);
    , _H(_E.result + _F.result - _G.result - _G.result)
    // I = Ry * E;
    , _I(pb,
         _in_R.Y,
         _E.result,
         Fqe_variable<ppT>(pb, FMT(annotation_prefix, " Ry*E")),
         FMT(annotation_prefix, " _I"))
    // out_coeffs.ell_0 = xi * J
    //   where J = theta * Qx - lambda * Qy
    // <=> lambda * Qy = theta * Qx - ell_0 * xi^{-1}
    , _theta_times_Qx(
          pb,
          -_out_coeffs.ell_vv,
          _Q_X,
          Fqe_variable<ppT>(pb, FMT(annotation_prefix, " theta*Qx")),
          FMT(annotation_prefix, " _theta_times_Qx"))
    , _lambda_times_Qy(
          pb,
          _out_coeffs.ell_vw,
          _Q_Y,
          _theta_times_Qx.result -
              (_out_coeffs.ell_0 * libff::bls12_377_twist.inverse()),
          FMT(annotation_prefix, " _lambda_times_Qy"))
    // out_Rx = lambda * H = ell_vw * H
    , _check_out_Rx(
          pb,
          _out_coeffs.ell_vw,
          _H,
          _out_R.X,
          FMT(annotation_prefix, " _check_out_Rx"))
    // out_Ry = theta * (G - H) - I = -ell_vv * (G-H) - I
    // <=> ell_vv * (H-G) = out_Ry + I
    , _check_out_Ry(
          pb,
          _out_coeffs.ell_vv,
          _H - _G.result,
          _out_R.Y + _I.result,
          FMT(annotation_prefix, " _check_out_Ry"))
    // out_Rz = Z1 * E;
    , _check_out_Rz(
          pb,
          _in_R.Z,
          _E.result,
          _out_R.Z,
          FMT(annotation_prefix, " _check_out_Rz"))
{
}

template<typename ppT>
void bls12_377_ate_add_gadget<ppT>::generate_r1cs_constraints()
{
    _A.generate_r1cs_constraints();
    _B.generate_r1cs_constraints();
    _C.generate_r1cs_constraints();
    _D.generate_r1cs_constraints();
    _E.generate_r1cs_constraints();
    _F.generate_r1cs_constraints();
    _G.generate_r1cs_constraints();
    _theta_times_Qx.generate_r1cs_constraints();
    _lambda_times_Qy.generate_r1cs_constraints();
    _check_out_Rx.generate_r1cs_constraints();
    _check_out_Ry.generate_r1cs_constraints();
    _check_out_Rz.generate_r1cs_constraints();
}

template<typename ppT>
void bls12_377_ate_add_gadget<ppT>::generate_r1cs_witness()
{
    const FqeT Qx = _Q_X.get_element();
    const FqeT Qy = _Q_Y.get_element();
    const FqeT Rx = _in_R.X.get_element();
    const FqeT Ry = _in_R.Y.get_element();
    const FqeT Rz = _in_R.Z.get_element();

    // ell_vv = -theta
    //   where
    //     theta = Ry - A
    //     A = Qy * Rz;
    // <=> A = Qy * Rz = ell_vv + Ry
    const FqeT A = Qy * Rz;
    const FqeT theta = Ry - A;
    _out_coeffs.ell_vv.generate_r1cs_witness(-theta);
    _A.result.evaluate();
    _A.generate_r1cs_witness();

    // ell_vw = lambda
    //   where
    //     lambda = Rx - B
    //     B = Qx * Rz
    // <=> B = Qx * Rz = Rx - ell_vw
    const FqeT B = Qx * Rz;
    const FqeT lambda = Rx - B;
    _out_coeffs.ell_vw.generate_r1cs_witness(lambda);
    _B.result.evaluate();
    _B.generate_r1cs_witness();
    // C = theta.squared() = ell_vv^2
    _C.generate_r1cs_witness();
    // D = lambda.squared() = ell_vw^2
    _D.generate_r1cs_witness();
    // E = lambda * D = D * ell_vw;
    _E.generate_r1cs_witness();
    // F = Rz * C
    _F.generate_r1cs_witness();
    // G = Rx * D;
    _G.generate_r1cs_witness();
    // H = E + F - (G + G);
    _H.evaluate();
    // I = Ry * E
    _I.generate_r1cs_witness();
    // out_coeffs.ell_0 = xi * J
    //   where J = theta * Qx - lambda * Qy
    // <=> lambda * Qy = theta * Qx - ell_0 * xi^{-1}
    _theta_times_Qx.A.evaluate();
    _theta_times_Qx.generate_r1cs_witness();
    const FqeT theta_times_Qx = _theta_times_Qx.result.get_element();
    const FqeT lambda_times_Qy = lambda * Qy;
    _out_coeffs.ell_0.generate_r1cs_witness(
        libff::bls12_377_twist * (theta_times_Qx - lambda_times_Qy));
    _lambda_times_Qy.result.evaluate();
    _lambda_times_Qy.generate_r1cs_witness();
    // out_Rx = lambda * H = ell_vw * H
    _check_out_Rx.generate_r1cs_witness();
    // out_Ry = theta * (G - H) - I = -ell_vv * (G-H) - I
    // <=> ell_vv * (H-G) = out_Ry + I
    const FqeT G = _G.result.get_element();
    const FqeT H = _H.get_element();
    const FqeT I = _I.result.get_element();
    _out_R.Y.generate_r1cs_witness(theta * (G - H) - I);
    _check_out_Ry.B.evaluate();
    _check_out_Ry.result.evaluate();
    _check_out_Ry.generate_r1cs_witness();
    // out_Rz = Z1 * E
    _check_out_Rz.generate_r1cs_witness();
}

// bls12_377_G2_precompute methods

template<typename ppT>
bls12_377_G2_precompute_gadget<ppT>::bls12_377_G2_precompute_gadget(
    libsnark::protoboard<libff::Fr<ppT>> &pb,
    const libsnark::G2_variable<ppT> &Q,
    bls12_377_G2_precomputation<ppT> &Q_prec,
    const std::string &annotation_prefix)
    : libsnark::gadget<libff::Fr<ppT>>(pb, annotation_prefix)
    , _R0(*Q.X, *Q.Y, Fqe_variable<ppT>(pb, FqeT::one(), "Fqe(1)"))
{
    // Track the R variable at each step. Initially it is _R0;
    const bls12_377_G2_proj<ppT> *currentR = &_R0;
    size_t num_dbl = 0;
    size_t num_add = 0;
    size_t num_Rs = 0;

    // Iterate through bits of loop_count
    bls12_377_miller_loop_bits bits;
    while (bits.next()) {
        _R.push_back(
            std::shared_ptr<bls12_377_G2_proj<ppT>>(new bls12_377_G2_proj<ppT>(
                pb, FMT(annotation_prefix, " R%zu", num_Rs++))));
        Q_prec._coeffs.push_back(std::shared_ptr<bls12_377_ate_ell_coeffs<ppT>>(
            new bls12_377_ate_ell_coeffs<ppT>(
                pb, FMT(annotation_prefix, " Q_prec_dbl_%zu", num_dbl++))));
        _ate_dbls.push_back(std::shared_ptr<bls12_377_ate_dbl_gadget<ppT>>(
            new bls12_377_ate_dbl_gadget<ppT>(
                pb,
                *currentR,
                *_R.back(),
                *Q_prec._coeffs.back(),
                FMT(annotation_prefix, " dbls[%zu]", bits.index()))));
        currentR = &(*_R.back());

        if (bits.current()) {
            _R.push_back(std::shared_ptr<bls12_377_G2_proj<ppT>>(
                new bls12_377_G2_proj<ppT>(
                    pb, FMT(annotation_prefix, " R%zu", num_Rs++))));
            Q_prec._coeffs.push_back(
                std::shared_ptr<bls12_377_ate_ell_coeffs<ppT>>(
                    new bls12_377_ate_ell_coeffs<ppT>(
                        pb,
                        FMT(annotation_prefix, " Q_prec_add_%zu", num_add++))));
            _ate_adds.push_back(std::shared_ptr<bls12_377_ate_add_gadget<ppT>>(
                new bls12_377_ate_add_gadget<ppT>(
                    pb,
                    *Q.X,
                    *Q.Y,
                    *currentR,
                    *_R.back(),
                    *Q_prec._coeffs.back(),
                    FMT(annotation_prefix, " adds[%zu]", bits.index()))));
            currentR = &(*_R.back());
        }
    }
}

template<typename ppT>
void bls12_377_G2_precompute_gadget<ppT>::generate_r1cs_constraints()
{
    size_t dbl_idx = 0;
    size_t add_idx = 0;

    // TODO: There should be no need to loop through the bits of loop_count
    // when generating the constraints (all variables have been allocated, so
    // the order of generation is not important). For now we do this to keep a
    // consistent loop in all methods.

    bls12_377_miller_loop_bits bits;
    while (bits.next()) {
        _ate_dbls[dbl_idx++]->generate_r1cs_constraints();
        if (bits.current()) {
            _ate_adds[add_idx++]->generate_r1cs_constraints();
        }
    }
}

template<typename ppT>
void bls12_377_G2_precompute_gadget<ppT>::generate_r1cs_witness()
{
    size_t dbl_idx = 0;
    size_t add_idx = 0;
    bls12_377_miller_loop_bits bits;
    while (bits.next()) {
        _ate_dbls[dbl_idx++]->generate_r1cs_witness();
        if (bits.current()) {
            _ate_adds[add_idx++]->generate_r1cs_witness();
        }
    }
}

// bls12_377_ate_compute_f_ell_P methods

template<typename ppT>
bls12_377_ate_compute_f_ell_P<ppT>::bls12_377_ate_compute_f_ell_P(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_linear_combination<FieldT> &Px,
    const libsnark::pb_linear_combination<FieldT> &Py,
    const bls12_377_ate_ell_coeffs<ppT> &ell_coeffs,
    const Fp12_2over3over2_variable<FqkT> &f,
    const Fp12_2over3over2_variable<FqkT> &f_out,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , _ell_vv_times_Px(
          pb,
          ell_coeffs.ell_vv,
          Px,
          Fqe_variable<ppT>(pb, FMT(annotation_prefix, " Px.ell_vv")),
          FMT(annotation_prefix, " _ell_vv_times_Px"))
    , _ell_vw_times_Py(
          pb,
          ell_coeffs.ell_vw,
          Py,
          Fqe_variable<ppT>(pb, FMT(annotation_prefix, " Py.ell_vw")),
          FMT(annotation_prefix, " _ell_vw_times_Py"))
    , _f_mul_ell_P(
          pb,
          f,
          ell_coeffs.ell_0,
          _ell_vv_times_Px.result,
          _ell_vw_times_Py.result,
          f_out,
          FMT(annotation_prefix, " _f_mul_ell_P"))
{
}

template<typename ppT>
const Fp12_2over3over2_variable<libff::Fqk<other_curve<ppT>>>
    &bls12_377_ate_compute_f_ell_P<ppT>::result() const
{
    return _f_mul_ell_P.result();
}

template<typename ppT>
void bls12_377_ate_compute_f_ell_P<ppT>::generate_r1cs_constraints()
{
    _ell_vv_times_Px.generate_r1cs_constraints();
    _ell_vw_times_Py.generate_r1cs_constraints();
    _f_mul_ell_P.generate_r1cs_constraints();
}

template<typename ppT>
void bls12_377_ate_compute_f_ell_P<ppT>::generate_r1cs_witness()
{
    _ell_vv_times_Px.generate_r1cs_witness();
    _ell_vw_times_Py.generate_r1cs_witness();
    _f_mul_ell_P.generate_r1cs_witness();
}

// bls12_377_miller_loop_gadget methods

template<typename ppT>
bls12_377_miller_loop_gadget<ppT>::bls12_377_miller_loop_gadget(
    libsnark::protoboard<FieldT> &pb,
    const bls12_377_G1_precomputation<ppT> &prec_P,
    const bls12_377_G2_precomputation<ppT> &prec_Q,
    const Fqk_variable<ppT> &result,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , _f0(pb, FqkT::one(), FMT(annotation_prefix, "f0"))
{
    size_t coeff_idx = 0;
    const Fp12_2over3over2_variable<FqkT> *f = &_f0;

    bls12_377_miller_loop_bits bits;
    while (bits.next()) {
        // f <- f^2
        _f_squared.push_back(
            std::shared_ptr<Fp12_2over3over2_square_gadget<FqkT>>(
                new Fp12_2over3over2_square_gadget<FqkT>(
                    pb,
                    *f,
                    Fp12_2over3over2_variable<FqkT>(
                        pb, FMT(annotation_prefix, " f^2")),
                    FMT(annotation_prefix, " _f_squared[%zu]", bits.index()))));
        f = &_f_squared.back()->result();

        // f <- f^2 * ell(P)
        _f_ell_P.push_back(std::shared_ptr<bls12_377_ate_compute_f_ell_P<ppT>>(
            new bls12_377_ate_compute_f_ell_P<ppT>(
                pb,
                *prec_P._Px,
                *prec_P._Py,
                *prec_Q._coeffs[coeff_idx++],
                *f,
                Fp12_2over3over2_variable<FqkT>(
                    pb, FMT(annotation_prefix, " f^2*ell(P)")),
                FMT(annotation_prefix, " _f_ell_P[%zu]", _f_ell_P.size()))));
        f = &_f_ell_P.back()->result();

        if (bits.current()) {
            // f <- f * ell(P)
            if (bits.last()) {
                _f_ell_P.push_back(
                    std::shared_ptr<bls12_377_ate_compute_f_ell_P<ppT>>(
                        new bls12_377_ate_compute_f_ell_P<ppT>(
                            pb,
                            *prec_P._Px,
                            *prec_P._Py,
                            *prec_Q._coeffs[coeff_idx++],
                            *f,
                            result,
                            FMT(annotation_prefix,
                                " _f_ell_P[%zu]",
                                _f_ell_P.size()))));
            } else {
                _f_ell_P.push_back(
                    std::shared_ptr<bls12_377_ate_compute_f_ell_P<ppT>>(
                        new bls12_377_ate_compute_f_ell_P<ppT>(
                            pb,
                            *prec_P._Px,
                            *prec_P._Py,
                            *prec_Q._coeffs[coeff_idx++],
                            *f,
                            Fp12_2over3over2_variable<FqkT>(
                                pb, FMT(annotation_prefix, " f*ell(P)")),
                            FMT(annotation_prefix,
                                " _f_ell_P[%zu]",
                                _f_ell_P.size()))));
            }
            f = &_f_ell_P.back()->result();
        }
    }
}

template<typename ppT>
const Fp12_2over3over2_variable<libff::Fqk<other_curve<ppT>>>
    &bls12_377_miller_loop_gadget<ppT>::result() const
{
    return _f_ell_P.back()->result();
}

template<typename ppT>
void bls12_377_miller_loop_gadget<ppT>::generate_r1cs_constraints()
{
    // TODO: everything is allocated, so constraint generation does not need
    // to be done in this order. For now, keep a consistent loop.

    size_t sqr_idx = 0;
    size_t f_ell_P_idx = 0;
    bls12_377_miller_loop_bits bits;
    while (bits.next()) {
        _f_squared[sqr_idx++]->generate_r1cs_constraints();
        _f_ell_P[f_ell_P_idx++]->generate_r1cs_constraints();
        if (bits.current()) {
            _f_ell_P[f_ell_P_idx++]->generate_r1cs_constraints();
        }
    }

    assert(sqr_idx == _f_squared.size());
    assert(f_ell_P_idx == _f_ell_P.size());
}

template<typename ppT>
void bls12_377_miller_loop_gadget<ppT>::generate_r1cs_witness()
{
    size_t sqr_idx = 0;
    size_t f_ell_P_idx = 0;
    bls12_377_miller_loop_bits bits;
    while (bits.next()) {
        _f_squared[sqr_idx++]->generate_r1cs_witness();
        _f_ell_P[f_ell_P_idx++]->generate_r1cs_witness();
        if (bits.current()) {
            _f_ell_P[f_ell_P_idx++]->generate_r1cs_witness();
        }
    }

    assert(sqr_idx == _f_squared.size());
    assert(f_ell_P_idx == _f_ell_P.size());
}

// bls12_377_final_exp_first_part_gadget methods

template<typename ppT>
bls12_377_final_exp_first_part_gadget<ppT>::
    bls12_377_final_exp_first_part_gadget(
        libsnark::protoboard<FieldT> &pb,
        const Fp12_2over3over2_variable<FqkT> &in,
        const Fp12_2over3over2_variable<FqkT> &result,
        const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , _in(in)
    , _result(result)
    , _B(pb,
         _in,
         Fp12_2over3over2_variable<FqkT>(pb, FMT(annotation_prefix, " in.inv")),
         FMT(annotation_prefix, " _B"))
    , _C(pb,
         _in.frobenius_map(6), // _A
         _B.result(),
         Fp12_2over3over2_variable<FqkT>(
             pb, FMT(annotation_prefix, " in.frobenius(6)*_B")),
         FMT(annotation_prefix, " _C"))
    , _D_times_C(
          pb,
          _C.result().frobenius_map(2), // _D
          _C.result(),
          _result,
          FMT(annotation_prefix, " _D_times_C"))
{
}

template<typename ppT>
const Fp12_2over3over2_variable<libff::Fqk<other_curve<ppT>>>
    &bls12_377_final_exp_first_part_gadget<ppT>::result() const
{
    return _result;
}

template<typename ppT>
void bls12_377_final_exp_first_part_gadget<ppT>::generate_r1cs_constraints()
{
    _B.generate_r1cs_constraints();
    _C.generate_r1cs_constraints();
    _D_times_C.generate_r1cs_constraints();
}

template<typename ppT>
void bls12_377_final_exp_first_part_gadget<ppT>::generate_r1cs_witness()
{
    _B.generate_r1cs_witness();
    _C._A.evaluate();
    _C.generate_r1cs_witness();
    _D_times_C._A.evaluate();
    _D_times_C.generate_r1cs_witness();
}

// bls12_377_exp_by_z_gadget methods

template<typename ppT>
bls12_377_exp_by_z_gadget<ppT>::bls12_377_exp_by_z_gadget(
    libsnark::protoboard<FieldT> &pb,
    const Fp12_2over3over2_variable<FqkT> &in,
    const Fp12_2over3over2_variable<FqkT> &result,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix), _in(in), _result(result)
{
    // There is some complexity in ensuring that the result uses _result as an
    // output variable. If bls12_377_final_exponent_is_z_neg, we perform all
    // square and multiplies into intermediate variables and then unitary
    // inverse into _result. Otherwise, care must be taken during the final
    // iteration so that _result holds the output from the final multiply.

    if (libff::bls12_377_final_exponent_is_z_neg) {
        initialize_z_neg(pb, annotation_prefix);
    } else {
        initialize_z_pos(pb, annotation_prefix);
    }
}

template<typename ppT>
void bls12_377_exp_by_z_gadget<ppT>::initialize_z_neg(
    libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix)
{
    const Fp12_2over3over2_variable<FqkT> *res = &_in;

    // Iterate through all bits, then perform a unitary_inverse into result

    const size_t num_bits = libff::bls12_377_final_exponent_z.num_bits();
    for (size_t bit_idx = num_bits - 1; bit_idx > 0; --bit_idx) {
        // result <- result.cyclotomic_squared()
        _squares.push_back(
            std::shared_ptr<cyclotomic_square>(new cyclotomic_square(
                pb,
                *res,
                Fp12_2over3over2_variable<FqkT>(
                    pb, FMT(annotation_prefix, " res^2")),
                FMT(annotation_prefix, " _squares[%zu]", _squares.size()))));
        res = &(_squares.back()->result());

        if (libff::bls12_377_final_exponent_z.test_bit(bit_idx - 1)) {
            // result <- result * elt
            _multiplies.push_back(std::shared_ptr<multiply>(new multiply(
                pb,
                *res,
                _in,
                Fp12_2over3over2_variable<FqkT>(
                    pb, FMT(annotation_prefix, " res*in")),
                FMT(annotation_prefix,
                    " _multiplies[%zu]",
                    _multiplies.size()))));
            res = &(_multiplies.back()->result());
        }
    }

    _inverse = std::shared_ptr<unitary_inverse>(new unitary_inverse(
        pb, *res, _result, FMT(annotation_prefix, " res.inv")));
}

template<typename ppT>
void bls12_377_exp_by_z_gadget<ppT>::initialize_z_pos(
    libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix)
{
    const Fp12_2over3over2_variable<FqkT> *res = &_in;

    // Iterate through all bits, leaving the last one as a special case.
    const size_t num_bits = libff::bls12_377_final_exponent_z.num_bits();
    for (size_t bit_idx = num_bits - 1; bit_idx > 1; --bit_idx) {
        // result <- result.cyclotomic_squared()
        _squares.push_back(
            std::shared_ptr<cyclotomic_square>(new cyclotomic_square(
                pb,
                *res,
                Fp12_2over3over2_variable<FqkT>(
                    pb, FMT(annotation_prefix, " res^2")),
                FMT(annotation_prefix, " _squares[%zu]", _squares.size()))));
        res = &(_squares.back()->result());

        if (libff::bls12_377_final_exponent_z.test_bit(bit_idx - 1)) {
            // result <- result * elt
            _multiplies.push_back(std::shared_ptr<multiply>(new multiply(
                pb,
                *res,
                _in,
                Fp12_2over3over2_variable<FqkT>(
                    pb, FMT(annotation_prefix, " res*in")),
                FMT(annotation_prefix,
                    " _multiplies[%zu]",
                    _multiplies.size()))));
            res = &(_multiplies.back()->result());
        }
    }

    // Write the output of the final iteration to result.
    assert(libff::bls12_377_final_exponent_z.test_bit(0));
    _squares.push_back(std::shared_ptr<cyclotomic_square>(new cyclotomic_square(
        pb,
        *res,
        Fp12_2over3over2_variable<FqkT>(pb, FMT(annotation_prefix, " res^2")),
        FMT(annotation_prefix, " _squares[%zu]", _squares.size()))));
    res = &(_squares.back()->result());

    _multiplies.push_back(std::shared_ptr<multiply>(new multiply(
        pb,
        *res,
        _in,
        _result,
        FMT(annotation_prefix, " _multiplies[%zu]", _multiplies.size()))));
}

template<typename ppT>
const Fp12_2over3over2_variable<libff::Fqk<other_curve<ppT>>>
    &bls12_377_exp_by_z_gadget<ppT>::result() const
{
    return _result;
}

template<typename ppT>
void bls12_377_exp_by_z_gadget<ppT>::generate_r1cs_constraints()
{
    size_t sqr_idx = 0;
    size_t mul_idx = 0;
    const size_t num_bits = libff::bls12_377_final_exponent_z.num_bits();
    for (size_t bit_idx = num_bits - 1; bit_idx > 0; --bit_idx) {
        _squares[sqr_idx++]->generate_r1cs_constraints();
        if (libff::bls12_377_final_exponent_z.test_bit(bit_idx - 1)) {
            _multiplies[mul_idx++]->generate_r1cs_constraints();
        }
    }

    if (_inverse) {
        _inverse->generate_r1cs_constraints();
    }
}

template<typename ppT>
void bls12_377_exp_by_z_gadget<ppT>::generate_r1cs_witness()
{
    size_t sqr_idx = 0;
    size_t mul_idx = 0;
    const size_t num_bits = libff::bls12_377_final_exponent_z.num_bits();
    for (size_t bit_idx = num_bits - 1; bit_idx > 0; --bit_idx) {
        _squares[sqr_idx++]->generate_r1cs_witness();
        if (libff::bls12_377_final_exponent_z.test_bit(bit_idx - 1)) {
            _multiplies[mul_idx++]->generate_r1cs_witness();
        }
    }

    if (_inverse) {
        _inverse->generate_r1cs_witness();
    }
}

// bls12_377_final_exp_last_part_gadget methods

template<typename ppT>
bls12_377_final_exp_last_part_gadget<ppT>::bls12_377_final_exp_last_part_gadget(
    libsnark::protoboard<FieldT> &pb,
    const Fp12_2over3over2_variable<FqkT> &in,
    const Fp12_2over3over2_variable<FqkT> &result,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , _in(in)
    , _result(result)
    // A = [-2]
    , _in_squared(
          pb,
          _in,
          Fp12_2over3over2_variable<FqkT>(pb, FMT(annotation_prefix, " in^2")),
          FMT(annotation_prefix, " _in_squared"))
    // B = [z]
    , _B(pb,
         _in,
         Fp12_2over3over2_variable<FqkT>(pb, FMT(annotation_prefix, " in^z")),
         FMT(annotation_prefix, " _B"))
    // C = [2z]
    , _C(pb,
         _B.result(),
         Fp12_2over3over2_variable<FqkT>(pb, FMT(annotation_prefix, " B^2")),
         FMT(annotation_prefix, " _C"))
    // D = [z-2]
    , _D(pb,
         _in_squared.result().unitary_inverse(), // _A
         _B.result(),
         Fp12_2over3over2_variable<FqkT>(pb, FMT(annotation_prefix, " A*B")),
         FMT(annotation_prefix, " _D"))
    // E = [z^2-2z]
    , _E(pb,
         _D.result(),
         Fp12_2over3over2_variable<FqkT>(pb, FMT(annotation_prefix, " D^z")),
         FMT(annotation_prefix, " _E"))
    // F = [z^3-2z^2]
    , _F(pb,
         _E.result(),
         Fp12_2over3over2_variable<FqkT>(pb, FMT(annotation_prefix, " E^z")),
         FMT(annotation_prefix, " _F"))
    // G = [z^4-2z^3]
    , _G(pb,
         _F.result(),
         Fp12_2over3over2_variable<FqkT>(pb, FMT(annotation_prefix, " F^z")),
         FMT(annotation_prefix, " _G"))
    // H = [z^4-2z^3+2z]
    , _H(pb,
         _G.result(),
         _C.result(),
         Fp12_2over3over2_variable<FqkT>(pb, FMT(annotation_prefix, " G*C")),
         FMT(annotation_prefix, " _H"))
    // I = [z^5-2z^4+2z^2]
    , _I(pb,
         _H.result(),
         Fp12_2over3over2_variable<FqkT>(pb, FMT(annotation_prefix, " H^z")),
         FMT(annotation_prefix, " _I"))
    // J = [-z+2]
    // K = [z^5-2z^4+2z^2-z+2]
    , _K(pb,
         _I.result(),
         _D.result().unitary_inverse(), // _J
         Fp12_2over3over2_variable<FqkT>(pb, FMT(annotation_prefix, " I*J")),
         FMT(annotation_prefix, " _K"))
    // L = [z^5-2z^4+2z^2-z+3] = [\lambda_0]
    , _L(pb,
         _K.result(),
         _in,
         Fp12_2over3over2_variable<FqkT>(pb, FMT(annotation_prefix, " K*in")),
         FMT(annotation_prefix, " _L"))
    // M = [-1]
    // N = [z^2-2z+1] = [\lambda_3]
    , _N(pb,
         _E.result(),
         _in,
         Fp12_2over3over2_variable<FqkT>(pb, FMT(annotation_prefix, " E*in")),
         FMT(annotation_prefix, " _N"))
    // O = [(z^2-2z+1) * (q^3)]
    // P = [z^4-2z^3+2z-1] = [\lambda_1]
    , _P(pb,
         _H.result(),
         _in.unitary_inverse(), // _M
         Fp12_2over3over2_variable<FqkT>(pb, FMT(annotation_prefix, " H*M")),
         FMT(annotation_prefix, " _P"))
    // Q = [(z^4-2z^3+2z-1) * q]
    // R = [z^3-2z^2+z] = [\lambda_2]
    , _R(pb,
         _F.result(),
         _B.result(),
         Fp12_2over3over2_variable<FqkT>(pb, FMT(annotation_prefix, " F*B")),
         FMT(annotation_prefix, " _R"))
    // S = [(z^3-2z^2+z) * (q^2)]
    // T = [(z^2-2z+1) * (q^3) + (z^3-2z^2+z) * (q^2)]
    , _T(pb,
         _N.result().frobenius_map(3), // _O
         _R.result().frobenius_map(2), // _S
         Fp12_2over3over2_variable<FqkT>(pb, FMT(annotation_prefix, " O*S")),
         FMT(annotation_prefix, " _T"))
    // U = [(z^2-2z+1) * (q^3) + (z^3-2z^2+z) * (q^2) + (z^4-2z^3+2z-1) * q]
    , _U(pb,
         _T.result(),
         _P.result().frobenius_map(1), // _Q
         Fp12_2over3over2_variable<FqkT>(pb, FMT(annotation_prefix, " T*Q")),
         FMT(annotation_prefix, " _U"))
    // result = [(z^2-2z+1) * (q^3) + (z^3-2z^2+z) * (q^2) + (z^4-2z^3+2z-1) * q
    //          + z^5-2z^4+2z^2-z+3]
    //        = [(p^4 - p^2 + 1)/r].
    , _U_times_L(
          pb,
          _U.result(),
          _L.result(),
          _result,
          FMT(annotation_prefix, " _U_times_L"))
{
}

template<typename ppT>
const Fp12_2over3over2_variable<libff::Fqk<other_curve<ppT>>>
    &bls12_377_final_exp_last_part_gadget<ppT>::result() const
{
    return _result;
}

template<typename ppT>
void bls12_377_final_exp_last_part_gadget<ppT>::generate_r1cs_constraints()
{
    _in_squared.generate_r1cs_constraints();
    _B.generate_r1cs_constraints();
    _C.generate_r1cs_constraints();
    _D.generate_r1cs_constraints();
    _E.generate_r1cs_constraints();
    _F.generate_r1cs_constraints();
    _G.generate_r1cs_constraints();
    _H.generate_r1cs_constraints();
    _I.generate_r1cs_constraints();
    _K.generate_r1cs_constraints();
    _L.generate_r1cs_constraints();
    _N.generate_r1cs_constraints();
    _P.generate_r1cs_constraints();
    _R.generate_r1cs_constraints();
    _T.generate_r1cs_constraints();
    _U.generate_r1cs_constraints();
    _U_times_L.generate_r1cs_constraints();
}

template<typename ppT>
void bls12_377_final_exp_last_part_gadget<ppT>::generate_r1cs_witness()
{
    _in_squared.generate_r1cs_witness();
    _B.generate_r1cs_witness();
    _C.generate_r1cs_witness();
    _D._A.evaluate();
    _D.generate_r1cs_witness();
    _E.generate_r1cs_witness();
    _F.generate_r1cs_witness();
    _G.generate_r1cs_witness();
    _H.generate_r1cs_witness();
    _I.generate_r1cs_witness();
    _K._B.evaluate();
    _K.generate_r1cs_witness();
    _L.generate_r1cs_witness();
    _N._A.evaluate();
    _N.generate_r1cs_witness();
    _P._B.evaluate();
    _P.generate_r1cs_witness();
    _R.generate_r1cs_witness();
    _T._A.evaluate();
    _T._B.evaluate();
    _T.generate_r1cs_witness();
    _U._B.evaluate();
    _U.generate_r1cs_witness();
    _U_times_L.generate_r1cs_witness();
}

// bls12_377_final_exp_gadget methods

template<typename ppT>
bls12_377_final_exp_gadget<ppT>::bls12_377_final_exp_gadget(
    libsnark::protoboard<libff::Fr<ppT>> &pb,
    const Fp12_2over3over2_variable<FqkT> &el,
    const libsnark::pb_variable<FieldT> &result_is_one,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , _first_part(
          pb,
          el,
          Fqk_variable<ppT>(pb, FMT(annotation_prefix, " _first_part_result")),
          FMT(annotation_prefix, " _first_part"))
    , _last_part(
          pb,
          _first_part.result(),
          Fqk_variable<ppT>(pb, FMT(annotation_prefix, " _last_part_result")),
          FMT(annotation_prefix, " _last_part"))
    , _result_is_one(result_is_one)
{
}

template<typename ppT>
void bls12_377_final_exp_gadget<ppT>::generate_r1cs_constraints()
{
    _first_part.generate_r1cs_constraints();
    _last_part.generate_r1cs_constraints();

    // Constrain result_is_one to be 0 or 1.
    libsnark::generate_boolean_r1cs_constraint<FieldT>(
        this->pb,
        _result_is_one,
        FMT(this->annotation_prefix, " result_is_one_boolean"));

    // Use the value of result_is_one to enable / disable the constraints on
    // the 12 components of the result of the final exponentiation in Fq12.
    Fqk_variable<ppT> result = _last_part.result();
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(
            _result_is_one, 1 - result._c0._c0.c0, 0),
        " c0.c0.c0==1");
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(_result_is_one, result._c0._c0.c1, 0),
        " c0.c0.c1==0");
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(_result_is_one, result._c0._c1.c0, 0),
        " c0.c1.c0==0");
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(_result_is_one, result._c0._c1.c1, 0),
        " c0.c1.c1==0");
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(_result_is_one, result._c0._c2.c0, 0),
        " c0.c2.c0==0");
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(_result_is_one, result._c0._c2.c1, 0),
        " c0.c2.c1==0");
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(_result_is_one, result._c1._c0.c0, 0),
        " c1.c0.c0==0");
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(_result_is_one, result._c1._c0.c1, 0),
        " c1.c0.c1==0");
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(_result_is_one, result._c1._c1.c0, 0),
        " c1.c1.c0==0");
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(_result_is_one, result._c1._c1.c1, 0),
        " c1.c1.c1==0");
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(_result_is_one, result._c1._c2.c0, 0),
        " c1.c2.c0==0");
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(_result_is_one, result._c1._c2.c1, 0),
        " c1.c2.c1==0");
}

template<typename ppT>
void bls12_377_final_exp_gadget<ppT>::generate_r1cs_witness()
{
    _first_part.generate_r1cs_witness();
    _last_part.generate_r1cs_witness();

    const FqkT result_val = _last_part.result().get_element();
    this->pb.val(_result_is_one) =
        (result_val == FqkT::one()) ? FieldT::one() : FieldT::zero();
}

template<typename ppT>
bls12_377_e_times_e_times_e_over_e_miller_loop_gadget<ppT>::
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
        const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , _f0(pb, FqkT::one(), FMT(annotation_prefix, "f0"))
    , _minus_P4_Y()
{
    _minus_P4_Y.assign(pb, -(*P4_prec._Py));
    size_t coeff_idx = 0;
    const Fp12_2over3over2_variable<FqkT> *f = &_f0;

    bls12_377_miller_loop_bits bits;
    while (bits.next()) {
        // f <- f^2
        _f_squared.emplace_back(new Fp12_2over3over2_square_gadget<FqkT>(
            pb,
            *f,
            Fp12_2over3over2_variable<FqkT>(pb, FMT(annotation_prefix, " f^2")),
            FMT(annotation_prefix, " _f_squared[%zu]", _f_squared.size())));
        f = &_f_squared.back()->result();

        // f <- f^2 * ell_Q1(P1)
        _f_ell_P.emplace_back(new bls12_377_ate_compute_f_ell_P<ppT>(
            pb,
            *P1_prec._Px,
            *P1_prec._Py,
            *Q1_prec._coeffs[coeff_idx],
            *f,
            Fp12_2over3over2_variable<FqkT>(
                pb, FMT(annotation_prefix, " f^2*ell_Q1(P1)")),
            FMT(annotation_prefix, " _f_ell_P1[%zu]", _f_ell_P.size())));
        f = &_f_ell_P.back()->result();

        // f <- f^2 * ell_Q2(P2)
        _f_ell_P.emplace_back(new bls12_377_ate_compute_f_ell_P<ppT>(
            pb,
            *P2_prec._Px,
            *P2_prec._Py,
            *Q2_prec._coeffs[coeff_idx],
            *f,
            Fp12_2over3over2_variable<FqkT>(
                pb, FMT(annotation_prefix, " f^2*ell_Q2(P2)")),
            FMT(annotation_prefix, " _f_ell_P[%zu]", _f_ell_P.size())));
        f = &_f_ell_P.back()->result();

        // f <- f^2 * ell_Q3(P3)
        _f_ell_P.emplace_back(new bls12_377_ate_compute_f_ell_P<ppT>(
            pb,
            *P3_prec._Px,
            *P3_prec._Py,
            *Q3_prec._coeffs[coeff_idx],
            *f,
            Fp12_2over3over2_variable<FqkT>(
                pb, FMT(annotation_prefix, " f^2*ell_Q3(P3)")),
            FMT(annotation_prefix, " _f_ell_P[%zu]", _f_ell_P.size())));
        f = &_f_ell_P.back()->result();

        // f <- f^2 * ell_Q1(P1)
        _f_ell_P.emplace_back(new bls12_377_ate_compute_f_ell_P<ppT>(
            pb,
            *P4_prec._Px,
            _minus_P4_Y,
            *Q4_prec._coeffs[coeff_idx],
            *f,
            Fp12_2over3over2_variable<FqkT>(
                pb, FMT(annotation_prefix, " f^2*ell_Q4(P4)")),
            FMT(annotation_prefix, " _f_ell_P[%zu]", _f_ell_P.size())));
        f = &_f_ell_P.back()->result();

        assert(0 == _f_ell_P.size() % 4);

        ++coeff_idx;

        if (bits.current()) {
            // f <- f * ell_Q1(P1)
            _f_ell_P.emplace_back(new bls12_377_ate_compute_f_ell_P<ppT>(
                pb,
                *P1_prec._Px,
                *P1_prec._Py,
                *Q1_prec._coeffs[coeff_idx],
                *f,
                Fp12_2over3over2_variable<FqkT>(
                    pb, FMT(annotation_prefix, " f*ell_Q1(P2)")),
                FMT(annotation_prefix, " _f_ell_P[%zu]", _f_ell_P.size())));
            f = &_f_ell_P.back()->result();

            // f <- f * ell_Q2(P2)
            _f_ell_P.emplace_back(new bls12_377_ate_compute_f_ell_P<ppT>(
                pb,
                *P2_prec._Px,
                *P2_prec._Py,
                *Q2_prec._coeffs[coeff_idx],
                *f,
                Fp12_2over3over2_variable<FqkT>(
                    pb, FMT(annotation_prefix, " f*ell_Q2(P2)")),
                FMT(annotation_prefix, " _f_ell_P[%zu]", _f_ell_P.size())));
            f = &_f_ell_P.back()->result();

            // f <- f * ell_Q3(P3)
            _f_ell_P.emplace_back(new bls12_377_ate_compute_f_ell_P<ppT>(
                pb,
                *P3_prec._Px,
                *P3_prec._Py,
                *Q3_prec._coeffs[coeff_idx],
                *f,
                Fp12_2over3over2_variable<FqkT>(
                    pb, FMT(annotation_prefix, " f*ell_Q3(P3)")),
                FMT(annotation_prefix, " _f_ell_P[%zu]", _f_ell_P.size())));
            f = &_f_ell_P.back()->result();

            // f <- f * ell_Q4(P4)
            if (bits.last()) {
                _f_ell_P.emplace_back(
                    std::shared_ptr<bls12_377_ate_compute_f_ell_P<ppT>>(
                        new bls12_377_ate_compute_f_ell_P<ppT>(
                            pb,
                            *P4_prec._Px,
                            _minus_P4_Y,
                            *Q4_prec._coeffs[coeff_idx],
                            *f,
                            result,
                            FMT(annotation_prefix,
                                " _f_ell_P[%zu]",
                                _f_ell_P.size()))));
            } else {
                _f_ell_P.emplace_back(new bls12_377_ate_compute_f_ell_P<ppT>(
                    pb,
                    *P4_prec._Px,
                    _minus_P4_Y,
                    *Q4_prec._coeffs[coeff_idx],
                    *f,
                    Fp12_2over3over2_variable<FqkT>(
                        pb, FMT(annotation_prefix, " f*ell_Q4(P4)")),
                    FMT(annotation_prefix, " _f_ell_P[%zu]", _f_ell_P.size())));
            }
            f = &_f_ell_P.back()->result();

            assert(0 == _f_ell_P.size() % 4);

            ++coeff_idx;
        }
    }
}

template<typename ppT>
void bls12_377_e_times_e_times_e_over_e_miller_loop_gadget<
    ppT>::generate_r1cs_constraints()
{
    size_t sqr_idx = 0;
    size_t f_ell_P_idx = 0;
    bls12_377_miller_loop_bits bits;
    while (bits.next()) {
        _f_squared[sqr_idx++]->generate_r1cs_constraints();
        _f_ell_P[f_ell_P_idx++]->generate_r1cs_constraints();
        _f_ell_P[f_ell_P_idx++]->generate_r1cs_constraints();
        _f_ell_P[f_ell_P_idx++]->generate_r1cs_constraints();
        _f_ell_P[f_ell_P_idx++]->generate_r1cs_constraints();
        if (bits.current()) {
            _f_ell_P[f_ell_P_idx++]->generate_r1cs_constraints();
            _f_ell_P[f_ell_P_idx++]->generate_r1cs_constraints();
            _f_ell_P[f_ell_P_idx++]->generate_r1cs_constraints();
            _f_ell_P[f_ell_P_idx++]->generate_r1cs_constraints();
        }
    }

    assert(sqr_idx == _f_squared.size());
    assert(f_ell_P_idx == _f_ell_P.size());
}

template<typename ppT>
void bls12_377_e_times_e_times_e_over_e_miller_loop_gadget<
    ppT>::generate_r1cs_witness()
{
    _minus_P4_Y.evaluate(this->pb);
    size_t sqr_idx = 0;
    size_t f_ell_P_idx = 0;
    bls12_377_miller_loop_bits bits;
    while (bits.next()) {
        _f_squared[sqr_idx++]->generate_r1cs_witness();
        _f_ell_P[f_ell_P_idx++]->generate_r1cs_witness();
        _f_ell_P[f_ell_P_idx++]->generate_r1cs_witness();
        _f_ell_P[f_ell_P_idx++]->generate_r1cs_witness();
        _f_ell_P[f_ell_P_idx++]->generate_r1cs_witness();
        if (bits.current()) {
            _f_ell_P[f_ell_P_idx++]->generate_r1cs_witness();
            _f_ell_P[f_ell_P_idx++]->generate_r1cs_witness();
            _f_ell_P[f_ell_P_idx++]->generate_r1cs_witness();
            _f_ell_P[f_ell_P_idx++]->generate_r1cs_witness();
        }
    }

    assert(sqr_idx == _f_squared.size());
    assert(f_ell_P_idx == _f_ell_P.size());
}

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_PAIRING_BLS12_377_PAIRING_TCC__
