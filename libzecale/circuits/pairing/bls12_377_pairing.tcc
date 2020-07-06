// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_PAIRING_BLS12_377_PAIRING_TCC__
#define __ZECALE_CIRCUITS_PAIRING_BLS12_377_PAIRING_TCC__

#include "libzecale/circuits/pairing/bls12_377_pairing.hpp"

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

private:
    ssize_t _i;
};

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

template<typename ppT> void bls12_377_G2_proj<ppT>::evaluate() const
{
    X.evaluate();
    Y.evaluate();
    Z.evaluate();
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
    const Fqe_variable<ppT> &ell_0,
    const Fqe_variable<ppT> &ell_vw,
    const Fqe_variable<ppT> &ell_vv)
    : ell_0(ell_0), ell_vw(ell_vw), ell_vv(ell_vv)
{
}

template<typename ppT> void bls12_377_ate_ell_coeffs<ppT>::evaluate() const
{
    ell_0.evaluate();
    ell_vw.evaluate();
    ell_vv.evaluate();
}

// bls12_377_ate_dbl_gadget methods

template<typename ppT>
bls12_377_ate_dbl_gadget<ppT>::bls12_377_ate_dbl_gadget(
    libsnark::protoboard<FqT> &pb,
    const bls12_377_G2_proj<ppT> &R,
    const std::string &annotation_prefix)
    : libsnark::gadget<libff::Fr<ppT>>(pb, annotation_prefix)
    , in_R(R)
    , out_R(pb, " R")

    // A = Rx * Ry / 2
    , A(pb, FMT(annotation_prefix, " A"))
    , check_A(
          pb, in_R.X, in_R.Y, A * FqT(2), FMT(annotation_prefix, " check_A"))

    // B = Ry^2
    , B(pb, FMT(annotation_prefix, " B"))
    , check_B(pb, in_R.Y, B, FMT(annotation_prefix, " check_B"))

    // C = Rz^2
    , C(pb, FMT(annotation_prefix, " C"))
    , check_C(pb, in_R.Z, C, FMT(annotation_prefix, "check_C"))

    // D = 3 * C
    // , D(C * FqT(3))

    // E = b' * D
    , E((C * libff::Fr<ppT>(3)) * libff::bls12_377_twist_coeff_b)

    // F = 3 * E
    , F(E + E + E)

    // G = (B + F) / 2  (added manually)
    , G(pb, FMT(annotation_prefix, " G"))

    // H = (Y + Z) ^ 2 - (B + C)
    , H(pb, FMT(annotation_prefix, " H"))
    // check: (Y + Z)^2 == H + B + C
    , Y_plus_Z(in_R.Y + in_R.Z)
    , H_plus_B_plus_C(H + B + C)
    , check_H(pb, Y_plus_Z, H_plus_B_plus_C, FMT(annotation_prefix, " check_H"))

    // I = (E - B)
    , I(E + (B * -libff::Fr<ppT>::one()))

    // J = Rx^2
    , J(pb, FMT(annotation_prefix, " J"))
    , check_J(pb, in_R.X, J, FMT(annotation_prefix, " check_J"))

    , E_squared(pb, FMT(annotation_prefix, " E^2"))
    , check_E_squared(
          pb, E, E_squared, FMT(annotation_prefix, " check_E_squared"))

    , G_squared(pb, FMT(annotation_prefix, " G^2"))
    , check_G_squared(
          pb, G, G_squared, FMT(annotation_prefix, " check_G_squared"))

    , B_minus_F(B + (F * -libff::Fr<ppT>::one()))

    // outRx = A * (B-F)
    , check_out_Rx(
          pb, A, B_minus_F, out_R.X, FMT(annotation_prefix, " check_out_Rx"))

    // outRy = G^2 - 3E^2
    // check: outRy + E^2 + E^2 + E^2 == G^2  (TODO: not required)
    , G_squared_minus_3_E_squared(
          G_squared + (E_squared * -libff::Fr<ppT>("3")))
    , check_out_Ry(
          pb,
          G_squared_minus_3_E_squared,
          {0}, // one
          out_R.Y,
          FMT(annotation_prefix, " check_out_Ry"))

    , check_out_Rz(pb, B, H, out_R.Z, FMT(annotation_prefix, " check_out_Rz"))

    // ell_0 = xi * I
    // ell_vw = -H
    // ell_vv = 3 * J
    , out_coeffs(
          I * libff::bls12_377_twist,
          H * -libff::Fr<ppT>(1),
          J * libff::Fr<ppT>(3))
{
}

template<typename ppT>
void bls12_377_ate_dbl_gadget<ppT>::generate_r1cs_constraints()
{
    check_A.generate_r1cs_constraints();
    check_B.generate_r1cs_constraints();
    check_C.generate_r1cs_constraints();

    // D = 3 * C
    // E = b' * D
    //   = b' * (C + C + C)  (2 constraints for mul by Fq2 constant)
    // F = 3 * E

    // G = (B + F) / 2 checked as 2 * G == B + F
    this->pb.add_r1cs_constraint(
        {1, 2 * G.c0, B.c0 + F.c0},
        FMT(this->annotation_prefix, " check_G.c0"));
    this->pb.add_r1cs_constraint(
        {1, 2 * G.c1, B.c1 + F.c1},
        FMT(this->annotation_prefix, " check_G.c1"));

    // H = (Y + Z) ^ 2 - (B + C)
    check_H.generate_r1cs_constraints();

    // I = E - B
    // J = Rx^2
    check_J.generate_r1cs_constraints();

    // E_squared
    check_E_squared.generate_r1cs_constraints();

    // G_squared
    check_G_squared.generate_r1cs_constraints();

    // B_minus_F
    // check_B_minus_F.generate_r1cs_constraints();

    // outRx = A * (B - F)
    check_out_Rx.generate_r1cs_constraints();

    // outRy = G^2 - 3 * E^2
    check_out_Ry.generate_r1cs_constraints();

    // outRz = B * H
    check_out_Rz.generate_r1cs_constraints();

    // There are just linear combinations, so no need for constraints:
    // ell_0 = xi * I
    // ell_vw = -H
    // ell_vv = 3 * J
}

template<typename ppT>
void bls12_377_ate_dbl_gadget<ppT>::generate_r1cs_witness(
    const libff::Fr<ppT> &two_inv)
{
    const FqeT Rx = in_R.X.get_element();
    const FqeT Ry = in_R.Y.get_element();
    const FqeT Rz = in_R.Z.get_element();

    // A = Rx * Ry / 2
    A.generate_r1cs_witness(two_inv * Rx * Ry);
    check_A.generate_r1cs_witness();

    // B = Ry^2
    check_B.generate_r1cs_witness();

    // C = Rz^2
    check_C.generate_r1cs_witness();

    // D = 3 * C
    // D.generate_r1cs_witness();

    // E = b' * D
    E.evaluate();
    assert(
        E.get_element() ==
        libff::Fr<ppT>(3) * C.get_element() * libff::bls12_377_twist_coeff_b);

    // F = 3 * E (linear comb)
    F.evaluate();
    assert(F.get_element() == libff::Fr<ppT>(3) * E.get_element());

    // G = (B + F) / 2
    G.generate_r1cs_witness(two_inv * (B.get_element() + F.get_element()));

    // H = (Y + Z) ^ 2 - (B + C)
    const FqeT Y_plus_Z_squared = (Ry + Rz).squared();
    H.generate_r1cs_witness(
        Y_plus_Z_squared - B.get_element() - C.get_element());
    check_H.generate_r1cs_witness();

    // I = E - B
    I.evaluate();

    // J = Rx^2
    check_J.generate_r1cs_witness();

    // E^2
    check_E_squared.generate_r1cs_witness();

    // G^2
    check_G_squared.generate_r1cs_witness();

    // out_Rx = A * (B - F) (assigned by check_outRx)
    B_minus_F.evaluate();
    assert(B.get_element() - F.get_element() == B_minus_F.get_element());
    check_out_Rx.generate_r1cs_witness();

    // out_Ry = G^2 - 3 * E^2
    G_squared_minus_3_E_squared.evaluate();
    check_out_Ry.generate_r1cs_witness();

    // out_Rz = B * H (assigned by check_outRz)
    check_out_Rz.generate_r1cs_witness();

    // ell_0 = xi * I (assigned by check_ell_0)
    // ell_vw = -H
    // ell_vv = 3 * J
    out_coeffs.evaluate();
}

// bls12_377_ate_add_gadget methods

template<typename ppT>
bls12_377_ate_add_gadget<ppT>::bls12_377_ate_add_gadget(
    libsnark::protoboard<libff::Fr<ppT>> &pb,
    const Fqe_variable<ppT> &in_Q_X,
    const Fqe_variable<ppT> &in_Q_Y,
    const bls12_377_G2_proj<ppT> &R,
    const std::string &annotation_prefix)
    : libsnark::gadget<libff::Fr<ppT>>(pb, annotation_prefix)
    , Q_X(in_Q_X)
    , Q_Y(in_Q_Y)
    , in_R(R)

    // A = Qy * Rz
    , A(pb, FMT(annotation_prefix, " A"))
    , check_A(pb, Q_Y, in_R.Z, A, FMT(annotation_prefix, " check_A"))
    // B = Qx * Rz;
    , B(pb, FMT(annotation_prefix, " B"))
    , check_B(pb, Q_X, in_R.Z, B, FMT(annotation_prefix, " check_B"))
    // theta = Ry - A;
    , theta(in_R.Y + (A * -libff::Fr<ppT>::one()))
    // lambda = Rx - B;
    , lambda(in_R.X + (B * -libff::Fr<ppT>::one()))
    // C = theta.squared();
    , C(pb, FMT(annotation_prefix, " C"))
    , check_C(pb, theta, C, FMT(annotation_prefix, " check_C"))
    // D = lambda.squared();
    , D(pb, FMT(annotation_prefix, " D"))
    , check_D(pb, lambda, D, FMT(annotation_prefix, " check_D"))
    // E = lambda * D;
    , E(pb, FMT(annotation_prefix, " E"))
    , check_E(pb, lambda, D, E, FMT(annotation_prefix, " check_E"))
    // F = Rz * C;
    , F(pb, FMT(annotation_prefix, " F"))
    , check_F(pb, in_R.Z, C, F, FMT(annotation_prefix, " check_F"))
    // G = Rx * D;
    , G(pb, FMT(annotation_prefix, " G"))
    , check_G(pb, in_R.X, D, G, FMT(annotation_prefix, " check_G"))
    // H = E + F - (G + G);
    , H(E + F + (G * -libff::Fr<ppT>(2)))
    // I = Ry * E;
    , I(pb, FMT(annotation_prefix, " I"))
    , check_I(pb, in_R.Y, E, I, FMT(annotation_prefix, " check_I"))
    // J = theta * Qx - lambda * Qy;
    , theta_times_Qx(pb, FMT(annotation_prefix, " theta_times_Qx"))
    , check_theta_times_Qx(
          pb,
          theta,
          Q_X,
          theta_times_Qx,
          FMT(annotation_prefix, " check_theta_times_Qx"))
    , lambda_times_Qy(pb, FMT(annotation_prefix, " lambda_times_Qy"))
    , check_lambda_times_Qy(
          pb,
          lambda,
          Q_Y,
          lambda_times_Qy,
          FMT(annotation_prefix, " check_lambda_times_Qy"))
    , J(theta_times_Qx + (lambda_times_Qy * -libff::Fr<ppT>::one()))

    // out_Rx = lambda * H;
    , out_Rx(pb, FMT(annotation_prefix, " out_Rx"))
    , check_out_Rx(
          pb, lambda, H, out_Rx, FMT(annotation_prefix, " check out_Rx"))
    // out_Ry = theta * (G - H) - I;
    , G_minus_H(G + (H * -libff::Fr<ppT>::one()))
    , theta_times_G_minus_H(
          pb, FMT(annotation_prefix, " theta_times_G_minus_H"))
    , check_theta_times_G_minus_H(
          pb,
          theta,
          G_minus_H,
          theta_times_G_minus_H,
          FMT(annotation_prefix, " check_theta_times_G_minus_H"))
    // out_Rz = Rza * E;
    , out_Rz(pb, FMT(annotation_prefix, " out_Rz"))
    , check_out_Rz(pb, in_R.Z, E, out_Rz, FMT(annotation_prefix, " check_Rz"))

    , out_R(
          out_Rx, theta_times_G_minus_H + (I * -libff::Fr<ppT>::one()), out_Rz)

    // out_coeffs.ell_0 = xi * J;
    // out_coeffs.ell_vw = lambda;
    // out_coeffs.ell_vv = -theta;
    , out_coeffs(
          J * libff::bls12_377_twist, lambda, theta * -libff::Fr<ppT>::one())
{
}

template<typename ppT>
void bls12_377_ate_add_gadget<ppT>::generate_r1cs_constraints()
{
    // A = Ry * Rz  (A assigned by check_A)
    check_A.generate_r1cs_constraints();
    // B = Rx * Rz  (B assigned by check_B)
    check_B.generate_r1cs_constraints();
    // theta = Ry - A;
    // lambda = Rx - B;
    // C = theta.squared()  (C assigned by check_C)
    check_C.generate_r1cs_constraints();
    // D = lambda.squared();
    check_D.generate_r1cs_constraints();
    // E = lambda * D;
    check_E.generate_r1cs_constraints();
    // F = Rz * C;
    check_F.generate_r1cs_constraints();
    // G = Rx * D;
    check_G.generate_r1cs_constraints();
    // H = E + F - (G + G);
    // I = Ry * E;
    check_I.generate_r1cs_constraints();
    // J = theta * Qx - lambda * Qy;
    check_theta_times_Qx.generate_r1cs_constraints();
    check_lambda_times_Qy.generate_r1cs_constraints();
    // out_Rx = lambda * H;
    check_out_Rx.generate_r1cs_constraints();
    // out_Ry = theta * (G - H) - I;
    check_theta_times_G_minus_H.generate_r1cs_constraints();
    // out_Rz = Z1 * E;
    check_out_Rz.generate_r1cs_constraints();
    // out_coeffs.ell_0 = xi * J;
    // out_coeffs.ell_VV = -theta;
    // out_coeffs.ell_VW = lambda;
}

template<typename ppT>
void bls12_377_ate_add_gadget<ppT>::generate_r1cs_witness()
{
    // A = Ry * Rz  (A assigned by check_A)
    check_A.generate_r1cs_witness();
    // B = Rx * Rz  (B assigned by check_B)
    check_B.generate_r1cs_witness();
    // theta = Ry - A;
    theta.evaluate();
    // lambda = Rx - B;
    lambda.evaluate();
    // C = theta.squared()  (C assigned by check_C)
    check_C.generate_r1cs_witness();
    // D = lambda.squared()  (D assigned by check_D)
    check_D.generate_r1cs_witness();
    // E = lambda * D  (E assigned by check_E)
    check_E.generate_r1cs_witness();
    // F = Rz * C  (F assigned by check_F)
    check_F.generate_r1cs_witness();
    // G = Rx * D;
    check_G.generate_r1cs_witness();
    // H = E + F - (G + G);
    H.evaluate();
    // I = Ry * E  (I assigned by check_I)
    check_I.generate_r1cs_witness();
    // J = theta * Qx - lambda * Qy;
    check_theta_times_Qx.generate_r1cs_witness();
    check_lambda_times_Qy.generate_r1cs_witness();
    J.evaluate();

    // out_Rx = lambda * H (assigned by check_out_Rx)
    check_out_Rx.generate_r1cs_witness();
    // out_Ry = theta * (G - H) - I;
    G_minus_H.evaluate();
    check_theta_times_G_minus_H.generate_r1cs_witness();
    // out_Rz = Z1 * E (assigned by check_out_Rz)
    check_out_Rz.generate_r1cs_witness();
    out_R.evaluate();

    // out_coeffs.ell_0 = xi * J;
    // out_coeffs.ell_vw = lambda;
    // out_coeffs.ell_vv = -theta;
    out_coeffs.evaluate();
}

// bls12_377_ate_precompute methods

template<typename ppT>
bls12_377_ate_precompute_gadget<ppT>::bls12_377_ate_precompute_gadget(
    libsnark::protoboard<libff::Fr<ppT>> &pb,
    const Fqe_variable<ppT> &Qx,
    const Fqe_variable<ppT> &Qy,
    const std::string &annotation_prefix)
    : libsnark::gadget<libff::Fr<ppT>>(pb, annotation_prefix)
    , _Qx(Qx)
    , _Qy(Qy)
    , _R0(Qx, Qy, Fqe_variable<ppT>(pb, FqeT::one(), "Fqe(1)"))
{
    // Track the R variable at each step. Initially it is _R0;
    const bls12_377_G2_proj<ppT> *currentR = &_R0;

    // Iterate through bits of loop_count
    bls12_377_miller_loop_bits bits;
    while (bits.next()) {
        _ate_dbls.push_back(std::shared_ptr<bls12_377_ate_dbl_gadget<ppT>>(
            new bls12_377_ate_dbl_gadget<ppT>(
                pb,
                *currentR,
                FMT(annotation_prefix, " dbls[%zu]", bits.index()))));
        currentR = &_ate_dbls.back()->out_R;

        if (bits.current()) {
            _ate_adds.push_back(std::shared_ptr<bls12_377_ate_add_gadget<ppT>>(
                new bls12_377_ate_add_gadget<ppT>(
                    pb,
                    _Qx,
                    _Qy,
                    *currentR,
                    FMT(annotation_prefix, " adds[%zu]", bits.index()))));
            currentR = &_ate_adds.back()->out_R;
        }
    }
}

template<typename ppT>
void bls12_377_ate_precompute_gadget<ppT>::generate_r1cs_constraints()
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
void bls12_377_ate_precompute_gadget<ppT>::generate_r1cs_witness()
{
    _R0.evaluate();

    const libff::bls12_377_Fq two_inv = libff::bls12_377_Fq("2").inverse();

    size_t dbl_idx = 0;
    size_t add_idx = 0;
    bls12_377_miller_loop_bits bits;
    while (bits.next()) {
        _ate_dbls[dbl_idx++]->generate_r1cs_witness(two_inv);
        if (bits.current()) {
            _ate_adds[add_idx++]->generate_r1cs_witness();
        }
    }
}

// bls12_377_ate_compute_f_ell_P methods

template<typename ppT>
bls12_377_ate_compute_f_ell_P<ppT>::bls12_377_ate_compute_f_ell_P(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable<FieldT> &Px,
    const libsnark::pb_variable<FieldT> &Py,
    const bls12_377_ate_ell_coeffs<ppT> &ell_coeffs,
    const Fp12_2over3over2_variable<FqkT> &f,
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
          Fp12_2over3over2_variable<FqkT>(pb, FMT(annotation_prefix, " new_f")),
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

// bls12_377_ate_miller_loop_gadget methods

template<typename ppT>
bls12_377_ate_miller_loop_gadget<ppT>::bls12_377_ate_miller_loop_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable<FieldT> &Px,
    const libsnark::pb_variable<FieldT> &Py,
    const Fqe_variable<ppT> &Qx,
    const Fqe_variable<ppT> &Qy,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , _Px(Px)
    , _Py(Py)
    , _Qx(Qx)
    , _Qy(Qy)
    , _Q_precomp(pb, Qx, Qy, FMT(annotation_prefix, " _Q_precomp"))
    , _f0(pb, FqkT::one(), FMT(annotation_prefix, " f0"))
{
    const std::vector<std::shared_ptr<bls12_377_ate_dbl_gadget<ppT>>>
        &ate_dbls = _Q_precomp._ate_dbls;
    const std::vector<std::shared_ptr<bls12_377_ate_add_gadget<ppT>>>
        &ate_adds = _Q_precomp._ate_adds;

    size_t dbl_idx = 0;
    size_t add_idx = 0;

    const Fp12_2over3over2_variable<FqkT> *f = &_f0;

    bls12_377_miller_loop_bits bits;
    while (bits.next()) {
        // f <- f^2
        Fp12_2over3over2_variable<FqkT> f_squared(
            pb, FMT(annotation_prefix, " f^2"));
        _f_squared.push_back(
            std::shared_ptr<Fp12_2over3over2_square_gadget<FqkT>>(
                new Fp12_2over3over2_square_gadget<FqkT>(
                    pb,
                    *f,
                    f_squared,
                    FMT(annotation_prefix, " compute_f^2"))));

        // f <- f^2 * ell(P)
        _f_ell_P.push_back(std::shared_ptr<bls12_377_ate_compute_f_ell_P<ppT>>(
            new bls12_377_ate_compute_f_ell_P<ppT>(
                pb,
                Px,
                Py,
                ate_dbls[dbl_idx++]->out_coeffs,
                f_squared,
                FMT(annotation_prefix, " f^2*ell(P)"))));
        f = &_f_ell_P.back()->result();

        if (bits.current()) {
            // f <- f * ell(P)
            _f_ell_P.push_back(
                std::shared_ptr<bls12_377_ate_compute_f_ell_P<ppT>>(
                    new bls12_377_ate_compute_f_ell_P<ppT>(
                        pb,
                        Px,
                        Py,
                        ate_adds[add_idx++]->out_coeffs,
                        *f,
                        FMT(annotation_prefix, " f*ell(P)"))));
            f = &_f_ell_P.back()->result();
        }
    }
}

template<typename ppT>
const Fp12_2over3over2_variable<libff::Fqk<other_curve<ppT>>>
    &bls12_377_ate_miller_loop_gadget<ppT>::result() const
{
    return _f_ell_P.back()->result();
}

template<typename ppT>
void bls12_377_ate_miller_loop_gadget<ppT>::generate_r1cs_constraints()
{
    // Precompute step
    _Q_precomp.generate_r1cs_constraints();

    // TODO: everything is allocated, so constraint generation does not need to
    // be done in this order. For now, keep a consistent loop.

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
void bls12_377_ate_miller_loop_gadget<ppT>::generate_r1cs_witness()
{
    // Precompute step
    _Q_precomp.generate_r1cs_witness();

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

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_PAIRING_BLS12_377_PAIRING_TCC__
