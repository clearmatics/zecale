// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CIRCUITS_PAIRING_BLS12_377_PAIRING_HPP__
#define __ZECALE_CIRCUITS_PAIRING_BLS12_377_PAIRING_HPP__

#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>
#include <libsnark/gadgetlib1/gadgets/fields/fp2_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/pairing_params.hpp>

namespace libzecale
{

/// Holds an element of G2 in homogeneous projective form. Used for
/// intermediate values of R in the miller loop.
template<typename ppT> class bls12_377_G2_proj
{
public:
    libsnark::Fqe_variable<ppT> X;
    libsnark::Fqe_variable<ppT> Y;
    libsnark::Fqe_variable<ppT> Z;

    bls12_377_G2_proj(
        libsnark::protoboard<libff::Fr<ppT>> &pb,
        const std::string &annotation_prefix)
        : X(pb, FMT(annotation_prefix, " X"))
        , Y(pb, FMT(annotation_prefix, " Y"))
        , Z(pb, FMT(annotation_prefix, " Z"))
    {
    }

    bls12_377_G2_proj(
        const libsnark::Fqe_variable<ppT> &X_var,
        const libsnark::Fqe_variable<ppT> &Y_var,
        const libsnark::Fqe_variable<ppT> &Z_var)
        : X(X_var), Y(Y_var), Z(Z_var)
    {
    }

    void evaluate() const
    {
        X.evaluate();
        Y.evaluate();
        Z.evaluate();
    }

    void generate_r1cs_witness(const libff::bls12_377_G2 &element)
    {
        X.generate_r1cs_witness(element.X);
        Y.generate_r1cs_witness(element.Y);
        Z.generate_r1cs_witness(element.Z);
    }
};

/// Not a gadget - holds the variables for the Fq2 coefficients of the tangent
/// line at some R, used during the doubling step.
template<typename ppT> class bls12_377_ate_ell_coeffs
{
public:
    const libsnark::Fqe_variable<ppT> ell_0;
    const libsnark::Fqe_variable<ppT> ell_vw;
    const libsnark::Fqe_variable<ppT> ell_vv;

    bls12_377_ate_ell_coeffs(
        const libsnark::Fqe_variable<ppT> &ell_0,
        const libsnark::Fqe_variable<ppT> &ell_vw,
        const libsnark::Fqe_variable<ppT> &ell_vv)
        : ell_0(ell_0), ell_vw(ell_vw), ell_vv(ell_vv)
    {
    }

    void evaluate() const
    {
        ell_0.evaluate();
        ell_vw.evaluate();
        ell_vv.evaluate();
    }
};

/// Gadget that relates some "current" bls12_377_G2_proj value in_R with the
/// result of the doubling step, that is some bls12_377_G2_proj out_R and the
/// bls12_377_ate_ell_coeffs holding the coefficients of the tangent at in_R.
/// Note that the output variables are allocated by this gadget.
template<typename ppT>
class bls12_377_ate_dbl_gadget : libsnark::gadget<libff::Fr<ppT>>
{
public:
    typedef libff::Fq<libsnark::other_curve<ppT>> FqT;
    typedef libff::Fqe<libsnark::other_curve<ppT>> FqeT;

    bls12_377_G2_proj<ppT> in_R;
    bls12_377_G2_proj<ppT> out_R;

    // A = Rx * Ry / 2
    libsnark::Fqe_variable<ppT> A;
    libsnark::Fqe_mul_gadget<ppT> check_A; // Rx * Ry = 2_times_A

    // B = Ry^2
    libsnark::Fqe_variable<ppT> B;
    libsnark::Fqe_sqr_gadget<ppT> check_B; // Ry^2 == B

    // C = Rz^2
    libsnark::Fqe_variable<ppT> C;
    libsnark::Fqe_sqr_gadget<ppT> check_C; // Rz^2 == C

    // D = 3 * C
    // libsnark::Fqe_variable<ppT> D;

    // E = b' * D
    libsnark::Fqe_variable<ppT> E;

    // F = 3 * E
    libsnark::Fqe_variable<ppT> F;

    // G = (B + F) / 2
    libsnark::Fqe_variable<ppT> G;
    // libsnark::Fqe_mul_by_lc_gadget<ppT> check_G; // 2 * G == B + F

    // H = (Y + 2) ^ 2 - (B + C)
    libsnark::Fqe_variable<ppT> H;
    libsnark::Fqe_variable<ppT> Y_plus_Z;
    libsnark::Fqe_variable<ppT> H_plus_B_plus_C;
    libsnark::Fqe_sqr_gadget<ppT> check_H; // Y_plus_Z^2 == H + B + C

    // I = E - B
    libsnark::Fqe_variable<ppT> I;

    // J = Rx^2
    libsnark::Fqe_variable<ppT> J;
    libsnark::Fqe_sqr_gadget<ppT> check_J; // Rx^2 == J

    // E^2
    libsnark::Fqe_variable<ppT> E_squared;
    libsnark::Fqe_sqr_gadget<ppT> check_E_squared;

    // G^2
    libsnark::Fqe_variable<ppT> G_squared;
    libsnark::Fqe_sqr_gadget<ppT> check_G_squared;

    // B - F
    libsnark::Fqe_variable<ppT> B_minus_F;

    // outRx = A * (B - F)
    libsnark::Fqe_mul_gadget<ppT> check_out_Rx;

    // outRy = G^2 - 3 * E^2
    // check: 1 * G_squared_minus_3_E_squared == outRy
    libsnark::Fqe_variable<ppT> G_squared_minus_3_E_squared;
    libsnark::Fqe_mul_by_lc_gadget<ppT> check_out_Ry;

    // outRz = B * H
    libsnark::Fqe_mul_gadget<ppT> check_out_Rz;

    // ell_0 = xi * I
    // ell_vw = -H
    // ell_vv = 3 * J
    bls12_377_ate_ell_coeffs<ppT> out_coeffs;

    bls12_377_ate_dbl_gadget(
        libsnark::protoboard<FqT> &pb,
        const bls12_377_G2_proj<ppT> &R,
        const std::string &annotation_prefix)
        : libsnark::gadget<libff::Fr<ppT>>(pb, annotation_prefix)
        , in_R(R)
        , out_R(pb, " R")

        // A = Rx * Ry / 2
        , A(pb, FMT(annotation_prefix, " A"))
        , check_A(
              pb,
              in_R.X,
              in_R.Y,
              A * FqT(2),
              FMT(annotation_prefix, " check_A"))

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
        , check_H(
              pb, Y_plus_Z, H_plus_B_plus_C, FMT(annotation_prefix, " check H"))

        // I = (E - B)
        , I(E + (B * -libff::Fr<ppT>::one()))

        // J = Rx^2
        , J(pb, FMT(annotation_prefix, " J"))
        , check_J(pb, in_R.X, J, FMT(annotation_prefix, " check Rx^2"))

        , E_squared(pb, FMT(annotation_prefix, " E^2"))
        , check_E_squared(
              pb, E, E_squared, FMT(annotation_prefix, " check E^2"))

        , G_squared(pb, FMT(annotation_prefix, " G^2"))
        , check_G_squared(
              pb, G, G_squared, FMT(annotation_prefix, " check G^2"))

        , B_minus_F(B + (F * -libff::Fr<ppT>::one()))

        // outRx = A * (B-F)
        , check_out_Rx(
              pb, A, B_minus_F, out_R.X, FMT(annotation_prefix, " check outRx"))

        // outRy = G^2 - 3E^2
        // check: outRy + E^2 + E^2 + E^2 == G^2  (TODO: not required)
        , G_squared_minus_3_E_squared(
              G_squared + (E_squared * -libff::Fr<ppT>("3")))
        , check_out_Ry(
              pb,
              G_squared_minus_3_E_squared,
              {0}, // one
              out_R.Y,
              FMT(annotation_prefix, " check outRy"))

        , check_out_Rz(
              pb, B, H, out_R.Z, FMT(annotation_prefix, " check outRz"))

        // ell_0 = xi * I
        // ell_vw = -H
        // ell_vv = 3 * J
        , out_coeffs(
              I * libff::bls12_377_twist,
              H * -libff::Fr<ppT>(1),
              J * libff::Fr<ppT>(3))
    {
    }

    void generate_r1cs_constraints()
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
            FMT(this->annotation_prefix, " check G.c0"));
        this->pb.add_r1cs_constraint(
            {1, 2 * G.c1, B.c1 + F.c1},
            FMT(this->annotation_prefix, " check G.c1"));

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

    // R should already be assigned. Computes all internal values and
    // outResult.
    void generate_r1cs_witness(const libff::Fr<ppT> &two_inv)
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
            E.get_element() == libff::Fr<ppT>(3) * C.get_element() *
                                   libff::bls12_377_twist_coeff_b);

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
};

template<typename ppT>
class bls12_377_ate_add_gadget : public libsnark::gadget<libff::Fr<ppT>>
{
public:
    typedef libff::Fq<libsnark::other_curve<ppT>> FqT;
    typedef libff::Fqe<libsnark::other_curve<ppT>> FqeT;

    libsnark::Fqe_variable<ppT> base_X;
    libsnark::Fqe_variable<ppT> base_Y;
    bls12_377_G2_proj<ppT> in_R;

    // A = Qy * Rz;
    libsnark::Fqe_variable<ppT> A;
    libsnark::Fqe_mul_gadget<ppT> check_A;
    // B = Qx * Rz;
    libsnark::Fqe_variable<ppT> B;
    libsnark::Fqe_mul_gadget<ppT> check_B;
    // theta = Ry - A;
    libsnark::Fqe_variable<ppT> theta;
    // lambda = Rx - B;
    libsnark::Fqe_variable<ppT> lambda;
    // C = theta.squared();
    libsnark::Fqe_variable<ppT> C;
    libsnark::Fqe_sqr_gadget<ppT> check_C;
    // D = lambda.squared();
    libsnark::Fqe_variable<ppT> D;
    libsnark::Fqe_sqr_gadget<ppT> check_D;
    // E = lambda * D;
    libsnark::Fqe_variable<ppT> E;
    libsnark::Fqe_mul_gadget<ppT> check_E;
    // F = Rz * C;
    libsnark::Fqe_variable<ppT> F;
    libsnark::Fqe_mul_gadget<ppT> check_F;
    // G = Rx * D;
    libsnark::Fqe_variable<ppT> G;
    libsnark::Fqe_mul_gadget<ppT> check_G;
    // H = E + F - (G + G);
    libsnark::Fqe_variable<ppT> H;
    // I = Ry * E;
    libsnark::Fqe_variable<ppT> I;
    libsnark::Fqe_mul_gadget<ppT> check_I;
    // J = theta * Qx - lambda * Qy;
    libsnark::Fqe_variable<ppT> theta_times_Qx;
    libsnark::Fqe_mul_gadget<ppT> check_theta_times_Qx;
    libsnark::Fqe_variable<ppT> lambda_times_Qy;
    libsnark::Fqe_mul_gadget<ppT> check_lambda_times_Qy;
    libsnark::Fqe_variable<ppT> J;

    // out_Rx = lambda * H;
    libsnark::Fqe_variable<ppT> out_Rx;
    libsnark::Fqe_mul_gadget<ppT> check_out_Rx;
    // out_Ry = theta * (G - H) - I;
    libsnark::Fqe_variable<ppT> G_minus_H;
    libsnark::Fqe_variable<ppT> theta_times_G_minus_H;
    libsnark::Fqe_mul_gadget<ppT> check_theta_times_G_minus_H;
    // out_Rz = Z1 * E;
    libsnark::Fqe_variable<ppT> out_Rz;
    libsnark::Fqe_mul_gadget<ppT> check_out_Rz;

    bls12_377_G2_proj<ppT> out_R;

    // out_coeffs.ell_0 = xi * J;
    // out_coeffs.ell_vw = lambda;
    // out_coeffs.ell_vv = -theta;
    bls12_377_ate_ell_coeffs<ppT> out_coeffs;

    bls12_377_ate_add_gadget(
        libsnark::protoboard<libff::Fr<ppT>> &pb,
        const libsnark::Fqe_variable<ppT> &base_X,
        const libsnark::Fqe_variable<ppT> &base_Y,
        const bls12_377_G2_proj<ppT> &R,
        const std::string &annotation_prefix)
        : libsnark::gadget<libff::Fr<ppT>>(pb, annotation_prefix)
        , base_X(base_X)
        , base_Y(base_Y)
        , in_R(R)

        // A = Qy * Rz
        , A(pb, FMT(annotation_prefix, " A"))
        , check_A(pb, base_Y, in_R.Z, A, FMT(annotation_prefix, " check A"))
        // B = Qx * Rz;
        , B(pb, FMT(annotation_prefix, " B"))
        , check_B(pb, base_X, in_R.Z, B, FMT(annotation_prefix, " check B"))
        // theta = Ry - A;
        , theta(in_R.Y + (A * -libff::Fr<ppT>::one()))
        // lambda = Rx - B;
        , lambda(in_R.X + (B * -libff::Fr<ppT>::one()))
        // C = theta.squared();
        , C(pb, FMT(annotation_prefix, " C"))
        , check_C(pb, theta, C, FMT(annotation_prefix, " check C"))
        // D = lambda.squared();
        , D(pb, FMT(annotation_prefix, " D"))
        , check_D(pb, lambda, D, FMT(annotation_prefix, " check D"))
        // E = lambda * D;
        , E(pb, FMT(annotation_prefix, " E"))
        , check_E(pb, lambda, D, E, FMT(annotation_prefix, " check E"))
        // F = Rz * C;
        , F(pb, FMT(annotation_prefix, " F"))
        , check_F(pb, in_R.Z, C, F, FMT(annotation_prefix, " check F"))
        // G = Rx * D;
        , G(pb, FMT(annotation_prefix, " G"))
        , check_G(pb, in_R.X, D, G, FMT(annotation_prefix, " check G"))
        // H = E + F - (G + G);
        , H(E + F + (G * -libff::Fr<ppT>(2)))
        // I = Ry * E;
        , I(pb, FMT(annotation_prefix, " I"))
        , check_I(pb, in_R.Y, E, I, FMT(annotation_prefix, " check I"))
        // J = theta * Qx - lambda * Qy;
        , theta_times_Qx(pb, FMT(annotation_prefix, " theta_times_Rx"))
        , check_theta_times_Qx(
              pb,
              theta,
              base_X,
              theta_times_Qx,
              FMT(annotation_prefix, " check_theta_times_Qx"))
        , lambda_times_Qy(pb, FMT(annotation_prefix, " lambda_times_Qy"))
        , check_lambda_times_Qy(
              pb,
              lambda,
              base_Y,
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
        , check_out_Rz(
              pb, in_R.Z, E, out_Rz, FMT(annotation_prefix, " check Rz"))

        , out_R(
              out_Rx,
              theta_times_G_minus_H + (I * -libff::Fr<ppT>::one()),
              out_Rz)

        // out_coeffs.ell_0 = xi * J;
        // out_coeffs.ell_vw = lambda;
        // out_coeffs.ell_vv = -theta;
        , out_coeffs(
              J * libff::bls12_377_twist,
              lambda,
              theta * -libff::Fr<ppT>::one())
    {
    }

    void generate_r1cs_constraints()
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

    void generate_r1cs_witness()
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
};

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_PAIRING_BLS12_377_PAIRING_HPP__
