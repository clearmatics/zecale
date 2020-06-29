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
template<typename ppT>
class bls12_377_G2_proj : libsnark::gadget<libff::Fr<ppT>>
{
public:
    libsnark::Fqe_variable<ppT> X;
    libsnark::Fqe_variable<ppT> Y;
    libsnark::Fqe_variable<ppT> Z;

    bls12_377_G2_proj(
        libsnark::protoboard<libff::Fr<ppT>> &pb,
        const std::string &annotation_prefix)
        : libsnark::gadget<libff::Fr<ppT>>(pb, annotation_prefix)
        , X(pb, FMT(annotation_prefix, " X"))
        , Y(pb, FMT(annotation_prefix, " Y"))
        , Z(pb, FMT(annotation_prefix, " Z"))
    {
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
    libsnark::Fqe_variable<ppT> ell_0;
    libsnark::Fqe_variable<ppT> ell_vw;
    libsnark::Fqe_variable<ppT> ell_vv;

    bls12_377_ate_ell_coeffs(
        const libsnark::Fqe_variable<ppT> &ell_0,
        const libsnark::Fqe_variable<ppT> &ell_vw,
        const libsnark::Fqe_variable<ppT> &ell_vv)
        : ell_0(ell_0), ell_vw(ell_vw), ell_vv(ell_vv)
    {
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
        out_coeffs.ell_0.evaluate();
        // ell_vw = -H
        out_coeffs.ell_vw.evaluate();
        // ell_vv = 3 * J
        out_coeffs.ell_vv.evaluate();
    }
};

} // namespace libzecale

#endif // __ZECALE_CIRCUITS_PAIRING_BLS12_377_PAIRING_HPP__
