// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzecale/circuits/pairing/bls12_377_membership_check_gadgets.hpp"
#include "libzecale/circuits/pairing/bw6_761_pairing_params.hpp"

#include <gtest/gtest.h>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>
#include <libff/algebra/curves/bw6_761/bw6_761_pp.hpp>
#include <libff/algebra/curves/curve_utils.hpp>
#include <libzeth/snarks/groth16/groth16_snark.hpp>

using wpp = libff::bw6_761_pp;
using npp = libzecale::other_curve<wpp>;
using snark = libzeth::groth16_snark<wpp>;
using Field = libff::Fr<wpp>;

namespace
{

void g1_membership_check_circuit(const libff::G1<npp> &g1_value)
{
    libsnark::protoboard<Field> pb;
    libsnark::G1_variable<wpp> g1(pb, " g1");
    libzecale::bls12_377_G1_membership_check_gadget<wpp> check_g1(
        pb, g1, "check_g1");

    check_g1.generate_r1cs_constraints();

    g1.generate_r1cs_witness(g1_value);
    check_g1.generate_r1cs_witness();

    ASSERT_EQ(
        g1_value.is_well_formed() && g1_value.is_in_safe_subgroup(),
        pb.is_satisfied());
}

void g2_membership_check_circuit(const libff::G2<npp> &g2_value)
{
    libsnark::protoboard<Field> pb;
    libsnark::G2_variable<wpp> g2(pb, " g2");
    libzecale::bls12_377_G2_membership_check_gadget<wpp> check_g2(
        pb, g2, "check_g2");

    check_g2.generate_r1cs_constraints();

    g2.generate_r1cs_witness(g2_value);
    check_g2.generate_r1cs_witness();

    ASSERT_EQ(
        g2_value.is_well_formed() && g2_value.is_in_safe_subgroup(),
        pb.is_satisfied());
}

TEST(BLS12_377_Membership_Check, G1ValidMember)
{
    const libff::G1<npp> g1_valid = libff::Fr<npp>(3) * libff::G1<npp>::one();
    g1_membership_check_circuit(g1_valid);
}

TEST(BLS12_377_Membership_Check, G1InvalidMember)
{
    const libff::G1<npp> g1_invalid =
        libff::g1_curve_point_at_x<libff::G1<npp>>(libff::Fq<npp>(3));
    g1_membership_check_circuit(g1_invalid);
}

TEST(BLS12_377_Membership_Check, G1NotWellFormed)
{
    const libff::G1<npp> g1_invalid(
        libff::Fq<npp>::one(), libff::Fq<npp>::one(), libff::Fq<npp>::one());
    ASSERT_FALSE(g1_invalid.is_well_formed());
    g1_membership_check_circuit(g1_invalid);
}

TEST(BLS12_377_Membership_Check, G2UntwistFrobeniusTwist)
{
    const libff::G2<npp> g2_val = libff::Fr<npp>(3) * libff::G2<npp>::one();
    const libff::G2<npp> g2_uft_val_expect = g2_val.untwist_frobenius_twist();

    libsnark::protoboard<Field> pb;
    libsnark::G2_variable<wpp> g2(pb, "g2");
    libsnark::G2_variable<wpp> g2_uft =
        libzecale::bls12_377_g2_untwist_frobenius_twist(pb, g2, 1, "g2_uft");
    g2.generate_r1cs_witness(g2_val);

    g2_uft.X->evaluate();
    g2_uft.Y->evaluate();
    const libff::G2<npp> g2_uft_val =
        libzecale::g2_variable_get_element<wpp>(g2_uft);
    ASSERT_EQ(g2_uft_val_expect, g2_uft_val);
}

TEST(BLS12_377_Membership_Check, G2ValidMember)
{
    const libff::G2<npp> g2_valid = libff::Fr<npp>(3) * libff::G2<npp>::one();
    g2_membership_check_circuit(g2_valid);
}

TEST(BLS12_377_Membership_Check, G2InvalidMember)
{
    const libff::G2<npp> g2_invalid =
        libff::g2_curve_point_at_x<libff::G2<npp>>(
            libff::Fq<npp>(3) * libff::Fqe<npp>::one());
    g2_membership_check_circuit(g2_invalid);
}

TEST(BLS12_377_Membership_Check, G2NotWellFormed)
{
    const libff::G2<npp> g2_invalid(
        libff::Fqe<npp>::one(), libff::Fqe<npp>::one(), libff::Fqe<npp>::one());
    ASSERT_FALSE(g2_invalid.is_well_formed());
    g2_membership_check_circuit(g2_invalid);
}

} // namespace

int main(int argc, char **argv)
{
    libff::bls12_377_pp::init_public_params();
    libff::bw6_761_pp::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
