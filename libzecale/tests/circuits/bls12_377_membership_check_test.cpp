// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
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

void populate_g1_membership_check_circuit(
    libsnark::protoboard<Field> &pb, const libff::G1<npp> &g1_value)
{
    libsnark::G1_variable<wpp> g1(pb, " g1");
    libzecale::bls12_377_G1_membership_check_gadget<wpp> check_g1(
        pb, g1, "check_g1");

    check_g1.generate_r1cs_constraints();

    g1.generate_r1cs_witness(g1_value);
    check_g1.generate_r1cs_witness();
}

TEST(BLS12_377_Membership_Check, G1ValidMember)
{
    const libff::G1<npp> g1_valid = libff::Fr<npp>(3) * libff::G1<npp>::one();
    libsnark::protoboard<Field> pb;
    populate_g1_membership_check_circuit(pb, g1_valid);
    ASSERT_TRUE(pb.is_satisfied());
}

TEST(BLS12_377_Membership_Check, G1InvalidMember)
{
    const libff::G1<npp> invalid_element =
        libff::g1_curve_point_at_x<libff::G1<npp>>(libff::Fq<npp>(3));
    libsnark::protoboard<Field> pb;
    populate_g1_membership_check_circuit(pb, invalid_element);
    ASSERT_FALSE(pb.is_satisfied());
}

} // namespace

int main(int argc, char **argv)
{
    libff::bls12_377_pp::init_public_params();
    libff::bw6_761_pp::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
