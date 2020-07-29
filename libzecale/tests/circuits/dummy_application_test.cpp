// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzecale/tests/circuits/dummy_application.hpp"

#include <gtest/gtest.h>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>
#include <libzeth/core/extended_proof.hpp>
#include <libzeth/serialization/r1cs_serialization.hpp>
#include <libzeth/snarks/groth16/groth16_snark.hpp>

// The application uses bls12-377 and the Groth16 snark.
using pp = libff::bls12_377_pp;
using FieldT = libff::Fr<pp>;
using snark = libzeth::groth16_snark<pp>;

namespace
{

TEST(DummyApplicationTest, DumpKeysAndProofs)
{
    libsnark::protoboard<FieldT> pb;

    // Circuit with a single public input 'a'.
    libsnark::pb_variable<FieldT> a_var;
    libsnark::pb_variable<FieldT> a_inv_var;
    a_var.allocate(pb, "a");
    a_inv_var.allocate(pb, "a");
    pb.set_input_sizes(1);
    libzecale::test::check_inverse_gadget<pp> check_a_inv(
        pb, a_var, a_inv_var, "check_a_inv");
    check_a_inv.generate_r1cs_constraints();

    // Keys
    const typename snark::keypair keypair = snark::generate_setup(pb);
    std::cout << "VERIFICATION KEY:\n";
    snark::verification_key_write_json(keypair.vk, std::cout);
    std::cout << "\n";

    // Create 6 extended proofs
    for (size_t i = 0; i < 6; ++i) {
        const FieldT a(i + 7);
        pb.val(a_var) = a;
        check_a_inv.generate_r1cs_witness();
        ASSERT_EQ(pb.val(check_a_inv._a_inv), a.inverse());

        std::cout << "PROOF " << std::to_string(i) << ":\n";

        typename snark::proof proof = snark::generate_proof(pb, keypair.pk);
        libsnark::r1cs_primary_input<FieldT> primary_input = pb.primary_input();
        ASSERT_TRUE(snark::verify(primary_input, proof, keypair.vk));

        libzeth::extended_proof<pp, snark>(
            std::move(proof), std::move(primary_input))
            .write_json(std::cout);
    }
}

} // namespace

int main(int argc, char **argv)
{
    libff::inhibit_profiling_counters = true;
    libff::inhibit_profiling_info = true;
    pp::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
