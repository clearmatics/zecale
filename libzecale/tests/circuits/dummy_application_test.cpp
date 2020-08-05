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
    libzecale::test::dummy_app_wrapper<pp, snark> dummy_app;

    // Keys
    const typename snark::keypair keypair = dummy_app.generate_keypair();
    std::cout << "VERIFICATION KEY:\n";
    snark::verification_key_write_json(keypair.vk, std::cout);
    std::cout << "\n";

    // Create 6 extended proofs
    for (size_t i = 0; i < 6; ++i) {
        libzeth::extended_proof<pp, snark> prf =
            dummy_app.prove(i + 7, keypair.pk);

        ASSERT_EQ(
            dummy_app._pb.val(dummy_app._a_inv),
            prf.get_primary_inputs()[0].inverse());
        ASSERT_TRUE(snark::verify(
            prf.get_primary_inputs(), prf.get_proof(), keypair.vk));

        std::cout << "PROOF " << std::to_string(i) << ":\n";
        prf.write_json(std::cout);
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
