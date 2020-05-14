// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzecale/core/application_pool.hpp"

#include "gtest/gtest.h"
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <stdio.h>

// zkSNARK templates instantiation
#include <libzeth/snarks/default/default_snark.hpp>

typedef libff::mnt4_pp ppT;

using namespace libzecale;

namespace
{

#ifdef ZKSNARK_PGHR13
libsnark::r1cs_ppzksnark_proof<ppT> get_dummy_proof()
{
    libsnark::r1cs_ppzksnark_proof<ppT> dummy_proof(
        libsnark::knowledge_commitment<libff::G1<ppT>, libff::G1<ppT>>(
            libff::G1<ppT>::random_element(), libff::G1<ppT>::random_element()),
        libsnark::knowledge_commitment<libff::G2<ppT>, libff::G1<ppT>>(
            libff::G2<ppT>::random_element(), libff::G1<ppT>::random_element()),
        libsnark::knowledge_commitment<libff::G1<ppT>, libff::G1<ppT>>(
            libff::G1<ppT>::random_element(), libff::G1<ppT>::random_element()),
        libff::G1<ppT>::random_element(),
        libff::G1<ppT>::random_element());

    return dummy_proof;
}

libsnark::r1cs_ppzksnark_verification_key<ppT> get_dummy_verification_key(
    size_t input_size)
{
    return libsnark::r1cs_ppzksnark_verification_key<
        ppT>::dummy_verification_key(input_size);
}
#endif

#ifdef ZKSNARK_GROTH16
libsnark::r1cs_gg_ppzksnark_proof<ppT> get_dummy_proof()
{
    libsnark::r1cs_gg_ppzksnark_proof<ppT> dummy_proof(
        libff::G1<ppT>::random_element(),
        libff::G2<ppT>::random_element(),
        libff::G1<ppT>::random_element());

    return dummy_proof;
}
libsnark::r1cs_gg_ppzksnark_verification_key<ppT> get_dummy_verification_key(
    size_t input_size)
{
    return libsnark::r1cs_gg_ppzksnark_verification_key<
        ppT>::dummy_verification_key(input_size);
}
#endif

TEST(MainTests, AddAndRetrieveTransactions)
{
    // Create an application pool with a dummy verification key
    // (set with arbitrary number of inputs)
    const size_t BATCH_SIZE = 2;
    std::string dummy_app_name = std::string("test_application");
    libzeth::default_snark<ppT>::VerificationKeyT vk =
        get_dummy_verification_key(42);
    application_pool<ppT, libzeth::default_snark<ppT>, BATCH_SIZE> pool(
        dummy_app_name, vk);

    // Get size of the pool before any addition
    ASSERT_EQ(pool.tx_pool_size(), (size_t)0);

    // Create a dummy extended proof to build the set of transactions to
    // aggregate
    libzeth::default_snark<ppT>::ProofT proof = get_dummy_proof();
    std::vector<libff::Fr<ppT>> dummy_inputs;
    dummy_inputs.push_back(libff::Fr<ppT>::random_element());
    dummy_inputs.push_back(libff::Fr<ppT>::random_element());
    dummy_inputs.push_back(libff::Fr<ppT>::random_element());
    libsnark::r1cs_primary_input<libff::Fr<ppT>> primary_inputs =
        libsnark::r1cs_primary_input<libff::Fr<ppT>>(dummy_inputs);

    libzeth::extended_proof<ppT, libzeth::default_snark<ppT>>
        dummy_extended_proof(proof, dummy_inputs);

    // Add transactions in the pool
    transaction_to_aggregate<ppT, libzeth::default_snark<ppT>> tx_a =
        transaction_to_aggregate<ppT, libzeth::default_snark<ppT>>(
            dummy_app_name, dummy_extended_proof, 1);
    transaction_to_aggregate<ppT, libzeth::default_snark<ppT>> tx_b =
        transaction_to_aggregate<ppT, libzeth::default_snark<ppT>>(
            dummy_app_name, dummy_extended_proof, 20);
    transaction_to_aggregate<ppT, libzeth::default_snark<ppT>> tx_c =
        transaction_to_aggregate<ppT, libzeth::default_snark<ppT>>(
            dummy_app_name, dummy_extended_proof, 12);
    transaction_to_aggregate<ppT, libzeth::default_snark<ppT>> tx_d =
        transaction_to_aggregate<ppT, libzeth::default_snark<ppT>>(
            dummy_app_name, dummy_extended_proof, 3);
    transaction_to_aggregate<ppT, libzeth::default_snark<ppT>> tx_e =
        transaction_to_aggregate<ppT, libzeth::default_snark<ppT>>(
            dummy_app_name, dummy_extended_proof, 120);

    pool.add_tx(tx_a);
    pool.add_tx(tx_b);
    pool.add_tx(tx_c);
    pool.add_tx(tx_d);
    pool.add_tx(tx_e);

    // Get size of the pool after insertion
    ASSERT_EQ(pool.tx_pool_size(), (size_t)5);

    // 2. Retrieve a batch
    auto batch = pool.get_next_batch();
    ASSERT_EQ(batch.size(), BATCH_SIZE);

    for (size_t i = 0; i < batch.size(); i++) {
        std::cout << "i: " << i << " val: ";
        batch[i].write_json(std::cout);
    }

    // Get size of the pool after batch retrieval
    ASSERT_EQ(pool.tx_pool_size(), (size_t)5 - BATCH_SIZE);
}

} // namespace

int main(int argc, char **argv)
{
    // Initialize the curve parameters before running the tests
    ppT::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
