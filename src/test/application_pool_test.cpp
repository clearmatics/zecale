// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "types/application_pool.hpp"

#include "gtest/gtest.h"
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libzeth/libsnark_helpers/debug_helpers.hpp>
#include <stdio.h>

typedef libff::mnt4_pp ppT;

using namespace libzecale;

namespace
{

TEST(MainTests, AddAndRetrieveTransactions)
{
    // Create an application pool with a dummy verification key (set with
    // arbitrary number of inputs)
    std::string dummy_app_name = std::string("test_application");
    libsnark::r1cs_ppzksnark_verification_key<ppT> dummy_vk =
        libsnark::r1cs_ppzksnark_verification_key<ppT>::dummy_verification_key(
            7);

    // We create a pool with a batch size of 2 here
    const size_t BATCH_SIZE = 2;
    application_pool<ppT, BATCH_SIZE> pool(dummy_app_name, dummy_vk);

    // Get size of the pool before any addition
    ASSERT_EQ(pool.tx_pool_size(), (size_t)0);

    // Create a dummy extended proof to build the set of transactions to
    // aggregate
    libsnark::r1cs_ppzksnark_proof<ppT> dummy_proof(
        libsnark::knowledge_commitment<libff::G1<ppT>, libff::G1<ppT>>(
            libff::G1<ppT>::random_element(), libff::G1<ppT>::random_element()),
        libsnark::knowledge_commitment<libff::G2<ppT>, libff::G1<ppT>>(
            libff::G2<ppT>::random_element(), libff::G1<ppT>::random_element()),
        libsnark::knowledge_commitment<libff::G1<ppT>, libff::G1<ppT>>(
            libff::G1<ppT>::random_element(), libff::G1<ppT>::random_element()),
        libff::G1<ppT>::random_element(),
        libff::G1<ppT>::random_element());

    std::vector<libff::Fr<ppT>> dummy_inputs;
    dummy_inputs.push_back(libff::Fr<ppT>::random_element());
    dummy_inputs.push_back(libff::Fr<ppT>::random_element());
    dummy_inputs.push_back(libff::Fr<ppT>::random_element());
    libsnark::r1cs_primary_input<libff::Fr<ppT>> primary_inputs =
        libsnark::r1cs_primary_input<libff::Fr<ppT>>(dummy_inputs);

    libzeth::extended_proof<ppT> dummy_extended_proof(
        dummy_proof, dummy_inputs);

    // Add transactions in the pool
    transaction_to_aggregate<ppT> tx_a =
        transaction_to_aggregate<ppT>(dummy_app_name, dummy_extended_proof, 1);
    transaction_to_aggregate<ppT> tx_b =
        transaction_to_aggregate<ppT>(dummy_app_name, dummy_extended_proof, 20);
    transaction_to_aggregate<ppT> tx_c =
        transaction_to_aggregate<ppT>(dummy_app_name, dummy_extended_proof, 12);
    transaction_to_aggregate<ppT> tx_d =
        transaction_to_aggregate<ppT>(dummy_app_name, dummy_extended_proof, 3);
    transaction_to_aggregate<ppT> tx_e = transaction_to_aggregate<ppT>(
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
        std::cout << "i: " << i << " val: " << batch[i] << std::endl;
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
