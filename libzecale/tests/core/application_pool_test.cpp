// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzecale/circuits/groth16_verifier/groth16_verifier_parameters.hpp"
#include "libzecale/circuits/pairing/mnt_pairing_params.hpp"
#include "libzecale/circuits/pghr13_verifier/pghr13_verifier_parameters.hpp"
#include "libzecale/core/application_pool.hpp"

#include "gtest/gtest.h"
#include <stdio.h>

using namespace libzecale;

namespace
{

template<typename snarkT> class dummy_provider
{
public:
    static typename snarkT::ProoT get_proof();
    static typename snarkT::VerificationKeyT get_verification_key(
        size_t input_size);
};

// PGHR13 implementation of dummy_provider
template<typename ppT> class dummy_provider<libzeth::pghr13_snark<ppT>>
{
public:
    static typename libzeth::pghr13_snark<ppT>::proof get_proof()
    {
        libsnark::r1cs_ppzksnark_proof<ppT> dummy_proof(
            libsnark::knowledge_commitment<libff::G1<ppT>, libff::G1<ppT>>(
                libff::G1<ppT>::random_element(),
                libff::G1<ppT>::random_element()),
            libsnark::knowledge_commitment<libff::G2<ppT>, libff::G1<ppT>>(
                libff::G2<ppT>::random_element(),
                libff::G1<ppT>::random_element()),
            libsnark::knowledge_commitment<libff::G1<ppT>, libff::G1<ppT>>(
                libff::G1<ppT>::random_element(),
                libff::G1<ppT>::random_element()),
            libff::G1<ppT>::random_element(),
            libff::G1<ppT>::random_element());

        return dummy_proof;
    }

    static typename libzeth::pghr13_snark<ppT>::verification_key
    get_verification_key(size_t input_size)
    {
        return libsnark::r1cs_ppzksnark_verification_key<
            ppT>::dummy_verification_key(input_size);
    }
};

// GROTH16 implementation of dummy_provider
template<typename ppT> class dummy_provider<libzeth::groth16_snark<ppT>>
{
public:
    static typename libzeth::groth16_snark<ppT>::proof get_proof()
    {
        libsnark::r1cs_gg_ppzksnark_proof<ppT> dummy_proof(
            libff::G1<ppT>::random_element(),
            libff::G2<ppT>::random_element(),
            libff::G1<ppT>::random_element());

        return dummy_proof;
    }

    static typename libzeth::groth16_snark<ppT>::verification_key
    get_verification_key(size_t input_size)
    {
        return libsnark::r1cs_gg_ppzksnark_verification_key<
            ppT>::dummy_verification_key(input_size);
    }
};

template<typename ppT, typename snarkT>
void test_add_and_retrieve_transactions()
{
    static const size_t num_inputs = 3;

    // Create an application pool with a dummy verification key
    // (set with arbitrary number of inputs)
    const size_t BATCH_SIZE = 2;
    std::string dummy_app_name = std::string("test_application");
    typename snarkT::verification_key vk =
        dummy_provider<snarkT>::get_verification_key(42);
    application_pool<ppT, snarkT, BATCH_SIZE> pool(dummy_app_name, vk);

    // Get size of the pool before any addition
    ASSERT_EQ(pool.tx_pool_size(), (size_t)0);

    // Create a dummy extended proof to build the set of transactions to
    // aggregate
    typename snarkT::proof proof = dummy_provider<snarkT>::get_proof();
    std::vector<libff::Fr<ppT>> dummy_inputs;
    for (size_t i = 0; i < num_inputs; ++i) {
        dummy_inputs.push_back(libff::Fr<ppT>::random_element());
    }

    libzeth::extended_proof<ppT, snarkT> dummy_extended_proof(
        std::move(proof), std::move(dummy_inputs));

    // Add transactions in the pool
    transaction_to_aggregate<ppT, snarkT> tx_a =
        transaction_to_aggregate<ppT, snarkT>(
            dummy_app_name, dummy_extended_proof, 1);
    transaction_to_aggregate<ppT, snarkT> tx_b =
        transaction_to_aggregate<ppT, snarkT>(
            dummy_app_name, dummy_extended_proof, 20);
    transaction_to_aggregate<ppT, snarkT> tx_c =
        transaction_to_aggregate<ppT, snarkT>(
            dummy_app_name, dummy_extended_proof, 12);
    transaction_to_aggregate<ppT, snarkT> tx_d =
        transaction_to_aggregate<ppT, snarkT>(
            dummy_app_name, dummy_extended_proof, 3);
    transaction_to_aggregate<ppT, snarkT> tx_e =
        transaction_to_aggregate<ppT, snarkT>(
            dummy_app_name, dummy_extended_proof, 120);

    pool.add_tx(tx_a);
    pool.add_tx(tx_b);
    pool.add_tx(tx_c);
    pool.add_tx(tx_d);
    pool.add_tx(tx_e);

    // Get size of the pool after insertion
    ASSERT_EQ(pool.tx_pool_size(), (size_t)5);

    // 2. Retrieve a batch
    std::array<libzecale::transaction_to_aggregate<ppT, snarkT>, BATCH_SIZE>
        batch;
    const size_t batch_size = pool.get_next_batch(batch);
    ASSERT_EQ(batch_size, BATCH_SIZE);

    for (size_t i = 0; i < BATCH_SIZE; ++i) {
        std::cout << "i: " << i << " val: ";
        batch[i].write_json(std::cout);
    }

    // Get size of the pool after batch retrieval
    ASSERT_EQ(pool.tx_pool_size(), (size_t)5 - BATCH_SIZE);
}

template<typename ppT> void test_add_and_retrieve_transactions_groth16()
{
    test_add_and_retrieve_transactions<ppT, libzeth::groth16_snark<ppT>>();
}

template<typename ppT> void test_add_and_retrieve_transactions_pghr13()
{
    test_add_and_retrieve_transactions<ppT, libzeth::pghr13_snark<ppT>>();
}

TEST(ApplicationPoolTests, AddAndRetrieveTransactionsMnt4Groth16)
{
    test_add_and_retrieve_transactions_groth16<libff::mnt4_pp>();
}

TEST(ApplicationPoolTests, AddAndRetrieveTransactionsMnt4Pghr13)
{
    test_add_and_retrieve_transactions_pghr13<libff::mnt4_pp>();
}

} // namespace

int main(int argc, char **argv)
{
    // Initialize the curve parameters before running the tests
    libff::mnt4_pp::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
