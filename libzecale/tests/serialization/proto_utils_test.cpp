// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzecale/serialization/proto_utils.hpp"

#include "gtest/gtest.h"
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libzeth/core/extended_proof.hpp>
#include <libzeth/serialization/proto_utils.hpp>
#include <libzeth/snarks/groth16/groth16_api_handler.hpp>
#include <libzeth/snarks/pghr13/pghr13_api_handler.hpp>
#include <stdio.h>
#include <zecale/api/aggregator.pb.h>
#include <zeth/api/ec_group_messages.pb.h>

using namespace libzecale;

namespace
{

template<typename ppT, typename snarkT, typename api_handlerT>
void test_parse_nested_transaction(
    const libzeth::extended_proof<ppT, snarkT> &mock_extended_proof)
{
    // Manually create the equivalent protobuf nested transaction
    zeth_proto::ExtendedProof *ext_proof_proto =
        new zeth_proto::ExtendedProof();
    api_handlerT::extended_proof_to_proto(mock_extended_proof, ext_proof_proto);
    zecale_proto::NestedTransaction nested_tx_proto;
    nested_tx_proto.set_application_name("zeth");
    nested_tx_proto.set_fee_in_wei(12);
    nested_tx_proto.set_allocated_extended_proof(ext_proof_proto);

    // Parse the protobuf nested transaction back to a nested_transaction
    // object, and compare the result to the original.
    nested_transaction<ppT, snarkT> nested_tx_decoded =
        nested_transaction_from_proto<ppT, api_handlerT>(nested_tx_proto);

    ASSERT_EQ(
        nested_tx_decoded.extended_proof().get_primary_inputs(),
        mock_extended_proof.get_primary_inputs());
    ASSERT_EQ(
        nested_tx_decoded.extended_proof().get_proof(),
        mock_extended_proof.get_proof());
    ASSERT_EQ(nested_tx_decoded.application_name(), "zeth");
    ASSERT_EQ(nested_tx_decoded.fee_wei(), 12);

    // ext_proof_proto will be deleted by the zecale_proto::NestedTransaction
    // destructor.
}

template<typename ppT> void test_parse_nested_transaction_pghr13()
{
    libsnark::r1cs_ppzksnark_proof<ppT> proof(
        libsnark::knowledge_commitment<libff::G1<ppT>, libff::G1<ppT>>(
            libff::G1<ppT>::random_element(), libff::G1<ppT>::random_element()),
        libsnark::knowledge_commitment<libff::G2<ppT>, libff::G1<ppT>>(
            libff::G2<ppT>::random_element(), libff::G1<ppT>::random_element()),
        libsnark::knowledge_commitment<libff::G1<ppT>, libff::G1<ppT>>(
            libff::G1<ppT>::random_element(), libff::G1<ppT>::random_element()),
        libff::G1<ppT>::random_element(),
        libff::G1<ppT>::random_element());

    std::vector<libff::Fr<ppT>> inputs;
    inputs.push_back(libff::Fr<ppT>::random_element());
    inputs.push_back(libff::Fr<ppT>::random_element());
    inputs.push_back(libff::Fr<ppT>::random_element());

    libzeth::extended_proof<ppT, libzeth::pghr13_snark<ppT>>
        mock_extended_proof(std::move(proof), std::move(inputs));

    test_parse_nested_transaction<
        ppT,
        libzeth::pghr13_snark<ppT>,
        libzeth::pghr13_api_handler<ppT>>(mock_extended_proof);
}

template<typename ppT> void test_parse_nested_transaction_groth16()
{
    // Format arbitrary data that will be parsed afterwards
    libsnark::r1cs_gg_ppzksnark_proof<ppT> proof(
        libff::G1<ppT>::random_element(),
        libff::G2<ppT>::random_element(),
        libff::G1<ppT>::random_element());

    std::vector<libff::Fr<ppT>> inputs;
    inputs.push_back(libff::Fr<ppT>::random_element());
    inputs.push_back(libff::Fr<ppT>::random_element());
    inputs.push_back(libff::Fr<ppT>::random_element());

    const libzeth::extended_proof<ppT, libzeth::groth16_snark<ppT>>
        mock_extended_proof(std::move(proof), std::move(inputs));

    test_parse_nested_transaction<
        ppT,
        libzeth::groth16_snark<ppT>,
        libzeth::groth16_api_handler<ppT>>(mock_extended_proof);
}

TEST(MainTests, ParseTransactionToAggregatePGHR13Mnt4)
{
    test_parse_nested_transaction_pghr13<libff::mnt4_pp>();
}

TEST(MainTests, ParseTransactionToAggregateGROTH16Mnt4)
{
    test_parse_nested_transaction_groth16<libff::mnt4_pp>();
}

} // namespace

int main(int argc, char **argv)
{
    // Initialize the curve parameters before running the tests
    libff::mnt4_pp::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
