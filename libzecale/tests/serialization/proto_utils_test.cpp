// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "api/aggregator.pb.h"
#include "api/ec_group_messages.pb.h"
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

using namespace libzecale;

namespace
{

template<typename ppT> void test_parse_transaction_to_aggregate_pghr13()
{
    // 1. Format arbitary data that will be parsed afterwards
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

    libsnark::r1cs_ppzksnark_proof<ppT> proofObj =
        mock_extended_proof.get_proof();
    zeth_proto::HexPointBaseGroup1Affine *a =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup1Affine *a_p =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup2Affine *b =
        new zeth_proto::HexPointBaseGroup2Affine();
    zeth_proto::HexPointBaseGroup1Affine *b_p =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup1Affine *c =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup1Affine *c_p =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup1Affine *h =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup1Affine *k =
        new zeth_proto::HexPointBaseGroup1Affine();

    a->CopyFrom(libzeth::point_g1_affine_to_proto<ppT>(proofObj.g_A.g));
    a_p->CopyFrom(libzeth::point_g1_affine_to_proto<ppT>(proofObj.g_A.h));
    b->CopyFrom(libzeth::point_g2_affine_to_proto<ppT>(proofObj.g_B.g));
    b_p->CopyFrom(libzeth::point_g1_affine_to_proto<ppT>(proofObj.g_B.h));
    c->CopyFrom(libzeth::point_g1_affine_to_proto<ppT>(proofObj.g_C.g));
    c_p->CopyFrom(libzeth::point_g1_affine_to_proto<ppT>(proofObj.g_C.h));
    h->CopyFrom(libzeth::point_g1_affine_to_proto<ppT>(proofObj.g_H));
    k->CopyFrom(libzeth::point_g1_affine_to_proto<ppT>(proofObj.g_K));

    std::stringstream inputs_ss;
    libzeth::primary_inputs_write_json(
        mock_extended_proof.get_primary_inputs(), inputs_ss);

    // Note on memory safety: set_allocated deleted the allocated objects
    // See:
    // https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
    zeth_proto::ExtendedProof *ext_proof = new zeth_proto::ExtendedProof();
    zeth_proto::ExtendedProofPGHR13 *grpc_extended_pghr13_proof_obj =
        new zeth_proto::ExtendedProofPGHR13();

    grpc_extended_pghr13_proof_obj->set_allocated_a(a);
    grpc_extended_pghr13_proof_obj->set_allocated_a_p(a_p);
    grpc_extended_pghr13_proof_obj->set_allocated_b(b);
    grpc_extended_pghr13_proof_obj->set_allocated_b_p(b_p);
    grpc_extended_pghr13_proof_obj->set_allocated_c(c);
    grpc_extended_pghr13_proof_obj->set_allocated_c_p(c_p);
    grpc_extended_pghr13_proof_obj->set_allocated_h(h);
    grpc_extended_pghr13_proof_obj->set_allocated_k(k);
    grpc_extended_pghr13_proof_obj->set_inputs(inputs_ss.str());

    ext_proof->set_allocated_pghr13_extended_proof(
        grpc_extended_pghr13_proof_obj);

    zecale_proto::TransactionToAggregate *grpc_tx_to_aggregate_obj =
        new zecale_proto::TransactionToAggregate();
    grpc_tx_to_aggregate_obj->set_application_name("zeth");
    grpc_tx_to_aggregate_obj->set_fee_in_wei(12);
    grpc_tx_to_aggregate_obj->set_allocated_extended_proof(ext_proof);

    // Parse the TransactionToAggregate
    transaction_to_aggregate<ppT, libzeth::pghr13_snark<ppT>> retrieved_tx =
        transaction_to_aggregate_from_proto<
            ppT,
            libzeth::pghr13_api_handler<ppT>>(*grpc_tx_to_aggregate_obj);

    ASSERT_EQ(
        retrieved_tx.extended_proof().get_primary_inputs(),
        mock_extended_proof.get_primary_inputs());
    ASSERT_EQ(
        retrieved_tx.extended_proof().get_proof(),
        mock_extended_proof.get_proof());
    ASSERT_EQ(retrieved_tx.application_name(), "zeth");
    ASSERT_EQ(retrieved_tx.fee_wei(), 12);

    // The destructor of `zecale_proto::TransactionToAggregate` should be
    // invoked which whould free the memory allocated for the fields of this
    // message
    delete grpc_tx_to_aggregate_obj;
}

template<typename ppT> void test_parse_transaction_to_aggregate_groth16()
{
    // 1. Format arbitary data that will be parsed afterwards
    libsnark::r1cs_gg_ppzksnark_proof<ppT> proof(
        libff::G1<ppT>::random_element(),
        libff::G2<ppT>::random_element(),
        libff::G1<ppT>::random_element());

    std::vector<libff::Fr<ppT>> inputs;
    inputs.push_back(libff::Fr<ppT>::random_element());
    inputs.push_back(libff::Fr<ppT>::random_element());
    inputs.push_back(libff::Fr<ppT>::random_element());

    libzeth::extended_proof<ppT, libzeth::groth16_snark<ppT>>
        mock_extended_proof(std::move(proof), std::move(inputs));

    libsnark::r1cs_gg_ppzksnark_proof<ppT> proofObj =
        mock_extended_proof.get_proof();
    zeth_proto::HexPointBaseGroup1Affine *a =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup2Affine *b =
        new zeth_proto::HexPointBaseGroup2Affine();
    zeth_proto::HexPointBaseGroup1Affine *c =
        new zeth_proto::HexPointBaseGroup1Affine();

    a->CopyFrom(libzeth::point_g1_affine_to_proto<ppT>(proofObj.g_A));
    b->CopyFrom(libzeth::point_g2_affine_to_proto<ppT>(proofObj.g_B)); // in G2
    c->CopyFrom(libzeth::point_g1_affine_to_proto<ppT>(proofObj.g_C));

    std::stringstream inputs_ss;
    libzeth::primary_inputs_write_json(
        mock_extended_proof.get_primary_inputs(), inputs_ss);

    // Note on memory safety: set_allocated deleted the allocated objects
    // See:
    // https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
    zeth_proto::ExtendedProof *ext_proof = new zeth_proto::ExtendedProof();
    zeth_proto::ExtendedProofGROTH16 *grpc_extended_groth16_proof_obj =
        new zeth_proto::ExtendedProofGROTH16();

    grpc_extended_groth16_proof_obj->set_allocated_a(a);
    grpc_extended_groth16_proof_obj->set_allocated_b(b);
    grpc_extended_groth16_proof_obj->set_allocated_c(c);
    grpc_extended_groth16_proof_obj->set_inputs(inputs_ss.str());

    ext_proof->set_allocated_groth16_extended_proof(
        grpc_extended_groth16_proof_obj);

    zecale_proto::TransactionToAggregate *grpc_tx_to_aggregate_obj =
        new zecale_proto::TransactionToAggregate();
    grpc_tx_to_aggregate_obj->set_application_name("zeth");
    grpc_tx_to_aggregate_obj->set_fee_in_wei(12);
    grpc_tx_to_aggregate_obj->set_allocated_extended_proof(ext_proof);

    // Parse the TransactionToAggregate
    transaction_to_aggregate<ppT, libzeth::groth16_snark<ppT>> retrieved_tx =
        transaction_to_aggregate_from_proto<
            ppT,
            libzeth::groth16_api_handler<ppT>>(*grpc_tx_to_aggregate_obj);

    ASSERT_EQ(
        retrieved_tx.extended_proof().get_primary_inputs(),
        mock_extended_proof.get_primary_inputs());
    ASSERT_EQ(
        retrieved_tx.extended_proof().get_proof(),
        mock_extended_proof.get_proof());
    ASSERT_EQ(retrieved_tx.application_name(), "zeth");
    ASSERT_EQ(retrieved_tx.fee_wei(), 12);

    // The destructor of `zecale_proto::TransactionToAggregate` should be
    // invoked which whould free the memory allocated for the fields of this
    // message
    delete grpc_tx_to_aggregate_obj;
}

TEST(MainTests, ParseTransactionToAggregatePGHR13Mnt4)
{
    test_parse_transaction_to_aggregate_pghr13<libff::mnt4_pp>();
}

TEST(MainTests, ParseTransactionToAggregateGROTH16Mnt4)
{
    test_parse_transaction_to_aggregate_groth16<libff::mnt4_pp>();
}

} // namespace

int main(int argc, char **argv)
{
    // Initialize the curve parameters before running the tests
    libff::mnt4_pp::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
