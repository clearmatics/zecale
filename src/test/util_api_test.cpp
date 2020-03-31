#include "api/aggregator.pb.h"
#include "api/util.pb.h"
#include "util.hpp"
#include "util_api.hpp"

#include "gtest/gtest.h"
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libzeth/libsnark_helpers/debug_helpers.hpp>
#include <stdio.h>

typedef libff::mnt4_pp ppT;
template<typename ppT> using proofT = libsnark::r1cs_gg_ppzksnark_proof<ppT>;

using namespace libzecale;

namespace
{

TEST(MainTests, ParseTransactionToAggregate)
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
    libsnark::r1cs_primary_input<libff::Fr<ppT>> primary_inputs =
        libsnark::r1cs_primary_input<libff::Fr<ppT>>(inputs);

    libzeth::extended_proof<ppT> mock_extended_proof(proof, primary_inputs);

    libsnark::r1cs_ppzksnark_proof<ppT> proofObj =
        mock_extended_proof.get_proof();
    aggregator_proto::HexPointBaseGroup1Affine *a =
        new aggregator_proto::HexPointBaseGroup1Affine();
    aggregator_proto::HexPointBaseGroup1Affine *a_p =
        new aggregator_proto::HexPointBaseGroup1Affine();
    aggregator_proto::HexPointBaseGroup2Affine *b =
        new aggregator_proto::HexPointBaseGroup2Affine(); // in G2
    aggregator_proto::HexPointBaseGroup1Affine *b_p =
        new aggregator_proto::HexPointBaseGroup1Affine();
    aggregator_proto::HexPointBaseGroup1Affine *c =
        new aggregator_proto::HexPointBaseGroup1Affine();
    aggregator_proto::HexPointBaseGroup1Affine *c_p =
        new aggregator_proto::HexPointBaseGroup1Affine();
    aggregator_proto::HexPointBaseGroup1Affine *h =
        new aggregator_proto::HexPointBaseGroup1Affine();
    aggregator_proto::HexPointBaseGroup1Affine *k =
        new aggregator_proto::HexPointBaseGroup1Affine();

    a->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_A.g));
    a_p->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_A.h));
    b->CopyFrom(format_hexPointBaseGroup2Affine<ppT>(proofObj.g_B.g)); // in G2
    b_p->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_B.h));
    c->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_C.g));
    c_p->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_C.h));
    h->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_H));
    k->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_K));

    libsnark::r1cs_ppzksnark_primary_input<ppT> pub_inputs =
        mock_extended_proof.get_primary_input();
    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < pub_inputs.size(); ++i) {
        ss << "0x"
           << libzeth::hex_from_libsnark_bigint<libff::Fr<ppT>>(
                  pub_inputs[i].as_bigint());
        if (i < pub_inputs.size() - 1) {
            ss << ", ";
        }
    }
    ss << "]";
    std::string inputs_json = ss.str();

    // Note on memory safety: set_allocated deleted the allocated objects
    // See:
    // https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
    aggregator_proto::ExtendedProof *ext_proof =
        new aggregator_proto::ExtendedProof();
    aggregator_proto::ExtendedProofPGHR13 *grpc_extended_pghr13_proof_obj =
        new aggregator_proto::ExtendedProofPGHR13();
    // aggregator_proto::ExtendedProofPGHR13 *grpc_extended_pghr13_proof_obj =
    // ext_proof->mutable_pghr13_extended_proof();

    grpc_extended_pghr13_proof_obj->set_allocated_a(a);
    grpc_extended_pghr13_proof_obj->set_allocated_a_p(a_p);
    grpc_extended_pghr13_proof_obj->set_allocated_b(b);
    grpc_extended_pghr13_proof_obj->set_allocated_b_p(b_p);
    grpc_extended_pghr13_proof_obj->set_allocated_c(c);
    grpc_extended_pghr13_proof_obj->set_allocated_c_p(c_p);
    grpc_extended_pghr13_proof_obj->set_allocated_h(h);
    grpc_extended_pghr13_proof_obj->set_allocated_k(k);
    grpc_extended_pghr13_proof_obj->set_inputs(inputs_json);

    ext_proof->set_allocated_pghr13_extended_proof(
        grpc_extended_pghr13_proof_obj);

    aggregator_proto::TransactionToAggregate *grpc_tx_to_aggregate_obj =
        new aggregator_proto::TransactionToAggregate();
    grpc_tx_to_aggregate_obj->set_application_name("zeth");
    grpc_tx_to_aggregate_obj->set_fee_in_wei(12);
    grpc_tx_to_aggregate_obj->set_allocated_extended_proof(ext_proof);

    // Parse the TransactionToAggregate
    transaction_to_aggregate<ppT> retrieved_tx =
        parse_transaction_to_aggregate<ppT>(*grpc_tx_to_aggregate_obj);

    ASSERT_EQ(
        retrieved_tx.extended_proof().get_primary_input(),
        mock_extended_proof.get_primary_input());
    ASSERT_EQ(
        retrieved_tx.extended_proof().get_proof(),
        mock_extended_proof.get_proof());
    ASSERT_EQ(retrieved_tx.application_name(), "zeth");
    ASSERT_EQ(retrieved_tx.fee_wei(), 12);

    // The destructor of `aggregator_proto::TransactionToAggregate` should be
    // invoked which whould free the memory allocated for the fields of this
    // message
    delete grpc_tx_to_aggregate_obj;
}

} // namespace

int main(int argc, char **argv)
{
    // Initialize the curve parameters before running the tests
    ppT::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
