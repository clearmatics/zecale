# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.api import aggregator_pb2_grpc
from zecale.api import aggregator_pb2
from zecale.core.aggregated_transaction import AggregatedTransaction
from zecale.core.proto_utils import aggregated_transaction_from_proto
import grpc
from zeth.core.zksnark import IZKSnarkProvider, IVerificationKey, ExtendedProof
from google.protobuf import empty_pb2
import json


class AggregatorClient:
    """
    Interface to Aggregator RPC calls. Interface uses the in-memory version of
    objects, internally converting to the protobuf versions.
    """

    def __init__(self, endpoint: str, zksnark: IZKSnarkProvider):
        self.endpoint = endpoint
        self.zksnark = zksnark
        self.wrapper_zksnark = zksnark

    def get_verification_key(self) -> IVerificationKey:
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = aggregator_pb2_grpc.AggregatorStub(channel)  # type: ignore
            vk_proto = stub.GetVerificationKey(empty_pb2.Empty())
            return self.wrapper_zksnark.verification_key_from_proto(vk_proto)

    def get_nested_verification_key_hash(self, vk: IVerificationKey) -> str:
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = aggregator_pb2_grpc.AggregatorStub(channel)  # type: ignore
            vk_proto = self.zksnark.verification_key_to_proto(vk)
            vk_hash_json = stub.GetNestedVerificationKeyHash(vk_proto).hash
            return json.loads(vk_hash_json)

    def register_application(self, vk: IVerificationKey, app_name: str) -> None:
        """
        Register an application. Throw an error with message if this fails for any
        reason.
        """
        app_desc = aggregator_pb2.ApplicationDescription()
        app_desc.application_name = app_name
        app_desc.vk.CopyFrom(self.zksnark.verification_key_to_proto(vk)) \
            # pylint: disable=no-member
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = aggregator_pb2_grpc.AggregatorStub(channel)  # type: ignore
            stub.RegisterApplication(app_desc)

    def submit_nested_transaction(
            self, name: str, transaction: ExtendedProof) -> None:
        """
        Submit a transactions (just an xtended proof for now) to the aggregator.
        """
        tx_to_aggregate = aggregator_pb2.NestedTransaction()
        tx_to_aggregate.application_name = name
        tx_to_aggregate.extended_proof.CopyFrom(  # pylint: disable=no-member
            self.zksnark.extended_proof_to_proto(transaction))
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = aggregator_pb2_grpc.AggregatorStub(channel)  # type: ignore
            stub.SubmitNestedTransaction(tx_to_aggregate)

    def get_aggregated_transaction(self, name: str) -> AggregatedTransaction:
        """
        Request an aggregated transaction.
        """
        agg_tx_request = aggregator_pb2.AggregatedTransactionRequest()
        agg_tx_request.application_name = name
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = aggregator_pb2_grpc.AggregatorStub(channel)  # type: ignore
            agg_tx_proto = stub.GenerateAggregatedTransaction(agg_tx_request)
        return aggregated_transaction_from_proto(
            self.wrapper_zksnark, agg_tx_proto)
