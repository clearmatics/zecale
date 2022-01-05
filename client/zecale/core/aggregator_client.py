# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.api import aggregator_pb2_grpc
from zecale.api import aggregator_pb2
from zecale.core.aggregated_transaction import AggregatedTransaction
from zecale.core.aggregator_config import AggregatorConfiguration
from zecale.core.nested_transaction import NestedTransaction
from zecale.core.proto_utils import aggregator_configuration_from_proto, \
    nested_transaction_to_proto, aggregated_transaction_from_proto
from zeth.core.zksnark import IZKSnarkProvider, IVerificationKey
import grpc
from google.protobuf import empty_pb2
import json


class AggregatorClient:
    """
    Interface to Aggregator RPC calls. Interface uses the in-memory version of
    objects, internally converting to the protobuf versions.
    """
    def __init__(self, endpoint: str):
        self.endpoint = endpoint

    def get_configuration(self) -> AggregatorConfiguration:
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = aggregator_pb2_grpc.AggregatorStub(channel)  # type: ignore
            config_proto = stub.GetConfiguration(empty_pb2.Empty())
            return aggregator_configuration_from_proto(config_proto)

    def get_verification_key(
            self, wrapper_zksnark: IZKSnarkProvider) -> IVerificationKey:
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = aggregator_pb2_grpc.AggregatorStub(channel)  # type: ignore
            vk_proto = stub.GetVerificationKey(empty_pb2.Empty())
            return wrapper_zksnark.verification_key_from_proto(vk_proto)

    def get_nested_verification_key_hash(
            self, nested_zksnark: IZKSnarkProvider, vk: IVerificationKey) -> str:
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = aggregator_pb2_grpc.AggregatorStub(channel)  # type: ignore
            vk_proto = nested_zksnark.verification_key_to_proto(vk)
            vk_hash_json = stub.GetNestedVerificationKeyHash(vk_proto).hash
            return json.loads(vk_hash_json)

    def register_application(
            self,
            nested_zksnark: IZKSnarkProvider,
            vk: IVerificationKey,
            app_name: str) -> None:
        """
        Register an application. Throw an error with message if this fails for any
        reason.
        """
        app_desc = aggregator_pb2.ApplicationDescription()
        app_desc.application_name = app_name
        app_desc.vk.CopyFrom(nested_zksnark.verification_key_to_proto(vk)) \
            # pylint: disable=no-member
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = aggregator_pb2_grpc.AggregatorStub(channel)  # type: ignore
            stub.RegisterApplication(app_desc)

    def submit_nested_transaction(
            self,
            nested_zksnark: IZKSnarkProvider,
            nested_tx: NestedTransaction) -> None:
        """
        Submit a nested transaction to the aggregator.
        """
        assert isinstance(nested_zksnark, IZKSnarkProvider)
        assert isinstance(nested_tx, NestedTransaction)
        nested_tx_proto = nested_transaction_to_proto(nested_zksnark, nested_tx)
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = aggregator_pb2_grpc.AggregatorStub(channel)  # type: ignore
            stub.SubmitNestedTransaction(nested_tx_proto)

    def get_aggregated_transaction(
            self,
            wrapper_zksnark: IZKSnarkProvider,
            name: str) -> AggregatedTransaction:
        """
        Request an aggregated transaction.
        """
        agg_tx_request = aggregator_pb2.AggregatedTransactionRequest()
        agg_tx_request.application_name = name
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = aggregator_pb2_grpc.AggregatorStub(channel)  # type: ignore
            agg_tx_proto = stub.GenerateAggregatedTransaction(agg_tx_request)
        return aggregated_transaction_from_proto(wrapper_zksnark, agg_tx_proto)
