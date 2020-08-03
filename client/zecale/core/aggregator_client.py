# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.api import aggregator_pb2_grpc
from zecale.api import aggregator_pb2
import grpc
from zeth.zksnark import IZKSnarkProvider, GenericVerificationKey, GenericProof
from google.protobuf import empty_pb2
from typing import Dict


class AggregatorClient:
    """
    Interface to Aggregator RPC calls. Interface uses the in-memory version of
    objects, internally converting to the protobuf versions.
    """

    def __init__(self, endpoint: str, zksnark: IZKSnarkProvider):
        self.endpoint = endpoint
        self.zksnark = zksnark
        self.wrapper_zksnark = zksnark

    def get_verification_key(self) -> Dict[str, object]:
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = aggregator_pb2_grpc.AggregatorStub(channel)  # type: ignore
            verificationkey = stub.GetVerificationKey(empty_pb2.Empty())
            return verificationkey

    def register_application(
            self, vk: GenericVerificationKey, app_name: str) -> None:
        """
        Register an application. Throw an error with message if this fails for any
        reason.
        """
        registration = aggregator_pb2.ApplicationRegistration()
        registration.application_name = app_name
        registration.vk.CopyFrom(self.zksnark.verification_key_to_proto(vk)) \
            # pylint: disable=no-member
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = aggregator_pb2_grpc.AggregatorStub(channel)  # type: ignore
            stub.RegisterApplication(registration)

    def submit_transaction(self, name: str, transaction: GenericProof) -> None:
        """
        Submit a transactions (just an xtended proof for now) to the aggregator.
        """
        tx_to_aggregate = aggregator_pb2.TransactionToAggregate()
        tx_to_aggregate.application_name = name
        tx_to_aggregate.extended_proof.CopyFrom(  # pylint: disable=no-member
            self.zksnark.proof_to_proto(transaction))
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = aggregator_pb2_grpc.AggregatorStub(channel)  # type: ignore
            stub.SubmitTransaction(tx_to_aggregate)

    def generate_aggregate_proof(self, name: str) -> GenericProof:
        """
        Request a aggregated proof.
        """
        agg_proof_request = aggregator_pb2.AggregateProofRequest()
        agg_proof_request.application_name = name
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = aggregator_pb2_grpc.AggregatorStub(channel)  # type: ignore
            proof_proto = stub.GenerateAggregateProof(agg_proof_request)
        return self.wrapper_zksnark.proof_from_proto(proof_proto)
