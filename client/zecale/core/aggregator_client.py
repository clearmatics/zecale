# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.api import aggregator_pb2_grpc
from zecale.api import aggregator_pb2
import grpc
from zeth.zksnark import IZKSnarkProvider, GenericVerificationKey
from google.protobuf import empty_pb2
from typing import Dict


class AggregatorClient:
    """
    Interface to Aggregator RPC calls.
    """

    def __init__(self, endpoint: str, zksnark: IZKSnarkProvider):
        self.endpoint = endpoint
        self.zksnark = zksnark

    def get_verification_key(self) -> Dict[str, object]:
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = aggregator_pb2_grpc.AggregatorStub(channel)  # type: ignore
            verificationkey = stub.GetVerificationKey(empty_pb2.Empty())
            return verificationkey

    def register_application(self, vk: GenericVerificationKey, app_name: str) -> None:
        """
        Register an application. Throw an error with message if this fails for any
        reason.
        """
        registration = aggregator_pb2.ApplicationRegistration()
        registration.application_name = app_name
        registration.vk.CopyFrom(self.zksnark.verification_key_to_proto(vk))
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = aggregator_pb2_grpc.AggregatorStub(channel)  # type: ignore




        raise Exception("unimplemented")
