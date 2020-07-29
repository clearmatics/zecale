# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

import api.aggregator_pb2
import grpc
from google.protobuf import empty_pb2
from typing import Dict


class AggregatorClient:
    """
    Interface to Aggregator RPC calls.
    """

    def __init__(self, endpoint: str):
        self.endpoint = endpoint

    def get_verification_key(self) -> Dict[str, object]:
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = api.aggregator_pb2_grpc.AggregatorStub(channel)  # type: ignore
            verificationkey = stub.GetVerificationKey(empty_pb2.Empty())
            return verificationkey
