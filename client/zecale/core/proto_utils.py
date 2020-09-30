# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.core.aggregated_transaction import AggregatedTransaction
from zecale.api import aggregator_pb2
from zeth.core.zksnark import IZKSnarkProvider
from typing import List


def aggregated_transaction_from_proto(
        zksnark: IZKSnarkProvider,
        aggregated_transaction_proto: aggregator_pb2.AggregatedTransaction
) -> AggregatedTransaction:
    """
    Convert a generic protobuf AggregatedTransactionRequest to an in-memory
    AggregatedTransaction
    """
    extproof = zksnark.extended_proof_from_proto(
        aggregated_transaction_proto.extended_proof)
    # TODO: add suport for nested parameters
    # nested_parameters = cast(List[str],
    #     json.loads(aggregated_transaction_proto.nested_parameters)
    nested_parameters: List[List[str]] = []
    return AggregatedTransaction(extproof, nested_parameters)
