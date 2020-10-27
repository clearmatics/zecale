# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.core.aggregated_transaction import AggregatedTransaction
from zecale.core.aggregator_config import AggregatorConfiguration
from zecale.core.nested_transaction import NestedTransaction
from zecale.api import aggregator_pb2
from zeth.core.zksnark import IZKSnarkProvider
from zeth.core.pairing import pairing_parameters_from_proto


def aggregator_configuration_from_proto(
        aggregator_config_proto: aggregator_pb2.AggregatorConfiguration
) -> AggregatorConfiguration:
    return AggregatorConfiguration(
        nested_snark_name=aggregator_config_proto.nested_snark_name,
        wrapper_snark_name=aggregator_config_proto.wrapper_snark_name,
        nested_pairing_parameters=pairing_parameters_from_proto(
            aggregator_config_proto.nested_pairing_parameters),
        wrapper_pairing_parameters=pairing_parameters_from_proto(
            aggregator_config_proto.wrapper_pairing_parameters))


def nested_transaction_to_proto(
        zksnark: IZKSnarkProvider,
        tx: NestedTransaction) -> aggregator_pb2.NestedTransaction:
    assert isinstance(tx, NestedTransaction)
    tx_proto = aggregator_pb2.NestedTransaction()
    tx_proto.application_name = tx.app_name
    tx_proto.extended_proof.CopyFrom(  # pylint: disable=no-member
        zksnark.extended_proof_to_proto(tx.ext_proof))
    tx_proto.parameters = tx.parameters
    return tx_proto


def aggregated_transaction_from_proto(
        zksnark: IZKSnarkProvider,
        aggregated_transaction_proto: aggregator_pb2.AggregatedTransaction
) -> AggregatedTransaction:
    """
    Convert a generic protobuf AggregatedTransactionRequest to an in-memory
    AggregatedTransaction
    """
    app_name = aggregated_transaction_proto.application_name
    extproof = zksnark.extended_proof_from_proto(
        aggregated_transaction_proto.extended_proof)
    nested_parameters = list(aggregated_transaction_proto.nested_parameters)
    return AggregatedTransaction(app_name, extproof, nested_parameters)
