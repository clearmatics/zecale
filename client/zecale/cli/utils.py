# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.core.aggregated_transaction import AggregatedTransaction
from zeth.core.zksnark import IVerificationKey, ExtendedProof, IZKSnarkProvider
import json


def load_verification_key(
        zksnark: IZKSnarkProvider, vk_file: str) -> IVerificationKey:
    """
    Load a JSON verification key from a file.
    """
    with open(vk_file, "r") as vk_f:
        return zksnark.verification_key_from_json_dict(json.load(vk_f))


# For now, a "transaction" is just an extended proof.
def load_extended_proof(zksnark: IZKSnarkProvider, tx_file: str) -> ExtendedProof:
    """
    Load a single transaction for some application.
    """
    with open(tx_file, "r") as tx_f:
        return ExtendedProof.from_json_dict(zksnark, json.load(tx_f))


def load_aggregated_transaction(
        zksnark: IZKSnarkProvider, agg_tx_file: str) -> AggregatedTransaction:
    """
    Load an aggreagted transction from a file
    """
    with open(agg_tx_file, "r") as tx_f:
        return AggregatedTransaction.from_json_dict(zksnark, json.load(tx_f))
