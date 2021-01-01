# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from zeth.core.zksnark import ExtendedProof, IZKSnarkProvider
from typing import Dict, Any, cast


class NestedTransaction:
    """
    A transaction to be batched into an AggregatedTransaction
    """
    def __init__(
            self,
            app_name: str,
            ext_proof: ExtendedProof,
            parameters: bytes,
            fee_in_wei: int):
        self.app_name = app_name
        self.ext_proof = ext_proof
        self.parameters = parameters
        self.fee_in_wei = fee_in_wei

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "app_name": self.app_name,
            "extended_proof": self.ext_proof.to_json_dict(),
            "parameters": self.parameters.hex(),
            "fee_in_wei": self.fee_in_wei
        }

    @staticmethod
    def from_json_dict(
            zksnark: IZKSnarkProvider,
            json_dict: Dict[str, Any]) -> NestedTransaction:
        app_name = json_dict["app_name"]
        ext_proof = ExtendedProof.from_json_dict(
            zksnark, cast(Dict[str, Any], json_dict["extended_proof"]))
        parameters = bytes.fromhex(json_dict["parameters"])
        fee_in_wei = json_dict["fee_in_wei"]

        return NestedTransaction(app_name, ext_proof, parameters, fee_in_wei)
