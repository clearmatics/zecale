# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from zeth.core.zksnark import IZKSnarkProvider, ExtendedProof
from typing import Dict, List, Any


class AggregatedTransaction:
    """
    An aggregated transaction, returned by the aggregator server.
    """
    def __init__(
            self,
            app_name: str,
            ext_proof: ExtendedProof,
            nested_parameters: List[bytes]):
        self.app_name = app_name
        self.ext_proof = ext_proof
        self.nested_parameters = nested_parameters

    @staticmethod
    def from_json_dict(
            zksnark: IZKSnarkProvider,
            json_dict: Dict[str, Any]) -> AggregatedTransaction:
        app_name = json_dict["app_name"]
        ext_proof = ExtendedProof.from_json_dict(zksnark, json_dict["ext_proof"])
        nested_parameters = \
            [bytes.fromhex(x) for x in json_dict["nested_parameters"]]
        return AggregatedTransaction(app_name, ext_proof, nested_parameters)

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "app_name": self.app_name,
            "ext_proof": self.ext_proof.to_json_dict(),
            "nested_parameters":  [x.hex() for x in self.nested_parameters],
        }
