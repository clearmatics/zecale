# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from zeth.core.zksnark import IZKSnarkProvider, ExtendedProof
from typing import Dict, List, Any, cast


class AggregatedTransaction:
    """
    An aggregated transaction, returned by the aggregator server.
    """
    def __init__(
            self,
            extproof: ExtendedProof,
            nested_parameters: List[List[str]]):
        self.extproof = extproof
        self.nested_parameters = nested_parameters

    @staticmethod
    def from_json_dict(
            zksnark: IZKSnarkProvider,
            json_dict: Dict[str, Any]) -> AggregatedTransaction:
        proof = zksnark.proof_from_json_dict(json_dict["proof"])
        inputs = cast(List[str], json_dict["inputs"])
        extproof = ExtendedProof(proof, inputs)
        nested_parameters = cast(
                List[List[str]], json_dict.get("nested_parameters", []))
        return AggregatedTransaction(extproof, nested_parameters)

    def to_json_dict(self) -> Dict[str, Any]:
        json_dict: Dict[str, Any] = self.extproof.to_json_dict()
        if self.nested_parameters:
            json_dict["nested_parameters"] = self.nested_parameters
        return json_dict
