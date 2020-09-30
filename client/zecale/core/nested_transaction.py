# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from zeth.core.zksnark import ExtendedProof, IZKSnarkProvider
from typing import Dict, Any


class NestedTransaction:
    """
    A transaction to be batched into an AggregatedTransaction
    """
    def __init__(
            self,
            app_name: str,
            ext_proof: ExtendedProof):
        self.app_name = app_name
        self.ext_proof = ext_proof

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "name": self.app_name,
            "extended_proof": self.ext_proof.to_json_dict(),
        }

    @staticmethod
    def _from_json_dict(
            zksnark: IZKSnarkProvider,
            json_dict: Dict[str, Any]) -> NestedTransaction:
        return NestedTransaction(
            app_name=json_dict["name"],
            ext_proof=ExtendedProof.from_json_dict(
                zksnark, json_dict["extended_proof"]))
