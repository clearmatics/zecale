# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from zeth.core.pairing import PairingParameters
from zeth.core.zksnark import get_zksnark_provider
from typing import Dict, Any, cast


class AggregatorConfiguration:
    """
    The configuration (snarks and pairing parameters) to be used for
    aggregation.
    """
    def __init__(
            self,
            nested_snark_name: str,
            wrapper_snark_name: str,
            nested_pairing_parameters: PairingParameters,
            wrapper_pairing_parameters: PairingParameters):
        self.nested_snark_name = nested_snark_name
        self.wrapper_snark_name = wrapper_snark_name
        self.nested_snark = get_zksnark_provider(nested_snark_name)
        self.wrapper_snark = get_zksnark_provider(wrapper_snark_name)
        self.nested_pairing_parameters = nested_pairing_parameters
        self.wrapper_pairing_parameters = wrapper_pairing_parameters

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "nested_snark_name": self.nested_snark_name,
            "wrapper_snark_name": self.wrapper_snark_name,
            "nested_pairing_parameters":
            self.nested_pairing_parameters.to_json_dict(),
            "wrapper_pairing_parameters":
            self.wrapper_pairing_parameters.to_json_dict()
        }

    @staticmethod
    def from_json_dict(json_dict: Dict[str, Any]) -> AggregatorConfiguration:
        return AggregatorConfiguration(
            nested_snark_name=cast(str, json_dict["nested_snark_name"]),
            wrapper_snark_name=cast(str, json_dict["wrapper_snark_name"]),
            nested_pairing_parameters=PairingParameters.from_json_dict(
                json_dict["nested_pairing_parameters"]),
            wrapper_pairing_parameters=PairingParameters.from_json_dict(
                json_dict["wrapper_pairing_parameters"]))
