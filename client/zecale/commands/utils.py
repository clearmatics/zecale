# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.zksnark import GenericVerificationKey
import json


def load_verification_key(verification_key: str) -> GenericVerificationKey:
    """
    Load a JSON verification key from a file.
    """
    with open(verification_key, "rb") as vk_f:
        return json.load(vk_f)
