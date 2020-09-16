# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.zksnark import GenericVerificationKey, GenericProof
import json


def load_verification_key(verification_key: str) -> GenericVerificationKey:
    """
    Load a JSON verification key from a file.
    """
    with open(verification_key, "rb") as vk_f:
        return json.load(vk_f)


# For now, a "transaction" is just an extended proof.
def load_transaction(tx_file: str) -> GenericProof:
    """
    Load a single transaction for some application.
    """
    with open(tx_file, "rb") as tx_f:
        return json.load(tx_f)
