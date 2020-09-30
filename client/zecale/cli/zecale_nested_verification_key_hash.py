# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from .command_context import CommandContext
from .utils import load_verification_key
from zeth.core.utils import hex_to_uint256_list
from click import command, argument, Context, pass_context


@command()
@argument("verification_key_file")
@pass_context
def nested_verification_key_hash(
        ctx: Context,
        verification_key_file: str) -> None:
    """
    Query the aggregator_server for the hash of a specific nested verification
    key. The verification key does not have to be registered.
    """
    cmd_ctx: CommandContext = ctx.obj

    # Load key and call the GetNestedVerificationKeyHash method
    vk = load_verification_key(cmd_ctx.zksnark, verification_key_file)
    aggregator_client = cmd_ctx.get_aggregator_client()
    vk_hash_hex = aggregator_client.get_nested_verification_key_hash(vk)

    # Decode the key into evm words and extract the lowest order one. Assert
    # that the higher order ints are all zero.
    vk_hash_evm = list(hex_to_uint256_list(vk_hash_hex))
    vk_hash = vk_hash_evm[-1]
    for i in vk_hash_evm[:-1]:
        assert i == 0, "expected higher orders words to be 0"

    print(vk_hash.to_bytes(32, byteorder='big').hex())
