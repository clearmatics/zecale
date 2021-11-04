# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.cli.command_context import CommandContext
from zecale.cli.utils import load_verification_key
from click import command, argument, Context, pass_context


@command()
@argument("verification_key_file")
@pass_context
def nested_verification_key_hash(
        ctx: Context,
        verification_key_file: str) -> None:
    """
    Query the aggregator-server for the hash of a specific nested verification
    key. The verification key does not have to be registered.
    """
    cmd_ctx: CommandContext = ctx.obj
    snark = cmd_ctx.get_nested_snark()

    # Load key and call the GetNestedVerificationKeyHash method
    vk = load_verification_key(snark, verification_key_file)
    aggregator_client = cmd_ctx.get_aggregator_client()
    vk_hash_hex = aggregator_client.get_nested_verification_key_hash(snark, vk)
    print(vk_hash_hex)
