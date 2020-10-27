# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.cli.utils import load_verification_key
from zecale.cli.command_context import CommandContext
from click import command, option, pass_context, Context


@command()
@option(
    "--key",
    required=True,
    help="Verification key file for application")
@option(
    "--name",
    required=True,
    help="Name of the application to register")
@pass_context
def register(ctx: Context, key: str, name: str) -> None:
    """
    Register an application using name and verification key
    """
    cmd_ctx: CommandContext = ctx.obj

    # Load verification key, and register against the given name.
    nested_snark = cmd_ctx.get_nested_snark()
    vk = load_verification_key(nested_snark, key)
    aggregator_client = cmd_ctx.get_aggregator_client()
    aggregator_client.register_application(nested_snark, vk, name)
