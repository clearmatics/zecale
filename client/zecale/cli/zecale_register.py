# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.cli.utils import load_verification_key
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
    cmd_ctx = ctx.obj

    # Load verification key, and register against the given name.
    vk = load_verification_key(cmd_ctx.zksnark, key)
    aggregator_client = cmd_ctx.get_aggregator_client()
    aggregator_client.register_application(vk, name)
