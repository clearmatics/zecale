# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from .utils import load_verification_key
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
    client_ctx = ctx.obj
    vk = load_verification_key(key)

    aggregator_client = client_ctx.get_aggregator_client()
    aggregator_client.register_application(vk, name)
