# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from commands.utils import open_aggregator_client, load_verification_key

from click import command, option, pass_context, Context, ClickException


@command()
@option("--verification-key", help="Verification key file for application")
@option("--application-name", help="Name of the application to register")
@pass_context
def register(ctx: Context, verification_key: str, application_name: str) -> None:
    client_ctx = ctx.obj;
    verification_key = load_verification_key(verification_key);
    aggregator_client = open_aggregator_client(client_ctx);
    aggregator_client.register_application(verification_key, application_name);

print("HHH")
