# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from click import command, option, pass_context, Context


@command()
@option("--verification-key", help="Verification key file for application")
@pass_context
def register(ctx: Context, verification_key: str) -> None:
    print(f"register: aggregator_server={ctx.obj.aggregator_server}")
    print(f"register: verification_key={verification_key}")
