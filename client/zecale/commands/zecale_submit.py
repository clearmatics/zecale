# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.commands.utils import load_transaction
from click import option, command, pass_context, Context


@command()
@option("--name", required=True, help="Target application name")
@option("--tx", required=True, help="Transaction to submit")
@pass_context
def submit(ctx: Context, name: str, tx: str) -> None:
    client_ctx = ctx.obj
    transaction = load_transaction(tx)

    aggregator_client = client_ctx.get_aggregator_client()
    aggregator_client.submit_transaction(name, transaction)
