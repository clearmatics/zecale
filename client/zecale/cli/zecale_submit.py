# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from .utils import load_transaction
from click import option, command, pass_context, Context


@command()
@option("--name", required=True, help="Target application name")
@option("--tx", required=True, help="Transaction to submit")
@pass_context
def submit(ctx: Context, name: str, tx: str) -> None:
    """
    Submit a nested transaction to the aggregation server
    """
    cmd_ctx = ctx.obj

    # Load nested transaction and submit to the aggregation server
    transaction = load_transaction(cmd_ctx.zksnark, tx)
    aggregator_client = cmd_ctx.get_aggregator_client()
    aggregator_client.submit_nested_transaction(name, transaction)
