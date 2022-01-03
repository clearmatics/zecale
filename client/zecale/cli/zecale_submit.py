# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.cli.utils import load_nested_transaction
from zecale.cli.command_context import CommandContext
from click import command, argument, pass_context, Context


@command()
@argument("tx_file")
@pass_context
def submit(ctx: Context, tx_file: str) -> None:
    """
    Submit a nested transaction to the aggregation server
    """
    cmd_ctx: CommandContext = ctx.obj

    # Load nested transaction and submit to the aggregation server
    nested_snark = cmd_ctx.get_nested_snark()
    nested_tx = load_nested_transaction(nested_snark, tx_file)
    aggregator_client = cmd_ctx.get_aggregator_client()
    aggregator_client.submit_nested_transaction(nested_snark, nested_tx)
