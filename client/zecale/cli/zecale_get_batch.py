# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.cli.defaults import BATCH_PROOF_FILENAME_DEFAULT
from zecale.cli.command_context import CommandContext
import json
from click import option, command, pass_context, Context


@command()
@option("--name", required=True, help="Target application name")
@option(
    "--batch-file",
    default=BATCH_PROOF_FILENAME_DEFAULT,
    help="Batch proof output file")
@pass_context
def get_batch(
        ctx: Context,
        name: str,
        batch_file: str) -> None:
    """
    Request an aggregated transaction for the given application name.
    """

    cmd_ctx: CommandContext = ctx.obj
    wrapper_snark = cmd_ctx.get_wrapper_snark()
    aggregator_client = cmd_ctx.get_aggregator_client()
    aggregated_tx = aggregator_client.get_aggregated_transaction(
        wrapper_snark, name)
    with open(batch_file, "w") as batch_f:
        json.dump(aggregated_tx.to_json_dict(), batch_f)
