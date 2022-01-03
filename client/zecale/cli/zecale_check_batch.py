# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.cli.utils import load_aggregated_transaction
from zecale.cli.command_context import CommandContext
from click import argument, option, command, pass_context, Context, ClickException


@command()
@argument("batch-file")
@option(
    "--batch-size",
    type=int,
    required=True,
    help="Number of nested proofs per batch")
@pass_context
def check_batch(ctx: Context, batch_file: str, batch_size: int) -> None:
    """
    Exit with error if result is not 1 for any nested proof
    """
    cmd_ctx: CommandContext = ctx.obj
    aggregated_tx = load_aggregated_transaction(
        cmd_ctx.get_wrapper_snark(), batch_file)
    inputs = aggregated_tx.ext_proof.inputs
    results = int(inputs[1], 16)
    print(f"results={hex(results)}")

    expect_results = (1 << batch_size) - 1
    if expect_results != results:
        raise ClickException("at least one nested proof judged as invalid")
