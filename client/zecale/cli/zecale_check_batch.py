# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.cli.utils import load_aggregated_transaction
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
    cmd_ctx = ctx.obj
    aggregated_tx = load_aggregated_transaction(cmd_ctx.zksnark, batch_file)
    inputs = aggregated_tx.ext_proof.inputs

    # Attempt to automatically detect the vk_hash param at position 0
    batch_offset = len(inputs) % batch_size
    inputs_per_batch = int((len(inputs) - batch_offset) / batch_size)
    print(f"inputs=\n{inputs}")

    for i in range(batch_size):
        result_idx = batch_offset + (inputs_per_batch * (i + 1)) - 1
        result = int(inputs[result_idx][2:], 16)
        print(f"result[{i}]={result}")
        if result != 1:
            raise ClickException("nested proof judged as invalid")
