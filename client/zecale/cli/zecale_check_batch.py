# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

import json
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
    with open(batch_file, "r") as batch_proof_f:
        batch_proof = json.load(batch_proof_f)

    # Attempt to automatically detect the vk_hash param at position 0
    inputs = batch_proof["inputs"]
    batch_offset = len(inputs) % batch_size
    inputs_per_batch = int((len(inputs) - batch_offset) / batch_size)
    print(f"inputs=\n{inputs}")

    for i in range(batch_size):
        result_idx = batch_offset + (inputs_per_batch * (i + 1)) - 1
        result = int(inputs[result_idx][2:], 16)
        print(f"result[{i}]={result}")
        if result != 1:
            raise ClickException("nested proof judged as invalid")
