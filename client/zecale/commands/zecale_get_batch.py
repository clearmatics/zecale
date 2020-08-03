# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.commands.defaults import BATCH_PROOF_FILENAME_DEFAULT
import json
from click import option, command, pass_context, Context


@command()
@option("--name", required=True, help="Target application name")
@option(
    "--batch-file",
    default=BATCH_PROOF_FILENAME_DEFAULT,
    help="Batch proof output file")
@pass_context
def get_batch(ctx: Context, name: str, batch_file: str) -> None:
    client_ctx = ctx.obj
    aggregator_client = client_ctx.get_aggregator_client()
    batch_proof = aggregator_client.generate_aggregate_proof(name)
    with open(batch_file, "w") as batch_proof_f:
        json.dump(batch_proof, batch_proof_f)
