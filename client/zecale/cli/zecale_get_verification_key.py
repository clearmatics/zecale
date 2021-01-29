# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.cli.defaults import AGGREGATOR_VERIFICATION_KEY_FILE_DEFAULT
from zecale.cli.command_context import CommandContext
import json
from click import option, command, pass_context, Context


@command()
@option(
    "--vk-out",
    "-o",
    default=AGGREGATOR_VERIFICATION_KEY_FILE_DEFAULT,
    help=f"Output file (default: {AGGREGATOR_VERIFICATION_KEY_FILE_DEFAULT})")
@pass_context
def get_verification_key(
        ctx: Context,
        vk_out: str) -> None:
    """
    Get the aggregator (wrapping) verification key from the aggregation server
    and write to a file.
    """
    cmd_ctx: CommandContext = ctx.obj
    aggregator_client = cmd_ctx.get_aggregator_client()
    aggregator_vk = aggregator_client.get_verification_key(
        cmd_ctx.get_wrapper_snark())
    with open(vk_out, "w") as vk_f:
        json.dump(aggregator_vk.to_json_dict(), vk_f)
