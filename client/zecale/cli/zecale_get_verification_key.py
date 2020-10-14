# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.cli.defaults import AGGREGATOR_VERIFICATION_KEY_FILE_DEFAULT
import json
from click import option, command, pass_context, Context


@command()
@option(
    "--verification-key-file",
    "-f",
    default=AGGREGATOR_VERIFICATION_KEY_FILE_DEFAULT,
    help="Write verification key to this file (default: "
    f"{AGGREGATOR_VERIFICATION_KEY_FILE_DEFAULT})")
@pass_context
def get_verification_key(
        ctx: Context,
        verification_key_file: str) -> None:
    """
    Get the aggregator (wrapping) verification key from the aggregation server
    and write to a file.
    """
    cmd_ctx = ctx.obj
    aggregator_client = cmd_ctx.get_aggregator_client()
    aggregator_vk = aggregator_client.get_verification_key()
    with open(verification_key_file, "w") as vk_f:
        json.dump(aggregator_vk.to_json_dict(), vk_f)
