# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.cli.defaults import APPLICATION_INSTANCE_FILE_DEFAULT
from zeth.core.contracts import InstanceDescription
from zeth.cli.utils import open_web3_from_network
import json
from click import command, argument, option, pass_context, Context, ClickException
from typing import Optional


@command()
@argument("scalar", type=int)
@option(
    "--instance-file",
    default=APPLICATION_INSTANCE_FILE_DEFAULT,
    help="File to write instance information to")
@option(
    "--check", type=int, help="Check the result against the given value")
@pass_context
def get(
        ctx: Context,
        scalar: int,
        instance_file: str,
        check: Optional[int]) -> None:
    """
    Query the deployed contract to find the value stored for a given scalar.
    (These values are the parameters submitted along side the proof for the
    given scalar.)
    """

    eth_network = ctx.obj["eth_network"]

    # Load the contract instance
    with open(instance_file, "r") as instance_f:
        instance_desc = InstanceDescription.from_json_dict(json.load(instance_f))

    # Instantiate
    web3 = open_web3_from_network(eth_network)
    app_contract = instance_desc.instantiate(web3)
    result: int = app_contract.functions.get(scalar).call()
    print(f"{scalar}: {result}")

    if (check is not None) and (result != check):
        raise ClickException("state check failed")
