# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from ..cli.defaults import APPLICATION_INSTANCE_FILE_DEFAULT
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
    "--check", type=int, help="Check the result against the given value (0|1)")
@pass_context
def get(
        ctx: Context,
        scalar: int,
        instance_file: str,
        check: Optional[int]) -> None:
    """
    Deploy the contract for a dummy application.
    """

    eth_network = ctx.obj["eth_network"]
    check_value: Optional[bool] = None if check is None else check != 0

    # Load the contract instance
    with open(instance_file, "r") as instance_f:
        instance_desc = InstanceDescription.from_json_dict(json.load(instance_f))

    # Instantiate
    web3 = open_web3_from_network(eth_network)
    app_contract = instance_desc.instantiate(web3)
    result = app_contract.functions.get(scalar).call()
    print(f"{scalar}: {result}")

    if (check_value is not None) and (result != check_value):
        raise ClickException("state check failed")
