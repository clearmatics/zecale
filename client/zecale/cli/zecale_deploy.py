# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from .defaults import AGGREGATOR_VERIFICATION_KEY_FILE_DEFAULT
from .command_context import CommandContext
from .utils import load_verification_key
from ..core.dispatcher_contract import DispatcherContract
from click import command, option, Context, pass_context
import json


@command()
@option(
    "--verification-key-file", "-f",
    default=AGGREGATOR_VERIFICATION_KEY_FILE_DEFAULT,
    help="Aggregator verification key file (default: "
    f"{AGGREGATOR_VERIFICATION_KEY_FILE_DEFAULT})")
@pass_context
def deploy(
        ctx: Context,
        verification_key_file: str) -> None:
    """
    Deploy the zecale dispatcher contract.
    """

    cmd_ctx: CommandContext = ctx.obj
    (eth_addr, eth_private_key) = cmd_ctx.get_eth_key_and_address()

    # Load verification key
    vk = load_verification_key(verification_key_file)

    # Deploy contract, passing the encoded key to the constructor
    web3 = cmd_ctx.get_web3()
    _dispatcher, dispatcher_instance = DispatcherContract.deploy(
        web3, vk, eth_addr, eth_private_key, cmd_ctx.zksnark)

    # Save the contract instance description
    with open(cmd_ctx.instance_file, "w") as instance_f:
        json.dump(dispatcher_instance.to_json_dict(), instance_f)
