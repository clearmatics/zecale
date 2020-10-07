# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.cli.defaults import AGGREGATOR_VERIFICATION_KEY_FILE_DEFAULT
from zecale.cli.command_context import CommandContext
from zecale.cli.utils import load_verification_key
from zecale.core.dispatcher_contract import DispatcherContract
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
    aggregator_config = cmd_ctx.get_aggregator_configuration()
    snark = aggregator_config.wrapper_snark
    pp = aggregator_config.wrapper_pairing_parameters
    (eth_addr, eth_private_key) = cmd_ctx.get_eth_key_and_address()

    # Load verification key
    vk = load_verification_key(snark, verification_key_file)

    # Deploy contract, passing the encoded key to the constructor
    web3 = cmd_ctx.get_web3()
    _dispatcher, dispatcher_instance = DispatcherContract.deploy(
        web3, snark, pp, vk, eth_addr, eth_private_key)

    # Save the contract instance description
    with open(cmd_ctx.instance_file, "w") as instance_f:
        json.dump(dispatcher_instance.to_json_dict(), instance_f)
