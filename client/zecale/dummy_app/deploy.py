# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from .defaults import VERIFICATION_KEY_FILE_DEFAULT
from ..core.utils import get_zecale_dir
from ..cli.defaults import APPLICATION_INSTANCE_FILE_DEFAULT, \
    INSTANCE_FILE_DEFAULT
from zeth.core.contracts import InstanceDescription
from zeth.cli.utils import open_web3_from_network, load_eth_address, \
    load_eth_private_key
from click import command, argument, option, pass_context, Context
from os.path import join
import json


ZECALE_DIR = get_zecale_dir()
CONTRACTS_DIR = join(ZECALE_DIR, "contracts")
DUMMY_APP_CONTRACT_FILE = join(CONTRACTS_DIR, "dummy_application.sol")
DUMMY_APP_CONTRACT_DEPLOY_GAS = 500000


@command()
@argument("verification-key-hash")
@option(
    "--dispatcher-instance-file",
    default=INSTANCE_FILE_DEFAULT,
    help="Dispatcher instance file")
@option(
    "--instance-file",
    default=APPLICATION_INSTANCE_FILE_DEFAULT,
    help="File to write dummy app instance information to")
@pass_context
def deploy(
        ctx: Context,
        verification_key_hash: str,
        dispatcher_instance_file: str,
        instance_file: str) -> None:
    """
    Deploy the contract for a dummy application.
    """

    eth_network = ctx.obj["eth_network"]
    eth_addr = ctx.obj["eth_addr"]
    eth_private_key = ctx.obj["eth_private_key"]

    # Load the dispatcher instance
    with open(dispatcher_instance_file, "r") as dispatcher_instance_f:
        dispatcher_desc = InstanceDescription.from_json_dict(
            json.load(dispatcher_instance_f))
        dispatcher_address = dispatcher_desc.address

    web3 = open_web3_from_network(eth_network)
    eth_address = load_eth_address(eth_addr)
    eth_private_key_data = load_eth_private_key(eth_private_key)
    instance_desc = InstanceDescription.deploy(
        web3,
        DUMMY_APP_CONTRACT_FILE,
        "DummyApplication",
        eth_addr,
        eth_private_key,
        DUMMY_APP_CONTRACT_DEPLOY_GAS,
        {"allow_paths": CONTRACTS_DIR},
        [dispatcher_address, verification_key_hash])

    with open(instance_file, "w") as instance_file_f:
        json.dump(instance_desc.to_json_dict(), instance_file_f)
