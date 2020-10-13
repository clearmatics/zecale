# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+


from zecale.dummy_app.deploy import deploy
from zecale.dummy_app.get import get
from zeth.cli.constants import ETH_NETWORK_FILE_DEFAULT
from zeth.cli.utils import get_eth_network
from click import group, option, pass_context, Context
from click_default_group import DefaultGroup  # type: ignore
from typing import Optional


@group(cls=DefaultGroup, default_if_no_args=True, default="--help")
@option(
    "--eth-network",
    help="Ethereum RPC endpoint, network or config file "
    f"(default: '{ETH_NETWORK_FILE_DEFAULT}')")
@option("--eth-addr", help="Sender's eth address or address filename")
@option("--eth-private-key", help="Sender's eth private key file")
@pass_context
def dummy_app(
        ctx: Context,
        eth_network: Optional[str],
        eth_addr: Optional[str],
        eth_private_key: Optional[str]) -> None:
    ctx.obj = {
        "eth_network": get_eth_network(eth_network),
        "eth_addr": eth_addr,
        "eth_private_key": eth_private_key,
    }


dummy_app.add_command(deploy)
dummy_app.add_command(get)
