# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.cli.defaults import INSTANCE_FILE_DEFAULT, \
    AGGREGATOR_SERVER_ENDPOINT_DEFAULT, AGGREGATOR_CONFIG_FILE_DEFAULT
from zecale.cli.command_context import CommandContext
from zecale.cli.zecale_get_verification_key import get_verification_key
from zecale.cli.zecale_deploy import deploy
from zecale.cli.zecale_nested_verification_key_hash import \
    nested_verification_key_hash
from zecale.cli.zecale_register import register
from zecale.cli.zecale_submit import submit
from zecale.cli.zecale_submit_batch import submit_batch
from zecale.cli.zecale_get_batch import get_batch
from zecale.cli.zecale_check_batch import check_batch
from zeth.cli.constants import ETH_NETWORK_FILE_DEFAULT
from grpc import RpcError
from click import group, option, pass_context, Context
from click_default_group import DefaultGroup  # type: ignore
import sys
from typing import Optional, Any


class HandleRpcExceptions(DefaultGroup):
    """
    A click group which handles uncaught RpcExceptions with a sensible message
    (similar to ClickException).
    """
    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        try:
            return DefaultGroup.__call__(self, *args, **kwargs)
        except RpcError as err:
            print(f"error: {err.details()}")  # pylint: disable=no-member
            sys.exit(1)


@group(cls=HandleRpcExceptions, default_if_no_args=True, default="--help")
@option(
    "--aggregator-server", "-a",
    default=AGGREGATOR_SERVER_ENDPOINT_DEFAULT,
    help="Aggregator server endpoint "
    f"(default={AGGREGATOR_SERVER_ENDPOINT_DEFAULT})")
@option(
    "--aggregator-config-file", "-c",
    default=AGGREGATOR_CONFIG_FILE_DEFAULT,
    help="Aggregator configuration file "
    f"(default={AGGREGATOR_CONFIG_FILE_DEFAULT})")
@option(
    "--instance-file", "-i",
    default=INSTANCE_FILE_DEFAULT,
    help=f"Zecale contract instance file (default={INSTANCE_FILE_DEFAULT})")
@option(
    "--eth-network",
    help="Ethereum RPC endpoint, network or config file "
    f"(default: '{ETH_NETWORK_FILE_DEFAULT}')")
@option("--eth-addr", help="Sender's eth address or address filename")
@option("--eth-private-key", help="Sender's eth private key file")
@pass_context
def zecale(
        ctx: Context,
        aggregator_server: str,
        aggregator_config_file: str,
        instance_file: str,
        eth_network: Optional[str],
        eth_addr: Optional[str],
        eth_private_key: Optional[str]) -> None:
    if ctx.invoked_subcommand == "help":
        ctx.invoke(help)
    ctx.obj = CommandContext(
        aggregator_server,
        aggregator_config_file,
        instance_file,
        eth_network,
        eth_addr,
        eth_private_key)


zecale.add_command(get_verification_key)
zecale.add_command(deploy)
zecale.add_command(nested_verification_key_hash)
zecale.add_command(register)
zecale.add_command(submit)
zecale.add_command(get_batch)
zecale.add_command(check_batch)
zecale.add_command(submit_batch)
