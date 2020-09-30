# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.cli.defaults import \
    AGGREGATOR_SERVER_ENDPOINT_DEFAULT, INSTANCE_FILE_DEFAULT
from zecale.cli.command_context import CommandContext
from zecale.cli.zecale_get_verification_key import get_verification_key
from zecale.cli.zecale_deploy import deploy
from zecale.cli.zecale_register import register
from zecale.cli.zecale_submit import submit
from zecale.cli.zecale_get_batch import get_batch
from zecale.cli.zecale_check_batch import check_batch
from grpc import RpcError
from click import group, option, pass_context, Context
from click_default_group import DefaultGroup  # type: ignore
import sys
from typing import Any


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
    "--instance-file", "-i",
    default=INSTANCE_FILE_DEFAULT,
    help=f"Zecale contract instance file (default={INSTANCE_FILE_DEFAULT})")
@pass_context
def zecale(
        ctx: Context,
        aggregator_server: str,
        instance_file: str) -> None:
    if ctx.invoked_subcommand == "help":
        ctx.invoke(help)
    ctx.obj = CommandContext(
        aggregator_server,
        instance_file)


zecale.add_command(get_verification_key)
zecale.add_command(deploy)
zecale.add_command(register)
zecale.add_command(submit)
zecale.add_command(get_batch)
zecale.add_command(check_batch)
zecale.add_command(help)
