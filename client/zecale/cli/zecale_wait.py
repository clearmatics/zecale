# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.cli.command_context import CommandContext
from click import command, argument, Context, pass_context


@command()
@argument("transaction-id")
@pass_context
def wait(
        ctx: Context,
        transaction_id: str) -> None:
    """
    Wait for a dispatcher transaction and print the result.
    """
    cmd_ctx: CommandContext = ctx.obj

    # TODO: Remove some of the verbosity in this command.

    # Get dispatcher contract information
    dispatcher_contract = cmd_ctx.get_dispatcher_contract()
    print(f"dispatcher_contract={dispatcher_contract}")

    # Retrieve the tx receipt and dump logs
    tx_receipt = cmd_ctx.get_web3().eth.waitForTransactionReceipt(
        transaction_id, 10000)

    gas_used = tx_receipt.gasUsed
    status = tx_receipt.status
    print(f"(gasUsed={gas_used}, status={status})")
    print(f"tx_receipt={tx_receipt}")

    # This is kept for convenience during contract development. It can be
    # removed once the contract code is stable.
    dispatcher_contract.dump_logs(tx_receipt)
