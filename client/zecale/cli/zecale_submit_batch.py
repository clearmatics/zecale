# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+


from zecale.cli.defaults import APPLICATION_INSTANCE_FILE_DEFAULT
from zecale.cli.command_context import CommandContext
from zecale.cli.utils import load_aggregated_transaction
from zeth.core.contracts import InstanceDescription
from click import command, argument, option, Context, pass_context, ClickException
import json


@command()
@argument("batch-file")
@option(
    "--application-instance-file", "-i",
    default=APPLICATION_INSTANCE_FILE_DEFAULT,
    help="Address or instance file of the application contract")
@option("--wait", is_flag=True, help="Wait for the resulting transaction")
@pass_context
def submit_batch(
        ctx: Context,
        batch_file: str,
        application_instance_file: str,
        wait: bool) -> None:
    """
    Submit an aggregated transaction ("batch") to a zecale dispatcher contract
    instance.
    """

    cmd_ctx: CommandContext = ctx.obj

    # Load the batch
    aggregated_tx = load_aggregated_transaction(cmd_ctx.zksnark, batch_file)

    # Load the application instance address
    with open(application_instance_file, "r") as app_instance_f:
        app_instance = InstanceDescription.from_json_dict(
            json.load(app_instance_f))

    # Open the dispatcher client and submit the batch to it
    eth_addr, eth_private_key = cmd_ctx.get_eth_key_and_address()
    dispatcher_contract = cmd_ctx.get_dispatcher_contract()
    tx_id = dispatcher_contract.process_batch(
        aggregated_tx, app_instance.address, eth_addr, eth_private_key)
    print(tx_id.hex())

    if wait:
        tx_receipt = cmd_ctx.get_web3().eth.waitForTransactionReceipt(
            tx_id, 10000)
        gas_used = tx_receipt.gasUsed
        status = tx_receipt.status
        print(f"(gasUsed={gas_used}, status={status})")
        if status != 1:
            raise ClickException("transaction failed")

        # This is kept for convenience during contract development. Can be
        # removed once the contract code is stable.
        dispatcher_contract.dump_logs(tx_receipt)
