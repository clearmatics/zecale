# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth_zecale.defaults import \
    ZETH_NESTED_TRANSACTION_FILE_DEFAULT, ZETH_APP_NAME
from zecale.core.nested_transaction import NestedTransaction
from zeth.core.mixer_client import \
    MixParameters, mix_parameters_to_dispatch_parameters
from zeth.core.prover_client import ProverConfiguration
from zeth.core.zksnark import get_zksnark_provider
from zeth.cli.constants import PROVER_CONFIGURATION_FILE_DEFAULT
from click import command, argument, option
import json


@command()
@argument("zeth_tx_file")
@option(
    "--prover-config-file",
    default=PROVER_CONFIGURATION_FILE_DEFAULT,
    help=f"Prover config file (default={PROVER_CONFIGURATION_FILE_DEFAULT})")
@option(
    "--output-file",
    "-o",
    default=ZETH_NESTED_TRANSACTION_FILE_DEFAULT,
    help=f"Output nested tx to file ({ZETH_NESTED_TRANSACTION_FILE_DEFAULT})")
def create_nested_tx(
        zeth_tx_file: str,
        prover_config_file: str,
        output_file: str) -> None:
    """
    Create a Zecale nested transaction from a zeth MixParameters object
    """

    # Load prover config (which is assumed to already exist)
    with open(prover_config_file, "r") as prover_config_f:
        prover_config = \
            ProverConfiguration.from_json_dict(json.load(prover_config_f))
    zksnark = zksnark = get_zksnark_provider(prover_config.zksnark_name)

    # Read the MixParameters
    with open(zeth_tx_file, "r") as zeth_tx_f:
        zeth_mix_params = \
            MixParameters.from_json_dict(zksnark, json.load(zeth_tx_f))

    # Convert to a nested transaction, and write to output file
    nested_tx = _create_zeth_nested_tx(zeth_mix_params, 0)
    with open(output_file, "w") as output_f:
        json.dump(nested_tx.to_json_dict(), output_f)


def _create_zeth_nested_tx(
        mix_params: MixParameters,
        fee_in_wei: int) -> NestedTransaction:
    # Encode the (nested) mix parameters to be passed through zecale, and
    # create a NestedTransaction object for this Zeth transaction.
    parameters = mix_parameters_to_dispatch_parameters(mix_params)
    return NestedTransaction(
        app_name=ZETH_APP_NAME,
        ext_proof=mix_params.extended_proof,
        parameters=parameters,
        fee_in_wei=fee_in_wei)
