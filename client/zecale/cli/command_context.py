# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.cli.defaults import AGGREGATOR_CONFIG_FILE_DEFAULT, \
    AGGREGATOR_SERVER_ENDPOINT_DEFAULT, INSTANCE_FILE_DEFAULT
from zecale.core.aggregator_client import AggregatorClient
from zecale.core.aggregator_config import AggregatorConfiguration
from zecale.core.dispatcher_contract import DispatcherContract
from zeth.core.zksnark import IZKSnarkProvider
from zeth.core.contracts import InstanceDescription
from zeth.cli.utils import get_eth_network, open_web3_from_network, \
    load_eth_address, load_eth_private_key
import json
from os.path import exists
from os import unlink
from typing import Tuple, Optional, Any

# pylint: disable=too-many-instance-attributes


class CommandContext:
    """
    Carries command-independent parameters from top-level command to
    sub-commands. Performs some basic operations common to commands, based on
    the current context and configuration.
    """

    def __init__(
            self,
            aggregator_server: str = AGGREGATOR_SERVER_ENDPOINT_DEFAULT,
            aggregator_config_file: str = AGGREGATOR_CONFIG_FILE_DEFAULT,
            instance_file: str = INSTANCE_FILE_DEFAULT,
            eth_network: Optional[str] = None,
            eth_addr: Optional[str] = None,
            eth_private_key: Optional[str] = None):
        # TODO: Separate nested and wrapper snarks
        self.aggregator_server = aggregator_server
        self.aggregator_config_file = aggregator_config_file
        self.instance_file = instance_file
        self.eth_network = eth_network
        self.eth_addr = eth_addr
        self.eth_private_key = eth_private_key
        self._web3: Optional[Any] = None
        self._aggregator_client: Optional[AggregatorClient] = None
        self._aggregator_config: Optional[AggregatorConfiguration] = None
        self._dispatcher_contract: Optional[DispatcherContract] = None

    def get_eth_key_and_address(self) -> Tuple[str, Optional[bytes]]:
        return (
            load_eth_address(self.eth_addr),
            load_eth_private_key(self.eth_private_key))

    def get_web3(self) -> Any:
        """
        Create and cache web3 connection.
        """
        if not self._web3:
            self._web3 = open_web3_from_network(get_eth_network(self.eth_network))
        return self._web3

    def get_aggregator_client(self) -> AggregatorClient:
        """
        Return an aggregator client for the appropriate endpoint. Created and
        cached when this function is first called.
        """
        if not self._aggregator_client:
            self._aggregator_client = AggregatorClient(self.aggregator_server)
        return self._aggregator_client

    def get_aggregator_configuration(self) -> AggregatorConfiguration:
        """
        Load the AggregatorConfiguration from a file, or request it from the
        aggregator server.
        """
        if self._aggregator_config is not None:
            return self._aggregator_config

        if exists(self.aggregator_config_file):
            with open(self.aggregator_config_file, "r") as aggregator_config_f:
                try:
                    self._aggregator_config = \
                        AggregatorConfiguration.from_json_dict(
                            json.load(aggregator_config_f))
                    return self._aggregator_config
                except Exception as ex:
                    print(f"removing `{self.aggregator_config_file}`: {ex}.")
                    unlink(self.aggregator_config_file)

        aggregator_client = self.get_aggregator_client()
        self._aggregator_config = aggregator_client.get_configuration()

        with open(self.aggregator_config_file, "w") as aggregator_config_f:
            json.dump(self._aggregator_config.to_json_dict(), aggregator_config_f)

        return self._aggregator_config

    def get_nested_snark(self) -> IZKSnarkProvider:
        return self.get_aggregator_configuration().nested_snark

    def get_wrapper_snark(self) -> IZKSnarkProvider:
        return self.get_aggregator_configuration().wrapper_snark

    def get_dispatcher_contract(self) -> Any:
        """
        Load (and cache) the dispatcher contract instance.
        """
        if not self._dispatcher_contract:
            with open(self.instance_file, "r") as instance_f:
                instance_dict = json.load(instance_f)
                instance = InstanceDescription.from_json_dict(instance_dict)
            self._dispatcher_contract = DispatcherContract(
                self.get_web3(), instance, self.get_wrapper_snark())
        return self._dispatcher_contract
