# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zecale.cli.defaults import AGGREGATOR_SERVER_ENDPOINT_DEFAULT, \
    INSTANCE_FILE_DEFAULT, ZKSNARK_NAME_DEFAULT
from zecale.core.aggregator_client import AggregatorClient
from zecale.core.dispatcher_contract import DispatcherContract
from zeth.core.zksnark import get_zksnark_provider
from zeth.core.contracts import InstanceDescription
from zeth.cli.utils import get_eth_network, open_web3_from_network, \
    load_eth_address, load_eth_private_key
import json
from typing import Tuple, Optional, Any


class CommandContext:
    """
    Carries command-independent parameters from top-level command to
    sub-commands. Performs some basic operations common to commands, based on
    the current context and configuration.
    """

    def __init__(
            self,
            aggregator_server: str = AGGREGATOR_SERVER_ENDPOINT_DEFAULT,
            instance_file: str = INSTANCE_FILE_DEFAULT,
            eth_network: Optional[str] = None,
            eth_addr: Optional[str] = None,
            eth_private_key: Optional[str] = None,
            zksnark_name: str = ZKSNARK_NAME_DEFAULT):
        # TODO: Separate nested and wrapper snarks
        self.aggregator_server = aggregator_server
        self.instance_file = instance_file
        self.eth_network = eth_network
        self.eth_addr = eth_addr
        self.eth_private_key = eth_private_key
        self.zksnark = get_zksnark_provider(zksnark_name)
        self._web3: Optional[Any] = None
        self._aggregator_client: Optional[AggregatorClient] = None
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
            self._aggregator_client = AggregatorClient(
                self.aggregator_server, self.zksnark)
        return self._aggregator_client

    def get_dispatcher_contract(self) -> Any:
        """
        Load (and cache) the dispatcher contract instance.
        """
        if not self._dispatcher_contract:
            with open(self.instance_file, "r") as instance_f:
                instance_dict = json.load(instance_f)
                instance = InstanceDescription.from_json_dict(instance_dict)
            self._dispatcher_contract = DispatcherContract(
                self.get_web3(), instance, self.zksnark)
        return self._dispatcher_contract
