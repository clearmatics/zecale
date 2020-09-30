# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from .defaults import AGGREGATOR_SERVER_ENDPOINT_DEFAULT, INSTANCE_FILE_DEFAULT, \
    ZKSNARK_NAME_DEFAULT
from ..core.aggregator_client import AggregatorClient
from zeth.core.zksnark import get_zksnark_provider
from zeth.cli.utils import get_eth_network, open_web3_from_network, \
    load_eth_address, load_eth_private_key
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
        self.aggregator_server = aggregator_server
        self.instance_file = instance_file
        self.eth_network = eth_network
        self.eth_addr = eth_addr
        self.eth_private_key = eth_private_key
        self.zksnark = get_zksnark_provider(zksnark_name)
        self.aggregator_client: Optional[AggregatorClient] = None
        self.web3: Optional[Any] = None

    def get_eth_key_and_address(self) -> Tuple[str, Optional[bytes]]:
        return (
            load_eth_address(self.eth_addr),
            load_eth_private_key(self.eth_private_key))

    def get_web3(self) -> Any:
        """
        Create and cache web3 connection.
        """
        if not self.web3:
            self.web3 = open_web3_from_network(get_eth_network(self.eth_network))
        return self.web3

    def get_aggregator_client(self) -> AggregatorClient:
        """
        Return an aggregator client for the appropriate endpoint. Created and
        cached when this function is first called.
        """
        if not self.aggregator_client:
            self.aggregator_client = AggregatorClient(
                self.aggregator_server, self.zksnark)
        return self.aggregator_client
