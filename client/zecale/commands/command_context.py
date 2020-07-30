# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from commands.defaults import \
    AGGREGATOR_SERVER_ENDPOINT_DEFAULT, ZKSNARK_NAME_DEFAULT
from zeth.zksnark import get_zksnark_provider
from zecale.core.aggregator_client import AggregatorClient
from typing import Optional


class CommandContext:
    """
    Carries command-independent parameters from top-level command to
    sub-commands. Performs some basic operations common to commands, based on
    the current context and configuration.
    """

    def __init__(
            self,
            aggregator_server: str = AGGREGATOR_SERVER_ENDPOINT_DEFAULT,
            zksnark_name: str = ZKSNARK_NAME_DEFAULT):
        self.aggregator_server = aggregator_server
        self.aggregator_client : Optional[AggregatorClient] = None
        self.zksnark = get_zksnark_provider

    def get_aggregaor_client(self) -> AggregatorClient:
        """
        Open the aggregator client for the appropriate
        """
        if not self.aggregator_client:
            self.aggregator_client = AggregatorClient(
                self.aggregator_server, self.zksnark)
        return self.aggregator_client
