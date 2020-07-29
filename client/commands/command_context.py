# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+


class CommandContext:
    """
    Carries command-independent parameters from top-level command to
    sub-commands.
    """
    def __init__(self, aggregator_server: str):
        self.aggregator_server = aggregator_server
