# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth_zecale.create_nested_tx import create_nested_tx
from click import group
from click_default_group import DefaultGroup  # type: ignore


@group(cls=DefaultGroup, default_if_no_args=True, default="--help")
def zeth_zecale() -> None:
    """
    Main entry point to Zeth-Zecale integration functionality.
    """


zeth_zecale.add_command(create_nested_tx)
