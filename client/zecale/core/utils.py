# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

import os
from os.path import normpath, join, dirname, exists


def get_zecale_dir() -> str:
    """
    Return the repository root either in ZECALE env var, or relative to this
    file.
    """
    zecale_dir = os.environ.get(
        "ZECALE",
        normpath(join(dirname(__file__), "..", "..", "..")))
    # Nasty, but this assert should protect against this path going out of date
    assert exists(join(zecale_dir, "client", "zecale", "core", "utils.py"))
    return zecale_dir
