# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

import sys
from setuptools import find_packages
from distutils.core import setup

if not hasattr(sys, 'base_prefix') or sys.base_prefix == sys.prefix:
    print("ERROR: This is not production software, install inside a venv")
    sys.exit(1)

if sys.version_info < (3, 7):
    print("ERROR: requires python >=3.7")
    sys.exit(1)

setup(
    name='zecale-client',
    version='0.5',
    description='Client to interact with Zecale server',
    packages=find_packages(),
    install_requires=[
        # Dependencies installed as part of zeth client. Further dependencies
        # are listed here:
    ],
    entry_points={
        'console_scripts': [
            'zecale-dummy-app=zecale.dummy_app.__main__:dummy_app',
            'zecale=zecale.cli.__main__:zecale',
            'zeth-zecale=zeth_zecale.__main__:zeth_zecale',
        ],
    }
)
