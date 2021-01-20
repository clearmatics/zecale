# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
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
    version='0.3',
    description='Client to interact with Zecale server',
    packages=find_packages(),
    # zip_safe=False,
    install_requires=[
        "mypy==0.790",
        "mypy-protobuf==1.23",
        "flake8==3.8.3",
        "pylint==2.6",
        "click==7.0",
        "click-default-group==1.2",
        "protobuf==3.13.0",
        "grpcio==1.33.2",
        "grpcio-tools==1.33.2",
    ],
    entry_points={
        'console_scripts': [
            'zecale_dummy_app=zecale.dummy_app.__main__:dummy_app',
            'zecale=zecale.cli.__main__:zecale',
            'zeth_zecale=zeth_zecale.__main__:zeth_zecale',
        ],
    }
)
