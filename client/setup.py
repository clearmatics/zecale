# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
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
    version='0.1',
    description='Client to interact with Zecale server',
    packages=find_packages(),
    # zip_safe=False,
    install_requires=[
        "mypy==0.720",
        "mypy-protobuf==1.23",
        "flake8==3.8.3",
        "pylint==2.4.3",
        "click==7.0",
        "click-default-group==1.2",
        "protobuf==3.13.0",
        "grpcio==1.30",
        "grpcio-tools==1.30",
    ],
    scripts=[
        "zecale/commands/zecale",
    ]
)
