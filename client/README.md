# Python client to interact with the Zecale aggregator

## Structure of the directory

### `zecale`

```
zecale
 |_ api
 |_ cli
 |_ core
 |_ dummy_app
```

This directory contains the API code for the Zecale client (`api`), its backend implementation (`core`), the code for the client CLI (`cli`), and the code of a helper CLI for a "dummy application" (`dummy_app`).

### `test_commands`

This directory contains a list of useful commands to help run the tests, as well as some minimal testing scenarios acting as integration tests.

### `tests`

The `tests` folder contains the unit tests of the `zecale` package.

## Setup

Ensure that the following are installed:

- Python 3.7 (See `python --version`)
- [venv](https://docs.python.org/3/library/venv.html#module-venv) module.
- gcc

First, ensure that the Zeth client has been setup as described in the [Zeth client setup documentation](https://github.com/clearmatics/zeth/blob/master/client/README.md).  (This step is required since the Zeth client setup process includes some code generation).  If this has not already been done, it can be performed as follows (assuming the current working directory is the Zecale repository root):
```console
$ pushd depends/zeth/client
$ python -m venv env
$ source env/bin/activate
(env)$ make setup
(env)$ deactivate
$ popd
```

For encapsulation, we suggest creating a Python virtualenv specific to the Zecale client tools.  The Zeth client will be installed as an editable package (a reference to, rather than a copy of, the package in `depends/zeth/client`) in this virtualenv. Setup is performed as follows:
```console
$ cd client
$ python -m venv env
$ source env/bin/activate
(env)$ make setup
```

Unless otherwise stated, we assume that all further commands are executed from within the Python virtualenv (indicated by the `(env)` prefix to the command prompt), and in the `client` directory. To enter the virtualenv from a new terminal, run the following:
```console
$ source env/bin/activate
```
(Alternatively, specify the full path to `client/env/bin/activate` to execute from outside the `client` directory).

## Execute unit tests

Unit tests for the client code can be executed as follows:
```console
(env)$ make check
```

## Launch a local Ethereum testnet

Zecale smart contracts require support for BW6-761 arithmetic, via precompiled contracts. A modified version of ganache-cli (which includes such support) can be launched from a docker image as follows (note that this should be run in its own terminal instance, from the repo root, and does not require the Python virtualenv to be active):
```console
$ depends/zeth/scripts/ganache-start
```
(See [Zeth](https://github.com/clearmatics/zeth/) for more information)

## Execute testing scripts

Once the `aggregator-server` and a custom `ganache-cli` instance are running, several scripts can be executed to test the CLIs as well as various aspects of the client and the contracts:

```console
(env)$ python test_commands/<script-name> <script-arguments>
```

for instance:
```console
(env)$ python test_commands/test_bw6_761_groth16_contract.py
```

A fuller integration test for the CLIs can also be executed:

```console
(env)$ cd ..
(env)$ ./scripts/test-client
```

# The `zecale` command line interface

The `zecale` command exposes Zecale operations via a command line interface. A brief description is given in this section. More details are available via `zecale --help`, and example usage can be seen in the [client test script](../scripts/test-client).  Note that `zecale` can be invoked from any directory, as long as the Python virtualenv is activated.

## Environment

Depending on the operation being performed, the `zecale` client must:
- interact with an Ethereum RPC host **that supports BW6 arithmetic** (e.g. [here](https://github.com/clearmatics/ganache-cli/tree/v6.10.1-clearmatics)),
- interact with the deployed Zecale contracts,
- request proofs and proof verification keys from `aggregator-server`

In a similar way as in Zeth, data is stored in files with
default file names (which can be overridden on the zecale commands).

The set of files required by Zecale for a single user to interact with a specific
deployment is described below.

- `eth-address` specifies an Ethereum address from which to transactions should
  be funded. Existing addresses may be copy-pasted into this file.
- `zecale-instance` contains the address and ABI for a single instance of the
  zecale dispatcher contract. This file is created by the deployment step below
  and should be distributed to each client that will use this instance.

Additionally, once the Zecale dispatcher is deployed, Zecale application
contracts can be deployed, using the address of the dispatcher. Upon
deployment of an application contract, an instance file `app-instance` will
be created.

## Deployment

### Deploy the Zecale dispatcher

Deployment compiles and deploys the contracts and initializes them with
appropriate data to create a new instance of the Zecale dispatcher. It requires
only an `eth-address` file mentioned above, where the address has sufficient
funds.

```console
# Create a clean directory for the deployer
(env)$ mkdir deployer
(env)$ cd deployer

# Specify an eth-address file for an (unlocked) Ethereum account
(env)$ echo 0x.... > eth-address

# Get the verification key
(env)$ zecale get-verification-key

# Compile and deploy
(env)$ zecale deploy

# Share the instance file with all clients
$ cp zecale-instance <destination>
```

### Deploy the Zecale Application

After deploying the the Zecale dispatcher, it is possible to deploy a Zecale
application. One can use the `DummyApplication` contract as an example:

```console
zecale_dummy_app deploy
```

For a more comprehensive overview on how to use Zecale with a base
application, please refer to the [zeth-zecale integration test script](../scripts/test-zeth-zecale).
