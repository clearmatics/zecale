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

First, make sure to setup the Zeth dependency in order to generate the
API files and be able to use the Zeth CLIs:
```console
$ cd $ZECALE/depends/zeth/client
$ python -m venv env
$ source env/bin/activate
(env)$ make setup
```

Then, Execute the following inside the `client` directory:
```console
$ cd $ZECALE/client
$ python -m venv env
$ source env/bin/activate
(env)$ make setup
```

We assume all further commands described here are executed from within the
Python virtualenv.  To enter the virtualenv from a new terminal, re-run
```console
$ source env/bin/activate
```

## Execute unit tests

```console
(env)$ make check
```

## Launch a local Ethereum testnet

In order for Zecale to work, it is necessary for the blockchain to support
BW6-761 arithmetic. As such, we assume below that the smart contracts are
deployed on an Ethereum testnet that supports BW6-761 precompiled contracts.

To do so, please follow the instructions below to run a modified version
of ganache-cli in a new terminal (see [Zeth](https://github.com/clearmatics/zeth/) for more information):
```console
cd ../depends/zeth/zeth_contracts
npm install # make sure that node and npm have the right versions
npm run testrpc
```

## Execute testing scripts

Once the `aggregator_server` and a custom `ganache-cli` instance are
running, several scripts can be executed to test the CLIs as well as
various aspects of the client and the contracts. You can run such tests
by doing:

```console
(env)$ python test_commands/<script-name> <script-arguments>
```

for instance:
```console
(env)$ python test_commands/test_bw6_761_groth16_contract.py
```

Moreover, the CLIs are tested using the following script:

```console
(env)$ cd ..
(env)$ ./scripts/test_client
```

# The `zecale` command line interface

The `zecale` command exposes Zecale operations via a command line interface. A
brief description is given in this section. More details are available via
`zecale --help`, and example usage can be seen in the [client test
script](../scripts/test_client).

## Environment

Depending on the operation being performed, the `zecale` client must:
- interact with an Ethereum RPC host **that supports BW6 arithmetic** (e.g. [here](https://github.com/clearmatics/ganache-cli/tree/v6.10.1-clearmatics)),
- interact with the deployed Zecale contracts,
- request proofs and proof verification keys from `aggregator_server`

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
