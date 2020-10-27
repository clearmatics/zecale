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

This directory contains the API code for the Zecale client (`api`), its backend implementation (`core`), the code for the client CLI (`cli`), and the code of an helper CLI for a "dummy application" (`dummy_app`).

### `test_commands`

This directory contains a list of useful commands to help run the tests, as well as some minimal testing scenarios acting as integration tests.

### `tests`

The `tests` folder contains the unit tests of the `zecale` package.

## Setup

Ensure that the following are installed:

- Python 3.7 (See `python --version`)
- [venv](https://docs.python.org/3/library/venv.html#module-venv) module.
- gcc

Execute the following inside the `client` directory.
```console
$ python -m venv env
$ source env/bin/activate
(env)$ make setup
```

(It may also be necessary to install solc manually if the `py-solc-x` package
fails to find it. See the instructions below.)

We assume all further commands described here are executed from within the
Python virtualenv.  To enter the virtualenv from a new terminal, re-run
```console
$ source env/bin/activate
```

## Execute unit tests

```console
(env)$ make check
```

## Execute testing scripts

These are scripts that allow to test various aspects of the client (as well as
its interactions with other components). You can run them by doing:

```console
(env)$ python test_commands/<script-name> <script-arguments>
```

for instance:
```console
(env)$ python test_commands/test_bw6_761_groth16_contract.py
```

## Note on solc compiler installation

Note that `make setup` will automatically install the solidity compiler in `$HOME/.solc`
(if required) and not in the python virtual environment.

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