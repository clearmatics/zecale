# Zecale

A zk-SNARK aggregator leveraging recursive composition of SNARKs.
This project can be used to scale privacy preserving solutions like [Zeth](https://github.com/clearmatics/zeth)

## Building and running the project:

### Environment

In order to follow the README below, you will need:
- [Docker](https://www.docker.com/get-started)
- [Npm](https://www.npmjs.com/get-npm) (at least version `6.4.1`)
- [Node](https://nodejs.org/en/) (at least version `v9.5.0`)
- [Python3](https://www.python.org/downloads/) (at least version `3.7`)

### Development dependencies (for building outside of the Docker container)

Immediate dependencies are provided as submodules and compiled during
the Zeth build. Ensure submodules are synced.

The following libraries are also required to build:

- grpc
- gmp
- boost
- openssl

#### Build the project

```bash
# Clone this repository:
git clone git@github.com:clearmatics/zecale.git
cd zecale

# All the commands below are run in the docker container
# Configure your environment
. ./setup_env.sh

# Initialize the submodules
git submodule update --init --recursive

# Compile the aggregator
mkdir build
cd build
cmake .. [<flags (see below)>]
# Compile all libraries and tools, including the prover_server
make
# (optional) Run the unit tests
make test
# (optional) Run the all tests (unit tests, syntax checks, etc)
make check

# Start the prover_server process
aggregator_server
```
