# Zecale (/zi:kale/)

A general purpose zk-SNARK aggregator leveraging recursive composition of SNARKs.

This project can be used to:
1. Scale privacy preserving solutions like [Zeth](https://github.com/clearmatics/zeth) by aggregating proofs off-chain (i.e. generate a proof of computational integrity of their validity) and settling a batch of transactions via a single transaction on-chain. This is also referred to as "zk-zk-rollups".
2. Wrap proofs for a given statement in order to hide the predicate that was evaluated. In other words, by setting the size of the batch to `1`, a "wrapping" proof is generated to prove the correct verification of another proof on witness the verification key and the public inputs. The wrapping proof can the be settled on-chain. This use is very similar to the "Zero-knowledge EXEcution environment" described in [Zexe](https://eprint.iacr.org/2018/962.pdf).

:rotating_light: **WARNING** This project is a Work In Progress (WIP). It is highly inefficient and has not been thoroughly reviewed. Please do not use in production!

## Building and running the `aggregator_server`:

:computer: **Warning** This project primarily targets x86_64 Linux and macOS platforms.

### Environment

In order to follow the README below, you will need:
- [Docker](https://www.docker.com/get-started)
- [Python3](https://www.python.org/downloads/) (at least version `3.7`)

Additionally, several tools from the GCC and LLVM tools suite are used to improve code quality and generate the documentation of the project. If these are installed they can be executed by passing options to the build:
- [Doxygen](http://www.doxygen.nl/)
- [clang-format](https://clang.llvm.org/docs/ClangFormat.html)
- [clang-tidy](https://clang.llvm.org/extra/clang-tidy/)
- [cppcheck](http://cppcheck.sourceforge.net/)
- [include-what-you-use](https://include-what-you-use.org/)
- [llvm-symbolizer](https://llvm.org/docs/CommandGuide/llvm-symbolizer.html)

### Build and run on host machine


#### Dependencies

Immediate dependencies are provided as submodules and compiled during the build. The following libraries are also required to build:
- grpc
- gmp
- boost

#### Build and run

```console
# Clone this repository:
git clone git@github.com:clearmatics/zecale.git
cd zecale

# Initialize the submodules
git submodule update --init --recursive

# Configure your environment
. ./setup_env.sh

# Compile the aggregator
mkdir build
cd build
cmake ..

# Compile all targets
make

# (optional) Run the unit tests
make test

# (optional) Run the all tests (unit tests, syntax checks, etc)
make check

# Start the aggregator_server process
aggregator_server
```

### Build and run in a docker container

```console
# Pull the zeth-base image (this project has the same configuration as Zeth)
docker pull clearmatics/zeth-base:latest

# Build the Zecale dev image
docker build -f Dockerfile-zecale -t zecale-dev:0.2 .

# Start the container
docker run -ti -p 50052:50052 --name zecale zecale-dev:0.2
```

### Generate the Doxygen documentation

To generate the documentation of Zecale:
```bash
cd build
cmake .. -DGEN_DOC=ON && make docs
```

### Compile the project using 'sanitizers'

You can select the sanitizer of your choice (one of the sanitizers listed [here](./cmake/sanitizers.cmake)) by passing the flag `-DSANITIZER=<sanitizer>` to `cmake`.

Example:
```bash
cd build
cmake -DCMAKE_C_COMPILER=/usr/bin/clang -DCMAKE_CXX_COMPILER=/usr/bin/clang++ -DSANITIZER=Address -DCMAKE_BUILD_TYPE=Debug ..
make check
```

### Run analysis tools on the code

Several tools can be ran on the code. These can be enabled via a set of compilation options.

Note: The `clang-tidy` target runs a clang-tidy python script that should be fetched from [here](https://github.com/llvm/llvm-project/blob/master/clang-tools-extra/clang-tidy/tool/run-clang-tidy.py). To do so, run: `cd build && wget https://raw.githubusercontent.com/llvm/llvm-project/master/clang-tools-extra/clang-tidy/tool/run-clang-tidy.py`

Example:
```bash
# run-clang-tidy.py needs to be in the PATH to be found
PATH=$PATH:${PWD}
chmod +x run-clang-tidy.py

cmake -DUSE_CLANG_FORMAT=ON -DUSE_CPP_CHECK=ON -DUSE_CLANG_TIDY=ON ..
make cppcheck
make clang-format
make clang-tidy
```

## Build and run the client

See the [client README](client/README.md) for instructions.

## License notices:

### Libsnark

```
The libsnark library is developed by SCIPR Lab (http://scipr-lab.org)
and contributors.

Copyright (c) 2012-2014 SCIPR Lab and contributors (see AUTHORS file).

All files, with the exceptions below, are released under the MIT License:

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
