#!/usr/bin/env bash

export ZECALE=`pwd`
export ZECALE_DEBUG_DIR=$ZECALE/debug

export ZECALE_SETUP_DIR=$ZECALE/zecale_setup
mkdir -p $ZECALE_SETUP_DIR

# Add the zecale executables in the PATH
export PATH=$ZECALE/build/aggregator_server:$ZECALE/build/libzecale/tests:$PATH