#!/bin/bash

export ZECALE=`pwd`
export ZECALE_DEBUG_DIR=$ZECALE/debug

mkdir -p $ZECALE/trusted_setup
export ZECALE_TRUSTED_SETUP_DIR=$ZECALE/trusted_setup

# Add the zecale executables in the PATH
export PATH=$ZECALE/build/src:$PATH
