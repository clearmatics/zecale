# Utility functions for CI tasks.
#
# All functions expect to be executed the root directory of the repository, and
# will exit with this as the current directory.

#
# AGGREGATOR
#

function aggregator_is_active() {
    zecale get-verification-key
}

function aggregator_start() {
    # Requires the client env (for aggregator_is_active)
    . client/env/bin/activate
    pushd build

    server_start \
        ./aggregator_server/aggregator-server \
        aggregator_is_active \
        aggregator.pid \
        aggregator.stdout

    popd # build
    deactivate
}

function aggregator_stop() {
    pushd build

    server_stop aggregator aggregator.pid

    popd # build
}
