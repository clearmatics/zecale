
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

    server_launch \
        ./aggregator_server/aggregator_server \
        aggregator_is_active \
        aggregator.pid \
        aggregator.stdout

    # ./aggregator_server/aggregator_server > aggregator.stdout &
    # echo $! > aggregator.pid

    # # Wait for server to be active
    # while ! aggregator_is_active ; do
    #     echo "aggregator_start: waiting for server ..."
    #     sleep 1
    # done
    # echo "aggregator_start:: aggregator is ACTIVE"

    popd # build
    deactivate
}

function aggregator_stop() {
    pushd build

    server_stop aggregator aggregator.pid

    # if ! [ -e aggregator.pid ] ; then
    #     echo "aggregator_stop: no PID file"
    #     return 1
    # fi

    # pid=`cat aggregator.pid`
    # while (kill "${pid}") ; do
    #     sleep 0.5
    # done
    # rm prover_server.pid
    # echo "prover_server_stop:: STOPPED"

    popd # build
}
