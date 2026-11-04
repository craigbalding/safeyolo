#!/bin/sh
# Run only the Coord shutdown test binary with the workflow fixture.
#
# Cargo gives every integration-test binary the workflow environment.  The
# proxy's regular tests deliberately use their own Coord state, so exposing
# the shared fixture to all of them changes their isolation boundary.
set -eu

case "${1##*/}" in
  coord_wait_shutdown-*)
    : "${SAFEYOLO_PROXY_COORD_DATA_DIR:?missing workflow Coord fixture directory}"
    : "${SAFEYOLO_PROXY_NATS_TEST_INSTANCE:?missing workflow NATS fixture identity}"
    export SAFEYOLO_COORD_DATA_DIR="$SAFEYOLO_PROXY_COORD_DATA_DIR"
    export SAFEYOLO_NATS_TEST_INSTANCE="$SAFEYOLO_PROXY_NATS_TEST_INSTANCE"
    ;;
  *)
    unset SAFEYOLO_COORD_DATA_DIR
    unset SAFEYOLO_NATS_TEST_INSTANCE
    ;;
esac

exec "$@"
