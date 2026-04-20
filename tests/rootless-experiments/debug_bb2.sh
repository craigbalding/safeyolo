#!/bin/bash
export SAFEYOLO_CONFIG_DIR=$HOME/.safeyolo-test
cd ~/proj/safeyolo && source .venv/bin/activate

RUNSC=$(which runsc)
ROOT=$SAFEYOLO_CONFIG_DIR/run
CID=safeyolo-bbtest
AGENT_DIR=$SAFEYOLO_CONFIG_DIR/agents/bbtest

mkdir -p $ROOT && chmod 777 $ROOT

# Clean stale
$RUNSC --root $ROOT delete --force $CID 2>/dev/null

# Create userns
aa-exec -p safeyolo-runsc -- unshare -Un sleep 60 &
UPID=$!
sleep 1
newuidmap $UPID 0 100000 1000 1000 1000 1 1001 101001 64534
newgidmap $UPID 0 100000 1000 1000 1000 1 1001 101001 64534

# nsenter and create
nsenter --user --net --target $UPID -- bash -c "
  echo id=\$(id)
  ip link set lo up
  ip addr add 10.200.0.1/32 dev lo
  $RUNSC --platform=kvm --host-uds=open --ignore-cgroups --network=host \
    --root $ROOT create --bundle $AGENT_DIR $CID 2>&1
  echo create_rc=\$?
  $RUNSC --ignore-cgroups --network=host --root $ROOT start $CID 2>&1
  echo start_rc=\$?
" 2>&1

sleep 2

# exec
nsenter --user --target $UPID -- $RUNSC --root $ROOT exec --user 1000:1000 $CID \
  /bin/sh -c 'id && echo ALIVE' 2>&1

# cleanup
nsenter --user --target $UPID -- $RUNSC --root $ROOT kill $CID 2>/dev/null
sleep 1
nsenter --user --target $UPID -- $RUNSC --root $ROOT delete $CID 2>/dev/null
kill $UPID 2>/dev/null
