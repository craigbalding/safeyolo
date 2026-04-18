#!/bin/bash
export SAFEYOLO_CONFIG_DIR=$HOME/.safeyolo-test
cd ~/proj/safeyolo && source .venv/bin/activate

RUNSC=$(which runsc)
ROOT=$HOME/.safeyolo-test/run
mkdir -p $ROOT && chmod 777 $ROOT
CID=safeyolo-bbtest
AGENT_DIR=$HOME/.safeyolo-test/agents/bbtest

echo "config.json exists: $(ls $AGENT_DIR/config.json 2>&1)"
echo "rootfs exists: $(ls -d $AGENT_DIR/rootfs 2>&1)"
echo "rootfs mounted: $(mount | grep $AGENT_DIR/rootfs | head -1)"

# Try manual userns creation
aa-exec -p safeyolo-runsc -- unshare -Un sleep 60 &
UPID=$!
sleep 1
echo "userns holder pid=$UPID"

newuidmap $UPID 0 100000 1000 1000 1000 1 1001 101001 64534 2>&1
echo "newuidmap rc=$?"
newgidmap $UPID 0 100000 1000 1000 1000 1 1001 101001 64534 2>&1
echo "newgidmap rc=$?"

nsenter --user --net --target $UPID -- bash -c "
  echo inside-userns: \$(id)
  ip link set lo up
  $RUNSC --platform=kvm --host-uds=open --ignore-cgroups --network=host \
    --root $ROOT create --bundle $AGENT_DIR $CID 2>&1
  echo create_rc=\$?
" 2>&1

kill $UPID 2>/dev/null
