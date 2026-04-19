#!/bin/bash
# T46: run fuse-overlayfs INSIDE the userns
set -e
cd ~/proj/safeyolo && source .venv/bin/activate

SHARE=$HOME/.safeyolo/share
BASE=$SHARE/rootfs-base
AGENT_DIR=$HOME/.safeyolo/agents/t46test

rm -rf $AGENT_DIR && mkdir -p $AGENT_DIR/rootfs-upper $AGENT_DIR/rootfs-work $AGENT_DIR/rootfs

sudo setfacl -m u:100000:rw /dev/kvm 2>/dev/null

aa-exec -p safeyolo-runsc -- unshare -Un sleep 30 &
UPID=$!
sleep 1
newuidmap $UPID 0 100000 1000 1000 $(id -u) 1 1001 101001 64534
newgidmap $UPID 0 100000 1000 1000 $(id -g) 1 1001 101001 64534

echo "=== mount fuse-overlayfs inside userns ==="
nsenter --user --target $UPID -- bash -c "
  echo id: \$(id)
  # chown upper/work to userns root
  chown root:root $AGENT_DIR/rootfs-upper $AGENT_DIR/rootfs-work
  # mount fuse-overlayfs as userns root
  fuse-overlayfs \
    -o lowerdir=$BASE,upperdir=$AGENT_DIR/rootfs-upper,workdir=$AGENT_DIR/rootfs-work,allow_other \
    $AGENT_DIR/rootfs 2>&1
  echo fuse_rc=\$?
  ls -la $AGENT_DIR/rootfs/ | head -5
  echo ---
  stat -c '%U:%G %a %n' $AGENT_DIR/rootfs/etc $AGENT_DIR/rootfs/home/agent
"

echo "=== host view of ownership ==="
ls -lan $AGENT_DIR/rootfs/ | head -5
ls -lan $AGENT_DIR/rootfs/home/agent/ | head -3

# Clean up
nsenter --user --target $UPID -- fusermount3 -u $AGENT_DIR/rootfs 2>/dev/null
kill $UPID 2>/dev/null
sudo setfacl -x u:100000 /dev/kvm 2>/dev/null
sudo rm -rf $AGENT_DIR
echo DONE
