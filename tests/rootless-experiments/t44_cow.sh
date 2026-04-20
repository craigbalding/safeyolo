#!/bin/bash
# T44: assess cost of per-agent rootfs copy vs shared overlay
set -e
cd ~/proj/safeyolo && source .venv/bin/activate

SHARE=$HOME/.safeyolo/share
BASE=$SHARE/rootfs-base
TAR=$SHARE/rootfs-base.tar

echo "=== filesystem type ==="
df -T $SHARE | tail -1

echo "=== base rootfs size ==="
du -sh $BASE 2>/dev/null || echo "no base dir"
du -sh $TAR 2>/dev/null || echo "no tarball"

echo "=== reflink support ==="
touch /tmp/t44_src
cp --reflink=auto /tmp/t44_src /tmp/t44_dst 2>&1 && echo "reflink: supported" || echo "reflink: not supported"
rm -f /tmp/t44_src /tmp/t44_dst

# Time a full copy (no reflink)
echo ""
echo "=== T44a: regular cp -a (measures actual I/O) ==="
DEST1=$HOME/.safeyolo/agents/t44-copy1/rootfs
mkdir -p $(dirname $DEST1)
time cp -a $BASE $DEST1 2>&1
echo "copy size: $(du -sh $DEST1 | cut -f1)"

# Time a reflink copy (if supported)
echo ""
echo "=== T44b: cp --reflink=auto (CoW if filesystem supports it) ==="
DEST2=$HOME/.safeyolo/agents/t44-copy2/rootfs
mkdir -p $(dirname $DEST2)
time cp -a --reflink=auto $BASE $DEST2 2>&1
echo "copy size: $(du -sh $DEST2 | cut -f1)"

# Disk usage comparison
echo ""
echo "=== disk usage ==="
echo "base:  $(du -sh $BASE | cut -f1)"
echo "copy1: $(du -sh $DEST1 | cut -f1)"
echo "copy2: $(du -sh $DEST2 | cut -f1)"
echo "total apparent: $(du -sh --apparent-size $BASE $DEST1 $DEST2 | tail -1)"
echo "total actual:   $(du -sh $BASE $DEST1 $DEST2 | tail -1)"

# Now simulate agent writes — how much additional space?
echo ""
echo "=== T44c: simulate agent activity (npm install footprint) ==="
# Create some files in copy2 to see incremental cost
dd if=/dev/urandom of=$DEST2/tmp/fake-npm-cache bs=1M count=50 2>/dev/null
echo "after 50MB write:"
echo "  copy2: $(du -sh $DEST2 | cut -f1)"

# Clean up
sudo rm -rf $HOME/.safeyolo/agents/t44-copy1 $HOME/.safeyolo/agents/t44-copy2 2>/dev/null
rm -rf $HOME/.safeyolo/agents/t44-copy1 $HOME/.safeyolo/agents/t44-copy2 2>/dev/null
echo "DONE"
