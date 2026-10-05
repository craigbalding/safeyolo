#!/bin/sh
# The G1 fixture crashes once, then retains one observable native child.
set -eu
directory=$1
literal=$2
mkdir -p "$directory"
count=0
if [ -f "$directory/attempts" ]; then count=$(cat "$directory/attempts"); fi
count=$((count + 1))
printf '%s\n' "$count" > "$directory/attempts"
printf '%s\n' "$literal" > "$directory/argument"
if [ "$count" -eq 1 ]; then
    printf 'configured-crash\n' >&2
    exit 41
fi
printf 'native-marker\n' > "$directory/marker"
exec sleep 120
