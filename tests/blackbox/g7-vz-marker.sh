#!/bin/sh
# The installed guest runs only native checks and one Coord send/read.
set -eu
room=$1
marker=$2
output=/home/agent/.g7
mkdir -m 0700 "$output"
id -u > "$output/uid"
/safeyolo/safeyolo-guest --version > "$output/guest.version"
/home/agent/.safeyolo/safeyolo-coord --version > "$output/coord.version"
# The native supervisor publishes its command identity just after spawning us.
# Wait for both native observations to report that this command is live.
attempt=0
until [ "$(/safeyolo/safeyolo-guest observe check)" = running ] &&
      /safeyolo/safeyolo-guest supervise check > "$output/supervision.json" &&
      grep -q '"state":"running"' "$output/supervision.json"; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 50 ] || { echo 'G7 command readiness expired' >&2; exit 1; }
    sleep 0.1
done
cp /safeyolo/host-launch-context.json "$output/context.json"
cat /safeyolo-status/per-run-started > "$output/per-run-started"
cat /safeyolo-status/vm-status > "$output/vm-status"
printf '{"room_name":"%s"}' "$room" |
    /home/agent/.safeyolo/safeyolo-coord call join_room > "$output/join.json"
printf '{"room_name":"%s","body":"%s","declared_content_type":"text/plain","notify":"none"}' "$room" "$marker" |
    /home/agent/.safeyolo/safeyolo-coord call send > "$output/send.json"
printf '{"room_name":"%s","since_sequence":0,"limit":10}' "$room" |
    /home/agent/.safeyolo/safeyolo-coord call read_room > "$output/read.json"
touch "$output/complete"
exec sleep 300
