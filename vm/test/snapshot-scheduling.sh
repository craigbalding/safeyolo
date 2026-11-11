#!/bin/bash
# Guest-only instrumentation for snapshot-smoke.sh. Run after the unchanged
# static init, before the orchestrator opens its per-run gate. All queues and
# output belong to this disposable guest. This probe never starts a daemon.
set -euo pipefail
status=/safeyolo-status
job_id=
installed=0

agent() { su agent -s /bin/bash -c "$1"; }

daemon_pids() {
    local rc=0
    pgrep -x "$1" || rc=$?
    # pgrep uses 1 for a successful empty result; other failures are unknown.
    [[ "$rc" = 0 || "$rc" = 1 ]] || return "$rc"
}

cleanup() {
    local rc=$?
    trap - EXIT
    if [[ "$installed" = 1 ]]; then agent 'crontab -r' || rc=1; fi
    if [[ -n "$job_id" ]]; then
        local pending
        if pending=$(agent atq); then
            if printf '%s\n' "$pending" | awk '{print $1}' | grep -qx "$job_id"; then
                agent "atrm $job_id" || rc=1
            fi
        else
            rc=1
        fi
    fi
    if [[ -f /var/log/safeyolo-scheduling.log ]]; then
        cp /var/log/safeyolo-scheduling.log "$status/scheduling.log" || rc=1
    fi
    if [[ "$rc" = 0 ]]; then
        echo passed > "$status/probe.done"
    else
        echo "guest probe exit $rc; inspect probe.log and scheduling.log" > "$status/probe.failed"
    fi
    exit "$rc"
}
trap cleanup EXIT

[[ ! -e /safeyolo/per-run-go ]]
[[ ! -e "$status/jobs" ]]
existing=$(agent 'crontab -l' 2>&1) || [[ "$existing" = 'no crontab for '* ]]
[[ -z "$existing" || "$existing" = 'no crontab for '* ]]
[[ -z "$(agent atq)" ]]
cat > /run/safeyolo/snapshot-canary <<'JOB'
#!/bin/sh
set -eu
test "$(id -u)" = 1000
printf '%s uid=%s pid=%s utc=%s\n' "$1" "$(id -u)" "$$" "$(date -u +%FT%TZ)" >> /safeyolo-status/jobs
JOB
chmod 0755 /run/safeyolo/snapshot-canary
printf 'MAILTO=""\n@reboot /run/safeyolo/snapshot-canary cron >> /safeyolo-status/cron.log 2>&1\n' > /run/safeyolo/snapshot-crontab
chmod 0644 /run/safeyolo/snapshot-crontab
agent 'crontab /run/safeyolo/snapshot-crontab'
installed=1
agent 'printf "/run/safeyolo/snapshot-canary at >> /safeyolo-status/at.log 2>&1\n" | TZ=UTC at -M now' 2> "$status/at-submission.txt"
job_id=$(awk '/^job / {print $2}' "$status/at-submission.txt")
[[ "$job_id" =~ ^[0-9]+$ ]]
agent 'crontab -l' > "$status/queued.txt"
agent atq >> "$status/queued.txt"
agent atq | awk '{print $1}' | grep -qx "$job_id"

ticks=0
while [[ ! -e /safeyolo/per-run-go ]]; do
    cron=$(daemon_pids cron)
    atd=$(daemon_pids atd)
    if [[ -n "$cron$atd" ]]; then
        echo 'Scheduler running while the per-run gate is absent' >&2
        exit 1
    fi
    [[ ! -e "$status/jobs" ]]
    # Both positive queue state and continued guest observations accompany
    # the absence checks. The host requires another sample after saving.
    ticks=$((ticks + 1))
    printf '%s\n' "$ticks" > "$status/quiet-ticks.tmp"
    mv "$status/quiet-ticks.tmp" "$status/quiet-ticks"
    echo ready > "$status/probe.ready"
    sleep 0.2
done

deadline=$((SECONDS + 90))
while :; do
    cron=$(daemon_pids cron)
    atd=$(daemon_pids atd)
    if [[ "$cron" =~ ^[0-9]+$ && "$atd" =~ ^[0-9]+$ && -s "$status/jobs" ]]; then
        if [[ $(awk '$1 == "cron" {n++} END {print n+0}' "$status/jobs") = 1 &&
              $(awk '$1 == "at" {n++} END {print n+0}' "$status/jobs") = 1 ]]; then
            printf 'cron=%s atd=%s\n' "$cron" "$atd" > "$status/daemons"
            break
        fi
    fi
    (( SECONDS < deadline )) || { echo 'Timed out waiting for one daemon pair and both canaries' >&2; exit 1; }
    sleep 0.2
done
[[ $(wc -l < "$status/jobs") = 2 ]]
cat "$status/queued.txt" "$status/daemons" "$status/jobs"
