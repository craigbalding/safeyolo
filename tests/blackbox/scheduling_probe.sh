#!/bin/bash
# Run as agent in an owned standard guest with an empty crontab/at queue.
# This focused probe uses no Python, model, or manual daemon startup.
set -euo pipefail
if [ ! -r /usr/local/lib/safeyolo/scheduling.sh ]; then
    echo 'cron/at unsupported in this image' >&2
    exit 77
fi
if [ "$(id -u)" != 1000 ]; then
    echo 'Run this probe as the guest agent user (uid 1000)' >&2
    exit 1
fi
if existing=$(LC_ALL=C crontab -l 2>&1); then
    :
elif [[ "$existing" == 'no crontab for '* ]]; then
    existing=
else
    printf '%s\n' "$existing" >&2
    exit 1
fi
pending=$(atq)
if [ -n "$existing" ] || [ -n "$pending" ]; then
    echo 'Use a disposable guest with an empty crontab and at queue' >&2
    exit 1
fi
mkdir -p /home/agent/.local/state
probe_dir=$(mktemp -d /home/agent/.local/state/scheduling-probe.XXXXXX)
queued_id=
cancel_id=
installed_crontab=0
cleanup() {
    result=$?
    trap - EXIT
    if [ "$installed_crontab" = 1 ]; then crontab -r || result=1; fi
    for owned_id in "$queued_id" "$cancel_id"; do
        if [ -n "$owned_id" ] && atq | awk '{print $1}' | grep -qx "$owned_id"; then
            atrm "$owned_id" || result=1
        fi
    done
    if [ "$result" = 0 ]; then
        rm -rf -- "$probe_dir"
    else
        echo "Probe failed; inspect $probe_dir and /var/log/safeyolo-scheduling.log" >&2
    fi
    exit "$result"
}
trap cleanup EXIT
cat > "$probe_dir/job.sh" <<'JOB'
#!/bin/sh
set -eu
test "$(id -u)" = 1000
test "$HOME" = /home/agent
test "$PWD" = /workspace
test -n "$PATH"
test -n "$HTTP_PROXY"
test "$HTTPS_PROXY" = "$HTTP_PROXY"
test -r "$SSL_CERT_FILE"
test "$REQUESTS_CA_BUNDLE" = "$SSL_CERT_FILE"
test "$NODE_EXTRA_CA_CERTS" = "$SSL_CERT_FILE"
agent_token=$(cat /app/agent_token) || exit
printf 'Authorization: Bearer %s\n' "$agent_token" |
    curl --silent --show-error --fail-with-body --max-time 10 --header @- \
        http://_safeyolo.proxy.internal/health > "$1.health"
grep -Eq '"agent_api"[[:space:]]*:[[:space:]]*"ok"' "$1.health"
printf 'uid=%s cwd=%s timezone=%s proxy-and-ca=present current-agent-api=ok\n' \
    "$(id -u)" "$PWD" "$(date +%Z)" > "$1"
JOB
printf '%s\n' 'MAILTO=""' "* * * * * /usr/local/bin/safeyolo-job /bin/sh $probe_dir/job.sh $probe_dir/cron >>$probe_dir/cron.log 2>&1" | crontab -
installed_crontab=1
crontab -l
# At captures deliberately stale settings. The execution wrapper must replace
# them with the current per-run values before the real daemon-fired request.
cd /home/agent
printf '%s\n' "/usr/local/bin/safeyolo-job /bin/sh $probe_dir/job.sh $probe_dir/at >>$probe_dir/at.log 2>&1" |
    HTTP_PROXY=http://127.0.0.1:1 SSL_CERT_FILE=/absent TZ=UTC at -M now 2> "$probe_dir/submission"
queued_id=$(awk '/^job / {print $2}' "$probe_dir/submission")
test -n "$queued_id"
printf '%s\n' "touch $probe_dir/cancelled" | TZ=UTC at -M now + 2 minutes 2> "$probe_dir/cancellation"
cancel_id=$(awk '/^job / {print $2}' "$probe_dir/cancellation")
test -n "$cancel_id"
atq
atrm "$cancel_id"
if atq | awk '{print $1}' | grep -qx "$cancel_id"; then
    echo 'Cancelled job is still queued' >&2
    exit 1
fi
deadline=$((SECONDS + 90))
while [ ! -s "$probe_dir/cron" ] || [ ! -s "$probe_dir/at" ]; do
    if [ "$SECONDS" -ge "$deadline" ]; then
        echo 'Real cron/at jobs did not complete before the deadline' >&2
        exit 1
    fi
    sleep 0.2
done
test ! -e "$probe_dir/cancelled"
cat "$probe_dir/cron" "$probe_dir/at"
echo 'Recurring execution, one-off execution and cancellation passed'
