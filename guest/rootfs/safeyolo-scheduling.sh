# Debian cron/at lifecycle, sourced by guest-init-per-run after its gate,
# clock, environment and credential setup. Job state stays in the existing
# per-agent rootfs overlay, in the packages' native spool directories.
SCHEDULER_LOG=/var/log/safeyolo-scheduling.log
CRON_PID=
ATD_PID=
SCHEDULER_SYSLOG_PID=
ATD_NOTIFY_READY_FILES=0
ATD_READY_FILES=

scheduler_log() {
    printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >> "$SCHEDULER_LOG"
}

start_guest_schedulers() {
    mkdir -p /var/log
    touch "$SCHEDULER_LOG"
    chmod 0644 "$SCHEDULER_LOG"
    if [ ! -f /safeyolo/per-run-go ]; then
        scheduler_log 'cron/at not started: per-run gate is closed; inspect the guest boot log'
        return
    fi

    # The Linux image's uid remap makes all shipped files guest-root-owned.
    # Restore package spool owners without changing existing job-file owners.
    install -d -o root -g crontab -m 1730 /var/spool/cron/crontabs
    install -d -o daemon -g daemon -m 1770 /var/spool/cron/atjobs /var/spool/cron/atspool
    if [ ! -e /var/spool/cron/atjobs/.SEQ ]; then
        printf '0\n' > /var/spool/cron/atjobs/.SEQ
    fi
    chown daemon:daemon /var/spool/cron/atjobs/.SEQ
    chmod 0600 /var/spool/cron/atjobs/.SEQ
    case "$(uname -r)" in
        *-gvisor)
            # Cron/at drop the agent's SETUID/SETGID capabilities in job
            # children. Their initgroups calls retain these native spool
            # groups, so the ordinary nosuid commands still work there.
            usermod -a -G crontab,daemon agent
            chmod 0660 /var/spool/cron/atjobs/.SEQ
            ATD_NOTIFY_READY_FILES=1
            ;;
    esac
    if [ -f /etc/at.deny ]; then
        chown root:daemon /etc/at.deny
    fi

    # VZ has a fresh /run tmpfs. Clear Linux's retained cron boot marker and
    # atd readiness file before these new, guest-owned daemon processes start.
    rm -f /run/crond.reboot /run/atd.pid

    # Cron emits runtime errors through syslog. BusyBox is already in the base.
    # Respect an existing guest syslog socket rather than replacing its owner.
    if [ ! -S /dev/log ]; then
        /usr/bin/busybox syslogd -n -O "$SCHEDULER_LOG" -s 256 -b 1 &
        SCHEDULER_SYSLOG_PID=$!
    fi
    /usr/sbin/cron -f -L 7 >> "$SCHEDULER_LOG" 2>&1 &
    CRON_PID=$!
    /usr/sbin/atd -d >> "$SCHEDULER_LOG" 2>&1 &
    ATD_PID=$!
    scheduler_log "started cron pid=$CRON_PID and atd pid=$ATD_PID; timezone=$(date +%Z)"
}

check_guest_schedulers() {
    [ -n "$CRON_PID$ATD_PID$SCHEDULER_SYSLOG_PID" ] || return 0
    local name pid result running label ready_files file ready_pid
    # Bash owns these children. Its job table distinguishes an exited child
    # from a live process without polling /proc or trusting a reused PID.
    running=$'\n'"$(jobs -pr)"$'\n'
    for name in CRON_PID ATD_PID SCHEDULER_SYSLOG_PID; do
        pid=${!name}
        [ -n "$pid" ] || continue
        if [[ "$running" != *$'\n'"$pid"$'\n'* ]]; then
            result=0
            wait "$pid" || result=$?
            case "$name" in
                CRON_PID) label=cron ;;
                ATD_PID) label=atd ;;
                *) label=syslogd ;;
            esac
            scheduler_log "$label exited (status=$result); scheduled work may not run; inspect this log and the guest boot log"
            printf -v "$name" '%s' ''
        fi
    done
    # atd writes its PID file after installing its HUP handler. Never send
    # the first notification before that child is ready to receive it.
    if [ "$ATD_NOTIFY_READY_FILES" = 1 ] && [ -n "$ATD_PID" ] &&
            [ -r /run/atd.pid ] && read -r ready_pid 2>/dev/null < /run/atd.pid &&
            [ "$ready_pid" = "$ATD_PID" ]; then
        # A capability-free at caller cannot signal atd. Forward native
        # ready-file changes through this existing guest-owner loop. The
        # executable bit is set only after at finishes writing each job;
        # the sequence file changes too early to serve as a notification.
        ready_files=
        for file in /var/spool/cron/atjobs/*; do
            if [ -f "$file" ] && [ -x "$file" ]; then
                ready_files+="$file"$'\n'
            fi
        done
        if [ "$ready_files" != "$ATD_READY_FILES" ]; then  # DOC: cli/src/safeyolo/agent_context/skills/safeyolo/references/scheduling.md
            kill -HUP "$ATD_PID" 2>/dev/null || scheduler_log 'atd queue notification failed; inspect this log and the guest boot log'
            ATD_READY_FILES=$ready_files
        fi
    fi
}

stop_guest_schedulers() {
    local pid
    for pid in "$CRON_PID" "$ATD_PID" "$SCHEDULER_SYSLOG_PID"; do
        [ -n "$pid" ] || continue
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    CRON_PID=
    ATD_PID=
    SCHEDULER_SYSLOG_PID=
    ATD_NOTIFY_READY_FILES=0
    ATD_READY_FILES=
}
