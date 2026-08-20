#!/usr/bin/env bash
# Diagnose Linux ETXTBSY after a SafeYolo agent edits a host-backed file.
#
# Run this through Bash so the diagnostic can start even when its own inode
# cannot be execve'd:
#
#   bash tests/rootless-experiments/etxtbsy-dcache/diagnose-etxtbsy.sh
#   bash tests/rootless-experiments/etxtbsy-dcache/diagnose-etxtbsy.sh --watch 30
#   bash tests/rootless-experiments/etxtbsy-dcache/diagnose-etxtbsy.sh --inspect path/to/another-script

set -uo pipefail

usage() {
    cat <<'EOF'
Usage: bash tests/rootless-experiments/etxtbsy-dcache/diagnose-etxtbsy.sh [--watch SECONDS]
       bash tests/rootless-experiments/etxtbsy-dcache/diagnose-etxtbsy.sh --inspect FILE

With no FILE, safely attempts a direct execve() of this diagnostic. The child
immediately exits without running the diagnostic again. This makes the script
a harmless probe for an inode that was just edited through a SafeYolo agent.

--watch waits for ETXTBSY to clear and reports how long the writable inode was
held. --inspect never executes FILE; it only reports its inode and open-file
holders.

Run as your normal user first. If /proc is mounted with hidepid and holders are
not visible, rerun the same command with sudo for a complete descriptor scan.
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 2
}

canonical_path() {
    local path="$1"
    if command -v realpath >/dev/null 2>&1; then
        realpath -- "$path"
    elif command -v readlink >/dev/null 2>&1; then
        readlink -f -- "$path"
    else
        (CDPATH= cd -- "$(dirname -- "$path")" && printf '%s/%s\n' "$PWD" "$(basename -- "$path")")
    fi
}

stat_identity() {
    local path="$1"
    if stat -Lc '%d:%i' -- "$path" >/dev/null 2>&1; then
        stat -Lc '%d:%i' -- "$path"
    else
        stat -f '%d:%i' -- "$path"
    fi
}

stat_summary() {
    local path="$1"
    if stat -Lc 'device=%d inode=%i mode=%A uid=%u gid=%g size=%s mtime=%y' -- "$path" >/dev/null 2>&1; then
        stat -Lc 'device=%d inode=%i mode=%A uid=%u gid=%g size=%s mtime=%y' -- "$path"
    else
        stat -f 'device=%d inode=%i mode=%Sp uid=%u gid=%g size=%z mtime=%Sm' -- "$path"
    fi
}

print_mount() {
    local path="$1"
    printf '\nFilesystem containing target:\n'
    if command -v findmnt >/dev/null 2>&1; then
        findmnt -T "$path" -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null || true
    elif command -v df >/dev/null 2>&1; then
        df -T "$path" 2>/dev/null || df "$path" 2>/dev/null || true
    else
        printf '  mount inspection unavailable (findmnt/df not found)\n'
    fi
}

print_runsc_processes() {
    printf '\nVisible gVisor runtime processes:\n'
    local rows
    rows="$(ps -eo pid=,ppid=,user=,stat=,comm= 2>/dev/null \
        | awk '$5 ~ /(^|-)runsc($|-)|gofer|gvisor_sentry/ {print}' || true)"
    if [ -n "$rows" ]; then
        printf '  PID     PPID USER         STAT COMMAND\n'
        printf '%s\n' "$rows"
    else
        printf '  none visible\n'
    fi
}

HOLDER_COUNT=0
RUNTIME_HOLDER_COUNT=0

scan_proc_holders() {
    local target="$1"
    local identity output counts body

    HOLDER_COUNT=0
    RUNTIME_HOLDER_COUNT=0
    identity="$(stat_identity "$target")" || return

    printf '\nWritable descriptors for target inode (%s):\n' "$identity"
    printf '  %-8s %-5s %-10s %-12s %s\n' PID FD FLAGS COMMAND EXE

    if [ ! -d /proc ]; then
        printf '  /proc is unavailable on this host\n'
        return
    fi

    # A single Python process is substantially faster than spawning stat/awk
    # once per descriptor on a machine with many processes.
    output="$(python3 - "$target" <<'PY'
import glob
import os
import sys

target = os.stat(sys.argv[1])
identity = (target.st_dev, target.st_ino)
holders = []
runtime_holders = 0

for fd_path in glob.iglob("/proc/[0-9]*/fd/[0-9]*"):
    try:
        current = os.stat(fd_path)
        if (current.st_dev, current.st_ino) != identity:
            continue
        _, _, pid, _, fd = fd_path.split("/")
        with open(f"/proc/{pid}/fdinfo/{fd}", encoding="ascii") as info:
            flags_text = next(
                line.split()[1] for line in info if line.startswith("flags:")
            )
        if int(flags_text, 8) & os.O_ACCMODE == os.O_RDONLY:
            continue
        try:
            with open(f"/proc/{pid}/comm", encoding="utf-8") as source:
                command = source.read().strip()
        except OSError:
            command = "?"
        try:
            executable = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            try:
                with open(f"/proc/{pid}/status", encoding="ascii") as source:
                    uid = next(
                        line.split()[1] for line in source if line.startswith("Uid:")
                    )
            except (OSError, StopIteration):
                uid = "?"
            executable = f"uid={uid}"
        holders.append((int(pid), int(fd), flags_text, command, executable))
        runtime_identity = f"{command} {executable}"
        if any(name in runtime_identity for name in ("runsc", "gofer", "gvisor_sentry")):
            runtime_holders += 1
    except (OSError, StopIteration, ValueError):
        continue

for pid, fd, flags, command, executable in sorted(holders):
    print(f"  {pid:<8} {fd:<5} {flags:<10} {command:<12} {executable}")
print(f"__COUNTS__ {len(holders)} {runtime_holders}")
PY
)"
    counts="${output##*$'\n'}"
    body="${output%$'\n'*}"
    if [ "$body" != "$output" ]; then
        printf '%s\n' "$body"
    fi
    read -r _ HOLDER_COUNT RUNTIME_HOLDER_COUNT <<< "$counts"

    if [ "$HOLDER_COUNT" -eq 0 ]; then
        printf '  none visible\n'
        if [ "$(id -u)" -ne 0 ]; then
            printf '  note: other-user descriptors may be hidden; rerun with sudo if ETXTBSY is active\n'
        fi
    fi
}

print_standard_tools() {
    local target="$1"
    if command -v lsof >/dev/null 2>&1; then
        printf '\nlsof output:\n'
        # -w suppresses unrelated warnings for mounts such as gvfs that lsof
        # encounters while building its device cache. The /proc inode scan
        # above remains the authoritative writer check.
        lsof -nP -w -- "$target" 2>/dev/null || true
    fi
    if command -v fuser >/dev/null 2>&1; then
        printf '\nfuser output:\n'
        # psmisc fuser does not consistently accept `--`. target has already
        # been canonicalized to an absolute path, so it cannot look like an
        # option. -I makes the comparison inode-based.
        fuser -v -I "$target" 2>&1 || true
    fi
}

PROBE_ERRNO=""
PROBE_MESSAGE=""

probe_self_execve() {
    local target="$1" output status
    PROBE_ERRNO=""
    PROBE_MESSAGE=""

    command -v python3 >/dev/null 2>&1 || die "python3 is required for an exact execve probe"
    output="$(SAFEYOLO_ETXTBSY_PROBE_CHILD=1 python3 - "$target" <<'PY'
import errno
import os
import sys

path = sys.argv[1]
try:
    os.execve(path, [path], os.environ.copy())
except OSError as error:
    name = errno.errorcode.get(error.errno, "UNKNOWN")
    print(f"{error.errno}\t{name}: {error.strerror}")
    raise SystemExit(125)
PY
)"
    status=$?

    if [ "$status" -eq 0 ]; then
        return 0
    fi
    if [ "$status" -eq 125 ]; then
        PROBE_ERRNO="${output%%$'\t'*}"
        PROBE_MESSAGE="${output#*$'\t'}"
        return 1
    fi
    PROBE_ERRNO="$status"
    PROBE_MESSAGE="unexpected probe failure: $output"
    return 1
}

print_verdict() {
    if [ "$PROBE_ERRNO" = "26" ]; then
        printf '\nVerdict: ETXTBSY reproduced by a direct host execve().\n'
        if [ "$RUNTIME_HOLDER_COUNT" -gt 0 ]; then
            printf 'A visible gVisor runtime process holds the inode writable; this implicates sandbox FD lifetime.\n'
        elif [ "$HOLDER_COUNT" -gt 0 ]; then
            printf 'A non-gVisor process visibly holds the inode writable; inspect the process listed above.\n'
        else
            printf 'No writable holder was visible. It may be transient or hidden by /proc permissions.\n'
        fi
    elif [ -z "$PROBE_ERRNO" ]; then
        printf '\nVerdict: direct host execve() succeeds now; ETXTBSY is not currently active.\n'
    else
        printf '\nVerdict: direct execve failed with %s (%s), not ETXTBSY.\n' "$PROBE_ERRNO" "$PROBE_MESSAGE"
    fi
}

if [ "${SAFEYOLO_ETXTBSY_PROBE_CHILD:-}" = "1" ]; then
    exit 0
fi

self="$(canonical_path "${BASH_SOURCE[0]}")" || die "cannot resolve diagnostic path"
target="$self"
inspect_only=false
watch_seconds=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --inspect)
            [ "$#" -ge 2 ] || die "--inspect requires FILE"
            target="$(canonical_path "$2")" || die "cannot resolve $2"
            inspect_only=true
            shift 2
            ;;
        --watch)
            [ "$#" -ge 2 ] || die "--watch requires SECONDS"
            [[ "$2" =~ ^[0-9]+$ ]] || die "--watch SECONDS must be a non-negative integer"
            watch_seconds="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

[ -f "$target" ] || die "target is not a regular file: $target"

printf 'SafeYolo ETXTBSY host diagnostic\n'
printf 'target: %s\n' "$target"
printf 'host:   %s\n' "$(uname -a)"
printf 'user:   uid=%s gid=%s\n' "$(id -u)" "$(id -g)"
printf 'stat:   %s\n' "$(stat_summary "$target")"

print_mount "$target"
print_runsc_processes

if [ "$inspect_only" = true ]; then
    scan_proc_holders "$target"
    print_standard_tools "$target"
    printf '\nInspection only: the target was not executed.\n'
    exit 0
fi

if probe_self_execve "$target"; then
    :
fi
scan_proc_holders "$target"
print_standard_tools "$target"
print_verdict

if [ "$watch_seconds" -gt 0 ] && [ "$PROBE_ERRNO" = "26" ]; then
    printf '\nWatching up to %ss for ETXTBSY to clear...\n' "$watch_seconds"
    started=$SECONDS
    deadline=$((SECONDS + watch_seconds))
    while [ "$SECONDS" -lt "$deadline" ]; do
        sleep 0.25
        if probe_self_execve "$target"; then
            printf 'ETXTBSY cleared after approximately %ss.\n' "$((SECONDS - started))"
            exit 0
        fi
        if [ "$PROBE_ERRNO" != "26" ]; then
            printf 'Probe changed to errno %s after approximately %ss: %s\n' \
                "$PROBE_ERRNO" "$((SECONDS - started))" "$PROBE_MESSAGE"
            exit 1
        fi
    done
    printf 'ETXTBSY remained active for the full %ss watch interval.\n' "$watch_seconds"
    scan_proc_holders "$target"
    exit 26
fi

if [ "$PROBE_ERRNO" = "26" ]; then
    exit 26
fi
if [ -n "$PROBE_ERRNO" ]; then
    exit 1
fi
exit 0
