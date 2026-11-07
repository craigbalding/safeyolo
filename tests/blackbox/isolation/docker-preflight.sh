#!/usr/bin/env bash
# In a disposable Linux/gVisor guest, run with guest sudo after installing
# docker.io, docker-cli and docker-compose. STATE must be a new absolute path
# under persistent guest home. --daemon reuses that data and runs only the
# foreground daemon for the installed lifecycle observer.
# It preserves diagnostics and stops its daemon on exit; it adds no host mount.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || $1 != /home/agent/* || ${2:-} != '' && ${2:-} != --daemon || ${2:-} != --daemon && -e $1 ]]; then
    echo 'usage: docker-preflight.sh /home/agent/STATE [--daemon]' >&2
    exit 64
fi
state=$1
data_root=${SAFEYOLO_DOCKER_DATA_ROOT:-$state/data}
mkdir -p "$data_root" /run/safeyolo-nested-docker
export DOCKER_HOST=unix:///run/safeyolo-nested-docker/docker.sock
export DOCKER_CONFIG="$state/client"
# Use the existing proxy and CA environment. Never inherit a Docker context
# that could silently substitute a daemon outside the selected sandbox.
unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH

docker --version > "$state/docker-version.txt"
dockerd --version > "$state/dockerd-version.txt"
runc --version > "$state/runc-version.txt"
docker compose version > "$state/compose-version.txt"
cat /proc/self/status > "$state/process-status.txt"
cat /proc/self/mountinfo > "$state/mountinfo.txt"
ip -j link show > "$state/interfaces.json"
ip -j route show > "$state/routes.json"

flags=(
    --host="$DOCKER_HOST"
    --data-root="$data_root"
    --exec-root=/run/safeyolo-nested-docker/exec
    --pidfile=/run/safeyolo-nested-docker/dockerd.pid
    --storage-driver=vfs
    --iptables=false --ip6tables=false
    --bridge=none --ip-forward=false --ip-masq=false
    --exec-opt native.cgroupdriver=cgroupfs
)
printf '%s\n' "${flags[@]}" > "$state/dockerd-flags.txt"
if [[ ${2:-} == --daemon ]]; then
    exec dockerd "${flags[@]}"
fi
dockerd "${flags[@]}" > "$state/dockerd.log" 2>&1 &
daemon=$!
cleanup() {
    if kill -0 "$daemon" 2>/dev/null; then
        kill -TERM "$daemon"
    fi
    # Preserve a nonzero daemon exit in its own file, separately from the
    # operation that failed. wait also reaps the owned child.
    if wait "$daemon"; then
        echo 0 > "$state/daemon-exit.txt"
    else
        echo "$?" > "$state/daemon-exit.txt"
    fi
}
trap cleanup EXIT

ready=false
for ((attempt=0; attempt<150; attempt++)); do
    # A formatted `docker info` can exit zero with only ClientInfo and a
    # ServerErrors array. Require a real server version before proceeding.
    server_version=$(docker info --format '{{.ServerVersion}}' 2> "$state/readiness-error.txt") || server_version=
    if [[ -n $server_version ]]; then
        docker info --format '{{json .}}' > "$state/docker-info.json"
        ready=true
        break
    fi
    if ! kill -0 "$daemon" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if [[ $ready != true ]]; then
    echo 'daemon-unavailable' > "$state/outcome.txt"
    echo "Docker did not become ready; inspect $state/dockerd.log" >&2
    exit 1
fi

# Debian is also the guest's package source. Pull and run are deliberately
# separate so a registry refusal cannot be reported as a runtime failure.
if ! docker pull debian:trixie-slim > "$state/pull.log" 2>&1; then
    echo 'pull-failed' > "$state/outcome.txt"
    exit 1
fi
docker image inspect debian:trixie-slim > "$state/image.json"
if ! docker run --name docker-preflight --network=host --rm debian:trixie-slim \
        /bin/echo nested-container-ran > "$state/run.log" 2>&1; then
    echo 'container-failed' > "$state/outcome.txt"
    exit 1
fi
echo 'container-ran' > "$state/outcome.txt"
