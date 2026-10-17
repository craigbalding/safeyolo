#!/usr/bin/env bash
# Run as guest root in an owned blackbox fixture, after the guest is ready.
set -euo pipefail
offline_inputs=${1:-}
# Positional arguments also work with an empty list under Bash 3's nounset.
set --
if [[ -n "$offline_inputs" ]]; then
    # These paths are inside the guest's mounted workspace, not host paths.
    if [[ "$offline_inputs" != /* ]]; then
        echo 'Offline guest test inputs need an absolute guest path.' >&2
        exit 1
    fi
    shopt -s nullglob
    debs=("$offline_inputs"/debs/*.deb)
    wheels=("$offline_inputs"/wheels/*.whl)
    if (( ${#debs[@]} == 0 || ${#wheels[@]} == 0 )); then
        echo "Offline guest test inputs need debs/*.deb and wheels/*.whl: $offline_inputs" >&2
        exit 1
    fi
    # Empty repository settings keep dependency resolution on local archives.
    DEBIAN_FRONTEND=noninteractive apt-get -o Dir::Etc::sourcelist=/dev/null \
        -o Dir::Etc::sourceparts=- -o Dpkg::Use-Pty=0 -y --no-install-recommends install "${debs[@]}"
    set -- --no-index --find-links "$offline_inputs/wheels"
elif ! python3 -m pip --version >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        # APT does not read SSL_CERT_FILE. Use the same per-instance CA as
        # the guest's other HTTPS clients, including on retained images.
        apt_tls_options=()
        if [[ -n ${SSL_CERT_FILE:-} ]]; then
            if [[ ! -f $SSL_CERT_FILE || ! -r $SSL_CERT_FILE ]]; then
                echo "The test guest TLS CA file is not readable: $SSL_CERT_FILE" >&2
                exit 1
            fi
            apt_tls_options=(-o "Acquire::https::CaInfo=$SSL_CERT_FILE")
        fi
        apt-get ${apt_tls_options[@]+"${apt_tls_options[@]}"} -o APT::Update::Error-Mode=any update
        DEBIAN_FRONTEND=noninteractive apt-get ${apt_tls_options[@]+"${apt_tls_options[@]}"} \
            install -y --no-install-recommends python3 python3-pip
    elif command -v apk >/dev/null 2>&1; then
        apk add python3 py3-pip
    else
        echo 'The test fixture needs Python, pip, pytest, httpx and pytest-timeout.' >&2
        exit 1
    fi
fi
# Exported from the host runner's lock. Include hashes for each dependency and
# retain interpreter markers, wheels and source archives from that lock.
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
python3 -m pip install --break-system-packages --require-hashes "$@" -r "$script_dir/guest-requirements.txt"
python3 -c 'import pytest, httpx, pytest_timeout'
