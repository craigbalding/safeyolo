#!/usr/bin/env bash
# Run as guest root in an owned blackbox fixture, after the guest is ready.
set -euo pipefail
offline_inputs=${1:-}
# Guest test dependencies belong to distro Python. Login shells and user mise
# runtimes can select different interpreters and unrelated pytest launchers.
python_and_pip_ready() {
    local versions
    versions=$(/usr/bin/python3 -c 'import sys, pip; print("Python", sys.version.split()[0]); print("pip", pip.__version__)') || return
    # An empty executable can return zero under Bash without running Python.
    [[ $versions == Python\ 3.*$'\npip '[0-9]* ]] || return 1
    printf '%s\n' "$versions"
}
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
    if ! python_and_pip_ready >/dev/null 2>&1; then
        # Restore payloads before APT configures Python. Its package scripts
        # can import a damaged standard library before APT replaces that file.
        for deb in "${debs[@]}"; do
            dpkg-deb --extract "$deb" /
        done
    fi
    # Empty repository settings keep dependency resolution on local archives.
    # Reinstall because same-version status does not prove usable package files.
    DEBIAN_FRONTEND=noninteractive apt-get -o Dir::Etc::sourcelist=/dev/null \
        -o Dir::Etc::sourceparts=- -o Dpkg::Use-Pty=0 -y --no-install-recommends --reinstall install "${debs[@]}"
    set -- --no-index --find-links "$offline_inputs/wheels"
elif ! python_and_pip_ready >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        # APT does not read SSL_CERT_FILE. Use the same per-instance CA as
        # the guest's other HTTPS clients, including on retained images.
        apt_tls_options=()
        if [[ -n ${SSL_CERT_FILE:-} ]]; then
            if [[ ! -f $SSL_CERT_FILE || ! -r $SSL_CERT_FILE ]]; then
                echo "The test guest TLS CA file is not readable: $SSL_CERT_FILE" >&2
                exit 1
            fi
            # APT's _apt user cannot read an owner-only injected CA. Stage
            # the public certificate without changing the original file.
            apt_ca=$(mktemp /tmp/safeyolo-blackbox-ca.XXXXXX)
            trap 'rm -f -- "$apt_ca"' EXIT
            install -m 0644 -- "$SSL_CERT_FILE" "$apt_ca"
            apt_tls_options=(-o "Acquire::https::CaInfo=$apt_ca")
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
if ! python_and_pip_ready; then
    echo 'Test guest Python and pip did not report working versions after package preparation.' >&2
    exit 1
fi
# Exported from the host runner's lock. Include hashes for each dependency and
# retain interpreter markers, wheels and source archives from that lock.
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
# Replace same-version files even when installed metadata is empty or damaged.
# Ignore installed records because pip cannot uninstall from a damaged RECORD.
/usr/bin/python3 -m pip install --break-system-packages --ignore-installed --require-hashes "$@" -r "$script_dir/guest-requirements.txt"
test_versions=$(/usr/bin/python3 -c 'import pytest, httpx; from pytest_timeout import pytest_configure; from importlib.metadata import version; print("pytest", pytest.__version__); print("httpx", httpx.__version__); print("pytest-timeout", version("pytest-timeout"))')
if [[ $test_versions != pytest\ [0-9]*$'\nhttpx '[0-9]*$'\npytest-timeout '[0-9]* ]]; then
    echo 'Test guest packages did not report working imports and versions.' >&2
    exit 1
fi
pytest_version=$(/usr/bin/python3 -m pytest --version)
if [[ $pytest_version != "${test_versions%%$'\n'*}" ]]; then
    echo 'Test guest pytest launcher did not report the imported pytest version.' >&2
    exit 1
fi
printf '%s\n' "$test_versions" "$pytest_version"
# Finish test-package writes before a caller can stop the owned guest.
# This does not establish the cause of any earlier damaged files.
sync
