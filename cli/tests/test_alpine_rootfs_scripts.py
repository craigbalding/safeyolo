"""Exercise both Alpine builders' output and failure paths without downloads.

The image/package tools are doubles. Real image builds and guest boot remain
separate acceptance checks.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILDERS = (
    REPO_ROOT / "contrib/alpine-minimal/build-alpine-rootfs.sh",
    REPO_ROOT / "contrib/alpine-browser/build-alpine-browser-rootfs.sh",
)
PROXY_VARIABLES = (
    "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy",
)


def _run_builder(
    tmp_path, builder, output, arch="arm64", failure="", build_ca=True, proxies=None,
):
    tools = tmp_path / "bin"
    tools.mkdir()
    driver = tools / "driver"
    driver.write_text(
        """#!/bin/bash
tool=${0##*/}
printf '%s' "$tool" >> "$TEST_CALLS"
printf '|%s' "$@" >> "$TEST_CALLS"
printf '\\n' >> "$TEST_CALLS"
case "$tool" in
  id) echo 12345 ;;
  sudo)
    [ "${1-}" = -v ] && exit 0
    exec env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \\
      -u NO_PROXY -u no_proxy -u SSL_CERT_FILE "$@"
    ;;
  skopeo) exit 0 ;;
  umoci) mkdir -p "${@: -1}/rootfs/"{etc,tmp,usr/local/bin,usr/share} ;;
  chroot)
    tree=$1
    shift
    if [ "${1-}" = env ]; then
      shift
      while [[ ${1-} == *=* ]]; do
        export "$1"
        shift
      done
    fi
    if [ -n "${SSL_CERT_FILE-}" ]; then
      [ "$(cat "$tree$SSL_CERT_FILE")" = build-test-ca ] || exit 45
    fi
    "$TEST_PYTHON" -c 'import json, os; print(json.dumps({k: os.environ[k] for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy", "SSL_CERT_FILE") if k in os.environ}))'
    [ "$TEST_FAILURE" != apk ] || exit 42
    ;;
  chown) [ "$TEST_FAILURE" != ownership ] || exit 43 ;;
  truncate) : > "${@: -1}" ;;
  mkfs.ext4)
    [ "$TEST_FAILURE" != pack ] || exit 44
    printf 'packed\\n' > "${@: -1}"
    ;;
esac
"""
    )
    driver.chmod(0o755)
    for name in ("id", "sudo", "skopeo", "umoci", "chroot", "chown", "truncate", "mkfs.ext4"):
        (tools / name).symlink_to(driver)
    guest = tmp_path / "guest"
    guest.mkdir()
    (guest / "install-guest-common.sh").write_text(
        'install_safeyolo_guest_common() { touch "$1/usr/local/bin/guest-installed"; }\n'
    )
    (guest / "install-novnc-assets.sh").write_text(
        '#!/bin/bash\nset -e\nmkdir -p "$1/usr/share/novnc"\n'
        'echo assets > "$1/usr/share/novnc/vnc.html"\n'
    )
    calls = tmp_path / "calls"
    destination = tmp_path / ("rootfs" if output == "TREE" else "rootfs.ext4")
    env = os.environ | {
        "PATH": f"{tools}:{os.environ['PATH']}",
        "TEST_CALLS": str(calls),
        "TEST_FAILURE": failure,
        "TEST_PYTHON": str(Path(sys.executable).resolve()),
        "SAFEYOLO_AGENT_NAME": "alpine-test",
        "SAFEYOLO_TARGET_ARCH": arch,
        "SAFEYOLO_GUEST_SRC_DIR": str(guest),
        "SAFEYOLO_ROOTFS_WORK_DIR": str(tmp_path / "work"),
        f"SAFEYOLO_ROOTFS_OUT_{output}": str(destination),
        "SAFEYOLO_ROOTFS_OUT_CACHE_PATHS": str(tmp_path / "cache-paths.txt"),
    }
    for name in PROXY_VARIABLES:
        env.pop(name, None)
    env.update(proxies or {})
    if build_ca:
        certificate = tmp_path / "build-ca.pem"
        certificate.write_text("build-test-ca\n")
        env["SSL_CERT_FILE"] = str(certificate)
    else:
        env.pop("SSL_CERT_FILE", None)
    result = subprocess.run(
        ["bash", "-c", 'umask 077; exec "$@"', "alpine-builder", str(builder)],
        env=env, capture_output=True, text=True,
    )
    return result, calls.read_text().splitlines(), destination


@pytest.mark.parametrize("builder", BUILDERS, ids=lambda path: path.parent.name)
@pytest.mark.parametrize("output", ("TREE", "EXT4"))
@pytest.mark.parametrize("arch", ("arm64", "amd64"))
def test_alpine_builder_outputs(tmp_path, builder, output, arch):
    result, calls, destination = _run_builder(tmp_path, builder, output, arch)

    assert result.returncode == 0, result.stderr
    pull = next(call for call in calls if call.startswith("skopeo|"))
    assert f"--override-arch={arch}" in pull
    assert "|docker://alpine:3.22|" in pull
    assert not any(call.startswith("sudo|skopeo|") for call in calls)
    assert any(call.startswith("sudo|umoci|unpack|") for call in calls)
    apk = next(call for call in calls if call.startswith("chroot|"))
    assert "|env|SSL_CERT_FILE=/tmp/safeyolo-apk-ca." in apk
    assert "|setpriv|" in apk
    assert not list((tmp_path / "work/tree/tmp").glob("safeyolo-apk-ca.*"))
    assert (tmp_path / "cache-paths.txt").read_text() == "/var/cache/apk\n"
    if output == "TREE":
        assert (destination / "usr/local/bin/guest-installed").is_file()
        assert destination.stat().st_mode & 0o777 == 0o755
        assert f"chown|-R|100000:100000|{destination}" in calls
        if builder == BUILDERS[1]:
            assets = destination / "usr/share/novnc"
            assert (assets / "vnc.html").read_text() == "assets\n"
            assert assets.stat().st_mode & 0o777 == 0o755
            assert (assets / "vnc.html").stat().st_mode & 0o777 == 0o644
    else:
        assert destination.read_text() == "packed\n"
        assert any("|-d|" in call for call in calls if call.startswith("mkfs.ext4|"))
        assert f"chown|12345:12345|{destination}" in calls


@pytest.mark.parametrize("builder", BUILDERS, ids=lambda path: path.parent.name)
def test_alpine_builder_uses_image_trust_without_build_ca(tmp_path, builder):
    result, calls, _ = _run_builder(tmp_path, builder, "TREE", build_ca=False)

    assert result.returncode == 0, result.stderr
    apk = next(call for call in calls if call.startswith("chroot|"))
    assert "|/sbin/apk|add|" in apk
    assert "SSL_CERT_FILE=" not in apk
    assert json.loads(result.stdout.splitlines()[3]) == {}


@pytest.mark.parametrize("builder", BUILDERS, ids=lambda path: path.parent.name)
@pytest.mark.parametrize("build_ca", (False, True))
def test_alpine_builder_preserves_configured_proxies(tmp_path, builder, build_ca):
    proxies = {
        "HTTP_PROXY": "http://build-proxy.invalid:8080",
        "HTTPS_PROXY": "http://build-proxy.invalid:8081",
        "http_proxy": "http://build-proxy.invalid:8082",
        "https_proxy": "http://build-proxy.invalid:8083",
        "NO_PROXY": "localhost,127.0.0.1,example with spaces",
        "no_proxy": "",
    }
    result, _, _ = _run_builder(tmp_path, builder, "TREE", build_ca=build_ca, proxies=proxies)

    assert result.returncode == 0, result.stderr
    actual = json.loads(result.stdout.splitlines()[3])
    assert {name: actual[name] for name in PROXY_VARIABLES} == proxies
    assert ("SSL_CERT_FILE" in actual) == build_ca


@pytest.mark.parametrize("builder", BUILDERS, ids=lambda path: path.parent.name)
@pytest.mark.parametrize(
    ("failure", "output", "status"),
    (("apk", "TREE", 42), ("ownership", "TREE", 43), ("pack", "EXT4", 44)),
)
def test_alpine_builder_does_not_report_failed_output_as_success(
    tmp_path, builder, failure, output, status,
):
    result, _, _ = _run_builder(tmp_path, builder, output, failure=failure)

    assert result.returncode == status, result.stderr
    assert "built successfully" not in result.stdout
    assert not (tmp_path / "cache-paths.txt").exists()
    assert not list((tmp_path / "work/tree/tmp").glob("safeyolo-apk-ca.*"))
