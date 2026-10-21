"""Exercise the boot CA block without running network or mount setup."""

import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("installed", "bundle"),
    (("instance-ca\n", "other-ca\n"), (None, "other-ca\n"),
     ("old-ca\n", "other-ca\n"), ("instance-ca\n", None),
     ("instance-ca\n", "other-ca\ninstance-ca\n")),
    ids=("stale-bundle", "missing-certificate", "changed-certificate",
         "missing-bundle", "already-trusted"),
)
def test_boot_refreshes_ca_bundle(tmp_path, installed, bundle):
    result, source, destination, store, calls, _ = _run_ca_block(
        tmp_path, installed, bundle,
    )

    assert result.returncode == 0, result.stderr
    assert destination.read_bytes() == source.read_bytes()
    assert source.read_text() in store.read_text()
    assert calls.read_text().splitlines() == ["refresh"]


def test_boot_without_instance_ca_leaves_store_unchanged(tmp_path):
    result, _, destination, store, calls, _ = _run_ca_block(
        tmp_path, "installed-ca\n", "other-ca\n", source_exists=False,
    )

    assert result.returncode == 0, result.stderr
    assert destination.read_text() == "installed-ca\n"
    assert store.read_text() == "other-ca\n"
    assert not calls.exists()


def test_boot_reports_ca_update_failure(tmp_path):
    result, _, destination, store, calls, console = _run_ca_block(
        tmp_path, "instance-ca\n", "other-ca\n", update_fails=True,
    )

    assert result.returncode == 0, result.stderr
    assert calls.read_text() == "refresh\n"
    assert "WARNING: update-ca-certificates failed" in console.read_text()
    assert destination.read_text() == "instance-ca\n"
    assert store.read_text() == "other-ca\n"


def _run_ca_block(
    tmp_path, installed, bundle, *, source_exists=True, update_fails=False,
):
    source = tmp_path / "source.pem"
    destination = tmp_path / "safeyolo.crt"
    store = tmp_path / "bundle.pem"
    calls = tmp_path / "updates"
    console = tmp_path / "console"
    if source_exists:
        source.write_text("instance-ca\n")
    if installed is not None:
        destination.write_text(installed)
    if bundle is not None:
        store.write_text(bundle)
    tools = tmp_path / "bin"
    tools.mkdir()
    updater = tools / "update-ca-certificates"
    updater.write_text(
        '#!/bin/sh\n'
        'echo refresh >> "$TEST_CALLS"\n'
        '[ "$TEST_UPDATE_FAILS" = 0 ] || exit 1\n'
        'cat "$TEST_CERT" >> "$TEST_BUNDLE"\n'
    )
    updater.chmod(0o755)
    text = (REPO_ROOT / "cli/src/safeyolo/guest-init-static.sh").read_text()
    block = text[text.index("SY_CERT_SRC="):text.index("# 4. SSH server")]
    block = block.replace("/safeyolo/mitmproxy-ca-cert.pem", str(source))
    block = block.replace("/usr/local/share/ca-certificates/safeyolo.crt", str(destination))
    block = block.replace("/dev/console", str(console))
    # An unchanged destination can be a read-only bind mount. Fail if the boot
    # block tries to overwrite it, even though its bytes already match.
    command = (
        'install() { cmp -s "$SY_CERT_SRC" "$SY_CERT_DST" && exit 91; '
        'command install "$@"; };\n' + block
    )
    result = subprocess.run(
        ["bash", "-ec", command],
        env=os.environ | {
            "PATH": f"{tools}:{os.environ['PATH']}",
            "TEST_CERT": str(destination), "TEST_BUNDLE": str(store),
            "TEST_CALLS": str(calls), "TEST_UPDATE_FAILS": str(int(update_fails)),
        },
        capture_output=True, text=True,
    )
    return result, source, destination, store, calls, console
