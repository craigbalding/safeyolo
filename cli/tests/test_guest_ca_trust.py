"""Exercise boot trust with Bash, OpenSSL and Debian's actual CA updater."""

import os
import shutil
import signal
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
OPENSSL = shutil.which("openssl")
UPDATER = shutil.which("update-ca-certificates")
pytestmark = pytest.mark.skipif(
    not Path("/etc/debian_version").is_file(), reason="Real Debian CA updater controls",
)


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    assert OPENSSL and UPDATER, "Guest trust controls need OpenSSL and Debian's updater"
    directory = tmp_path_factory.mktemp("boot-certificates")
    for name in ("system", "instance", "rotated", "untrusted"):
        # The base CA and instance CA collide in the subject hash. Both
        # remain usable through the directory index with different keys.
        subject = "system" if name == "instance" else name
        subprocess.run(
            [OPENSSL, "req", "-x509", "-newkey", "ec", "-pkeyopt",
             "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", f"/CN={subject}",
             "-keyout", str(directory / f"{name}.key"),
             "-out", str(directory / f"{name}.crt")],
            check=True, capture_output=True, timeout=10,
        )
    return directory


@pytest.fixture
def trust_store(tmp_path, certificates):
    for name in ("system", "local", "store", "hooks", "bin"):
        (tmp_path / name).mkdir()
    (tmp_path / "debian_version").touch()
    (tmp_path / "config").write_text("system.crt\n!disabled.crt\n")
    shutil.copyfile(certificates / "system.crt", tmp_path / "system/system.crt")
    shutil.copyfile(certificates / "untrusted.crt", tmp_path / "system/disabled.crt")
    updater = tmp_path / "bin/update-ca-certificates"
    updater.write_text(
        '#!/bin/sh\n'
        'echo refresh >> "$TEST_ROOT/updates"\n'
        '[ ! -f "$TEST_ROOT/update-fails" ] || exit 1\n'
        'exec "$TEST_UPDATER" --certsconf "$TEST_ROOT/config" '
        '--certsdir "$TEST_ROOT/system" --localcertsdir "$TEST_ROOT/local" '
        '--etccertsdir "$TEST_ROOT/store" --hooksdir "$TEST_ROOT/hooks"\n'
    )
    updater.chmod(0o755)
    openssl = tmp_path / "bin/openssl"
    openssl.write_text(
        '#!/bin/sh\n'
        'if [ "$1" = rehash ] && [ -f "$TEST_ROOT/rehash-fails-once" ]; then\n'
        '    rm "$TEST_ROOT/rehash-fails-once"; exit 1\n'
        'fi\n'
        'exec "$TEST_OPENSSL" "$@"\n'
    )
    openssl.chmod(0o755)
    # Seed the same prepared distro bundle/index that the image supplies.
    subprocess.run(
        [str(updater)], env=_environment(tmp_path), check=True,
        capture_output=True, timeout=10,
    )
    (tmp_path / "updates").unlink()
    shutil.copyfile(certificates / "instance.crt", tmp_path / "source.pem")
    shutil.copyfile(tmp_path / "source.pem", tmp_path / "local/safeyolo.crt")
    return tmp_path


def test_fresh_boot_reuses_prepared_system_trust(trust_store, certificates):
    root = trust_store
    prepared = (root / "store/ca-certificates.crt").read_bytes()
    result = _run_ca_block(root)

    assert result.returncode == 0, result.stderr
    assert not (root / "updates").exists()
    assert (root / "local/safeyolo.crt").read_bytes() == (root / "source.pem").read_bytes()
    assert (root / "store/ca-certificates.crt").read_bytes().startswith(prepared)
    _assert_trust(root, certificates, "system", "instance")


def test_fresh_boot_preserves_complete_distro_bundle(trust_store, certificates):
    root = trust_store
    for path in (root / "store").iterdir():
        path.unlink()
    empty_local = root / "empty-local"
    empty_local.mkdir()
    subprocess.run(
        [UPDATER, "--certsconf", "/etc/ca-certificates.conf",
         "--certsdir", "/usr/share/ca-certificates", "--localcertsdir", str(empty_local),
         "--etccertsdir", str(root / "store"), "--hooksdir", str(root / "hooks")],
        env=_environment(root), check=True, capture_output=True, timeout=30,
    )
    prepared = (root / "store/ca-certificates.crt").read_bytes()
    assert b"-----BEGIN CERTIFICATE-----" in prepared
    result = _run_ca_block(root)

    assert result.returncode == 0, result.stderr
    assert not (root / "updates").exists()
    assert (root / "store/ca-certificates.crt").read_bytes().startswith(prepared)
    _assert_trust(root, certificates, "instance", rejected="system")


def test_repeated_boot_refreshes_retained_store_without_duplicate_ca(trust_store, certificates):
    root = trust_store
    assert _run_ca_block(root).returncode == 0
    assert _run_ca_block(root).returncode == 0

    assert (root / "updates").read_text().splitlines() == ["refresh"]
    assert (root / "store/ca-certificates.crt").read_bytes().count(
        (root / "source.pem").read_bytes(),
    ) == 1
    _assert_trust(root, certificates, "system", "instance")


@pytest.mark.parametrize("bound_destination", [False, True], ids=["copied", "read-only-bind"])
def test_rotated_ca_replaces_old_trust(trust_store, certificates, bound_destination):
    root = trust_store
    assert _run_ca_block(root).returncode == 0
    shutil.copyfile(certificates / "rotated.crt", root / "source.pem")
    if bound_destination:
        # Linux binds the current host CA at the destination before boot.
        shutil.copyfile(root / "source.pem", root / "local/safeyolo.crt")
    result = _run_ca_block(root)

    assert result.returncode == 0, result.stderr
    assert (root / "updates").read_text() == "refresh\n"
    _assert_trust(root, certificates, "system", "rotated", rejected="instance")


@pytest.mark.parametrize("bound_destination", [False, True], ids=["copied", "read-only-bind"])
@pytest.mark.parametrize("interrupted", [False, True], ids=["failed-update", "interrupted-removal"])
def test_retained_rotation_retries_after_incomplete_repair(
    trust_store, certificates, bound_destination, interrupted,
):
    root = trust_store
    assert _run_ca_block(root).returncode == 0
    retained = (root / "store/ca-certificates.crt").read_bytes()
    shutil.copyfile(certificates / "rotated.crt", root / "source.pem")
    if bound_destination:
        shutil.copyfile(root / "source.pem", root / "local/safeyolo.crt")
    if interrupted:
        result = _run_ca_block(root, interrupt_alias_removal=True)
        assert result.returncode == -signal.SIGKILL
        assert not (root / "updates").exists()
    else:
        (root / "update-fails").touch()
        result = _run_ca_block(root)
        assert result.returncode == 0, result.stderr
        assert "WARNING: update-ca-certificates failed" in (root / "console").read_text()
        (root / "update-fails").unlink()
    assert not (root / "store/safeyolo.pem").exists()
    assert (root / "store/ca-certificates.crt").read_bytes() == retained
    assert (root / "store/.safeyolo-ca-repair-needed").exists()

    result = _run_ca_block(root)

    assert result.returncode == 0, result.stderr
    _assert_trust(root, certificates, "system", "rotated", rejected="instance")
    assert (root / "updates").read_text().splitlines() == ["refresh"] * (1 if interrupted else 2)
    assert not (root / "store/.safeyolo-ca-repair-needed").exists()


def test_repair_state_failure_preserves_retained_entry(trust_store, certificates):
    root = trust_store
    assert _run_ca_block(root).returncode == 0
    retained = (root / "store/ca-certificates.crt").read_bytes()
    marker = root / "store/.safeyolo-ca-repair-needed"
    marker.symlink_to(root / "absent/marker")
    shutil.copyfile(certificates / "rotated.crt", root / "source.pem")
    result = _run_ca_block(root)

    assert result.returncode != 0
    assert (root / "store/safeyolo.pem").is_symlink()
    assert (root / "store/ca-certificates.crt").read_bytes() == retained
    assert not (root / "updates").exists()
    marker.unlink()
    assert _run_ca_block(root).returncode == 0
    _assert_trust(root, certificates, "system", "rotated", rejected="instance")


def test_new_image_or_configuration_rebuilds_retained_trust(trust_store, certificates):
    root = trust_store
    assert _run_ca_block(root).returncode == 0
    shutil.copyfile(certificates / "rotated.crt", root / "system/system.crt")
    result = _run_ca_block(root)

    assert result.returncode == 0, result.stderr
    assert (root / "updates").read_text() == "refresh\n"
    _assert_trust(root, certificates, "rotated", "instance", rejected="system")


@pytest.mark.parametrize("missing", ["local/safeyolo.crt", "store/ca-certificates.crt", "empty-bundle"])
def test_boot_repairs_missing_trust_files(trust_store, certificates, missing):
    root = trust_store
    if missing == "empty-bundle":
        (root / "store/ca-certificates.crt").write_bytes(b"")
    else:
        (root / missing).unlink()
    result = _run_ca_block(root)

    assert result.returncode == 0, result.stderr
    _assert_trust(root, certificates, "system", "instance")
    assert (root / "updates").exists() == (missing != "local/safeyolo.crt")


@pytest.mark.parametrize("dangling", [False, True], ids=["incomplete-index", "dangling"])
def test_boot_repairs_incomplete_instance_entry(trust_store, certificates, dangling):
    root = trust_store
    target = root / ("absent.crt" if dangling else "local/safeyolo.crt")
    (root / "store/safeyolo.pem").symlink_to(target)
    result = _run_ca_block(root)

    assert result.returncode == 0, result.stderr
    assert (root / "updates").read_text() == "refresh\n"
    _assert_trust(root, certificates, "system", "instance")


def test_custom_update_hook_keeps_distro_path(trust_store, certificates):
    root = trust_store
    hook = root / "hooks/custom-trust"
    hook.write_text('#!/bin/sh\ncat > "$TEST_ROOT/hook-input"\n')
    hook.chmod(0o755)
    result = _run_ca_block(root)

    assert result.returncode == 0, result.stderr
    assert (root / "updates").read_text() == "refresh\n"
    assert f'+{root}/store/safeyolo.pem' in (root / "hook-input").read_text()
    _assert_trust(root, certificates, "system", "instance")


def test_other_distros_keep_existing_updater(trust_store, certificates):
    root = trust_store
    (root / "debian_version").unlink()
    result = _run_ca_block(root)

    assert result.returncode == 0, result.stderr
    assert (root / "updates").read_text() == "refresh\n"
    _assert_trust(root, certificates, "system", "instance")


def test_failed_index_falls_back_to_distro_repair(trust_store, certificates):
    root = trust_store
    (root / "rehash-fails-once").touch()
    result = _run_ca_block(root)

    assert result.returncode == 0, result.stderr
    assert (root / "updates").read_text() == "refresh\n"
    assert not list((root / "store").glob("ca-certificates.crt.*"))
    _assert_trust(root, certificates, "system", "instance")


def test_failed_update_warns_and_next_boot_repairs(trust_store, certificates):
    root = trust_store
    (root / "rehash-fails-once").touch()
    (root / "update-fails").touch()
    prepared = (root / "store/ca-certificates.crt").read_bytes()
    result = _run_ca_block(root)

    assert result.returncode == 0, result.stderr
    assert "WARNING: update-ca-certificates failed" in (root / "console").read_text()
    assert (root / "store/ca-certificates.crt").read_bytes() == prepared
    assert not list((root / "store").glob("ca-certificates.crt.*"))
    assert not (root / "store/safeyolo.pem").exists()
    assert (root / "store/.safeyolo-ca-repair-needed").exists()
    (root / "update-fails").unlink()
    assert _run_ca_block(root).returncode == 0
    assert (root / "updates").read_text().splitlines() == ["refresh", "refresh"]
    assert not (root / "store/.safeyolo-ca-repair-needed").exists()
    _assert_trust(root, certificates, "system", "instance")


def test_failed_certificate_read_does_not_commit_partial_bundle(trust_store, certificates):
    root = trust_store
    (root / "update-fails").touch()
    prepared = (root / "store/ca-certificates.crt").read_bytes()
    result = _run_ca_block(root, fail_certificate_read=True)

    assert result.returncode == 0, result.stderr
    assert (root / "store/ca-certificates.crt").read_bytes() == prepared
    assert not list((root / "store").glob("ca-certificates.crt.*"))
    assert "WARNING: update-ca-certificates failed" in (root / "console").read_text()
    (root / "update-fails").unlink()
    assert _run_ca_block(root).returncode == 0
    _assert_trust(root, certificates, "system", "instance")


def test_boot_without_instance_ca_leaves_store_unchanged(trust_store):
    root = trust_store
    (root / "source.pem").unlink()
    prepared = (root / "store/ca-certificates.crt").read_bytes()
    result = _run_ca_block(root)

    assert result.returncode == 0, result.stderr
    assert (root / "store/ca-certificates.crt").read_bytes() == prepared
    assert not (root / "updates").exists()
    assert not (root / "store/safeyolo.pem").exists()


def _assert_trust(root, certificates, *trusted, rejected="untrusted"):
    for ca, expected in [*((name, 0) for name in trusted), (rejected, 2)]:
        for option, path in (("-CAfile", root / "store/ca-certificates.crt"),
                             ("-CApath", root / "store")):
            result = subprocess.run(
                [OPENSSL, "verify", "-no-CAfile", "-no-CApath", "-no-CAstore",
                 option, str(path), str(certificates / f"{ca}.crt")],
                capture_output=True, text=True, timeout=10,
            )
            assert result.returncode == expected, result.stdout + result.stderr


def _environment(root):
    return os.environ | {
        "PATH": f"{root / 'bin'}:{os.environ['PATH']}",
        "TEST_ROOT": str(root), "TEST_UPDATER": UPDATER, "TEST_OPENSSL": OPENSSL,
    }


def _run_ca_block(root, *, fail_certificate_read=False, interrupt_alias_removal=False):
    text = (REPO_ROOT / "cli/src/safeyolo/guest-init-static.sh").read_text()
    block = text[text.index("SY_CERT_SRC="):text.index("# 4. SSH server")]
    for source, destination in (
        ("/safeyolo/mitmproxy-ca-cert.pem", root / "source.pem"),
        ("/usr/local/share/ca-certificates/safeyolo.crt", root / "local/safeyolo.crt"),
        ("/etc/ssl/certs", root / "store"),
        ("/etc/debian_version", root / "debian_version"),
        ("/etc/ca-certificates/update.d", root / "hooks"),
        ("/dev/console", root / "console"),
    ):
        block = block.replace(source, str(destination))
    # An unchanged destination can be a read-only bind mount. Catch attempts
    # to rewrite it even when fixture ownership would allow the write.
    command = (
        'install() { cmp -s "$SY_CERT_SRC" "$SY_CERT_DST" && exit 91; '
        'command install "$@"; };\n'
    )
    if fail_certificate_read:
        command += 'cat() { [ "$1" != "$SY_CERT_DST" ] && command cat "$@"; };\n'
    if interrupt_alias_removal:
        command += (
            'rm() { command rm "$@"; '
            'if [ "$2" = "$SY_PEM" ]; then kill -KILL "$$"; fi; };\n'
        )
    return subprocess.run(
        ["/bin/bash", "-ec", command + block], env=_environment(root),
        capture_output=True, text=True, timeout=10,
    )
