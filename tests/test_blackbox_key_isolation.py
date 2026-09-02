"""Regression tests for the blackbox private-key scanner."""

import importlib.util
from pathlib import Path

import pytest


def _load_key_isolation():
    module_path = (
        Path(__file__).parent
        / "blackbox"
        / "isolation"
        / "test_key_isolation.py"
    )
    spec = importlib.util.spec_from_file_location(
        "blackbox_key_isolation",
        module_path,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "key_name",
    (
        "ssh_host_ecdsa_key",
        "ssh_host_ed25519_key",
        "ssh_host_rsa_key",
    ),
)
def test_private_key_scanner_allows_expected_sshd_host_keys(tmp_path, key_name):
    key_isolation = _load_key_isolation()
    key_path = tmp_path / "etc" / "ssh" / key_name
    key_path.parent.mkdir(parents=True)
    key_path.write_text("-----BEGIN OPENSSH " + "PRIVATE KEY-----\nfixture\n")

    assert key_isolation._find_unexpected_private_keys(tmp_path) == []


@pytest.mark.parametrize(
    "relative_path",
    (
        "etc/ssh/ssh_host_dsa_key",
        "etc/ssh/ssh_host_ed25519_key.backup",
        "home/agent/.ssh/id_ed25519",
    ),
)
def test_private_key_scanner_rejects_every_other_path(tmp_path, relative_path):
    key_isolation = _load_key_isolation()
    key_path = tmp_path / relative_path
    key_path.parent.mkdir(parents=True)
    key_path.write_text("-----BEGIN OPENSSH " + "PRIVATE KEY-----\nfixture\n")

    assert key_isolation._find_unexpected_private_keys(tmp_path) == [
        f"/{relative_path}"
    ]
