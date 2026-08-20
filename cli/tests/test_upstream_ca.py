"""Tests for persistent additional upstream CA configuration."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from safeyolo.cli import app


@pytest.fixture
def ca_bundle(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Upstream CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    bundle = tmp_path / "additional-ca.pem"
    bundle.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return bundle


def test_set_persists_absolute_bundle_path(cli_runner, tmp_config_dir, ca_bundle):
    bundle = ca_bundle

    with patch("safeyolo.commands.proxy.is_proxy_running", return_value=False):
        result = cli_runner.invoke(app, ["proxy", "upstream-ca", "set", str(bundle)])

    assert result.exit_code == 0
    assert "Applies on next SafeYolo start" in result.output
    config = yaml.safe_load((tmp_config_dir / "config.yaml").read_text())
    assert config["proxy"]["upstream_ca_cert"] == str(bundle.resolve())


def test_set_requires_restart_when_proxy_is_running(
    cli_runner, tmp_config_dir, ca_bundle
):
    bundle = ca_bundle

    with patch("safeyolo.commands.proxy.is_proxy_running", return_value=True):
        result = cli_runner.invoke(app, ["proxy", "upstream-ca", "set", str(bundle)])

    assert result.exit_code == 0
    assert "Restart SafeYolo" in result.output


def test_set_rejects_missing_bundle(cli_runner, tmp_config_dir, tmp_path):
    result = cli_runner.invoke(
        app,
        ["proxy", "upstream-ca", "set", str(tmp_path / "missing.pem")],
    )

    assert result.exit_code == 2
    assert "CA bundle not found" in result.output


def test_set_rejects_bundle_containing_private_key(
    cli_runner, tmp_config_dir, tmp_path
):
    bundle = tmp_path / "unsafe.pem"
    bundle.write_text(
        "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n"
        "-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----\n"
    )

    result = cli_runner.invoke(app, ["proxy", "upstream-ca", "set", str(bundle)])

    assert result.exit_code == 2
    assert "must not contain a private key" in result.output


def test_remove_clears_persistent_bundle(cli_runner, tmp_config_dir, tmp_path):
    config_path = tmp_config_dir / "config.yaml"
    config = yaml.safe_load(config_path.read_text())
    config["proxy"]["upstream_ca_cert"] = str(tmp_path / "additional-ca.pem")
    config_path.write_text(yaml.safe_dump(config, sort_keys=False))

    with patch("safeyolo.commands.proxy.is_proxy_running", return_value=False):
        result = cli_runner.invoke(app, ["proxy", "upstream-ca", "remove"])

    assert result.exit_code == 0
    config = yaml.safe_load(config_path.read_text())
    assert config["proxy"]["upstream_ca_cert"] == ""


def test_show_marks_environment_override_as_transient(
    cli_runner, tmp_config_dir, monkeypatch
):
    monkeypatch.setenv("SAFEYOLO_CA_CERT", "/tmp/transient-ca.pem")

    result = cli_runner.invoke(app, ["proxy", "upstream-ca", "show"])

    assert result.exit_code == 0
    assert "not configured" in result.output
    assert "/tmp/transient-ca.pem" in result.output
    assert "not persistent" in result.output
