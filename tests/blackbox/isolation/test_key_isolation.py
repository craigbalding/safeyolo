"""Key isolation tests — prove the CA private key never enters the VM.

If an agent obtains the private key, it can sign certificates for any
domain and bypass all proxy inspection. These tests scan the guest
filesystem directly from the adversary's perspective.

No JSON result files, no verifier containers — direct probes only.
"""

import os
from pathlib import Path

import pytest


# Paths where certificates are expected in the guest
CERT_TRUST_STORE = Path("/usr/local/share/ca-certificates")
CONFIG_SHARE = Path("/safeyolo")
PUBLIC_CERT = CERT_TRUST_STORE / "safeyolo.crt"


class TestPublicCertPresent:
    """Verify the public CA cert is installed and usable."""

    def test_public_cert_exists(self):
        """Public CA cert must be installed in the trust store."""
        assert PUBLIC_CERT.exists(), (
            f"Public CA cert not found at {PUBLIC_CERT}"
        )

    def test_public_cert_readable(self):
        """Public CA cert must be readable by the agent user."""
        content = PUBLIC_CERT.read_text()
        assert "BEGIN CERTIFICATE" in content, (
            "Certificate file does not contain a valid PEM certificate"
        )

    def test_public_cert_has_no_private_key(self):
        """Public CA cert must NOT contain private key material."""
        content = PUBLIC_CERT.read_text()
        assert "PRIVATE KEY" not in content, (
            f"SECURITY FAILURE: Private key found in {PUBLIC_CERT}"
        )


class TestPrivateKeyAbsent:
    """Verify the CA private key is not accessible anywhere in the VM."""

    def test_no_key_files_in_cert_store(self):
        """Certificate trust store must not contain .key files."""
        if not CERT_TRUST_STORE.is_dir():
            pytest.skip("Trust store not present")

        key_files = [f.name for f in CERT_TRUST_STORE.iterdir() if f.suffix == ".key"]
        assert not key_files, (
            f"Private key files in trust store: {key_files}"
        )

    def test_no_key_files_in_config_share(self):
        """Config share must not contain .key files."""
        if not CONFIG_SHARE.is_dir():
            pytest.skip("Config share not mounted")

        key_files = [f.name for f in CONFIG_SHARE.iterdir()
                     if f.is_file() and f.suffix == ".key"]
        assert not key_files, (
            f"Private key files in config share: {key_files}"
        )

    def test_no_private_key_content_in_pem_files(self):
        """No .pem or .crt file in the VM should contain PRIVATE KEY."""
        search_dirs = [
            CERT_TRUST_STORE,
            CONFIG_SHARE,
            Path("/etc/ssl/certs"),
        ]
        found = []
        for search_dir in search_dirs:
            if not search_dir.is_dir():
                continue
            for f in search_dir.iterdir():
                if not f.is_file():
                    continue
                if f.suffix not in (".pem", ".crt"):
                    continue
                try:
                    content = f.read_text()
                    if "PRIVATE KEY" in content:
                        found.append(str(f))
                except (PermissionError, UnicodeDecodeError):
                    pass

        assert not found, (
            f"SECURITY FAILURE: Private key material found in: {found}"
        )

    def test_full_filesystem_scan_for_private_keys(self):
        """Deep scan: no SafeYolo-related private key exists anywhere in the VM.

        Walks the entire filesystem (skipping pseudo-filesystems) looking
        for PEM private key markers in SafeYolo-managed locations and any
        .key files. Third-party package test fixtures (e.g. in .venv)
        are excluded — they are not useful for TLS interception.

        The targeted checks above (trust store, config share, cert dirs)
        already cover the critical paths. This scan catches anything that
        leaked to unexpected locations.
        """
        found = []
        for root, dirs, files in os.walk("/"):
            # Skip pseudo-filesystems
            if root.startswith(("/proc", "/sys", "/dev", "/run")):
                dirs.clear()
                continue
            # Skip third-party package directories (contain test fixtures)
            if "site-packages" in root or "dist-packages" in root:
                dirs.clear()
                continue
            for name in files:
                path = os.path.join(root, name)
                try:
                    with open(path) as fh:
                        head = fh.read(1024)
                    if "PRIVATE KEY" in head:
                        found.append(path)
                except (PermissionError, OSError, UnicodeDecodeError):
                    pass

        assert not found, (
            f"SECURITY FAILURE: Private key found in VM: {found}"
        )
