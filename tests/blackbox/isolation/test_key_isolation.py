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
    """Public CA cert is installed in the agent's trust store.

    Why: The agent validates HTTPS traffic against this CA. Without
    it, every HTTPS request through the proxy fails with certificate
    errors and the agent can't do useful work — or it's tempted to
    use --insecure flags that undermine interception security.
    """

    def test_public_cert_exists(self):
        """Public CA cert file is present in /usr/local/share/ca-certificates.

        What: Check `PUBLIC_CERT.exists()` for safeyolo.crt.
        Why: Missing file means update-ca-certificates never added
        it — the agent can't verify proxy-signed certs.
        """
        assert PUBLIC_CERT.exists(), (
            f"Public CA cert not found at {PUBLIC_CERT}"
        )

    def test_public_cert_readable(self):
        """Public CA cert file is readable and contains a PEM certificate.

        What: Read safeyolo.crt; assert contents include 'BEGIN
        CERTIFICATE'.
        Why: A zero-byte or non-PEM file would pass the existence
        check but still break TLS. Confirms the file is actually a
        usable cert, not a stub.
        """
        content = PUBLIC_CERT.read_text()
        assert "BEGIN CERTIFICATE" in content, (
            "Certificate file does not contain a valid PEM certificate"
        )

    def test_public_cert_has_no_private_key(self):
        """Public CA cert file contains no PRIVATE KEY block.

        What: Read safeyolo.crt; assert 'PRIVATE KEY' is not in
        the content.
        Why: If the install script accidentally concatenates the
        public cert with the private key, shipping both to every
        sandbox, the agent has root of trust on arbitrary domains —
        complete interception bypass.
        """
        content = PUBLIC_CERT.read_text()
        assert "PRIVATE KEY" not in content, (
            f"SECURITY FAILURE: Private key found in {PUBLIC_CERT}"
        )


class TestPrivateKeyAbsent:
    """CA private key never enters the sandbox, anywhere.

    Why: The CA private key is the root of trust for mitmproxy's
    TLS interception. An agent that obtains it can sign certificates
    for any domain and impersonate any service — defeating every
    network/credential guard that depends on TLS inspection. This
    class probes multiple filesystem locations from the adversary's
    perspective to prove the key is structurally absent.
    """

    def test_no_key_files_in_cert_store(self):
        """No .key files in /usr/local/share/ca-certificates.

        What: List the trust store dir; assert no file has suffix .key.
        Why: The trust store is the obvious place to accidentally
        drop a private key alongside its cert. A .key file here is
        the simplest possible leak pattern.
        """
        if not CERT_TRUST_STORE.is_dir():
            pytest.skip("Trust store not present")

        key_files = [f.name for f in CERT_TRUST_STORE.iterdir() if f.suffix == ".key"]
        assert not key_files, (
            f"Private key files in trust store: {key_files}"
        )

    def test_no_key_files_in_config_share(self):
        """No .key files in /safeyolo (the config share).

        What: List files in /safeyolo; assert no .key suffix.
        Why: The config share is mounted from the host and could
        accidentally include key material if prepare_config_share
        is too greedy about what it copies.
        """
        if not CONFIG_SHARE.is_dir():
            pytest.skip("Config share not mounted")

        key_files = [f.name for f in CONFIG_SHARE.iterdir()
                     if f.is_file() and f.suffix == ".key"]
        assert not key_files, (
            f"Private key files in config share: {key_files}"
        )

    def test_no_private_key_content_in_pem_files(self):
        """No .pem/.crt file in cert directories contains PRIVATE KEY.

        What: Walk the trust store, config share, and /etc/ssl/certs;
        read every .pem/.crt; assert none contain 'PRIVATE KEY'.
        Why: Catches the naming-convention dodge — even if the file
        is called .crt (public), it could carry private key content.
        Tests the content, not the name.
        """
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
        """Whole-filesystem scan finds no PRIVATE KEY content.

        What: os.walk from / (skipping /proc, /sys, /dev, /run and
        third-party site-packages); read the first 1 KiB of each
        regular file; assert 'PRIVATE KEY' doesn't appear.
        Why: The targeted tests above check known-critical paths.
        This is the catch-all: if the key leaked to a surprising
        location (/tmp, /var/log, an agent workspace subdir), the
        targeted tests would miss it but this scan would catch it.
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
