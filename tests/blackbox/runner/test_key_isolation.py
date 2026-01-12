"""
Black box tests for private CA key isolation.

The private CA key is the crown jewel of SafeYolo's security model.
If an agent obtains the private key, they can:
- Sign their own certificates for any domain
- MITM their own connections without SafeYolo detecting it
- Completely bypass all proxy inspection

These tests verify that:
1. The public CA volume contains ONLY the public certificate
2. The private key is NOT accessible in the public volume
3. The public cert is readable and valid

The key-isolation-verifier container writes results to JSON for test assertions.
Additionally, this test file performs Python-based verification using the
mounted /certs-public volume.

NOTE: These tests only run when using the security overlay:
  docker compose -f docker-compose.yml -f docker-compose.security.yml up
"""

import json
from pathlib import Path

import pytest


# Path to key isolation test results (from key-isolation-verifier container)
KEY_ISOLATION_RESULTS_PATH = Path("/security-results/key-isolation.json")

# Path to public CA volume (mounted in test-runner for additional validation)
CERTS_PUBLIC_PATH = Path("/certs-public")


@pytest.fixture(scope="module")
def key_isolation_results():
    """Load key isolation test JSON results from verifier."""
    if not KEY_ISOLATION_RESULTS_PATH.exists():
        pytest.skip(
            "Key isolation results not found - run with security overlay: "
            "docker compose -f docker-compose.yml -f docker-compose.security.yml up"
        )

    content = KEY_ISOLATION_RESULTS_PATH.read_text()
    return json.loads(content)


class TestPrivateKeyIsolation:
    """Verify private CA key is not accessible outside safeyolo container."""

    def test_public_cert_exists(self, key_isolation_results):
        """Public CA certificate must exist for agents to trust.

        Agents need the public CA cert to trust the proxy's certificates.
        """
        assert key_isolation_results["public_cert_exists"], (
            "Public CA certificate missing from public volume! "
            "Agents won't be able to trust the proxy."
        )

    def test_no_private_key_file_in_public_volume(self, key_isolation_results):
        """Private key file must NOT exist in public CA volume.

        CRITICAL: The public volume should only contain the public certificate.
        Files like mitmproxy-ca.pem (without -cert) or *.key indicate a leak.
        """
        assert not key_isolation_results["private_key_in_public_volume"], (
            "SECURITY FAILURE: Private key file found in public volume! "
            "Agents can steal the CA private key."
        )

    def test_public_cert_is_readable(self, key_isolation_results):
        """Public CA cert must be readable by agents.

        The cert needs to be accessible so agents can add it to their
        trust store.
        """
        assert key_isolation_results["public_cert_readable"], (
            "Public CA certificate is not readable! "
            "Check permissions on the public CA volume."
        )

    def test_no_private_key_in_cert_content(self, key_isolation_results):
        """Public cert file must NOT contain private key material.

        Some misconfigurations bundle the private key with the cert.
        The public cert file should contain ONLY the certificate.
        """
        assert not key_isolation_results["private_key_in_cert_content"], (
            "SECURITY FAILURE: Private key found in certificate file! "
            "The public cert file contains private key material."
        )

    def test_all_key_isolation_checks_passed(self, key_isolation_results):
        """Overall key isolation must be properly configured."""
        assert key_isolation_results["all_passed"], (
            "SECURITY FAILURE: Key isolation is incomplete. "
            "Review individual test failures for details."
        )


class TestPublicVolumeDirectAccess:
    """Additional Python-based validation of the mounted public CA volume.

    These tests directly inspect the /certs-public volume mounted in the
    test-runner container, providing defense-in-depth verification beyond
    what the shell-based verifier checks.
    """

    @pytest.fixture(scope="class")
    def public_volume_available(self):
        """Check if public CA volume is mounted."""
        if not CERTS_PUBLIC_PATH.exists():
            pytest.skip(
                "Public CA volume not mounted - run with security overlay"
            )
        return True

    def test_public_volume_has_no_key_files(self, public_volume_available):
        """Verify no private key files exist via direct directory scan."""
        dangerous_patterns = [".key", "private", "mitmproxy-ca.pem"]

        for filepath in CERTS_PUBLIC_PATH.iterdir():
            filename = filepath.name.lower()

            # Skip files that explicitly have "cert" in the name
            if "cert" in filename:
                continue

            for pattern in dangerous_patterns:
                if pattern in filename:
                    pytest.fail(
                        f"SECURITY FAILURE: Suspicious file '{filepath.name}' "
                        f"in public CA volume! Pattern '{pattern}' suggests private key."
                    )

    def test_cert_file_contains_only_certificate(self, public_volume_available):
        """Verify cert files contain certificate, not private key."""
        for filepath in CERTS_PUBLIC_PATH.iterdir():
            if not filepath.is_file():
                continue

            try:
                content = filepath.read_text()
            except (PermissionError, UnicodeDecodeError):
                continue

            if "PRIVATE KEY" in content:
                pytest.fail(
                    f"SECURITY FAILURE: File '{filepath.name}' contains "
                    f"private key material! This is a critical key leak."
                )

    def test_at_least_one_certificate_present(self, public_volume_available):
        """Verify at least one valid certificate exists."""
        found_cert = False

        for filepath in CERTS_PUBLIC_PATH.iterdir():
            if not filepath.is_file():
                continue

            try:
                content = filepath.read_text()
                if "BEGIN CERTIFICATE" in content:
                    found_cert = True
                    break
            except (PermissionError, UnicodeDecodeError):
                continue

        assert found_cert, (
            "No valid certificate found in public CA volume! "
            "Agents won't be able to trust the proxy."
        )
