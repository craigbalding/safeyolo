"""
Black box tests for runtime security properties.

These tests verify that SafeYolo runs with proper security hardening:
1. Non-root execution (limits blast radius of container compromise)
2. No dangerous Linux capabilities (SYS_ADMIN, NET_ADMIN, etc.)
3. Not running in privileged mode
4. Seccomp filtering enabled

The tests read JSON results from the security-verifier container, which uses
CDK (Container Development Kit) to assess the actual runtime security posture.

See: https://github.com/cdk-team/CDK

NOTE: These tests only run when using the security overlay:
  docker compose -f docker-compose.yml -f docker-compose.security.yml up
"""

import json
from pathlib import Path

import pytest


# Path to CDK evaluation results (mounted from security-verifier container)
CDK_RESULTS_PATH = Path("/security-results/cdk-evaluate.json")


@pytest.fixture(scope="module")
def cdk_results():
    """Load CDK evaluation JSON results."""
    if not CDK_RESULTS_PATH.exists():
        pytest.skip(
            "CDK results not found - run with security overlay: "
            "docker compose -f docker-compose.yml -f docker-compose.security.yml up"
        )

    content = CDK_RESULTS_PATH.read_text()
    return json.loads(content)


class TestNonRootExecution:
    """Verify SafeYolo runs as a non-root user."""

    def test_runs_as_nonroot_uid(self, cdk_results):
        """Container process must not run as UID 0 (root)."""
        uid = cdk_results["uid"]
        assert uid != 0, "SECURITY FAILURE: Container running as root (UID=0)!"

    def test_runs_as_nonroot_gid(self, cdk_results):
        """Container process must not run as GID 0 (root group)."""
        gid = cdk_results["gid"]
        assert gid != 0, "Container running as GID 0 (root group)"


class TestContainerSecurity:
    """Verify container security configuration via CDK evaluation."""

    def test_container_not_privileged(self, cdk_results):
        """Container must not be running in privileged mode.

        Privileged mode grants full host access - this would be a critical
        security failure.
        """
        assert not cdk_results["privileged"], (
            "SECURITY FAILURE: Container running in privileged mode! "
            "This grants full host access."
        )

    def test_no_sys_admin_capability(self, cdk_results):
        """Container must not have SYS_ADMIN capability.

        SYS_ADMIN is the most dangerous capability - it allows:
        - Mounting filesystems
        - Namespace manipulation
        - Various admin operations that enable container escape
        """
        caps = cdk_results["capabilities"]
        assert not caps["has_sys_admin"], (
            "SECURITY FAILURE: Container has SYS_ADMIN capability! "
            "This enables container escape via mount/namespace tricks."
        )

    def test_no_sys_module_capability(self, cdk_results):
        """Container must not have SYS_MODULE capability.

        SYS_MODULE allows loading kernel modules - trivial escape vector.
        """
        caps = cdk_results["capabilities"]
        assert not caps["has_sys_module"], (
            "SECURITY FAILURE: Container has SYS_MODULE capability! "
            "This enables container escape via kernel module loading."
        )

    def test_no_dac_read_search_capability(self, cdk_results):
        """Container must not have DAC_READ_SEARCH capability.

        DAC_READ_SEARCH allows reading any file on the host.
        """
        caps = cdk_results["capabilities"]
        assert not caps["has_dac_read_search"], (
            "SECURITY FAILURE: Container has DAC_READ_SEARCH capability! "
            "This allows reading arbitrary host files."
        )

    def test_seccomp_enabled(self, cdk_results):
        """Container must have seccomp filtering enabled.

        Seccomp restricts available syscalls, reducing attack surface.
        """
        assert not cdk_results["seccomp_disabled"], (
            "SECURITY FAILURE: Seccomp is disabled! "
            "Container has access to all syscalls."
        )


class TestNoExploitableConditions:
    """Verify CDK found no exploitable conditions."""

    def test_no_critical_findings(self, cdk_results):
        """CDK should not report any critical security findings."""
        count = cdk_results["critical_findings_count"]
        assert count == 0, (
            f"SECURITY FAILURE: CDK found {count} critical issue(s). "
            "Check /security-results/cdk-evaluate-raw.txt for details."
        )

    def test_no_docker_socket_mounted(self, cdk_results):
        """Docker socket must not be mounted in container.

        Mounting /var/run/docker.sock allows spawning privileged containers.
        """
        assert not cdk_results["docker_socket_mounted"], (
            "SECURITY FAILURE: Docker socket appears to be mounted! "
            "This allows spawning privileged containers."
        )

    def test_all_security_checks_passed(self, cdk_results):
        """Overall security posture must be acceptable."""
        assert cdk_results["all_passed"], (
            "SECURITY FAILURE: One or more security checks failed. "
            "Review individual test failures for details."
        )
