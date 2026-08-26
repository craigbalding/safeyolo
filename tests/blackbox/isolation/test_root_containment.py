"""Guest-root capability and containment tests.

These tests are invoked through ``safeyolo agent shell --root``. Guest root is
an intentional SafeYolo feature for package installation and repair; the
security property is that this privilege stops at the gVisor or microVM
boundary.
"""

import os
import shutil
import socket
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import pytest


def _is_gvisor() -> bool:
    """Return whether the current guest is a gVisor sandbox."""
    try:
        result = subprocess.run(
            ["dmesg"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return "Starting gVisor" in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


class TestGuestRootCapability:
    """Guest root is available and useful inside the isolated environment.

    Why: Agents need to install distro packages and repair their own guest
    environment. A test suite which only proves non-root operation can miss a
    broken sudo/root path even though that path is a supported feature.
    """

    def test_root_shell_has_uid_zero(self):
        """The operator-selected root shell really runs as guest UID 0.

        What: Read the effective and real process UIDs and require both to be
        zero when the suite is launched with ``agent shell --root``.
        Why: Merely accepting the CLI flag is not useful acceptance evidence;
        package installation and guest repair require actual guest-root
        privileges.
        """
        assert os.getuid() == 0, f"Expected guest UID 0, got {os.getuid()}"
        assert os.geteuid() == 0, f"Expected guest EUID 0, got {os.geteuid()}"

    def test_root_can_install_local_apt_package(self):
        """Guest root can install and remove a local package with apt/dpkg.

        What: Build a minimal local Debian package, install it through apt,
        verify its payload under /usr/local, then purge it without network
        downloads.
        Why: This exercises the filesystem overlay and package database that
        real ``apt`` installs depend on, while keeping acceptance deterministic
        and independent of an external mirror.
        """
        required = ("apt-get", "dpkg", "dpkg-deb")
        missing = [binary for binary in required if shutil.which(binary) is None]
        assert not missing, (
            f"Default guest is missing package tools required for the root acceptance probe: {', '.join(missing)}"
        )

        package = "safeyolo-blackbox-root-smoke"
        payload = Path("/usr/local/share/safeyolo-blackbox/root-capability")
        with tempfile.TemporaryDirectory(prefix="safeyolo-root-pkg-") as tmp:
            build_root = Path(tmp) / package
            control_dir = build_root / "DEBIAN"
            staged_payload = build_root / payload.relative_to("/")
            control_dir.mkdir(parents=True)
            staged_payload.parent.mkdir(parents=True)
            (control_dir / "control").write_text(
                "\n".join(
                    (
                        f"Package: {package}",
                        "Version: 1.0",
                        "Architecture: all",
                        "Maintainer: SafeYolo blackbox",
                        "Description: guest-root acceptance probe",
                        "",
                    )
                )
            )
            staged_payload.write_text("guest root can install packages\n")
            deb = Path(tmp) / f"{package}.deb"

            built = subprocess.run(
                ["dpkg-deb", "--build", str(build_root), str(deb)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            assert built.returncode == 0, built.stderr

            installed = subprocess.run(
                [
                    "apt-get",
                    "install",
                    "-y",
                    "--no-install-recommends",
                    str(deb),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
            )
            try:
                assert installed.returncode == 0, installed.stderr
                assert payload.read_text() == "guest root can install packages\n"
            finally:
                subprocess.run(
                    ["dpkg", "--purge", package],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )


class TestGuestRootContainment:
    """Guest root cannot cross the SafeYolo isolation boundary.

    Why: UID 0 is intentionally powerful inside the guest. It must still be
    unable to bypass proxy-only egress, reach host listeners, modify the
    host-backed SafeYolo share, or access a host virtualization device.
    """

    def test_root_direct_egress_blocked(self):
        """Guest root cannot bypass the proxy with a direct connection.

        What: Use curl with all proxy handling disabled against a public IP
        and require the connection to fail.
        Why: Package-management privilege must not also grant an unobserved
        network path around SafeYolo's policy and credential controls.
        """
        result = subprocess.run(
            [
                "curl",
                "-s",
                "--noproxy",
                "*",
                "--connect-timeout",
                "3",
                "-o",
                "/dev/null",
                "http://1.1.1.1",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode != 0, "Guest root reached 1.1.1.1 directly"

    def test_root_proxy_path_works(self):
        """Guest root retains the authorised proxy egress path.

        What: Send an HTTP request through HTTP_PROXY to the allowlisted test
        host and require a 200 response.
        Why: A direct-egress failure is only meaningful when the intended
        proxy path is a working positive control for the same root process.
        """
        proxy = os.environ.get("HTTP_PROXY", "")
        assert proxy, "HTTP_PROXY not set in guest-root shell"
        result = subprocess.run(
            [
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--proxy",
                proxy,
                "-H",
                "X-SafeYolo-Test-Context: run=root-isolation;agent=bbtest",
                "http://httpbin.org/get",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.stdout.strip() == "200", (
            f"Guest-root proxy request failed: rc={result.returncode} stderr={result.stderr}"
        )

    def test_root_cannot_reach_live_host_listener(self):
        """Guest root cannot connect to a known-live host TCP service.

        What: Read the harness listener port from the read-only config share
        and attempt a direct TCP connection to the host address.
        Why: Testing a live listener distinguishes real host isolation from a
        connection failure caused only by choosing an unused port.
        """
        marker = Path("/safeyolo/host-listener-port")
        if not marker.exists():
            pytest.skip("Host-listener marker not provided by harness")
        proxy = os.environ.get("HTTP_PROXY", "")
        host = urlparse(proxy).hostname
        if not host:
            pytest.skip(f"Could not derive host endpoint from {proxy!r}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            with pytest.raises((TimeoutError, ConnectionRefusedError, OSError)):
                sock.connect((host, int(marker.read_text().strip())))
        finally:
            sock.close()

    def test_root_cannot_modify_host_config_share(self):
        """Guest root cannot write the host-backed SafeYolo config share.

        What: Attempt to create a probe beneath /safeyolo and require an
        operating-system error with no file left behind.
        Why: A writable share would let a root package maintainer script
        mutate host-side proxy or agent configuration across the boundary.
        """
        probe = Path("/safeyolo/guest-root-write-probe")
        with pytest.raises(OSError):
            probe.write_text("boundary failure\n")
        assert not probe.exists(), f"Guest root created host-share file {probe}"

    def test_gvisor_root_cannot_access_host_kvm_device(self):
        """The host KVM device is not exposed inside a gVisor sandbox.

        What: In a gVisor lane, assert /dev/kvm is absent even in a
        guest-root shell; hardware microVMs use their own device boundary.
        Why: The Linux KVM lane gives gVisor's sentry host-side access to KVM;
        passing that device through to the agent would expose a powerful host
        virtualization interface outside the intended boundary.
        """
        if not _is_gvisor():
            pytest.skip("Host /dev/kvm passthrough probe applies to gVisor")
        assert not Path("/dev/kvm").exists(), "/dev/kvm exposed to guest root"
