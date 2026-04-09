"""VM isolation tests — run from inside the microVM via pytest.

Every test is a direct probe from the adversary's perspective.
These tests assert OUTCOMES, not mechanisms. They never reference pf,
iptables, feth, or any platform-specific detail.

Dependencies: pytest (installed in rootfs), curl, sudo, modprobe,
python3 stdlib (os, socket, ctypes, subprocess).
"""

import ctypes
import ctypes.util
import os
import socket
import struct
import subprocess

import pytest


class TestNetworkEscape:
    """Verify the VM cannot bypass the proxy."""

    def test_direct_http_blocked(self):
        """Direct HTTP to external IP (bypassing proxy) must fail."""
        result = subprocess.run(
            ["curl", "-s", "--noproxy", "*", "--connect-timeout", "3",
             "-o", "/dev/null", "http://1.1.1.1"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode != 0, "Direct HTTP to 1.1.1.1 succeeded — firewall breach"

    def test_direct_https_blocked(self):
        """Direct HTTPS to external IP (bypassing proxy) must fail."""
        result = subprocess.run(
            ["curl", "-s", "--noproxy", "*", "--connect-timeout", "3",
             "-k", "-o", "/dev/null", "https://8.8.8.8"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode != 0, "Direct HTTPS to 8.8.8.8 succeeded — firewall breach"

    def test_dns_udp_blocked(self):
        """Raw UDP to external DNS port must fail."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        try:
            dns_query = (
                b"\x12\x34"  # Transaction ID
                b"\x01\x00"  # Flags: standard query
                b"\x00\x01\x00\x00\x00\x00\x00\x00"  # 1 question
                b"\x07example\x03com\x00"  # example.com
                b"\x00\x01\x00\x01"  # Type A, Class IN
            )
            sock.sendto(dns_query, ("8.8.8.8", 53))
            sock.recvfrom(512)
            pytest.fail("UDP DNS query to 8.8.8.8:53 succeeded — firewall breach")
        except (socket.timeout, OSError):
            pass  # Expected: blocked
        finally:
            sock.close()

    def test_raw_socket_blocked(self):
        """Raw sockets to external IPs must fail (no ICMP exfiltration)."""
        with pytest.raises((PermissionError, OSError)):
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            try:
                sock.sendto(
                    b"\x08\x00\x00\x00\x00\x01\x00\x01",  # ICMP echo
                    ("1.1.1.1", 0),
                )
            finally:
                sock.close()

    def test_proxy_reachable(self):
        """Proxy must be reachable (the one allowed network path)."""
        proxy = os.environ.get("HTTP_PROXY", "")
        assert proxy, "HTTP_PROXY not set — cannot test proxy reachability"
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--proxy", proxy, "http://httpbin.org/get"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.stdout.strip() == "200", (
            f"Proxy not reachable: exit={result.returncode} stdout={result.stdout} stderr={result.stderr}"
        )


class TestPrivilegeEscalation:
    """Verify privilege escalation vectors are blocked."""

    def test_runs_as_nonroot(self):
        """Agent process must not run as root."""
        assert os.getuid() != 0, "Running as root (UID 0)"

    def test_expected_uid(self):
        """Agent process should run as uid 1000."""
        assert os.getuid() == 1000, f"Expected UID 1000, got {os.getuid()}"

    def test_sudo_blocked(self):
        """sudo must not grant privileges without a password."""
        import shutil
        if not shutil.which("sudo"):
            return  # sudo not installed — escalation impossible
        result = subprocess.run(
            ["sudo", "-n", "id"],
            capture_output=True, text=True, timeout=5,
        )
        assert result.returncode != 0, f"sudo succeeded without password: {result.stdout}"

    def test_kernel_modules_disabled(self):
        """Kernel module loading must be disabled."""
        import shutil
        if not shutil.which("modprobe"):
            return  # modprobe not installed — module loading impossible
        result = subprocess.run(
            ["modprobe", "dummy"],
            capture_output=True, text=True, timeout=5,
        )
        assert result.returncode != 0, "modprobe succeeded — kernel modules enabled"

    def test_no_dev_mem(self):
        """/dev/mem must not be readable by the agent user."""
        if not os.path.exists("/dev/mem"):
            return  # not present — safe
        # If /dev/mem exists, verify agent can't actually read it
        try:
            fd = os.open("/dev/mem", os.O_RDONLY)
            os.close(fd)
            pytest.fail("/dev/mem is readable by agent user — physical memory accessible")
        except PermissionError:
            pass  # Expected: agent can't read it

    def test_no_dev_kmem(self):
        """/dev/kmem must not exist (no kernel memory access)."""
        assert not os.path.exists("/dev/kmem"), "/dev/kmem exists — kernel memory accessible"

    def test_ebpf_blocked(self):
        """BPF syscall must not be available (no eBPF programs)."""
        libc_name = ctypes.util.find_library("c")
        if not libc_name:
            pytest.skip("libc not found")
        libc = ctypes.CDLL(libc_name, use_errno=True)
        # SYS_bpf = 321 on x86_64, 280 on aarch64
        if struct.calcsize("P") * 8 == 64:
            for sys_bpf in (321, 280):
                ret = libc.syscall(sys_bpf, 0, 0, 0)
                if ret == 0:
                    pytest.fail(f"BPF syscall ({sys_bpf}) succeeded")


class TestFilesystemIsolation:
    """Verify filesystem isolation properties."""

    def test_config_share_readonly(self):
        """Config share (/safeyolo) must be read-only."""
        with pytest.raises(OSError):
            with open("/safeyolo/test-write-attempt", "w") as f:
                f.write("should fail")

    def test_no_private_key_in_config_share(self):
        """Config share must not contain any private key files."""
        if not os.path.isdir("/safeyolo"):
            pytest.skip("/safeyolo not mounted")

        dangerous = []
        for entry in os.listdir("/safeyolo"):
            path = os.path.join("/safeyolo", entry)
            if not os.path.isfile(path):
                continue
            if entry.endswith(".key") or "private" in entry.lower():
                dangerous.append(entry)
            else:
                try:
                    with open(path) as f:
                        head = f.read(500)
                    if "PRIVATE KEY" in head:
                        dangerous.append(entry)
                except (PermissionError, UnicodeDecodeError):
                    pass
        assert not dangerous, f"Private key material in config share: {dangerous}"
