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


class TestHostAdjacentReachability:
    """Verify the sandbox cannot reach the host beyond the proxy.

    The migration from Docker's private bridge to host-level firewall
    rules (iptables on Linux, pf on macOS) introduces the risk of
    "pass by default" leaks: anything the firewall didn't explicitly
    block is reachable. These tests actively probe that — any success
    connecting to a host-side service other than the proxy is a breach.
    """

    @staticmethod
    def _host_ip_from_proxy() -> str:
        proxy = os.environ.get("HTTP_PROXY", "")
        if not proxy:
            pytest.skip("HTTP_PROXY not set")
        from urllib.parse import urlparse
        host = urlparse(proxy).hostname
        if not host:
            pytest.skip(f"Could not parse host from HTTP_PROXY={proxy!r}")
        return host

    def _assert_tcp_unreachable(self, host: str, port: int, context: str) -> None:
        """Attempt TCP connect with short timeout; must fail at network layer.

        A successful connect (even if the handshake is later refused by an
        app-layer auth check) counts as a breach. We assert on the socket
        connect result, not on any response payload — the property we care
        about is that no packet reaches the service's listener socket.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            try:
                sock.connect((host, port))
            except (socket.timeout, ConnectionRefusedError, OSError):
                return  # expected: firewall blocked the connect
            pytest.fail(
                f"TCP connect to {host}:{port} ({context}) succeeded — "
                f"this is a host-reachability breach. The sandbox must only "
                f"reach the proxy."
            )
        finally:
            sock.close()

    def test_admin_api_unreachable(self):
        """SafeYolo admin API (default 9090, test instance 9190) must not be
        reachable from the sandbox. Admin API grants policy/mode control —
        agent reachability would defeat the sandbox.
        """
        host = self._host_ip_from_proxy()
        for port in (9090, 9190):
            self._assert_tcp_unreachable(host, port, f"admin API port {port}")

    def test_host_ssh_unreachable(self):
        """Host SSH (:22) is a realistic reachable service on many Linux
        hosts; it must not be reachable from the sandbox. Lets `agent run`
        on a host that happens to run sshd fail safe instead of exposing it.
        """
        host = self._host_ip_from_proxy()
        self._assert_tcp_unreachable(host, 22, "host SSH")

    def test_arbitrary_host_port_unreachable(self):
        """An unused ephemeral port on the host must be unreachable — proves
        the firewall is block-by-default for host-destined traffic, not
        pass-by-default with a narrow deny list. Uses 44444 (IANA
        unregistered) as a port nothing legitimate is listening on.
        """
        host = self._host_ip_from_proxy()
        self._assert_tcp_unreachable(host, 44444, "arbitrary unused port 44444")

    def test_sinkhole_direct_unreachable(self):
        """Sinkhole ports bind to 0.0.0.0 on the host during test runs, so
        they're a real, listening target. Sandbox traffic to those ports
        must only reach them *via the proxy* (which routes specific
        hostnames there); direct sandbox → host-sinkhole-port connects
        must be firewall-blocked. This is the strongest version of the
        "arbitrary port" check because it can't pass trivially — there
        is definitely something listening.
        """
        host = self._host_ip_from_proxy()
        for port in (18080, 18443, 19999):
            self._assert_tcp_unreachable(host, port, f"sinkhole port {port}")


class TestPrivilegeEscalation:
    """Verify privilege escalation vectors are blocked."""

    def test_runs_as_nonroot(self):
        """Agent process must not run as root."""
        assert os.getuid() != 0, "Running as root (UID 0)"

    def test_expected_uid(self):
        """Agent process should run as uid 1000."""
        assert os.getuid() == 1000, f"Expected UID 1000, got {os.getuid()}"

    def test_cannot_gain_root(self):
        """Agent must not be able to escalate to root."""
        with pytest.raises(PermissionError):
            os.setuid(0)

    def test_kernel_modules_disabled(self):
        """Kernel module loading must be disabled.

        Calls init_module(2) directly. A hardened kernel (CONFIG_MODULES=n)
        or a gVisor sandbox returns a non-success errno; either keeps the
        agent from loading kernel code. We assert only that the syscall
        did not succeed — the specific errno varies by platform
        (ENOSYS on a modules-disabled kernel; EPERM/EACCES on gVisor's
        user-space kernel layer).
        """
        import platform as _platform
        # SYS_init_module is architecture-specific.
        _SYS_INIT_MODULE = {"x86_64": 175, "aarch64": 105}.get(_platform.machine())
        if _SYS_INIT_MODULE is None:
            pytest.skip(f"SYS_init_module number unknown for {_platform.machine()}")
        libc_name = ctypes.util.find_library("c")
        if not libc_name:
            pytest.skip("libc not found")
        libc = ctypes.CDLL(libc_name, use_errno=True)
        ret = libc.syscall(_SYS_INIT_MODULE, None, 0, None)
        err = ctypes.get_errno()
        assert ret == -1, (
            "init_module syscall succeeded — kernel-module loading is not blocked"
        )
        assert err != 0, f"init_module returned -1 with errno=0 (unexpected)"

    def test_no_dev_mem(self):
        """/dev/mem must not exist (no physical memory access)."""
        assert not os.path.exists("/dev/mem"), "/dev/mem exists — physical memory accessible"

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
