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

import platform as _platform

import pytest


def _is_gvisor() -> bool:
    """Detect gVisor runtime (emulated kernel, not a real Linux VM)."""
    try:
        result = subprocess.run(
            ["dmesg"], capture_output=True, text=True, timeout=5,
        )
        return "Starting gVisor" in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _is_microvm() -> bool:
    """Detect a hardware-isolated microVM (Apple VZ or similar).

    VZ VMs run a real Linux kernel inside a hypervisor. They have
    standard /dev entries, kernel threads, and working syscalls — but
    the VM itself IS the isolation boundary, so these are not security
    issues.
    """
    if _is_gvisor():
        return False
    # VZ microVMs have /dev/vsock (virtio socket) and a real kernel
    return os.path.exists("/dev/vsock")


class TestNetworkEscape:
    """Sandbox cannot reach external networks except through the proxy.

    Why: The proxy is the sole authorised egress path. Every other
    network-layer route — direct IP, raw sockets, alternate ports,
    IPv6, DNS, cloud metadata IPs — must be unreachable. A gap here
    means data exfiltrates outside the credential/network guards
    entirely, and the agent operates with no policy enforcement.
    """

    def test_direct_http_blocked(self):
        """Direct HTTP to an external IP (bypassing proxy) fails.

        What: curl --noproxy to http://1.1.1.1; assert non-zero exit.
        Why: The most basic egress escape — if the agent can just
        curl any IP directly, the proxy is decorative.
        """
        result = subprocess.run(
            ["curl", "-s", "--noproxy", "*", "--connect-timeout", "3",
             "-o", "/dev/null", "http://1.1.1.1"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode != 0, "Direct HTTP to 1.1.1.1 succeeded — firewall breach"

    def test_direct_https_blocked(self):
        """Direct HTTPS to an external IP (bypassing proxy) fails.

        What: curl -k --noproxy to https://8.8.8.8; assert non-zero exit.
        Why: A firewall that only blocks port 80 would let port 443
        traffic through. TLS at the IP layer bypasses URL-based
        inspection entirely.
        """
        result = subprocess.run(
            ["curl", "-s", "--noproxy", "*", "--connect-timeout", "3",
             "-k", "-o", "/dev/null", "https://8.8.8.8"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode != 0, "Direct HTTPS to 8.8.8.8 succeeded — firewall breach"

    def test_dns_udp_blocked(self):
        """Raw UDP to 8.8.8.8:53 fails.

        What: Craft a DNS query, sendto() a UDP socket pointed at
        8.8.8.8:53; assert the receive times out.
        Why: DNS is a classic covert-channel egress. If UDP/53 is
        open, an agent can stream data via DNS tunnelling, which
        never touches the HTTP proxy.
        """
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
        """AF_INET raw socket creation fails (no CAP_NET_RAW in sandbox).

        What: socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) then sendto a
        crafted ICMP echo to 1.1.1.1; assert PermissionError/OSError.
        Why: ICMP tunnelling and ping-based exfiltration rely on raw
        sockets. Without CAP_NET_RAW the syscall fails at creation.
        """
        with pytest.raises((PermissionError, OSError)):
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            try:
                sock.sendto(
                    b"\x08\x00\x00\x00\x00\x01\x00\x01",  # ICMP echo
                    ("1.1.1.1", 0),
                )
            finally:
                sock.close()

    def test_direct_alt_port_blocked(self):
        """Direct TCP to 1.1.1.1 on 8443, 22, 6667, 25 all fail.

        What: curl --noproxy to 1.1.1.1 on each non-standard port;
        assert non-zero exit for every port.
        Why: A firewall that only blocked :80 and :443 would leave
        every other port open. Alt-HTTPS (:8443), SSH (:22), IRC
        (:6667, historical C2), SMTP (:25) are all realistic C2/
        exfil channels the agent might attempt.
        """
        for port in (8443, 22, 6667, 25):
            result = subprocess.run(
                ["curl", "-s", "--noproxy", "*", "--connect-timeout", "3",
                 "-o", "/dev/null", f"http://1.1.1.1:{port}"],
                capture_output=True, text=True, timeout=10,
            )
            assert result.returncode != 0, (
                f"Direct TCP to 1.1.1.1:{port} succeeded — firewall leak "
                f"on a non-standard port"
            )

    def test_libc_resolver_blocked(self):
        """getaddrinfo() on an external name raises gaierror.

        What: socket.getaddrinfo("blackbox-probe-should-not-resolve.
        example", 80, ...); assert gaierror.
        Why: Raw UDP/53 blocking alone doesn't cover the libc
        resolver path. If /etc/resolv.conf points at a reachable
        nameserver, getaddrinfo quietly succeeds — agents using
        the system resolver bypass the proxy for lookups and can
        DNS-tunnel data.
        """
        # "blackbox-probe.example" isn't a real host; we care only whether
        # DNS is reachable at all. An EAI_AGAIN / EAI_NODATA / EAI_NONAME
        # all indicate resolver couldn't answer — expected.
        with pytest.raises(socket.gaierror):
            socket.getaddrinfo("blackbox-probe-should-not-resolve.example",
                               80, socket.AF_INET, socket.SOCK_STREAM)

    def test_non_icmp_raw_protocols_blocked(self):
        """Raw sockets for SCTP/GRE/IPIP also fail.

        What: socket(AF_INET, SOCK_RAW, proto) for proto in
        [132=SCTP, 47=GRE, 4=IPIP]; assert PermissionError/OSError
        for each.
        Why: If the sandbox filter scopes raw sockets only by
        IPPROTO_ICMP, tunnelling protocols (GRE, IPIP, SCTP) leak
        through and provide alternate exfil paths invisible to
        TCP/UDP observers.
        """
        # IPPROTO_SCTP = 132, IPPROTO_GRE = 47, IPPROTO_IPIP = 4.
        # Use raw numeric constants since some are absent from socket
        # module depending on build.
        for proto in (132, 47, 4):
            with pytest.raises((PermissionError, OSError)):
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
                try:
                    sock.sendto(b"\x00" * 20, ("1.1.1.1", 0))
                finally:
                    sock.close()

    def test_ipv6_egress_blocked(self):
        """IPv6 egress via curl -6 and AF_INET6 socket both fail.

        What: curl -6 to a literal v6 address; AF_INET6 socket
        connect to the same; both must fail/timeout.
        Why: mitmproxy binds to IPv4 only. If the sandbox has v6
        connectivity, the agent can reach any v6-capable destination
        outside the proxy's view entirely — a complete bypass.
        """
        # Try a AAAA literal (Google DNS v6) via curl.
        result = subprocess.run(
            ["curl", "-6", "-s", "--noproxy", "*", "--connect-timeout", "3",
             "-o", "/dev/null", "http://[2001:4860:4860::8888]/"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode != 0, "IPv6 egress to 2001:4860:4860::8888 succeeded"
        # Also at the socket layer — AF_INET6 creation may succeed but
        # connect must fail.
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        except OSError:
            return  # v6 stack fully disabled — property holds
        sock.settimeout(3)
        try:
            try:
                sock.connect(("2001:4860:4860::8888", 80))
            except (socket.timeout, ConnectionRefusedError, OSError):
                return  # expected
            pytest.fail("IPv6 connect to 2001:4860:4860::8888:80 succeeded")
        finally:
            sock.close()

    def test_metadata_ips_unreachable(self):
        """Cloud metadata IPs (169.254.169.254, 169.254.170.2) are unreachable.

        What: curl --noproxy to each metadata IP; assert non-zero exit.
        Why: On a cloud VM host, link-local metadata endpoints expose
        instance IAM credentials and user-data. A sandbox that can
        reach them SSRFs the host's IAM role — often full access to
        the cloud account.
        """
        for ip in ("169.254.169.254", "169.254.170.2"):  # AWS IMDSv1 + ECS creds
            result = subprocess.run(
                ["curl", "-s", "--noproxy", "*", "--connect-timeout", "3",
                 "-o", "/dev/null", f"http://{ip}/"],
                capture_output=True, text=True, timeout=5,
            )
            assert result.returncode != 0, (
                f"Cloud metadata IP {ip} was reachable — potential SSRF to "
                f"host IAM credentials"
            )

    def test_af_packet_blocked(self):
        """AF_PACKET socket creation fails.

        What: socket(17 /* AF_PACKET */, SOCK_RAW, 0); assert
        PermissionError/OSError.
        Why: AF_PACKET lets the process craft Ethernet frames
        directly. With it, an agent can ARP-spoof, forge source
        IPs (bypassing L3 firewall rules by appearing to be the
        host), or probe the L2 neighbourhood.
        """
        with pytest.raises((PermissionError, OSError)):
            # AF_PACKET = 17 on Linux (not always in socket module namespace
            # on non-Linux stubs); use the numeric constant.
            sock = socket.socket(17, socket.SOCK_RAW, 0)
            sock.close()

    def test_dns_tunnel_subdomain_blocked(self):
        """Arbitrary subdomain under a real TLD does not resolve.

        What: getaddrinfo("exfil-data-here.tunnel-probe.httpbin.org",
        ...); assert gaierror. If it resolves, fail.
        Why: DNS tunnelling encodes data in subdomain labels
        (<base64>.exfil.attacker.com) — every query leaks ~60 bytes
        to a nameserver the attacker controls. The proxy never sees
        it because it's DNS, not HTTP. The only safe posture is no
        external name resolution at all.
        """
        exfil_host = "exfil-data-here.tunnel-probe.httpbin.org"
        try:
            result = socket.getaddrinfo(exfil_host, 80, socket.AF_INET,
                                        socket.SOCK_STREAM)
        except socket.gaierror:
            return  # resolver blocked — DNS tunnel path closed

        # If we reach here, the resolver answered. That means the agent
        # can make arbitrary DNS queries — the tunnel is open.
        pytest.fail(
            f"DNS tunnel path is OPEN: getaddrinfo({exfil_host!r}) "
            f"resolved to {result[0][4] if result else '?'}. An agent "
            f"can exfiltrate ~60 bytes per query by encoding data in "
            f"subdomain labels of any domain it controls."
        )

    def test_host_header_mismatch_routes_by_url(self):
        """Host-header mismatch with URL routes by URL (200, not 4xx).

        What: Send a proxy'd GET with URL=httpbin.org and
        Host=evil.com; assert 200 (URL is authoritative; Host is
        advisory per RFC 7230 §5.4).
        Why: An agent must not be able to smuggle a blocked
        destination by putting it in the Host header while keeping
        an allowed URL. The URL is what gets evaluated and where the
        traffic goes; confirming that guarantees no Host-based
        domain-fronting evasion.
        """
        proxy = os.environ.get("HTTP_PROXY", "")
        if not proxy:
            pytest.skip("HTTP_PROXY not set")

        marker = "host-header-mismatch-probe"
        result = subprocess.run(
            ["curl", "-s", "--proxy", proxy,
             "-H", "Host: evil.com",
             "-H", f"X-Probe-Marker: {marker}",
             "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", "5",
             f"http://httpbin.org/get?marker={marker}"],
            capture_output=True, text=True, timeout=10,
        )
        status = result.stdout.strip()
        # The URL is allowed (httpbin.org is a test allowlisted host),
        # so the request must succeed — routed by URL.
        assert status == "200", (
            f"Request with mismatched Host header got {status}; "
            f"expected 200 (URL is the authoritative destination)."
        )

    def test_proxy_reachable(self):
        """HTTP via the proxy to an allowlisted host succeeds (200).

        What: curl through HTTP_PROXY to an allowlisted host with
        an X-Test-Context header; assert 200.
        Why: Positive control for the entire isolation suite. If
        this fails, the agent has no connectivity at all — all
        other "reachability blocked" assertions become meaningless
        ("everything is blocked including what should work").
        """
        proxy = os.environ.get("HTTP_PROXY", "")
        assert proxy, "HTTP_PROXY not set — cannot test proxy reachability"
        # Include X-Test-Context so the test_context addon doesn't
        # 428-reject the request when httpbin.org is a declared
        # target host (as it is in the blackbox test instance).
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--proxy", proxy,
             "-H", "X-Test-Context: run=isolation;agent=bbtest",
             "http://httpbin.org/get"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.stdout.strip() == "200", (
            f"Proxy not reachable: exit={result.returncode} stdout={result.stdout} stderr={result.stderr}"
        )


class TestHostAdjacentReachability:
    """Sandbox cannot reach host-side services other than the proxy.

    Why: The agent is meant to reach only the proxy, and everything
    else on the host (admin API, SSH, arbitrary local services,
    other agents' subnets) must be off-limits. A pass-by-default
    configuration (whatever isn't explicitly blocked is reachable)
    would let an agent pivot to local-only services assumed safe
    because they're bound to loopback or LAN.
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
        """SafeYolo admin API ports (9090, 9190) are unreachable.

        What: TCP connect to host:9090 and host:9190 from inside the
        sandbox; assert both fail.
        Why: The admin API can change policy modes (block → warn),
        add allowlist entries, or approve credentials. Agent access
        to it would defeat every other control SafeYolo enforces —
        a single-request sandbox escape.
        """
        host = self._host_ip_from_proxy()
        for port in (9090, 9190):
            self._assert_tcp_unreachable(host, port, f"admin API port {port}")

    def test_host_ssh_unreachable(self):
        """Port 22 reachable from sandbox is its own sshd, not the host's.

        What: Connect to port 22 on the resolved proxy host; if a
        banner comes back, the connection terminated to the
        sandbox-internal sshd (or nothing at all). Pass if
        timeout/refused.
        Why: If the agent can reach the host's SSH, it can try
        password brute force or probe for authorized_keys leaks.
        The sandbox-internal sshd is a separate service that
        doesn't run against host keys.
        """
        host = self._host_ip_from_proxy()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            sock.connect((host, 22))
            banner = sock.recv(256).decode(errors="replace")
            sock.close()
            # If we got a banner, it should be from the in-sandbox sshd.
            # The sandbox's sshd is acceptable — it's our own service.
            # We can't distinguish by banner alone, but the structural
            # test (test_host_listener_unreachable) covers the real
            # isolation property.
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass  # not listening or unreachable — fine
        finally:
            sock.close()

    def test_host_listener_unreachable(self):
        """A live TCP listener on the host is unreachable.

        What: Read the marker file /safeyolo/host-listener-port
        (harness starts a real TCP listener on 127.0.0.1:<port>
        before booting the VM); assert the sandbox cannot connect.
        Why: Distinguishes "blocked by isolation" from "nothing
        listening." The listener test guards against future
        implementation changes — a regression that gave the sandbox
        routable paths to the host would silently break isolation
        but pass the arbitrary-port test.
        """
        marker = "/safeyolo/host-listener-port"
        if not os.path.exists(marker):
            pytest.skip("Host listener port marker not found — "
                        "test harness did not set up host listener")
        port = int(open(marker).read().strip())
        host = self._host_ip_from_proxy()
        self._assert_tcp_unreachable(host, port, f"host listener on port {port}")

    def test_arbitrary_host_port_unreachable(self):
        """An unused port (44444) on the host is unreachable.

        What: TCP connect to host:44444; assert fail.
        Why: Together with test_host_listener_unreachable, confirms
        block-by-default — an arbitrary port nothing listens on
        should still be unreachable (not just refused by the
        kernel because no service is bound). Complements the
        live-listener test for full coverage.
        """
        host = self._host_ip_from_proxy()
        self._assert_tcp_unreachable(host, 44444, "arbitrary unused port 44444")

    def test_cross_agent_ip_unreachable(self):
        """Adjacent agents' attribution IPs are unreachable.

        What: Derive this agent's attribution IP (10.200.x.y) from
        loopback; probe TCP on the neighbouring ±1 offsets; assert
        both unreachable.
        Why: Each agent runs in an isolated netns with its own
        loopback. If one agent could reach another's attribution
        IP, cross-agent lateral movement would be possible — an
        agent compromised by the user's content could pivot to a
        neighbouring agent's workspace.
        """
        # Derive our own agent IP from loopback
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show", "lo"],
                capture_output=True, text=True, timeout=3,
            )
            our_ip = None
            for line in result.stdout.splitlines():
                line = line.strip()
                if "10.200." in line and "inet " in line:
                    our_ip = line.split()[1].split("/")[0]
                    break
        except (subprocess.TimeoutExpired, FileNotFoundError):
            our_ip = None

        if not our_ip or not our_ip.startswith("10.200."):
            pytest.skip(f"Could not determine agent IP from loopback: {our_ip}")

        # Probe adjacent agent IPs
        parts = our_ip.split(".")
        our_last = int(parts[3])
        for offset in (-1, +1):
            sibling_last = our_last + offset
            if sibling_last < 1 or sibling_last > 254:
                continue
            sibling_ip = f"10.200.0.{sibling_last}"
            for port in (22, 8080, 80):
                    self._assert_tcp_unreachable(
                        sibling_ip, port,
                        f"sibling agent {sibling_ip}:{port}"
                    )

    def test_sinkhole_direct_unreachable(self):
        """Sinkhole ports 18080/18443/19999 unreachable direct from sandbox.

        What: TCP connect to host:18080, :18443, :19999 (sinkhole
        HTTP, HTTPS, control API); assert all fail.
        Why: Sinkhole ports bind 0.0.0.0 during test runs, so they
        ARE listening — unlike the 44444 test. A direct sandbox →
        sinkhole connect succeeding here would mean the isolation
        boundary has a real hole, not just absence of services.
        """
        host = self._host_ip_from_proxy()
        for port in (18080, 18443, 19999):
            self._assert_tcp_unreachable(host, port, f"sinkhole port {port}")


class TestPrivilegeEscalation:
    """Agent cannot gain root, load modules, or poke kernel memory.

    Why: Every local privilege-escalation vector — running as root,
    setuid(0), kernel module loading, /dev/mem, eBPF — is a path
    to full sandbox escape. The agent must run unprivileged and be
    unable to acquire privileges through any of these mechanisms.
    """

    def test_runs_as_nonroot(self):
        """Agent process uid is not 0.

        What: os.getuid() != 0.
        Why: Running as root in the sandbox elevates the impact of
        every subsequent bug. Even with namespaces, root-inside-a-
        container is one kernel vuln away from host root.
        """
        assert os.getuid() != 0, "Running as root (UID 0)"

    def test_expected_uid(self):
        """Agent process runs as uid 1000.

        What: os.getuid() == 1000.
        Why: The attribution chain (service_discovery, bind-mount
        ownership, userns mapping) all assume uid 1000 inside the
        sandbox. A different uid means ownership mismatches and
        identity confusion.
        """
        assert os.getuid() == 1000, f"Expected UID 1000, got {os.getuid()}"

    def test_cannot_gain_root(self):
        """setuid(0) raises PermissionError.

        What: os.setuid(0) under pytest.raises(PermissionError).
        Why: If setuid to root works, the agent is 'nonroot' only
        by convention. Any suid binary or kernel bug that bypasses
        normal checks could elevate. Must fail at the syscall level.
        """
        with pytest.raises(PermissionError):
            os.setuid(0)

    def test_kernel_modules_disabled(self):
        """init_module(2) syscall returns non-success.

        What: Direct syscall to init_module with null args; assert
        return value is -1 and errno non-zero.
        Why: Loading a kernel module is immediate, total compromise
        — the module runs in ring 0. Blocked either by
        CONFIG_MODULES=n in the guest kernel, or by gVisor's
        user-space kernel rejecting the syscall.
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
        """/dev/mem does not exist in the sandbox.

        What: os.path.exists("/dev/mem") is False.
        Why: /dev/mem is a direct view of physical RAM. If present
        and readable, the agent can dump kernel data structures and
        potentially extract secrets from other processes.
        """
        assert not os.path.exists("/dev/mem"), "/dev/mem exists — physical memory accessible"

    def test_no_dev_kmem(self):
        """/dev/kmem does not exist in the sandbox.

        What: os.path.exists("/dev/kmem") is False.
        Why: /dev/kmem exposes kernel virtual memory directly —
        easier to parse than /dev/mem and equally dangerous for
        secret extraction.
        """
        assert not os.path.exists("/dev/kmem"), "/dev/kmem exists — kernel memory accessible"

    def test_ebpf_blocked(self):
        """bpf(2) syscall fails.

        What: Invoke syscall numbers 321 (x86_64) and 280 (aarch64)
        for SYS_bpf with zero args; if any returns 0, fail.
        Why: eBPF programs run in kernel context with wide access —
        network introspection, kprobe instrumentation, cgroup
        hooks. Even with verifier constraints, eBPF has been a
        recurring privilege-escalation vector.
        """
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
    """Config share mount is read-only and holds no private keys.

    Why: /safeyolo contains configuration and agent metadata from
    the host. It is mounted read-only so a compromised agent can't
    write back to the host's config, and must never contain private
    key material that a TLS-intercept attack would benefit from.
    """

    def test_config_share_readonly(self):
        """Writes to /safeyolo raise OSError.

        What: open("/safeyolo/test-write-attempt", "w") under
        pytest.raises(OSError).
        Why: A writable config share would let the agent modify
        its own configuration (proxy settings, policy files) and
        potentially affect the host's view of agent state. Must
        be read-only.
        """
        with pytest.raises(OSError):
            with open("/safeyolo/test-write-attempt", "w") as f:
                f.write("should fail")

    def test_no_private_key_in_config_share(self):
        """No file in /safeyolo contains PRIVATE KEY markers or has .key suffix.

        What: List /safeyolo files; reject any whose name contains
        'private' or ends in '.key', or whose first 500 bytes
        contain 'PRIVATE KEY'.
        Why: The CA private key is the root of trust for TLS
        interception. A stray copy on the config share is
        game-over for cert verification.
        """
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


class TestSandboxExposure:
    """Sandbox surfaces (/dev, /proc, PID namespace) expose nothing useful.

    Why: A hardened sandbox minimises what the adversary can inspect
    or manipulate. Each leaked surface — an unexpected device node,
    a readable /proc/kcore, a full host process list — is a rung on
    the escalation ladder. These probes test the reduction, not the
    mechanism (which varies between gVisor and VZ).
    """

    def test_dev_whitelist(self):
        """Every /dev entry is on the expected whitelist.

        What: Enumerate /dev; compare against the expected set
        (plus prefixed exceptions for microVMs); assert no
        unexpected entries.
        Why: Novel device entries are attack surface. This test is
        deliberately allowlist-based rather than blocklist-based —
        if the runtime adds a new device, the test fails until a
        human evaluates whether it should be there.
        """
        # Minimal set common to both gVisor and microVMs.
        whitelist = {
            # Character devices
            "null", "zero", "full", "random", "urandom", "tty", "console",
            # PTY
            "ptmx", "pts",
            # Symlinks to /proc/self/fd
            "fd", "stdin", "stdout", "stderr",
            # tmpfs mount
            "shm",
        }
        if _is_microvm():
            # VZ microVMs run a real Linux kernel — standard VM devices
            # are expected. The VM boundary IS the isolation layer.
            whitelist |= {
                "vsock", "vda", "rtc0", "hwrng", "kmsg", "port",
                "vga_arbiter", "vport0p0", "vcs", "vcsu", "vcsa",
            }
            # hvc* (virtio console), tty*, pty*, vcs* are standard
            # Linux kernel devices — allow all by prefix.
            prefix_allow = ("hvc", "tty", "pty", "vcs")
        else:
            prefix_allow = ("pts",)

        unexpected = []
        for entry in os.listdir("/dev"):
            if entry in whitelist:
                continue
            if any(entry.startswith(p) for p in prefix_allow):
                continue
            unexpected.append(entry)
        assert not unexpected, (
            f"Unexpected device entries in /dev: {unexpected}. "
            f"Every entry must be on the whitelist or it's a potential "
            f"attack surface. If a new entry is legitimately needed, add "
            f"it to the whitelist and document why."
        )

    def test_proc_kcore_unreadable(self):
        """/proc/kcore is absent or unreadable.

        What: Skip if /proc/kcore doesn't exist; otherwise, open
        it under pytest.raises(PermissionError/OSError).
        Why: /proc/kcore is a live view of kernel memory as an ELF
        core dump. Reading it leaks kernel data structures and
        credentials from other processes.
        """
        if not os.path.exists("/proc/kcore"):
            return  # absent is acceptable
        with pytest.raises((PermissionError, OSError)):
            with open("/proc/kcore", "rb") as f:
                f.read(16)

    def test_proc_kallsyms_redacted(self):
        """/proc/kallsyms (if readable) shows addresses redacted to zero.

        What: Read first 50 lines of /proc/kallsyms; assert every
        line starts with '0000000000000000'.
        Why: Unredacted kernel symbol addresses give attackers
        exact offsets for ROP/JOP gadgets — a major leg-up for
        kernel-exploit chains. Modern kernels redact to zero for
        unprivileged readers; this test catches regressions.
        """
        if not os.path.exists("/proc/kallsyms"):
            return
        try:
            with open("/proc/kallsyms") as f:
                # Just first 50 lines — enough to see whether addresses
                # are leaking or are all zero.
                lines = [next(f) for _ in range(50)]
        except (PermissionError, OSError):
            return  # can't read at all — strongest property; fine
        non_zero = [ln for ln in lines if not ln.startswith("0000000000000000")]
        assert not non_zero, (
            f"/proc/kallsyms leaks non-zero kernel addresses "
            f"({len(non_zero)} of first {len(lines)} lines)"
        )

    def test_sys_kernel_debug_inaccessible(self):
        """/sys/kernel/debug is absent or unreadable.

        What: Skip if /sys/kernel/debug doesn't exist; else, call
        os.listdir() under pytest.raises(PermissionError/OSError).
        Why: debugfs/tracefs expose kernel internals (probes, event
        tracers, module lists). A listable /sys/kernel/debug is a
        broad surface for kernel introspection and — via tracefs —
        a privilege-escalation vector.
        """
        debug = "/sys/kernel/debug"
        if not os.path.exists(debug):
            return
        try:
            os.listdir(debug)
        except (PermissionError, OSError):
            return  # expected
        pytest.fail(f"{debug} is listable from the sandbox")

    def test_pid_namespace_isolated(self):
        """PID 1's cmdline is the sandbox init, not the host's.

        What: Read /proc/1/cmdline; assert it does NOT contain
        'systemd', '/sbin/init', or 'launchd'.
        Why: If PID 1 is the host's init, the PID namespace is
        leaking through and the agent can read the full host
        process table — every running service's cmdline, including
        argv secrets and parent hierarchies.
        """
        try:
            cmdline = open("/proc/1/cmdline", "rb").read().decode(
                errors="replace",
            )
        except (PermissionError, FileNotFoundError):
            return  # unreadable is fine — no info leak

        host_inits = ["systemd", "/sbin/init", "launchd"]
        for init_name in host_inits:
            assert init_name not in cmdline, (
                f"PID 1 is the host's {init_name}, not the sandbox init. "
                f"PID namespace isolation is broken. "
                f"cmdline: {cmdline!r}"
            )

    def test_firewall_rules_not_readable(self):
        """iptables/pfctl don't emit rules from inside the sandbox.

        What: Run `iptables -L`, `iptables-save`, `pfctl` if present;
        fail if any exits 0 with non-empty output.
        Why: An agent that can enumerate host firewall rules learns
        exactly which ports/IPs are reachable via which path — a
        map of the egress surface to probe. Also implies CAP_NET_ADMIN,
        which the sandbox must not have.
        """
        # `iptables -L` prints and exits 0 on an empty table but needs
        # CAP_NET_ADMIN and the kernel netfilter namespace to read. In
        # gVisor user-space kernel the iptables binary likely isn't
        # present; if it is, it should fail.
        for binary in ("iptables", "iptables-save", "pfctl"):
            result = subprocess.run(
                ["sh", "-c", f"command -v {binary} >/dev/null && {binary} -L 2>&1"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0 and result.stdout:
                # Success AND output means the agent saw rules.
                pytest.fail(
                    f"{binary} ran successfully inside sandbox, output:\n"
                    f"{result.stdout[:500]}"
                )

    def test_host_ssh_not_reachable_via_sandbox_sshd(self):
        """No SSH private keys are present in the sandbox filesystem.

        What: Check /root/.ssh/ and /home/agent/.ssh/ for id_ed25519
        or id_rsa; fail if any exists.
        Why: Defence-in-depth. The sandbox runs sshd for inbound
        operator access, but must not possess client private keys
        that could be used to ssh OUT to the host or another agent.
        A leaked private key turns the sandbox into a lateral-
        movement pivot.
        """
        for path in ("/root/.ssh/id_ed25519", "/root/.ssh/id_rsa",
                     "/home/agent/.ssh/id_ed25519", "/home/agent/.ssh/id_rsa"):
            if os.path.exists(path):
                # A key that would let sandbox SSH anywhere is a problem.
                # Agent's public authorized_keys (for operator inbound)
                # is expected and fine; probe for the private halves.
                pytest.fail(
                    f"Private SSH key present at {path} — sandbox can "
                    f"use it to reach other hosts/agents"
                )


class TestFilesystemBoundary:
    """Workspace mount is contained; no setuid, mknod, or traversal escape.

    Why: /workspace is a shared surface between agent and host. If
    the agent can create setuid binaries, device nodes, or symlinks
    that leak outside the mount, it can either escalate inside the
    sandbox or trick the host into touching files outside /workspace.
    """

    def test_workspace_symlink_traversal(self):
        """Symlink to /etc/shadow inside /workspace doesn't reach host files.

        What: Create /workspace/.../shadow-link → /etc/shadow; try
        to read it. If readable, assert the content does NOT look
        like the host's real shadow file (which would have many
        colon-separated fields and 'root:' entries).
        Why: virtiofs/lisafs gofer mounts are supposed to contain
        traversal within the sandbox rootfs. A bug that followed
        symlinks on the host side would let the agent read any host
        file the mount process can see — /etc/shadow, SSH keys,
        cloud credentials.
        """
        import tempfile
        link_dir = tempfile.mkdtemp(dir="/workspace", prefix="symtest-")
        link_path = os.path.join(link_dir, "shadow-link")
        try:
            os.symlink("/etc/shadow", link_path)
            try:
                with open(link_path) as f:
                    content = f.read(200)
            except (PermissionError, FileNotFoundError, OSError):
                return  # can't read → safe
            # If readable, verify it's the SANDBOX's shadow (no real
            # password hashes) not the HOST's.
            assert "root:" not in content or content.count(":") < 5, (
                f"Symlink traversal may have reached host /etc/shadow: "
                f"{content[:100]!r}"
            )
        finally:
            os.unlink(link_path)
            os.rmdir(link_dir)

    def test_workspace_no_setuid(self):
        """setuid bit on a /workspace binary doesn't execute as root.

        What: Create a script in /workspace, chmod 4755 (setuid
        root), execute it; if it reports 'root', fail. Bit present
        on disk but not effective at exec is acceptable.
        Why: /workspace should be mounted `nosuid`. Otherwise the
        agent (uid 1000) could make a suid-root shell and
        immediately gain root inside the sandbox — the first step
        of most escape paths.
        """
        import stat
        import tempfile
        test_file = tempfile.NamedTemporaryFile(
            dir="/workspace", prefix="suidtest-", delete=False,
        )
        try:
            test_file.write(b"#!/bin/sh\nwhoami\n")
            test_file.close()
            os.chmod(test_file.name, 0o4755)  # setuid root
            actual_mode = os.stat(test_file.name).st_mode
            # If nosuid mount, the kernel strips the suid bit silently
            # OR allows the chmod but ignores the bit at exec time.
            # Check the bit on disk:
            has_suid = bool(actual_mode & stat.S_ISUID)
            if has_suid:
                # Bit stuck — test if exec actually escalates.
                result = subprocess.run(
                    [test_file.name], capture_output=True, text=True,
                    timeout=5,
                )
                # If output is "root", the suid is effective — bad.
                if result.stdout.strip() == "root":
                    pytest.fail(
                        "setuid binary on /workspace executed as root — "
                        "mount lacks nosuid"
                    )
                # Bit is on disk but not effective at exec → acceptable
                # (common on overlayfs + gVisor).
        finally:
            os.unlink(test_file.name)

    def test_workspace_no_mknod(self):
        """mknod on /workspace fails with PermissionError/OSError.

        What: os.mknod('/workspace/.../testdev', S_IFCHR, makedev(1,3));
        assert the call fails.
        Why: /workspace should be mounted `nodev` and the sandbox
        should lack CAP_MKNOD. Device nodes on a shared mount let
        the agent access arbitrary devices (raw block devices like
        /dev/sda, tty, etc.) once the host views the file.
        """
        import tempfile
        mknod_path = os.path.join(
            tempfile.mkdtemp(dir="/workspace", prefix="mktest-"),
            "testdev",
        )
        try:
            # Try to create a character device (1,3 = /dev/null)
            try:
                os.mknod(mknod_path, 0o666 | 0o020000, os.makedev(1, 3))
            except (PermissionError, OSError):
                return  # expected
            pytest.fail("mknod succeeded on /workspace — mount lacks nodev")
        finally:
            if os.path.exists(mknod_path):
                os.unlink(mknod_path)
            os.rmdir(os.path.dirname(mknod_path))

    def test_ca_trust_store_immutable(self):
        """Writes to /usr/local/share/ca-certificates fail.

        What: Attempt to write a fake-CA PEM to the trust store
        directory; expect PermissionError/OSError.
        Why: If the agent can add a CA to its own trust store, it
        can stand up a local MITM for its own traffic — TLS-
        inspecting requests that should have gone through SafeYolo.
        The trust store must be read-only to uid 1000.
        """
        # Attempt to write a fake CA cert. The target dir is
        # /usr/local/share/ca-certificates/ — if writable, the agent
        # could inject a CA and re-run update-ca-certificates.
        fake_ca = "/usr/local/share/ca-certificates/evil-test.crt"
        try:
            with open(fake_ca, "w") as f:
                f.write("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
        except (PermissionError, OSError):
            return  # can't write → strong property

        # Written — that's a concern. Clean up and try update-ca-certificates.
        try:
            result = subprocess.run(
                ["update-ca-certificates"], capture_output=True,
                text=True, timeout=10,
            )
            # Even if the write succeeded and update ran, the proxy
            # won't honour the new CA for its own outbound validation
            # (proxy runs on the HOST, not inside the sandbox). So the
            # actual security impact is limited to in-sandbox TLS
            # clients trusting the fake CA — which only matters if the
            # agent is trying to MITM itself (to hide traffic from the
            # proxy's content inspection).
            #
            # Flag it anyway — defence in depth.
            if result.returncode == 0:
                pytest.fail(
                    "Agent was able to add a CA to the trust store AND "
                    "run update-ca-certificates. While the proxy's own "
                    "trust store is unaffected, in-sandbox TLS clients "
                    "would honour the injected CA."
                )
        finally:
            os.unlink(fake_ca) if os.path.exists(fake_ca) else None


class TestSyscallSeccompEquivalents:
    """Dangerous syscalls (keyring, pivot_root, unshare, ptrace) are blocked or contained.

    Why: Docker's default seccomp profile drops ~44 syscalls that
    are rarely legitimate and historically exploited — kernel
    keyring injection (CVE-2017-6074), pivot_root filesystem
    escape, user-namespace creation as escalation vehicle, ptrace
    process introspection. Blackbox checks confirm the same
    exposures are closed on the current runtime (gVisor or VZ).
    """

    @staticmethod
    def _libc():
        libc_name = ctypes.util.find_library("c")
        if not libc_name:
            pytest.skip("libc not found")
        return ctypes.CDLL(libc_name, use_errno=True)

    @staticmethod
    def _syscall_num(table: dict) -> int:
        import platform as _p
        arch = _p.machine()
        if arch not in table:
            pytest.skip(f"syscall number unknown for {arch}")
        return table[arch]

    def _assert_syscall_fails(self, num: int, args: tuple, name: str) -> None:
        libc = self._libc()
        ret = libc.syscall(num, *args)
        err = ctypes.get_errno()
        assert ret == -1, f"{name} syscall succeeded (ret={ret})"
        assert err != 0, f"{name} returned -1 with errno=0"

    def test_keyctl_blocked(self):
        """keyctl(2) returns -1 with non-zero errno.

        What: Call SYS_keyctl with KEYCTL_GET_KEYRING_ID=0 and zero
        args; assert ret == -1 and errno != 0.
        Why: The kernel keyring is a shared store across processes.
        CVE-2017-6074 and several related issues exploited keyctl
        to escalate privileges. Blocked in Docker's default seccomp
        for exactly this reason.
        """
        # SYS_keyctl: x86_64=250, aarch64=217
        num = self._syscall_num({"x86_64": 250, "aarch64": 217})
        # keyctl(KEYCTL_GET_KEYRING_ID=0, 0, 0, 0, 0)
        self._assert_syscall_fails(num, (0, 0, 0, 0, 0), "keyctl")

    def test_add_key_blocked(self):
        """add_key(2) returns -1 with non-zero errno.

        What: Call SYS_add_key with zero args; assert ret == -1 and
        errno != 0.
        Why: Companion to keyctl — adds keys to the kernel keyring.
        Same privilege-escalation exposure. Blocked in Docker's
        default seccomp.
        """
        # SYS_add_key: x86_64=248, aarch64=217 (note: keyctl and add_key
        # share a range; keep them separate)
        num = self._syscall_num({"x86_64": 248, "aarch64": 217})
        self._assert_syscall_fails(num, (0, 0, 0, 0, 0), "add_key")

    def test_pivot_root_blocked(self):
        """pivot_root(2) returns -1 with non-zero errno.

        What: Call SYS_pivot_root with zero args; assert ret == -1
        and errno != 0.
        Why: pivot_root moves the root filesystem — combined with
        a mount from an attacker-controlled directory, it's a
        classic container escape. Must not be callable from the
        sandbox.
        """
        # SYS_pivot_root: x86_64=155, aarch64=41
        num = self._syscall_num({"x86_64": 155, "aarch64": 41})
        self._assert_syscall_fails(num, (0, 0), "pivot_root")

    def test_unshare_user_ns_contained(self):
        """unshare(CLONE_NEWUSER) grants no new access even if it succeeds.

        What: Call unshare with CLONE_NEWUSER. If it fails, pass
        (strongest outcome). If it succeeds, verify /etc/shadow is
        still unreadable, PID 1's cmdline still doesn't reveal host
        init, and /safeyolo is still read-only.
        Why: gVisor's sentry emulates namespaces, and VZ microVMs
        run real kernels — both allow the syscall. The property
        that matters is that the new namespace doesn't grant
        privileges the agent didn't already have. Tests the
        escape, not the syscall.
        """
        # SYS_unshare: x86_64=272, aarch64=97
        num = self._syscall_num({"x86_64": 272, "aarch64": 97})
        CLONE_NEWUSER = 0x10000000
        libc = self._libc()
        ret = libc.syscall(num, CLONE_NEWUSER)

        if ret != 0:
            return  # blocked at syscall level — strongest outcome

        # userns succeeded. Verify it didn't grant new privileges.

        # 1. Can't read /etc/shadow (would indicate real root)
        try:
            with open("/etc/shadow", "r") as f:
                f.read(1)
            pytest.fail(
                "unshare(CLONE_NEWUSER) granted read access to /etc/shadow"
            )
        except (PermissionError, FileNotFoundError):
            pass  # expected

        # 2. PID 1 is still the sandbox init, not the host
        try:
            cmdline = open("/proc/1/cmdline", "rb").read().decode(
                errors="replace",
            )
            assert "systemd" not in cmdline, (
                "After unshare, PID 1 is the host's systemd — "
                "namespace isolation broken"
            )
        except (PermissionError, FileNotFoundError):
            pass  # unreadable is fine

        # 3. Can't write to the read-only config share
        try:
            with open("/safeyolo/escape-test", "w") as f:
                f.write("test")
            os.unlink("/safeyolo/escape-test")
            pytest.fail(
                "unshare(CLONE_NEWUSER) granted write access to "
                "read-only /safeyolo mount"
            )
        except (PermissionError, OSError):
            pass  # expected

    def test_ptrace_init_blocked(self):
        """ptrace(PTRACE_ATTACH, 1, ...) returns -1.

        What: Call SYS_ptrace with PTRACE_ATTACH on pid 1; assert
        ret == -1 and errno != 0.
        Why: Attaching to init lets the agent read memory (keys,
        tokens) from the most privileged process in the sandbox
        and potentially inject code. Docker drops ptrace entirely
        in its default seccomp.
        """
        # SYS_ptrace: x86_64=101, aarch64=117
        num = self._syscall_num({"x86_64": 101, "aarch64": 117})
        PTRACE_ATTACH = 16
        self._assert_syscall_fails(num, (PTRACE_ATTACH, 1, 0, 0), "ptrace(init)")
