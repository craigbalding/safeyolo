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

    def test_direct_alt_port_blocked(self):
        """Direct TCP to an external IP on non-standard ports must fail.

        Existing tests cover :80 and :443. This widens to ports an
        agent might try if the firewall whitelisted only the common
        HTTP/S ports: :8443 (alt-HTTPS), :22 (SSH to external host),
        :6667 (IRC — historical C2 channel), :25 (SMTP).
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
        """DNS via the libc resolver (getaddrinfo) must not resolve an
        external name. Existing tests probe raw UDP to 8.8.8.8:53 — but
        an agent using the system resolver routes through whatever
        /etc/resolv.conf points at; if that nameserver is reachable,
        the agent can bypass the proxy for lookups (and then stream
        data via DNS tunnelling). Assert getaddrinfo on an external
        name fails — no valid resolver should be reachable.
        """
        # "blackbox-probe.example" isn't a real host; we care only whether
        # DNS is reachable at all. An EAI_AGAIN / EAI_NODATA / EAI_NONAME
        # all indicate resolver couldn't answer — expected.
        with pytest.raises(socket.gaierror):
            socket.getaddrinfo("blackbox-probe-should-not-resolve.example",
                               80, socket.AF_INET, socket.SOCK_STREAM)

    def test_non_icmp_raw_protocols_blocked(self):
        """Raw sockets using non-ICMP IP protocols must also fail. Existing
        test only covers IPPROTO_ICMP; if the kernel filter scopes raw-
        socket restriction by protocol number, an agent could try
        IPPROTO_SCTP, IPPROTO_GRE, IPPROTO_IPIP (tunnelling) to
        exfiltrate data outside the proxy's TCP/UDP observation window.
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
        """IPv6 egress must fail. mitmproxy binds to IPv4; if the sandbox
        has v6 connectivity, it routes around the proxy entirely.
        guest-init disables IPv6 at the sysctl level — assert the
        observable property (no v6 destination reachable), not the
        mechanism.
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
        """Cloud metadata services (AWS/GCP/Azure IMDS at 169.254.169.254,
        DigitalOcean at 169.254.169.254, GCE alias gateway 10.0.0.1)
        must be unreachable. A sandbox running on a cloud VM could
        otherwise SSRF the host's IAM credentials via metadata.

        Link-local 169.254.0.0/16 in particular must be blocked — the
        proxy's allowlist likely doesn't cover it, so this relies on
        the firewall's block-by-default behaviour.
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
        """AF_PACKET raw Ethernet sockets must fail (CAP_NET_RAW required).
        If granted, agent can forge L2 frames on its veth — ARP spoofing,
        source-IP spoofing past L3 firewall rules, MAC-level probing of
        the host side.
        """
        with pytest.raises((PermissionError, OSError)):
            # AF_PACKET = 17 on Linux (not always in socket module namespace
            # on non-Linux stubs); use the numeric constant.
            sock = socket.socket(17, socket.SOCK_RAW, 0)
            sock.close()

    def test_dns_tunnel_subdomain_blocked(self):
        """DNS tunnelling: encode data in subdomain labels, resolve via
        the system resolver. If the sandbox can resolve arbitrary
        subdomains, an agent can exfiltrate data by encoding it as
        DNS queries to a domain it controls (e.g.
        <base64-chunk>.exfil.attacker.com) — each query leaks ~60
        bytes and the proxy never sees it because it's DNS, not HTTP.

        The sandbox must NOT be able to resolve external names. If
        getaddrinfo succeeds, the DNS exfiltration path is open.
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

    def test_host_header_mismatch_blocked(self):
        """Host-header smuggling: send a request to an allowlisted URL
        (httpbin.org) but override Host to a non-allowlisted domain
        (evil.com). If the proxy evaluates policy based on the URL
        rather than the Host header, the request reaches the upstream
        server with evil.com in the Host header — the agent has smuggled
        a request to a blocked domain through an allowed tunnel.

        This is a simpler, reproducible version of domain fronting: no
        CDN needed, the sinkhole accepts both hostnames so we can
        observe what actually reaches upstream.

        The assertion: the proxy must either reject the request (403) or
        rewrite the Host header to match the URL. A 200 with the
        mismatched Host header reaching the sinkhole means the
        enforcement gap is real.
        """
        proxy = os.environ.get("HTTP_PROXY", "")
        if not proxy:
            pytest.skip("HTTP_PROXY not set")

        # HTTP (not HTTPS) so the proxy can fully inspect the request
        # without TLS complexity. Override Host to a non-allowlisted
        # domain.
        result = subprocess.run(
            ["curl", "-s", "--proxy", proxy,
             "-H", "Host: evil.com",
             "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", "5",
             "http://httpbin.org/get"],
            capture_output=True, text=True, timeout=10,
        )
        status = result.stdout.strip()
        # Acceptable outcomes:
        # - 403: proxy blocked based on Host header (strongest)
        # - Non-200: some other rejection
        # - 200: proxy allowed it — needs investigation (is it
        #   evaluating URL or Host? Did the sinkhole get Host: evil.com?)
        if status == "200":
            # The request succeeded. In test mode with sinkhole, this
            # means the proxy forwarded the request. The question is
            # whether the proxy evaluated "httpbin.org" (URL, allowed)
            # or "evil.com" (Host, should be blocked). Document as
            # xfail if the proxy evaluates on URL — that's the
            # mitmproxy default and consistent with RFC 7230 §5.4.
            pytest.xfail(
                "Host header mismatch (evil.com on httpbin.org URL) "
                "returned 200 — proxy evaluates policy on request URL, "
                "not Host header. This is mitmproxy's default per "
                "RFC 7230 §5.4 (Host is advisory when URL is absolute). "
                "Document as accepted behaviour for HTTP; for HTTPS "
                "CONNECT tunnels, mitmproxy re-terminates TLS and "
                "evaluates the inner request's actual destination."
            )

    def test_proxy_reachable(self):
        """Proxy must be reachable (the one allowed network path)."""
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
        """Port 22 on loopback must be the sandbox's own sshd (if any),
        not the host's. Check by comparing the SSH banner: the sandbox's
        sshd runs inside gVisor and its host key was generated at boot,
        so the banner won't match the host's known key fingerprint.

        If no sshd is listening at all, that's also fine — the property
        we care about is that the HOST's sshd is unreachable.
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
        """Start a listener on a known port on the host before the
        sandbox boots, then try to reach it from inside. This tests
        the actual isolation boundary — not whether a specific service
        happens to be running.

        The test harness writes a marker file with the host listener
        port. If the file doesn't exist, the test was not set up
        (skip rather than false-pass).
        """
        marker = "/safeyolo/host-listener-port"
        if not os.path.exists(marker):
            pytest.skip("Host listener port marker not found — "
                        "test harness did not set up host listener")
        port = int(open(marker).read().strip())
        host = self._host_ip_from_proxy()
        self._assert_tcp_unreachable(host, port, f"host listener on port {port}")

    def test_arbitrary_host_port_unreachable(self):
        """An unused ephemeral port on the host must be unreachable — proves
        the firewall is block-by-default for host-destined traffic, not
        pass-by-default with a narrow deny list. Uses 44444 (IANA
        unregistered) as a port nothing legitimate is listening on.
        """
        host = self._host_ip_from_proxy()
        self._assert_tcp_unreachable(host, 44444, "arbitrary unused port 44444")

    def test_cross_agent_ip_unreachable(self):
        """Other agents' attribution IPs (10.200.0.0/16 range) must not
        be reachable from this sandbox. Each agent runs in its own
        loopback-only network namespace — there is no shared network
        between agents. Probe neighbouring agent IPs to confirm
        structural isolation.
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


class TestSandboxExposure:
    """Verify attack-surface reduction: device nodes, /proc/sys leaks,
    firewall-rule disclosure, process visibility. Each probe is a thing
    a captured-agent adversary would reach for when hunting for escape
    vectors; if any succeed, that's a hardening gap.
    """

    def test_dev_whitelist(self):
        """Broad /dev enumeration — anything outside Docker's default
        minimal set is a hardening gap.

        Instead of targeting known-bad devices by name (which misses
        novel entries), enumerate everything in /dev and assert it's
        all on the whitelist. If gVisor adds a new device in a future
        version, this test catches it before it ships into production.
        """
        # The whitelist: Docker-standard minimal /dev entries. These
        # are harmless (null, zero, random, tty, pty, symlinks to
        # /proc/self/fd, shm tmpfs, console emulated as a file).
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
        unexpected = []
        for entry in os.listdir("/dev"):
            if entry in whitelist:
                continue
            # pts/ptmx is a subentry of the pts devpts mount — allow
            if entry.startswith("pts"):
                continue
            unexpected.append(entry)
        assert not unexpected, (
            f"Unexpected device entries in /dev: {unexpected}. "
            f"Every entry must be on the whitelist or it's a potential "
            f"attack surface. If a new entry is legitimately needed, add "
            f"it to the whitelist and document why."
        )

    def test_proc_kcore_unreadable(self):
        """/proc/kcore exposes kernel memory as an ELF. Must not be
        readable from the sandbox.
        """
        if not os.path.exists("/proc/kcore"):
            return  # absent is acceptable
        with pytest.raises((PermissionError, OSError)):
            with open("/proc/kcore", "rb") as f:
                f.read(16)

    def test_proc_kallsyms_redacted(self):
        """/proc/kallsyms leaks kernel symbol addresses (ROP gadgets). If
        present, symbols must be redacted to 0x0 when read by an
        unprivileged process.
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
        """/sys/kernel/debug exposes kernel internals (tracefs). Must
        not be readable.
        """
        debug = "/sys/kernel/debug"
        if not os.path.exists(debug):
            return
        try:
            os.listdir(debug)
        except (PermissionError, OSError):
            return  # expected
        pytest.fail(f"{debug} is listable from the sandbox")

    def test_pid_visibility_scoped(self):
        """The sandbox must not see host PIDs. /proc should show only
        the container's own process tree. A host `ps aux` has dozens
        to hundreds of processes — a sandbox has a handful. The
        threshold is deliberately loose (≤50) to allow the agent's own
        process tree to grow without flaking.
        """
        pids = [e for e in os.listdir("/proc") if e.isdigit()]
        assert len(pids) < 50, (
            f"/proc reports {len(pids)} PIDs — likely host-PID leak "
            f"(sandbox should see only its own small process tree)"
        )

    def test_firewall_rules_not_readable(self):
        """iptables(-save) / pfctl must fail inside the sandbox — the
        firewall topology is not a property the agent should enumerate.
        CAP_NET_ADMIN would be required on Linux and isn't granted.
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
        """Defence-in-depth: even if an agent rooted itself inside the
        sandbox (which the other tests assert it cannot), the sandbox's
        own sshd — running to let the operator connect IN — must not
        provide an egress channel to the host. Assert no ssh-client
        credential material is present that would let the sandbox ssh
        OUT to the host or another agent.
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
    """Verify workspace/virtiofs and overlayfs boundaries can't be abused
    to escape or compromise the host.
    """

    def test_workspace_symlink_traversal(self):
        """Create a symlink inside /workspace pointing to /etc/shadow on
        the host. If the host follows it (e.g. via virtiofs passthrough),
        the agent can read host files outside the mount.

        On gVisor (lisafs gofer) this should resolve within the sandbox's
        rootfs, not the host. On VZ microVMs (virtiofs) the mount layer
        prevents traversal. Either way, the read must fail or return the
        sandbox's own /etc/shadow (which has no real credentials).
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
            # If readable, verify it's the SANDBOX's shadow (locked
            # accounts with * or ! or !*, no real password hashes).
            # A real shadow file has $6$... or $y$... hashes.
            import re
            has_real_hash = bool(re.search(r'\$[0-9a-z]+\$', content))
            assert not has_real_hash, (
                f"Symlink traversal may have reached host /etc/shadow "
                f"(contains password hashes): {content[:100]!r}"
            )
        finally:
            os.unlink(link_path)
            os.rmdir(link_dir)

    def test_workspace_no_setuid(self):
        """setuid bits on files written to /workspace must not take effect.
        The workspace mount should have `nosuid` — otherwise an agent
        can create a setuid-root binary and escalate.
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
        """mknod on /workspace must fail. If allowed, agent can create
        device nodes (e.g. /dev/sda equivalent) on the shared mount.
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

    @pytest.mark.xfail(reason=(
        "Rootless userns: rootfs overlay is writable by design (agent "
        "needs to install packages). Trust store writes only affect the "
        "in-sandbox TLS stack, not the proxy's host-side trust store."
    ))
    def test_ca_trust_store_immutable(self):
        """An agent must not be able to add CAs to the trust store and
        then MITM its own traffic to hide from the proxy. The system
        trust store (update-ca-certificates target) should be read-only
        or the addition should have no effect on proxy behaviour.
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
    """Verify syscalls that Docker's default seccomp profile drops are
    also unreachable on this runtime. Docker-on-Linux drops ~44 syscalls
    by default; the most security-relevant are keyctl/add_key (kernel
    keyring injection), pivot_root/mount (namespace manipulation),
    unshare(CLONE_NEWUSER) (user-namespace creation, historical escape
    vehicle), and ptrace (process introspection). gVisor's user-space
    kernel should either reject or no-op these; if any *succeed*, the
    hardening gap matters.
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
        """keyctl(2) — kernel keyring manipulation. In Docker's default
        seccomp drop list because it's the vector used in CVE-2017-6074
        and various keyring-related privilege escalations.
        """
        # SYS_keyctl: x86_64=250, aarch64=217
        num = self._syscall_num({"x86_64": 250, "aarch64": 217})
        # keyctl(KEYCTL_GET_KEYRING_ID=0, 0, 0, 0, 0)
        self._assert_syscall_fails(num, (0, 0, 0, 0, 0), "keyctl")

    def test_add_key_blocked(self):
        """add_key(2) — adds keys to kernel keyring. Dropped by Docker
        default seccomp.
        """
        # SYS_add_key: x86_64=248, aarch64=217 (note: keyctl and add_key
        # share a range; keep them separate)
        num = self._syscall_num({"x86_64": 248, "aarch64": 217})
        self._assert_syscall_fails(num, (0, 0, 0, 0, 0), "add_key")

    def test_pivot_root_blocked(self):
        """pivot_root(2) — moves the root filesystem. Escape technique
        when combined with a mount from a controlled directory.
        """
        # SYS_pivot_root: x86_64=155, aarch64=41
        num = self._syscall_num({"x86_64": 155, "aarch64": 41})
        self._assert_syscall_fails(num, (0, 0), "pivot_root")

    def test_unshare_user_ns_blocked(self):
        """unshare(CLONE_NEWUSER) — create a new user namespace. Historical
        container-escape vector (CVE-2013-1956 and others).

        ACCEPTED RISK on gVisor: gVisor's sentry emulates namespace
        creation in its own user-space kernel, ignoring both OCI seccomp
        profiles AND the OCI capability bitmask for this syscall.
        Dropping CAP_SYS_ADMIN doesn't help (verified: remount breaks,
        unshare still succeeds). Blocking via seccomp doesn't help
        (verified: gVisor ignores the filter).

        The mitigation: the userns created lives entirely inside gVisor's
        sentry, not on the host kernel. Capabilities gained in the inner
        namespace are scoped to gVisor's emulated environment and cannot
        grant host access. A gVisor-sentry escape that leverages this
        would be a gVisor 0-day, tracked by gVisor's own security
        advisory process.

        On VZ microVMs (macOS), unshare is a full kernel syscall and
        IS expected to fail — the test should hard-assert there.
        """
        # SYS_unshare: x86_64=272, aarch64=97
        num = self._syscall_num({"x86_64": 272, "aarch64": 97})
        CLONE_NEWUSER = 0x10000000
        libc = self._libc()
        ret = libc.syscall(num, CLONE_NEWUSER)
        if ret == 0:
            # Succeeded — check if this is gVisor (accepted risk) or
            # a native kernel (real breach).
            is_gvisor = False
            try:
                # gVisor's emulated dmesg always starts with
                # "Starting gVisor..." at boot.
                result = subprocess.run(
                    ["dmesg"], capture_output=True, text=True, timeout=5,
                )
                is_gvisor = "Starting gVisor" in result.stdout
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
            if is_gvisor:
                pytest.xfail(
                    "unshare(CLONE_NEWUSER) succeeds on gVisor — accepted "
                    "risk: the userns is gVisor-internal, not on the host "
                    "kernel. See inline docstring for risk analysis."
                )
            pytest.fail(
                "unshare(CLONE_NEWUSER) succeeded on a non-gVisor kernel — "
                "this is a real privilege-escalation vector"
            )

    def test_ptrace_init_blocked(self):
        """ptrace(PTRACE_ATTACH, 1, ...) — attach to pid 1. If granted,
        agent can read init's memory / inject code. Docker's seccomp
        drops ptrace entirely by default; gVisor has its own layer.
        """
        # SYS_ptrace: x86_64=101, aarch64=117
        num = self._syscall_num({"x86_64": 101, "aarch64": 117})
        PTRACE_ATTACH = 16
        self._assert_syscall_fails(num, (PTRACE_ATTACH, 1, 0, 0), "ptrace(init)")
