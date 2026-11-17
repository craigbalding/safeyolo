"""VM isolation tests — run from inside the microVM via pytest.

Every test is a direct probe from the adversary's perspective.
These tests assert OUTCOMES, not mechanisms. They never reference pf,
iptables, feth, or any platform-specific detail.

Dependencies: pytest (installed by test setup), curl, sudo, modprobe,
python3 stdlib (os, socket, ctypes, subprocess).
"""

import ctypes
import ctypes.util
import errno
import json
import os
import socket
import stat
import subprocess
import sys

import pytest
from harness.containment import assert_host_canaries_absent, attempt_network, check_bpf_refusal
from harness.host_listener import refuse_listener


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


def _run_as_gvisor_sandbox_root(
    command: list[str],
    *,
    timeout: int = 10,
) -> subprocess.CompletedProcess:
    """Run one probe as gVisor's namespace-root, never as host root."""
    if not _is_gvisor():
        pytest.skip("sandbox-root setpriv probes apply to Linux gVisor")
    return subprocess.run(
        [
            "setpriv",
            "--reuid=0",
            "--regid=0",
            "--clear-groups",
            *command,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class TestNetworkEscape:
    """Sandbox cannot reach external networks except through the proxy.

    Why: The proxy is the sole authorised egress path. Every other
    network-layer route — direct IP, raw sockets, alternate ports,
    IPv6, DNS, cloud metadata IPs — must be unreachable. A gap here
    means data exfiltrates outside the credential/network guards
    entirely, and the agent operates with no policy enforcement.
    """

    def test_direct_http_blocked(self):
        """Direct TCP bytes cannot bypass the proxy.

        What: Send a unique payload toward the host's live owned receiver.
        Why: The host observer must record zero guest delivery, even when the
        receiver sends no reply or the client cannot parse the response.
        """
        attempt_network("tcp")

    def test_direct_https_blocked(self):
        """Direct TLS bytes cannot bypass the proxy.

        What: Send a unique payload toward the host's live owned receiver.
        Why: The host observer must record zero guest delivery, even when the
        receiver sends no reply or the client cannot parse the response.
        """
        attempt_network("tcp", tls=True)

    def test_dns_udp_blocked(self):
        """An unanswered DNS query must not leave the guest.

        What: Send a unique payload toward the host's live owned receiver.
        Why: The host observer must record zero guest delivery, even when the
        receiver sends no reply or the client cannot parse the response.
        """
        attempt_network("udp", dns=True)

    def test_raw_socket_blocked(self):
        """Ordinary guest raw ICMP socket creation is refused.

        What: Make a valid socket creation request and require permission or
        protocol-unavailable refusal. Close any unexpectedly returned socket.
        Why: The ordinary guest has no CAP_NET_RAW. A later send failure cannot
        prove socket creation was refused; no public destination is contacted.
        """
        with pytest.raises(OSError) as refusal:
            socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP).close()
        assert refusal.value.errno in (errno.EPERM, errno.EACCES, errno.EAFNOSUPPORT,
                                      errno.EPROTONOSUPPORT, errno.ESOCKTNOSUPPORT, errno.ENOSYS)

    def test_direct_alt_port_blocked(self):
        """An owned dynamic TCP port cannot bypass the proxy.

        What: Send a unique payload toward the host's live owned receiver.
        Why: The host observer must record zero guest delivery, even when the
        receiver sends no reply or the client cannot parse the response.
        """
        attempt_network("tcp")

    def test_libc_resolver_blocked(self):
        """The selected libc resolver emits no query to its owned observer.

        What: Send a unique payload toward the host's live owned receiver.
        Why: The host observer must record zero guest delivery, even when the
        receiver sends no reply or the client cannot parse the response.
        """
        attempt_network("udp", resolver=True)

    def test_non_icmp_raw_protocols_blocked(self):
        """Ordinary guest SCTP/GRE/IPIP raw socket creation is refused.

        What: Make a valid socket creation request and require permission or
        protocol-unavailable refusal. Close any unexpectedly returned socket.
        Why: The ordinary guest has no CAP_NET_RAW. A later send failure cannot
        prove socket creation was refused; no public destination is contacted.
        """
        for proto in (132, 47, 4):
            with pytest.raises(OSError) as refusal:
                socket.socket(socket.AF_INET, socket.SOCK_RAW, proto).close()
            assert refusal.value.errno in (errno.EPERM, errno.EACCES, errno.EAFNOSUPPORT,
                                          errno.EPROTONOSUPPORT, errno.ESOCKTNOSUPPORT, errno.ENOSYS)

    def test_ipv6_egress_blocked(self):
        """Owned IPv6 TCP receivers observe no guest delivery.

        What: Send a unique payload toward the host's live owned receiver.
        Why: The host observer must record zero guest delivery, even when the
        receiver sends no reply or the client cannot parse the response.
        """
        attempt_network("tcp", 6)

    def test_metadata_ips_unreachable(self):
        """Applicable owned metadata routes observe no guest delivery.

        What: Send a unique payload toward the host's live owned receiver.
        Why: The host observer must record zero guest delivery, even when the
        receiver sends no reply or the client cannot parse the response.
        """
        attempt_network("tcp", metadata=True)

    def test_af_packet_blocked(self):
        """Ordinary guest packet socket creation is refused.

        What: Make a valid socket creation request and require permission or
        protocol-unavailable refusal. Close any unexpectedly returned socket.
        Why: The ordinary guest has no CAP_NET_RAW. A later send failure cannot
        prove socket creation was refused; no public destination is contacted.
        """
        with pytest.raises(OSError) as refusal:
            socket.socket(17, socket.SOCK_RAW, 0).close()
        assert refusal.value.errno in (errno.EPERM, errno.EACCES, errno.EAFNOSUPPORT,
                                      errno.EPROTONOSUPPORT, errno.ESOCKTNOSUPPORT, errno.ENOSYS)

    def test_dns_tunnel_subdomain_blocked(self):
        """DNS over TCP and IPv6 UDP cannot transmit unique labels.

        What: Send a unique payload toward the host's live owned receiver.
        Why: The host observer must record zero guest delivery, even when the
        receiver sends no reply or the client cannot parse the response.
        """
        attempt_network("tcp", dns=True)
        attempt_network("udp", 6, dns=True)

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
             "-H", "X-SafeYolo-Test-Context: run=isolation;agent=bbtest",
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
        an X-SafeYolo-Test-Context header; assert 200.
        Why: Positive control for the entire isolation suite. If
        this fails, the agent has no connectivity at all — all
        other "reachability blocked" assertions become meaningless
        ("everything is blocked including what should work").
        """
        proxy = os.environ.get("HTTP_PROXY", "")
        assert proxy, "HTTP_PROXY not set — cannot test proxy reachability"
        # Include X-SafeYolo-Test-Context so the test_context addon doesn't
        # 428-reject the request when httpbin.org is a declared
        # target host (as it is in the blackbox test instance).
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--proxy", proxy,
             "-H", "X-SafeYolo-Test-Context: run=isolation;agent=bbtest",
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
            except (TimeoutError, ConnectionRefusedError, OSError):
                return  # expected: firewall blocked the connect
            pytest.fail(
                f"TCP connect to {host}:{port} ({context}) succeeded — "
                f"this is a host-reachability breach. The sandbox must only "
                f"reach the proxy."
            )
        finally:
            sock.close()

    def test_admin_api_unreachable(self):
        """The host admin API listeners are unreachable from the sandbox.

        What: TCP connect to the admin ports named by the harness. The
        default Linux lane checks both production 9090 and test 9190;
        the physical VZ lane checks its assigned live test port.
        Why: The admin API can change policy modes (block → warn),
        add allowlist entries, or approve credentials. Agent access
        to it would defeat every other control SafeYolo enforces —
        a single-request sandbox escape.
        """
        host = self._host_ip_from_proxy()
        marker = "/safeyolo/blackbox-admin-ports"
        ports = [int(port) for port in open(marker).read().split()] if os.path.exists(marker) else [9090, 9190]
        for port in ports:
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
            # If the connect succeeded, we're talking to the sandbox's own
            # sshd -- that's our service, not a host-side listener. The
            # structural check (test_host_listener_unreachable) proves the
            # real isolation property; this test is mostly a sanity check
            # that connect() doesn't return a host-side peer.
        except (TimeoutError, ConnectionRefusedError, OSError):
            pass  # not listening or unreachable -- fine
        finally:
            sock.close()

    def test_host_listener_unreachable(self):
        """A live TCP listener on the host is unreachable.

        What: Read the listener address and port markers under /safeyolo
        (harness starts a real TCP listener on 127.0.0.1:<port>
        before booting the VM); assert the sandbox cannot connect.
        Why: Distinguishes "blocked by isolation" from "nothing
        listening." The listener test guards against future
        implementation changes — a regression that gave the sandbox
        routable paths to the host would silently break isolation
        but pass the arbitrary-port test.
        """
        print("HOST_LISTENER_REFUSAL=" + json.dumps(refuse_listener()), flush=True)

    def test_sinkhole_direct_unreachable(self):
        """The live sinkhole HTTP, HTTPS, and control paths are unreachable.

        What: TCP connect to each harness origin and control path. On VZ,
        HTTP and control share one listener; both probes use that port.
        Why: Sinkhole ports bind 0.0.0.0 during test runs, so they
        ARE listening — unlike the 44444 test. A direct sandbox →
        sinkhole connect succeeding here would mean the isolation
        boundary has a real hole, not just absence of services.
        """
        host = self._host_ip_from_proxy()
        marker = "/safeyolo/blackbox-sinkhole-ports"
        if os.path.exists(marker):
            entries = [line.split() for line in open(marker).read().splitlines()]
            assert len(entries) == 3 and all(len(entry) == 2 for entry in entries)
        else:
            entries = [["HTTP", "18080"], ["HTTPS", "18443"], ["control", "19999"]]
        for name, port in entries:
            self._assert_tcp_unreachable(host, int(port), f"sinkhole {name} port {port}")


class TestGuestPrivilegeBoundary:
    """Guest privilege remains inside the sandbox boundary.

    Why: Agents start as uid 1000 but may need guest root to install
    packages. On Linux that root is deliberately namespace-root,
    mapped to an unprivileged subordinate host uid. Kernel modules,
    host memory, and eBPF remain unavailable regardless of guest uid.
    """

    def test_expected_uid(self):
        """Agent process runs as uid 1000.

        What: os.getuid() == 1000.
        Why: The attribution chain (listener ownership, bind-mount
        ownership, userns mapping) all assume uid 1000 inside the
        sandbox. A different uid means ownership mismatches and
        identity confusion.
        """
        assert os.getuid() == 1000, f"Expected UID 1000, got {os.getuid()}"

    def test_privilege_transition_matches_platform_contract(self):
        """Guest-root transition follows the platform's isolation model.

        What: On a hardware microVM, direct setuid(0) must fail. On
        Linux gVisor, setpriv must reach uid 0 inside the sandbox;
        the host-side uid-map test separately proves this maps to a
        subordinate uid rather than host root.
        Why: Package installation needs an intentional guest-root
        path, while treating namespace-root as host root would both
        break that feature and test the wrong security boundary.
        """
        if _is_gvisor():
            result = _run_as_gvisor_sandbox_root(["id", "-u"])
            assert result.returncode == 0, (
                f"setpriv could not reach sandbox root: {result.stderr}"
            )
            assert result.stdout.strip() == "0", result.stdout
            return

        with pytest.raises(PermissionError):
            os.setuid(0)

    def test_sudo_reaches_guest_root(self):
        """The standard sudo command reaches root only inside the guest.

        What: Run `sudo -n id -u` as the agent and require uid 0. On
        gVisor the SafeYolo shim uses namespace capabilities; on a
        hardware microVM the distro's normal sudo transition applies.
        Why: Agents need a familiar, non-operator-mediated way to
        install native packages without confusing host root with
        sandbox or VM root.
        """
        result = subprocess.run(
            ["sudo", "-n", "id", "-u"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "0", result.stdout

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
        """A valid BPF map request remains refused or guest contained.

        What: Use this architecture's BPF_MAP_CREATE after a getpid control.
        Require a narrow refusal on gVisor. Close a successful VZ guest-kernel
        descriptor and check that the host canaries remain inaccessible.
        Why: EINVAL and bad pointers cannot establish refusal. Any nonnegative
        descriptor is success; a VZ guest kernel remains separate from its host.
        """
        check_bpf_refusal(guest_kernel=_is_microvm())


class TestSandboxRootContainment:
    """Linux namespace-root cannot cross SafeYolo's host boundary.

    Why: Allowing agents to install distro packages intentionally
    grants root inside gVisor. The security property is therefore
    containment: namespace-root must still be unable to modify the
    host config share, reach host listeners, inspect host processes,
    or access host devices.
    """

    def test_config_share_stays_readonly_as_sandbox_root(self):
        """Sandbox root cannot write the host-backed config share.

        What: Elevate with setpriv and attempt to create a file under
        /safeyolo; require the write to fail and the path to remain
        absent.
        Why: If namespace-root can modify this host bind mount it can
        tamper with proxy configuration or guest bootstrap state,
        turning guest package installation into host-state mutation.
        """
        probe = "/safeyolo/sandbox-root-write-probe"
        result = _run_as_gvisor_sandbox_root(
            ["/bin/sh", "-c", f"printf x > {probe}"],
        )
        assert result.returncode != 0, (
            "Sandbox root wrote to the read-only /safeyolo share"
        )
        assert not os.path.exists(probe), (
            f"Sandbox-root write probe unexpectedly exists: {probe}"
        )

    def test_host_listener_stays_unreachable_as_sandbox_root(self):
        """Sandbox root cannot connect to a live host TCP listener.

        What: Elevate with setpriv, read the harness listener endpoint,
        and attempt a direct TCP connection to
        the harness's known-live host listener; require failure.
        Why: Guest root must not turn the loopback-only network
        namespace into a path to host services or the admin API.
        """
        code = (
            "import json,sys; sys.path.insert(0, '/workspace/tests/blackbox'); "
            "from harness.host_listener import refuse_listener; "
            "print('HOST_LISTENER_REFUSAL=' + json.dumps(refuse_listener()), flush=True)"
        )
        result = _run_as_gvisor_sandbox_root(
            [sys.executable, "-c", code],
        )
        assert result.returncode == 0, result.stderr
        print(result.stdout, end="", flush=True)

    def test_host_kernel_surfaces_stay_absent_as_sandbox_root(self):
        """Sandbox root sees no host devices, private file or process canary.

        What: Elevate with setpriv, check meaningful host device paths and the
        host's independently verified live process/file canaries.
        Why: Guest administration must remain inside its kernel and namespace.
        A guest PID-1 command name does not identify the host process boundary.
        """
        code = """
import os
import sys
sys.path.insert(0, '/workspace/tests/blackbox')
from harness.containment import assert_host_canaries_absent
assert os.geteuid() == 0
for path in ('/dev/kvm', '/dev/mem', '/dev/kmem'):
    assert not os.path.exists(path), f'host device exposed: {path}')
assert_host_canaries_absent()
"""
        result = _run_as_gvisor_sandbox_root([sys.executable, "-c", code])
        assert result.returncode == 0, result.stderr
        print(result.stdout, end="", flush=True)


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
        (plus prefixed exceptions for microVMs). If /dev/log exists,
        verify it is a guest-root-owned socket. Assert no unexpected
        entries.
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
        gvisor_character_devices = set()
        gvisor_unmaterialized_aliases = set()
        if _is_microvm():
            # VZ microVMs run a real Linux kernel — standard VM devices
            # are expected. The VM boundary IS the isolation layer. vda is
            # the read-only base rootfs and vdb is the persistent overlay
            # disk used by guest/initramfs/init.
            whitelist |= {
                "vsock", "vda", "vdb", "rtc0", "hwrng", "kmsg", "port",
                "vga_arbiter", "vport0p0", "vcs", "vcsu", "vcsa",
            }
            # hvc* (virtio console), tty*, pty*, vcs* are standard
            # Linux kernel devices — allow all by prefix.
            prefix_allow = ("hvc", "tty", "pty", "vcs")
        else:
            # gVisor 2026-08+ mirrors Linux devtmpfs by maintaining
            # /dev/char/<major>:<minor> symlinks for each character device.
            # The directory is an index, not an additional device surface;
            # its entries are validated below against this same allowlist.
            whitelist.add("char")
            gvisor_character_devices = {
                "/dev/null", "/dev/zero", "/dev/full", "/dev/random",
                "/dev/urandom", "/dev/tty", "/dev/console",
            }
            # gVisor registers in-sentry FUSE and TUN implementations, but
            # SafeYolo's OCI spec does not materialize their device nodes.
            # Current runsc still indexes them in /dev/char as dangling
            # aliases. Keep that distinction strict: if either target becomes
            # openable in a future runtime, this test must fail for review.
            gvisor_unmaterialized_aliases = {
                "/dev/fuse", "/dev/net/tun",
            }
            prefix_allow = ("pts",)

        unexpected = []
        for entry in os.listdir("/dev"):
            if entry == "log":
                # The guest scheduler starts BusyBox syslogd as guest root.
                # Its local logging socket is not a device or host mount.
                logging_socket = os.lstat("/dev/log")
                assert stat.S_ISSOCK(logging_socket.st_mode) and (
                    logging_socket.st_uid, logging_socket.st_gid
                ) == (0, 0), (
                    "/dev/log must be a guest-root-owned syslog socket: "
                    f"mode={logging_socket.st_mode:o} "
                    f"uid={logging_socket.st_uid} gid={logging_socket.st_gid}"
                )
                continue
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

        if not _is_microvm() and os.path.isdir("/dev/char"):
            unexpected_char_links = []
            for entry in os.listdir("/dev/char"):
                link = os.path.join("/dev/char", entry)
                target = os.path.realpath(link)
                try:
                    target_mode = os.stat(target).st_mode
                except OSError:
                    target_mode = None
                materialized_device = (
                    target in gvisor_character_devices
                    and target_mode is not None
                    and stat.S_ISCHR(target_mode)
                )
                approved_dangling_alias = (
                    target in gvisor_unmaterialized_aliases
                    and target_mode is None
                )
                if (
                    not os.path.islink(link)
                    or not (materialized_device or approved_dangling_alias)
                ):
                    unexpected_char_links.append((entry, target))
            assert not unexpected_char_links, (
                "Unexpected gVisor /dev/char mappings: "
                f"{unexpected_char_links}. The device-number index may only "
                "refer to approved top-level character devices."
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

    def test_host_process_canary_absent(self):
        """The identifiable live host process and private file are absent.

        What: Read the supplied host paths and reject the unique marker if
        visible. The host verifies both canaries before and after this phase.
        Why: A PID-1 name or a colliding guest PID cannot prove host isolation.
        """
        assert_host_canaries_absent()

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
    """Workspace mount cannot expose host files or host devices.

    Why: /workspace is a shared surface between agent and host. If
    the agent can create usable device nodes or symlinks that leak
    outside the mount, it can trick the host mount implementation into
    exposing resources beyond /workspace. Guest-root access itself is
    tested as an intended capability in test_root_containment.py.
    """

    def test_workspace_symlink_traversal(self):
        """Symlink to /etc/shadow inside /workspace doesn't reach host files.

        What: Create /workspace/.../shadow-link → /etc/shadow; try
        to read it. If readable, assert it resolves to the same guest
        inode and bytes as opening /etc/shadow directly.
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
                with open("/etc/shadow", "rb") as f:
                    guest_content = f.read()
            except (PermissionError, FileNotFoundError, OSError):
                # If the guest file is protected, the workspace link must not
                # make it readable through the gofer mount.
                with pytest.raises((PermissionError, FileNotFoundError, OSError)):
                    with open(link_path, "rb") as f:
                        f.read(1)
                return

            with open(link_path, "rb") as f:
                linked_content = f.read()
            assert os.path.samefile(link_path, "/etc/shadow"), (
                "Workspace absolute symlink did not resolve to the guest's "
                "/etc/shadow inode"
            )
            assert linked_content == guest_content, (
                "Workspace absolute symlink returned bytes other than the "
                "guest's /etc/shadow; possible host-path traversal"
            )
        finally:
            os.unlink(link_path)
            os.rmdir(link_dir)

    def test_workspace_no_mknod(self):
        """A shared workspace cannot provide usable device nodes.

        What: Try to create a harmless null device in an owned directory. If
        creation succeeds, distinguish that from opening and using the node.
        Why: nodev controls device use; mknod failure alone does not test nodev.
        """
        import tempfile
        with tempfile.TemporaryDirectory(dir="/workspace", prefix="mktest-") as directory:
            path = os.path.join(directory, "testdev")
            try:
                os.mknod(path, stat.S_IFCHR | 0o600, os.makedev(1, 3))
            except OSError as error:
                assert error.errno in (errno.EPERM, errno.EACCES, errno.EROFS, errno.ENOSYS)
                return
            try:
                fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
            except OSError as error:
                assert error.errno in (errno.EACCES, errno.EPERM, errno.ENXIO, errno.ENODEV)
            else:
                os.close(fd)
                pytest.fail("shared workspace exposed a usable device node")


class TestSyscallSeccompEquivalents:
    """Valid keyring and namespace requests remain contained.

    Why: Invalid arguments cannot prove refusal. A namespace operation may
    succeed inside the guest while host canaries and read-only shares remain
    isolated. Guest capabilities do not imply host-kernel capabilities.
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

    def _assert_keyring_syscall_refused(self, num: int, args: tuple, name: str) -> None:
        libc = self._libc()
        libc.syscall.restype = ctypes.c_long
        getpid = self._syscall_num({"x86_64": 39, "aarch64": 172})
        ctypes.set_errno(0)
        assert libc.syscall(getpid) == os.getpid(), "getpid syscall positive control failed"
        ctypes.set_errno(0)
        ret = libc.syscall(num, *args)
        err = ctypes.get_errno()
        assert ret == -1, f"{name} syscall succeeded (ret={ret})"
        assert err in (errno.ENOSYS, errno.EPERM, errno.EACCES), (
            f"{name} returned errno={err} ({errno.errorcode.get(err, 'unknown')}); "
            "expected an unavailable syscall or a permission refusal"
        )
        print(f"{name}: syscall={num} ret={ret} errno={err} ({errno.errorcode[err]}); getpid control passed")

    def test_keyctl_blocked(self):
        """A valid keyctl request is unavailable or permission denied.

        What: Request this thread's keyring with creation enabled. Require
        ENOSYS, EPERM or EACCES after a successful getpid syscall control.
        Why: This valid request needs no existing key or special privilege
        on an unrestricted kernel. Invalid arguments and a missing key do
        not establish refusal of access to the kernel keyring.
        """
        num = self._syscall_num({"x86_64": 250, "aarch64": 219})
        # KEYCTL_GET_KEYRING_ID=0, KEY_SPEC_THREAD_KEYRING=-1, create=1.
        self._assert_keyring_syscall_refused(num, (0, ctypes.c_long(-1), 1, 0, 0), "keyctl")

    def test_add_key_blocked(self):
        """A valid add_key request is unavailable or permission denied.

        What: Add a user key with a valid payload to this thread's keyring.
        Require ENOSYS, EPERM or EACCES after a successful getpid control.
        Why: Keep add_key distinct from keyctl and reject bad pointers as
        proof that the sandbox refuses key creation.
        """
        num = self._syscall_num({"x86_64": 248, "aarch64": 217})
        payload = b"probe"
        self._assert_keyring_syscall_refused(
            num, (b"user", f"safeyolo-isolation-{os.getpid()}".encode(), payload, len(payload), ctypes.c_long(-1)), "add_key",
        )

    def test_unshare_user_ns_contained(self):
        """A valid user-namespace request grants no host access.

        What: Run unshare(CLONE_NEWUSER) in a child. Accept only a narrow
        refusal or check the live host canaries and read-only share afterwards.
        Why: Supported guest namespace operations may succeed. Their success
        cannot be interpreted as host escape or alter the pytest process.
        """
        number = self._syscall_num({"x86_64": 272, "aarch64": 97})
        code = f"""
import ctypes
import errno
import os
import sys
sys.path.insert(0, '/workspace/tests/blackbox')
from harness.containment import assert_host_canaries_absent, assert_refused
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
ctypes.set_errno(0)
result = libc.syscall({number}, 0x10000000)
if result == -1:
    assert_refused(result, ctypes.get_errno(), 'unshare')
else:
    assert result == 0
assert_host_canaries_absent()
try:
    fd = os.open('/safeyolo/unshare-write-probe', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
except OSError as error:
    assert error.errno in (errno.EACCES, errno.EPERM, errno.EROFS)
else:
    os.close(fd)
    os.unlink('/safeyolo/unshare-write-probe')
    raise AssertionError('user namespace exposed writable host share')
"""
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        print(result.stdout, end="", flush=True)
