# Security Verification

Evidence and verification procedures for SafeYolo's security claims. For the security model and properties, see [SECURITY.md](../SECURITY.md).

## Proxy Process

mitmproxy runs as a host process — not in a container. The proxy's
integrity depends on pinned dependencies and the guest images it
provisions to sandboxes.

### Proxy Hardening

| Aspect | Implementation | Where |
|--------|----------------|-------|
| Python deps | Locked with hashes in `uv.lock` (hash-pinned, `--frozen`) | [uv.lock](../uv.lock) |
| mitmproxy version | Pinned in `pyproject.toml` | [pyproject.toml](../pyproject.toml) |
| No root at runtime | Started by the operator, runs as the operator's uid | n/a |
| Bind address | Loopback by default; listen host configurable | [cli/src/safeyolo/proxy.py](../cli/src/safeyolo/proxy.py) |
| Admin API gating | Bearer token in `~/.safeyolo/data/admin_token`, mode 0600 | [addons/admin_api.py](../addons/admin_api.py), [addons/admin_shield.py](../addons/admin_shield.py) |
| Tokens never in argv | Tokens passed via file paths / env vars, not CLI args | [tests/blackbox/host/security/test_firewall_structural.py](../tests/blackbox/host/security/test_firewall_structural.py) |

## Agent Sandbox

Each agent runs in an isolated sandbox with **no external network interface**.

| Platform | Runtime | Rootfs | Isolation |
|----------|---------|--------|-----------|
| macOS (Apple Silicon) | `safeyolo-vm` on Apple Virtualization.framework | per-agent ext4 disk image | Hardware-backed microVM |
| Linux (x86_64 / arm64) | `runsc` (gVisor) in an unprivileged user namespace | single shared EROFS image, memory-backed writable overlay | Sentry-emulated kernel; optional KVM hardware platform |

### Sandbox Hardening

| Aspect | Implementation | Where |
|--------|----------------|-------|
| No external interface | Sandbox netns has only loopback (Linux); VM has no virtio-net (macOS) | [cli/src/safeyolo/platform/linux.py](../cli/src/safeyolo/platform/linux.py), [cli/src/safeyolo/platform/darwin.py](../cli/src/safeyolo/platform/darwin.py) |
| Only egress = proxy UDS | Per-agent Unix socket bind-mounted at `/safeyolo/proxy.sock` inside the sandbox | [cli/src/safeyolo/proxy_bridge.py](../cli/src/safeyolo/proxy_bridge.py) |
| Identity on every flow | PROXY protocol v2 header stamped by the bridge; parsed by `next_layer` addon | [addons/proxy_protocol.py](../addons/proxy_protocol.py) |
| Rootless on Linux | `runsc` runs inside an unprivileged userns (`newuidmap`/`newgidmap`); zero sudo at agent-run time | [cli/src/safeyolo/platform/linux.py](../cli/src/safeyolo/platform/linux.py) |
| Agent user | Runs as uid 1000 inside the sandbox; host operator uid maps to 1000 via userns | [guest/rootfs-customize-hook.sh](../guest/rootfs-customize-hook.sh) |
| Minimal capabilities | CAP_CHOWN / CAP_DAC_OVERRIDE / CAP_NET_ADMIN for init only — no CAP_NET_RAW, no CAP_SYS_ADMIN | [cli/src/safeyolo/platform/linux.py](../cli/src/safeyolo/platform/linux.py) |
| Read-only config share | `/safeyolo` mounted `ro` | [cli/src/safeyolo/vm.py](../cli/src/safeyolo/vm.py) |
| Read-only rootfs (Linux) | EROFS image; writable overlay lives in gVisor's sentry, not on disk | [guest/build-rootfs.sh](../guest/build-rootfs.sh) |

### Build Verification

Build everything from source (no pre-built images):

```bash
# Build the guest rootfs and kernel artefacts
cd guest && ./build-all.sh && cd ..
mkdir -p ~/.safeyolo/share && cp guest/out/* ~/.safeyolo/share/

# Install the CLI + proxy dependencies from the hash-pinned lockfile
uv sync --all-packages --frozen

# macOS only: the Swift VM helper
cd vm && make install && cd ..
```

Verify the shipped artefacts:

```bash
# Hash-check the EROFS rootfs (Linux) or ext4 image (macOS)
sha256sum ~/.safeyolo/share/rootfs-base.erofs     # Linux
sha256sum ~/.safeyolo/share/rootfs-base.ext4      # macOS

# See what the proxy is actually running with (tokens never appear here)
pgrep -a mitmdump

# Host-level prerequisites + current sandbox runtime detection
safeyolo setup       # apply one-time config (AppArmor, /dev/kvm udev rule)
safeyolo doctor      # full health check; reports runtime, isolation
                     # platform (KVM vs systrap), userns prerequisites,
                     # guest images, running agents
```

## Automated Security Testing

The [blackbox test suite](../tests/blackbox/) verifies SafeYolo's security guarantees end-to-end using real microVMs. Tests are split across two domains:

**Host-side proxy tests** (`tests/blackbox/host/`):

| Test | Verifies |
|------|----------|
| Credential routing | API keys only forwarded to authorized hosts |
| Credential blocking | Exfiltration attempts blocked, sinkhole receives nothing |
| Access control | Allowed domains pass, rate limits enforced |
| Header stripping | Proxy-Authorization removed before forwarding |

**VM-side isolation tests** (`tests/blackbox/isolation/`):

| Test | Verifies |
|------|----------|
| Non-root execution | `setuid(0)` fails with PermissionError |
| Network isolation | Direct HTTP/HTTPS/DNS blocked, proxy-only egress |
| Kernel modules disabled | `init_module` syscall returns ENOSYS |
| No /dev/mem | Physical memory device does not exist |
| No eBPF | BPF syscall blocked |
| Key isolation | No private key material anywhere in the VM filesystem |
| Config share read-only | Agent cannot write to /safeyolo mount |

See [`test_vm_isolation.py`](../tests/blackbox/isolation/test_vm_isolation.py) and [`test_key_isolation.py`](../tests/blackbox/isolation/test_key_isolation.py).

## Dependency Trust

Direct and transitive dependencies evaluated for security posture. Last reviewed: 2026-01-05.

### Direct Dependencies

| Package | Trust | Notes |
|---------|-------|-------|
| mitmproxy | HIGH | Core dependency. Security-focused project, well-audited. |
| httpx | HIGH | Encode org. Widely used async HTTP client. |
| pydantic | HIGH | Very popular validation library. |
| pyyaml | HIGH | Industry standard YAML parser. |
| yarl | HIGH | aio-libs. URL parsing. |
| tenacity | HIGH | Retry library. |
| confusable-homoglyphs | MEDIUM | Homoglyph detection. New maintainer at [sr.ht](https://sr.ht/~valhalla/confusable_homoglyphs/) (2024). No known CVEs. Isolated with try/except fallback. |

### Transitive Dependencies (via mitmproxy)

| Package | Trust | Notes |
|---------|-------|-------|
| publicsuffix2 | MEDIUM | Last release Dec 2019. No CVEs. Works fine, won't have new TLDs. |
| ldap3 | MEDIUM | LDAP library. Used by mitmproxy for NTLM/auth features we don't use. |
| pyperclip | MEDIUM | Clipboard access. Used by mitmproxy's interactive console. Low risk in container. |
| kaitaistruct | MEDIUM | Binary protocol parsing. Kaitai Project. |
| cryptography, tornado, flask, jinja2 | HIGH | Well-maintained. All pinned versions patched against known CVEs. |

All installed package versions verified clean against [OSV.dev](https://osv.dev).

## Code Pointers

| Area | Location |
|------|----------|
| Policy engine | [policy_engine.py](../addons/policy_engine.py) |
| Credential detection | [credential_guard.py](../addons/credential_guard.py) |
| Credential type mapping | [detection/credentials.py](../addons/detection/credentials.py) |
| HMAC fingerprinting | [utils.py](../addons/utils.py) |
| Shannon entropy | [detection/credentials.py](../addons/detection/credentials.py) |
| Budget tracking | [budget_tracker.py](../addons/budget_tracker.py) |
| Homoglyph detection | [network_guard.py](../addons/network_guard.py) |
| Circuit breaker | [circuit_breaker.py](../addons/circuit_breaker.py) |
| Service gateway | [service_gateway.py](../addons/service_gateway.py) |
| Admin API auth | [admin_api.py](../addons/admin_api.py) |
| Request ID | [request_id.py](../addons/request_id.py) |
| Request logging | [request_logger.py](../addons/request_logger.py) |
| Startup verification | [start-safeyolo.sh](../scripts/start-safeyolo.sh) |
| Blackbox tests | [tests/blackbox/](../tests/blackbox/) |
