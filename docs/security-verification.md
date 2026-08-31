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
| Admin API listener | Binds directly to `127.0.0.1` without hostname or reverse-DNS resolution, preserving the host-local boundary without making startup depend on the host resolver | [cli/src/safeyolo/mitm_addons/admin_api.py](../cli/src/safeyolo/mitm_addons/admin_api.py) |
| Admin API gating | Bearer token in `~/.safeyolo/data/admin_token`, mode 0600 | [cli/src/safeyolo/mitm_addons/admin_api.py](../cli/src/safeyolo/mitm_addons/admin_api.py), [cli/src/safeyolo/mitm_addons/admin_shield.py](../cli/src/safeyolo/mitm_addons/admin_shield.py) |
| Tokens never in argv | Tokens passed via file paths / env vars, not CLI args | [tests/blackbox/host/security/test_firewall_structural.py](../tests/blackbox/host/security/test_firewall_structural.py) |

## Agent Sandbox

Each agent runs in an isolated sandbox with **no external network interface**.

| Platform | Runtime | Rootfs | Isolation |
|----------|---------|--------|-----------|
| macOS (Apple Silicon) | `safeyolo-vm` on Apple Virtualization.framework | per-agent ext4 disk image | Hardware-backed microVM |
| Linux (x86_64 / arm64) | `runsc` (gVisor) in an unprivileged user namespace | shared directory tree at `~/.safeyolo/share/rootfs-tree/` used as gVisor's OCI `root.path`; a per-agent file-backed overlay persists across stop and run by default; `--ephemeral` selects a memory-backed overlay that is discarded on stop | Sentry-emulated kernel; optional KVM hardware platform |

### Sandbox Hardening

| Aspect | Implementation | Where |
|--------|----------------|-------|
| No external interface | Sandbox netns has only loopback (Linux); VM has no virtio-net (macOS) | [cli/src/safeyolo/platform/linux.py](../cli/src/safeyolo/platform/linux.py), [cli/src/safeyolo/platform/darwin.py](../cli/src/safeyolo/platform/darwin.py) |
| Only egress = proxy UDS | Private per-agent directory mounted read-only at `/safeyolo/proxy`, containing `proxy.sock` | [cli/src/safeyolo/sockets.py](../cli/src/safeyolo/sockets.py) |
| Identity on every flow | Mitmproxy's per-agent `UnixInstance` parses `<ip>_<agent>/proxy.sock` and stamps `client.peername = (ip, 0)` | [`proxy_modes/unix_listener.py`](../cli/src/safeyolo/proxy_modes/unix_listener.py) |
| Rootless on Linux | `runsc` runs inside an unprivileged userns (`newuidmap`/`newgidmap`); zero sudo at agent-run time | [cli/src/safeyolo/platform/linux.py](../cli/src/safeyolo/platform/linux.py) |
| Agent and guest-root identities | Starts as uid 1000; Linux may intentionally enter sandbox uid 0 for package installation. Userns maps uid 1000 to the operator and uid 0 to subordinate host uid 100000, never host root | [cli/src/safeyolo/platform/linux.py](../cli/src/safeyolo/platform/linux.py) |
| Capability boundary | The Linux OCI process receives the capabilities needed for guest init and namespace-root package management, but no CAP_SYS_ADMIN; host authority remains bounded by the outer userns and gVisor | [cli/src/safeyolo/platform/linux.py](../cli/src/safeyolo/platform/linux.py) |
| Read-only config share | `/safeyolo` mounted `ro` | [cli/src/safeyolo/vm.py](../cli/src/safeyolo/vm.py) |
| Rootfs overlay (Linux) | Shared directory tree at `~/.safeyolo/share/rootfs-tree/` used as gVisor's OCI `root.path`; the default per-agent file-backed overlay persists across stop and run; `--ephemeral` selects a memory-backed overlay that is discarded on stop | [guest/build-rootfs.sh](../guest/build-rootfs.sh), [cli/src/safeyolo/platform/linux.py](../cli/src/safeyolo/platform/linux.py) |

### Build Verification

Build everything from source (no pre-built images):

```bash
# Build the guest rootfs and kernel artefacts
cd guest && ./build-all.sh && cd ..
# `sudo cp -a` preserves the uid-100000 tree ownership required by
# rootless gVisor on Linux; a plain cp would chown-to-you and break
# the sandbox.
mkdir -p ~/.safeyolo/share && sudo cp -a guest/out/* ~/.safeyolo/share/

# Install the CLI + proxy dependencies from the hash-pinned lockfile
uv sync --all-packages --frozen

# macOS only: the Swift VM helper
cd vm && make install && cd ..
```

Verify the shipped artefacts:

```bash
# Linux: directory tree at ~/.safeyolo/share/rootfs-tree/ used as
# gVisor's OCI root.path. Content is not a single hashable artefact;
# spot-check with a manifest walk.
find ~/.safeyolo/share/rootfs-tree -type f | wc -l   # Linux

# macOS: single ext4 image consumed by Apple Virtualization.framework
sha256sum ~/.safeyolo/share/rootfs-base.ext4         # macOS

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

Policy-file assurance is scoped separately in
[Policy File Assurance: Threat-Model Decision](policy-assurance-threat-model.md).
Because agents cannot directly write the host-owned policy file, that strategy
prioritizes semantic permission deltas, cross-agent isolation, concurrent
mutation integrity, and fail-closed behavior over generic parser fuzzing.

Focused policy transaction and budget regressions run in normal pytest
discovery. The broader deterministic campaign runs nightly or manually through
`.github/workflows/policy-chaos.yml` and retains machine-readable evidence:

```bash
uv run python -m tools.policy_chaos run \
  --published-seeds --output /tmp/policy-chaos.json
```

The default command creates only temporary policies. Abrupt-VM-death checks use
the separately guarded `fault prepare-power-cut` / `fault recover` protocol on
disposable KVM VPS guests. Those results are evidence about guest VM death,
not a claim about physical storage power-loss durability.

Before its old/new policy oracle runs, fault mode snapshots every referenced
`[lists]` file and rewrites only the disposable oracle copies to generated
paths inside the temporary directory. Relative, nested, absolute, and symlinked
source declarations keep their production lookup semantics without becoming
oracle write targets. A missing, unreadable, invalid, or conflicting dependency
ends the command with a named `INFRASTRUCTURE_ERROR`; the oracle never falls
back to an all-deny policy or re-reads a live source list after snapshotting.

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
| Guest-root containment | macOS rejects direct `setuid(0)`; Linux permits namespace-root but verifies its subordinate host uid mapping, read-only host shares, host network isolation, device isolation, and PID isolation |
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
| Policy engine | [policy_engine.py](../cli/src/safeyolo/mitm_addons/policy_engine.py) |
| Credential detection | [credential_guard.py](../cli/src/safeyolo/mitm_addons/credential_guard.py) |
| Credential type mapping | [detection/credentials.py](../cli/src/safeyolo/detection/credentials.py) |
| HMAC fingerprinting | [detection/matching.py](../cli/src/safeyolo/detection/matching.py) |
| Shannon entropy | [detection/credentials.py](../cli/src/safeyolo/detection/credentials.py) |
| Budget tracking | [budget_tracker.py](../cli/src/safeyolo/policy/budget_tracker.py) |
| Homoglyph detection | [network_guard.py](../cli/src/safeyolo/mitm_addons/network_guard.py) |
| Circuit breaker | [circuit_breaker.py](../cli/src/safeyolo/mitm_addons/circuit_breaker.py) |
| Service gateway | [service_gateway.py](../cli/src/safeyolo/mitm_addons/service_gateway.py) |
| Admin API auth | [admin_api.py](../cli/src/safeyolo/mitm_addons/admin_api.py) |
| Request ID | [request_id.py](../cli/src/safeyolo/mitm_addons/request_id.py) |
| Request logging | [request_logger.py](../cli/src/safeyolo/mitm_addons/request_logger.py) |
| Production addon startup | [traffic_master.py](../cli/src/safeyolo/traffic_master.py) and [mitm_addons](../cli/src/safeyolo/mitm_addons/__init__.py) |
| Blackbox tests | [tests/blackbox/](../tests/blackbox/) |
| Policy assurance threat model | [policy-assurance-threat-model.md](policy-assurance-threat-model.md) |
