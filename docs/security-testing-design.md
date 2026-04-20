# SafeYolo Security Testing Design

## Overview

Security tests run against real infrastructure — real proxy, real
sandbox, real microVM or rootless gVisor container. No mocks, no
Docker, no shortcuts. Every test class has a structured docstring
(Title + Why) and every test function states the probe and the
consequence if the property didn't hold; `docs/blackbox-coverage.md`
is generated from those docstrings.

Tests are split across two execution domains:

- **Host pytest** (`tests/blackbox/host/`): Proxy functional tests and
  agent-identity checks. Runs on the host where sinkhole, admin API,
  and proxy are directly accessible.
- **VM pytest** (`tests/blackbox/isolation/`): Isolation tests. Runs
  inside the sandbox (VZ microVM on macOS, gVisor on Linux) via
  `safeyolo agent shell`, probing from the adversary's perspective.

## Quick Start

```bash
cd tests/blackbox

# Run all tests
./run-tests.sh

# Proxy tests only
./run-tests.sh --proxy

# Isolation tests only
./run-tests.sh --isolation

# Verbose output
./run-tests.sh --verbose
```

## Architecture

```
Host (pytest)                          VM (pytest via SSH)
├── proxy_client → proxy:8080          ├── test_vm_isolation.py
├── sinkhole.get_requests() → :19999   │   ├── setuid(0) fails
├── admin_client → :9090               │   ├── init_module → ENOSYS
└── no VM interaction needed           │   ├── SOCK_RAW → PermissionError
                                       │   └── /dev/mem not found
                                       └── test_key_isolation.py
                                           ├── cert exists & readable
                                           ├── no .key files anywhere
                                           └── full filesystem scan
```

The `run-tests.sh` script orchestrates:
1. Generate test certs (keys stored outside repo tree)
2. Start sinkhole (HTTP/HTTPS capture server)
3. Start proxy in test mode (`safeyolo start --test`)
4. Boot a BYOA microVM with the repo as workspace
5. Run host-side pytest (credential guard, network guard)
6. Run VM-side pytest via `safeyolo agent shell`
7. Cleanup

## Test Suites

### Proxy Functional Tests (host-side)

| File | Tests |
|------|-------|
| `test_credential_guard.py` | Credential routing to authorized hosts, exfiltration blocking, block response content |
| `test_network_guard.py` | Domain access control, rate limiting, Proxy-Authorization stripping |

**Verification method:** The sinkhole captures all upstream traffic. Tests query
the sinkhole control API to verify what *actually reached* the upstream — not
what the proxy said it blocked.

### VM Isolation Tests (in-VM)

| File | Tests |
|------|-------|
| `test_vm_isolation.py` | Network escape (HTTP/HTTPS/DNS/raw socket), privilege escalation (setuid, kernel modules, /dev/mem, eBPF), filesystem isolation |
| `test_key_isolation.py` | Public cert present, no private keys in trust store/config share/full filesystem |

**Verification method:** Direct probes from inside the VM. Tests call syscalls
directly (setuid, init_module, BPF) rather than relying on userspace tools.

## Key Design Decisions

### Host tests verify the proxy, VM tests verify isolation

The host has direct access to the sinkhole control API (port 19999) and admin
API (port 9090). The VM's firewall correctly blocks both — that's a security
property we test, not a problem to work around.

### Private keys outside the repo

Test cert private keys are stored in `~/.safeyolo/test-certs/`, not in the repo
tree. The workspace is mounted into agent VMs via VirtioFS — keys in the repo
would be accessible to agents. The `test_full_filesystem_scan_for_private_keys`
test verifies this on every run.

### Test kernel properties directly

Privilege escalation tests call syscalls directly:
- `os.setuid(0)` — can the agent become root?
- `init_module(2)` — does the kernel support loadable modules?
- `BPF` syscall — is eBPF available?

This tests the actual security property regardless of whether userspace tools
(sudo, modprobe) are installed.

### Ground truth TLS

A dedicated test CA signs the sinkhole certificate. The proxy verifies it the
same way it verifies production certs. No `ssl_insecure` flags. See
[`certs/README.md`](../tests/blackbox/certs/README.md).

## Files

| File | Purpose |
|------|---------|
| `run-tests.sh` | Orchestrator (idempotent, reuses running services) |
| `host/conftest.py` | Host-side fixtures (sinkhole, proxy, admin clients) |
| `host/sinkhole_client.py` | Sinkhole control API client |
| `host/test_credential_guard.py` | Credential routing/blocking tests |
| `host/test_network_guard.py` | Access control, rate limiting tests |
| `isolation/test_vm_isolation.py` | Network escape, privilege escalation tests |
| `isolation/test_key_isolation.py` | Private key isolation tests |
| `harness/sinkhole_router.py` | mitmproxy addon redirecting test traffic to sinkhole |
| `sinkhole/server.py` | HTTP/HTTPS capture server |
| `certs/generate-certs.sh` | Test CA and sinkhole cert generation |
