# Black Box Tests

SafeYolo's trust anchor. These tests prove two things:

1. **SafeYolo does what it claims** — credentials are blocked, domains are enforced, rate limits work
2. **A malicious agent cannot escape** — network bypass, privilege escalation, key theft are tested

If these tests pass, the security contract holds. If they fail, nothing else matters.

## Execution Model

Tests are split across two execution domains:

**Host-side pytest** (`host/`) — proxy functional tests. Runs on the host where
sinkhole, admin API, and proxy are directly accessible on localhost. Sends
requests through the proxy and verifies what the sinkhole captured.

**VM-side pytest** (`isolation/`) — isolation tests. Runs inside a real microVM
via SSH. Probes network escape, privilege escalation, and filesystem isolation
from the adversary's perspective.

```
Host (pytest)                          VM (pytest via SSH)
├── proxy_client → proxy:8080          ├── test_vm_isolation.py
├── sinkhole.get_requests() → :19999   │   ├── curl --noproxy '*' ...
├── admin_client → :9090               │   ├── os.getuid() != 0
└── no VM interaction needed           │   ├── socket.SOCK_RAW fails
                                       │   └── /dev/mem not found
                                       └── test_key_isolation.py
                                           ├── cert exists & readable
                                           ├── no .key files
                                           └── full filesystem scan
```

## Design Principles

**Host tests verify the proxy, VM tests verify isolation.** The host has
access to the sinkhole control API and admin API. The VM's firewall correctly
blocks both — which is a security property we test, not a problem to work around.

**Platform-independent assertions.** Tests assert outcomes, never mechanisms.
`curl --noproxy '*' http://1.1.1.1` fails regardless of whether pf or
iptables dropped it.

**Never duplicate production logic.** Tests use the real proxy, real addons,
real firewall rules, real TLS. No mocks, no shortcuts.

**Ground truth TLS.** A dedicated test CA signs sinkhole certificates.
The proxy verifies these the same way it verifies production certs.
See `certs/README.md`.

## Test Suites

### Proxy Functional Tests (`host/`)

| Test | Attack Scenario | Security Property |
|------|----------------|-------------------|
| Credential to authorized host | Normal operation | Forwarded with credential intact |
| Credential to unauthorized host | Exfiltration attempt | 428 + sinkhole receives nothing |
| Request without credentials | Normal operation | Passes through |
| Allowed domain | Normal operation | 200 response |
| Rate limit within budget | Normal operation | All requests succeed |
| Proxy-Authorization header | Header exfiltration | Stripped before forwarding |
| Block response content | Audit trail | Contains event_id and approval guidance |

### VM Isolation Tests (`isolation/`)

| Test | Attack Vector | Expected Result |
|------|--------------|-----------------|
| Direct HTTP bypass | `curl --noproxy '*' http://1.1.1.1` | Connection dropped |
| Direct HTTPS bypass | `curl --noproxy '*' https://8.8.8.8` | Connection dropped |
| DNS exfiltration | UDP to 8.8.8.8:53 | Blocked |
| Raw socket | `SOCK_RAW` ICMP | PermissionError |
| Proxy reachable | `curl` through proxy | 200 |
| Non-root | `id -u` | 1000 |
| Cannot gain root | `setuid(0)` | PermissionError |
| No kernel modules | `init_module` syscall | ENOSYS |
| No /dev/mem | Check path | Not found |
| No eBPF | BPF syscall | Returns -1 |
| Config share read-only | Write to /safeyolo | EROFS |
| No private keys | Filesystem scan | No PRIVATE KEY found |
| Public cert present | Check trust store | safeyolo.crt exists |

## Running

```bash
# All suites
./run-tests.sh

# Proxy functional tests only (host-side)
./run-tests.sh --proxy

# VM isolation tests only (in-VM)
./run-tests.sh --isolation

# Verbose
./run-tests.sh --verbose
```

## Adding Tests

When adding a new test, ask: *"What would a malicious agent try?"*

- **Proxy tests** go in `host/` — if you need to verify what reached upstream
  via the sinkhole, or test proxy policy decisions
- **Isolation tests** go in `isolation/` — if you're testing what an agent
  can or cannot do from inside the VM
- Assert outcomes, not mechanisms — never reference pf, iptables, or feth
