# Security Verification

Evidence and verification procedures for SafeYolo's security claims. For the security model and properties, see [SECURITY.md](../SECURITY.md).

## Container Security

**Don't trust pre-built images?** Build locally from source:

```bash
docker build -t safeyolo .
```

### Container Hardening

| Aspect | Implementation | Where |
|--------|----------------|-------|
| Base image | `python:3.13-slim` pinned by SHA256 digest | [Dockerfile](../Dockerfile) |
| OS packages | Single package: tmux (no curl, no network tools) | [Dockerfile](../Dockerfile) |
| Python deps | Locked with hashes in `uv.lock` | [uv.lock](../uv.lock) |
| No Docker socket | Container cannot access Docker API | [docker-compose.yml](../docker-compose.yml) |
| Non-root | Runs as host UID/GID via compose | [docker-compose.yml](../docker-compose.yml) |
| Read-only root | `read_only: true` with tmpfs for /tmp | [docker-compose.yml](../docker-compose.yml) |

### What the Container Can Access

- **Mounted volumes only:** `~/.safeyolo/` for config, logs, certs
- **Network:** Listens on configured ports (8080, 9090 by default)
- **No host filesystem:** Cannot read/write outside mounted paths
- **No Docker socket:** Neither proxy nor agent containers have `/var/run/docker.sock` mounted — all Docker operations are performed by the CLI on the host

### Build Verification

```bash
# Build from source
docker build -t safeyolo:local .

# Verify digest matches Dockerfile
docker inspect safeyolo:local --format='{{.Config.Image}}'

# Check no unexpected SUID binaries
docker run --rm safeyolo:local find / -perm -4000 2>/dev/null

# Verify runs as non-root
docker run --rm safeyolo:local id
```

## Automated Security Testing

The [blackbox test suite](../tests/blackbox/) runs container security verification on every CI build using [CDK (Container Development Kit)](https://github.com/cdk-team/CDK):

| Test | Verifies |
|------|----------|
| Non-root execution | UID/GID != 0 |
| No privileged mode | `--privileged` not set |
| No dangerous capabilities | SYS_ADMIN, SYS_MODULE, DAC_READ_SEARCH absent |
| Seccomp enabled | Syscall filtering active |
| No Docker socket | `/var/run/docker.sock` not mounted |
| Network isolation | Direct internet access blocked, DNS blocked, proxy-only egress |

See [`test_runtime_security.py`](../tests/blackbox/runner/test_runtime_security.py) and [`test_sandbox_isolation.py`](../tests/blackbox/runner/test_sandbox_isolation.py).

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
