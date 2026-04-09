# Blackbox Test Certificates

## Rationale: Ground Truth Testing

The blackbox test harness is **ground truth** — it mirrors SafeYolo's production TLS behavior exactly:

- **Production**: SafeYolo verifies upstream certificates against system CAs (DigiCert, Let's Encrypt, etc.)
- **Tests**: SafeYolo verifies sinkhole's certificate against the test CA

No shortcuts:
- No `ssl_insecure=true` flags
- No skipping TLS verification
- No self-signed certificates generated on-the-fly

## File Layout

Private keys are stored **outside the repo tree** so they are never visible inside agent VMs (the workspace is mounted via VirtioFS).

| File | Location | Purpose |
|------|----------|---------|
| `ca.crt` | `tests/blackbox/certs/` (repo) | Test CA certificate — trusted by proxy via `--test` mode |
| `sinkhole.crt` | `tests/blackbox/certs/` (repo) | Sinkhole certificate — signed by test CA, multi-SAN |
| `ca.key` | `~/.safeyolo/test-certs/` (host) | Test CA private key — used to sign sinkhole cert |
| `sinkhole.key` | `~/.safeyolo/test-certs/` (host) | Sinkhole private key |

## How It Works

1. `run-tests.sh` calls `generate-certs.sh --force` on every run
2. Keys are written to `~/.safeyolo/test-certs/`, public certs to `tests/blackbox/certs/`
3. Any legacy `.key` files in the repo directory are deleted
4. The proxy starts in test mode (`safeyolo start --test`), which trusts the test CA
5. The sinkhole loads its cert and key from the respective locations
6. When tests make HTTPS requests through the proxy:
   - Proxy terminates client TLS (using mitmproxy CA)
   - Proxy connects to sinkhole over HTTPS
   - Proxy verifies sinkhole's cert against test CA

## SANs

The sinkhole cert includes SANs for all test hostnames:
- `api.openai.com`, `api.anthropic.com`, `api.github.com`
- `evil.com`, `attacker.com`, `httpbin.org`, `failing.test`, `legitimate-api.com`
- `localhost`, `127.0.0.1` (IP SAN for direct connections)

## Regenerating

```bash
./generate-certs.sh --force
```

This happens automatically on every `run-tests.sh` invocation.

## Security

Private keys never enter the repo tree or the VM workspace. The `test_full_filesystem_scan_for_private_keys` isolation test verifies this on every run.
