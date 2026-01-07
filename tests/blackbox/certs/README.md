# Blackbox Test Certificates

## Rationale: Ground Truth Testing

The blackbox test harness is **ground truth** - it must mirror SafeYolo's production TLS behavior exactly:

- **Production**: SafeYolo verifies upstream certificates against system CAs (DigiCert, Let's Encrypt, etc.)
- **Tests**: SafeYolo verifies sinkhole's certificate against the test CA

No shortcuts:
- No `ssl_insecure=true` flags
- No skipping TLS verification
- No self-signed certificates generated on-the-fly

## Design Principle: Never Duplicate Production Logic

The blackbox test uses the **same `start-safeyolo.sh` script** as production, configured via
environment variables:

- `SAFEYOLO_HEADLESS=true` - Use mitmdump (no tmux/TUI)
- `SAFEYOLO_CA_CERT=/test-ca/ca.crt` - Trust test CA for upstream connections

This ensures tests always mirror production behavior. Any fix to production TLS handling
automatically applies to tests.

## Files

| File | Purpose |
|------|---------|
| `ca.crt` | Test CA certificate - trusted via SAFEYOLO_CA_CERT env var |
| `ca.key` | Test CA private key - used to sign sinkhole cert (not needed at runtime) |
| `sinkhole.crt` | Sinkhole's certificate - signed by test CA, includes all test hostnames as SANs |
| `sinkhole.key` | Sinkhole's private key |

## How It Works

1. **Test CA** is created once and committed to repo
2. **Sinkhole cert** is signed by test CA with SANs for all test hostnames:
   - api.openai.com, api.anthropic.com, evil.com, attacker.com, httpbin.org, etc.
3. At test startup:
   - SafeYolo runs as non-root (uid 1000) - matching production
   - `start-safeyolo.sh` sees `SAFEYOLO_CA_CERT=/test-ca/ca.crt`
   - Sets `SSL_CERT_FILE` to trust test CA for upstream connections
   - Sinkhole cert/key are mounted into sinkhole container
4. When tests make HTTPS requests:
   - SafeYolo terminates client TLS (using mitmproxy CA)
   - SafeYolo connects to sinkhole over HTTPS
   - SafeYolo verifies sinkhole's cert against test CA ✓

## Regenerating Certificates

```bash
./generate-certs.sh --force
```

This is only needed if:
- Adding new test hostnames (update SANs in script)
- Certificates expired (valid for 10 years)
- Compromised (test environment only, low risk)

## Security Note

These certificates are for **testing only**. The CA private key is committed to the repo,
which is acceptable because:
- Test CA is only trusted within the isolated Docker test network
- No production systems trust this CA
- The CA is clearly named "SafeYolo Blackbox Test CA"
