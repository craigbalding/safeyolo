# TLS Certificate Management

This document explains how SafeYolo's TLS interception works and how to configure CA trust.

## How TLS Interception Works

SafeYolo is a TLS-intercepting (MITM) proxy. When you make an HTTPS request through SafeYolo:

1. Your client connects to SafeYolo and sends a CONNECT request
2. SafeYolo establishes a TLS connection with you using a certificate it generates on-the-fly
3. SafeYolo connects to the real server and establishes a separate TLS session
4. SafeYolo can now see the decrypted traffic between both endpoints

For this to work without SSL errors, your client must trust the Certificate Authority (CA) that SafeYolo uses to sign its on-the-fly certificates.

## The SafeYolo CA

On first run, SafeYolo generates a **unique, local CA** stored in `~/.safeyolo/certs/`:

```
~/.safeyolo/certs/
├── mitmproxy-ca-cert.pem    # Public certificate
├── mitmproxy-ca-cert.cer    # Same cert in DER format
├── mitmproxy-ca.pem         # Private key (NEVER share this)
└── mitmproxy-ca.p12         # PKCS12 bundle
```

This CA is unique to your installation. Only someone with access to the private key could abuse it.

## Per-Process CA Trust (Recommended)

SafeYolo uses per-process environment variables for CA trust. This avoids modifying your system trust store:

```bash
eval $(safeyolo cert env)
```

This sets:

```bash
# CA trust (per-process, not system-wide)
export NODE_EXTRA_CA_CERTS=~/.safeyolo/certs/mitmproxy-ca-cert.pem
export REQUESTS_CA_BUNDLE=~/.safeyolo/certs/mitmproxy-ca-cert.pem
export SSL_CERT_FILE=~/.safeyolo/certs/mitmproxy-ca-cert.pem
export GIT_SSL_CAINFO=~/.safeyolo/certs/mitmproxy-ca-cert.pem

# Proxy settings
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
```

These environment variables configure:
- **Node.js** - via `NODE_EXTRA_CA_CERTS`
- **Python requests/httpx** - via `REQUESTS_CA_BUNDLE`
- **OpenSSL/curl** - via `SSL_CERT_FILE`
- **Git** - via `GIT_SSL_CAINFO`

### Benefits of per-process trust

1. **No sudo required** - No system-wide changes
2. **Scoped** - Only affects your current shell session
3. **Reversible** - Close the terminal and trust is gone
4. **Safe** - Can't accidentally leave CA installed

## Docker Containers (Sandbox Mode)

For Sandbox Mode, SafeYolo automatically mounts the CA certificate into agent containers and sets the environment variables. The docker-compose templates handle this:

```yaml
volumes:
  - safeyolo-certs:/certs:ro
environment:
  - NODE_EXTRA_CA_CERTS=/certs/mitmproxy-ca-cert.pem
  - SSL_CERT_FILE=/certs/mitmproxy-ca-cert.pem
  - REQUESTS_CA_BUNDLE=/certs/mitmproxy-ca-cert.pem
```

Use `safeyolo secure setup` to generate properly configured templates.

## Certificate Pinning

Some applications embed expected certificate fingerprints ("pinning") and will refuse connections even with the CA configured.

### Symptoms

- SSL errors only for specific apps/domains
- "Certificate verification failed" even with CA env vars set
- Apps work without proxy but fail through SafeYolo

### Solutions

**Option 1: TLS passthrough (recommended)**

Add to your config to skip inspection for pinned domains:

```yaml
# In ~/.safeyolo/config.yaml
tls_passthrough:
  - pinned-app.example.com
  - another-pinned-domain.com
```

Traffic passes through encrypted without inspection. SafeYolo still logs the connection.

**Option 2: Disable pinning in the app**

For development, some apps have flags to disable pinning:
- `NODE_TLS_REJECT_UNAUTHORIZED=0` (Node.js - use carefully)
- `--ignore-certificate-errors` (Chrome/Electron)
- App-specific debug flags

## Security Considerations

### What you're trusting

The SafeYolo CA is:
- **Locally generated** and unique to your machine
- **Private** - only someone with access to `~/.safeyolo/certs/mitmproxy-ca.pem` could abuse it
- **Scoped** - per-process env vars don't affect other applications

### Best practices

1. **Keep the private key secure** - Don't commit it, don't share it
2. **Use Sandbox Mode for autonomous agents** - Prevents bypass attempts
3. **Use per-process trust** - Avoid system-wide CA installation

## Troubleshooting

### "Certificate not trusted" errors

1. Verify env vars are set: `echo $SSL_CERT_FILE`
2. Re-run: `eval $(safeyolo cert env)`
3. Check if app uses bundled certs instead of system/env certs

### Different behavior in different apps

Each app handles certificates differently:
- **Python requests** - Uses `REQUESTS_CA_BUNDLE` or `certifi`
- **Node.js** - Uses `NODE_EXTRA_CA_CERTS`
- **Go** - Uses `SSL_CERT_FILE` or system certs
- **Java** - Uses its own keystore (may need separate configuration)
- **curl** - Uses `SSL_CERT_FILE` or `--cacert` flag

### Viewing certificate details

```bash
safeyolo cert show
```

Shows certificate location, fingerprint, and file size.

## Reference

This is the same approach used by:
- mitmproxy (SafeYolo is built on this)
- Fiddler
- Charles Proxy
- OWASP ZAP

For deeper technical details, see mitmproxy's documentation:
https://docs.mitmproxy.org/stable/concepts-certificates/
