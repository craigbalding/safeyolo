# TLS Certificate Management

This document explains how SafeYolo's TLS interception works, the security implications, and how to handle edge cases like certificate pinning.

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
├── mitmproxy-ca-cert.pem    # Public certificate (install this)
├── mitmproxy-ca-cert.cer    # Same cert in DER format
├── mitmproxy-ca.pem         # Private key (NEVER share this)
└── mitmproxy-ca.p12         # PKCS12 bundle
```

This CA is unique to your installation. Unlike commercial root CAs, it cannot be used by anyone else to intercept your traffic - unless they obtain your private key.

## Installing the CA

```bash
# Interactive installation with auto-detection
safeyolo cert install

# See what would happen without making changes
safeyolo cert install --dry-run

# View certificate details
safeyolo cert show
```

### Manual installation

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ~/.safeyolo/certs/mitmproxy-ca-cert.pem
```

**Linux (Debian/Ubuntu):**
```bash
sudo cp ~/.safeyolo/certs/mitmproxy-ca-cert.pem \
  /usr/local/share/ca-certificates/safeyolo.crt
sudo update-ca-certificates
```

**Linux (RHEL/CentOS/Fedora):**
```bash
sudo cp ~/.safeyolo/certs/mitmproxy-ca-cert.pem \
  /etc/pki/ca-trust/source/anchors/safeyolo.crt
sudo update-ca-trust
```

**Windows:**
```powershell
certutil -addstore -f ROOT $HOME\.safeyolo\certs\mitmproxy-ca-cert.pem
```

## Removing the CA

When you're done using SafeYolo, remove the CA from your trust store:

```bash
safeyolo cert uninstall
```

Or manually:

**macOS:**
```bash
sudo security delete-certificate -c mitmproxy /Library/Keychains/System.keychain
```

**Linux:**
```bash
sudo rm /usr/local/share/ca-certificates/safeyolo.crt  # Debian
sudo rm /etc/pki/ca-trust/source/anchors/safeyolo.crt  # RHEL
sudo update-ca-certificates  # or update-ca-trust
```

**Windows:**
Open `certmgr.msc` > Trusted Root Certification Authorities > Certificates > find "mitmproxy" > Delete

## Security Considerations

### What you're trusting

Installing a root CA means your system will trust any certificate signed by that CA. For SafeYolo:

- The CA is **locally generated** and unique to your machine
- Only someone with access to `~/.safeyolo/certs/mitmproxy-ca.pem` could abuse it
- SafeYolo only runs locally - it's not exposed to the network

### Best practices

1. **Only install on development machines** - Never on production or shared systems
2. **Keep the private key secure** - Don't commit it, don't share it
3. **Remove when not using SafeYolo** - Reduce your trust surface
4. **Use chokepoint mode for untrusted code** - Prevents bypass attempts

### Comparison to other proxies

This is the standard approach used by:
- mitmproxy (SafeYolo is built on this)
- Fiddler (uses "DO_NOT_TRUST_FiddlerRoot" as a reminder)
- Charles Proxy
- OWASP ZAP

For deeper technical details, see mitmproxy's excellent documentation:
https://docs.mitmproxy.org/stable/concepts-certificates/

## Certificate Pinning

Some applications embed expected certificate fingerprints ("pinning") and will refuse connections even when your system trusts the SafeYolo CA.

### Symptoms

- SSL errors only for specific apps/domains
- "Certificate verification failed" even after installing CA
- Apps work without proxy but fail through SafeYolo

### Solutions

**Option 1: Exclude the domain (recommended for non-essential hosts)**

Add to your config:

```yaml
# In ~/.safeyolo/config.yaml
tls_passthrough:
  - pinned-app.example.com
  - another-pinned-domain.com
```

Traffic to these domains passes through encrypted without inspection.

**Option 2: Disable pinning in the app (if you control it)**

For development, many apps have flags to disable pinning:
- `NODE_TLS_REJECT_UNAUTHORIZED=0` (Node.js - use carefully)
- `--ignore-certificate-errors` (Chrome/Electron)
- App-specific debug flags

**Option 3: Accept limited visibility**

If you can't disable pinning and the host isn't essential to inspect, use passthrough. SafeYolo will still log that a connection was made, just not its contents.

### Common pinned applications

- Some mobile apps (when testing via proxy)
- Electron apps with embedded pinning
- Corporate security tools
- Some Google services

## Docker Containers

Containers need the CA installed separately from the host:

```yaml
# docker-compose.yml
services:
  myapp:
    volumes:
      - ~/.safeyolo/certs/mitmproxy-ca-cert.pem:/usr/local/share/ca-certificates/safeyolo.crt:ro
    # For Debian-based images, run update-ca-certificates in entrypoint
```

For images that need explicit cert paths:
```bash
curl --cacert /usr/local/share/ca-certificates/safeyolo.crt https://example.com
```

Or set the environment variable:
```bash
export SSL_CERT_FILE=/usr/local/share/ca-certificates/safeyolo.crt
export REQUESTS_CA_BUNDLE=/usr/local/share/ca-certificates/safeyolo.crt
```

## Troubleshooting

### "Certificate not trusted" errors

1. Verify CA is installed: `safeyolo check`
2. Check the app uses system trust store (not bundled certs)
3. Try the specific app's cert configuration

### CA installed but HTTPS still fails

1. Some apps need restart after CA changes
2. Check for certificate pinning (see above)
3. Verify proxy is actually being used: `curl -v --proxy http://localhost:8080 https://httpbin.org/ip`

### Different behavior in different apps

Each app may handle certificates differently:
- System apps usually use OS trust store
- Python: uses `certifi` or system certs depending on config
- Node.js: uses system certs by default
- Go: uses system certs
- Java: uses its own keystore (needs separate import)
