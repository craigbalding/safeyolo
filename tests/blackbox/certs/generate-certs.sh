#!/bin/bash
#
# Generate test CA and sinkhole certificates for blackbox tests.
#
# Rationale (Ground Truth Testing):
#   The blackbox test harness must mirror SafeYolo's production TLS behavior.
#   In production, SafeYolo verifies upstream certificates against system CAs.
#   For tests, we create a test CA that SafeYolo trusts, and sinkhole presents
#   certificates signed by this CA. No TLS shortcuts, no ssl_insecure flags.
#
# Generated files:
#   ca.crt / ca.key       - Test CA (added to SafeYolo's trust store)
#   sinkhole.crt / .key   - Sinkhole cert (signed by test CA, multi-SAN)
#
# Usage:
#   ./generate-certs.sh           # Generate if missing
#   ./generate-certs.sh --force   # Regenerate all
#

set -e

CERT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$CERT_DIR"

# Check if regeneration requested
if [ "$1" = "--force" ]; then
    rm -f ca.crt ca.key sinkhole.crt sinkhole.key sinkhole.csr
fi

# Skip if certs already exist
if [ -f ca.crt ] && [ -f sinkhole.crt ]; then
    echo "Certificates already exist. Use --force to regenerate."
    exit 0
fi

echo "=== Generating Test CA and Sinkhole Certificates ==="
echo ""
echo "Rationale: Ground truth testing requires real TLS verification."
echo "SafeYolo will verify sinkhole's cert against this test CA,"
echo "mirroring production behavior with public CAs."
echo ""

# 1. Generate Test CA
echo "1. Generating Test CA..."
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes \
    -key ca.key \
    -sha256 \
    -days 3650 \
    -out ca.crt \
    -subj "/CN=SafeYolo Blackbox Test CA/O=SafeYolo Test/C=US"

echo "   Created: ca.crt, ca.key"

# 2. Generate sinkhole certificate with SANs for all test hostnames
echo "2. Generating sinkhole certificate..."

# Create OpenSSL config with SANs
cat > sinkhole-openssl.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = sinkhole
O = SafeYolo Blackbox Test
C = US

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
# All hostnames that sinkhole impersonates in tests
DNS.1 = sinkhole
DNS.2 = api.openai.com
DNS.3 = api.anthropic.com
DNS.4 = api.github.com
DNS.5 = evil.com
DNS.6 = attacker.com
DNS.7 = httpbin.org
DNS.8 = failing.test
DNS.9 = legitimate-api.com
DNS.10 = localhost
EOF

# Generate key and CSR
openssl genrsa -out sinkhole.key 2048
openssl req -new \
    -key sinkhole.key \
    -out sinkhole.csr \
    -config sinkhole-openssl.cnf

# Sign with CA
openssl x509 -req \
    -in sinkhole.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out sinkhole.crt \
    -days 365 \
    -sha256 \
    -extensions v3_req \
    -extfile sinkhole-openssl.cnf

# Cleanup
rm -f sinkhole.csr sinkhole-openssl.cnf ca.srl

echo "   Created: sinkhole.crt, sinkhole.key"
echo ""
echo "=== Certificate Generation Complete ==="
echo ""
echo "Files:"
echo "  ca.crt        - Test CA certificate (mount into SafeYolo, add to trust store)"
echo "  ca.key        - Test CA private key (keep secure, not needed at runtime)"
echo "  sinkhole.crt  - Sinkhole certificate (mount into sinkhole)"
echo "  sinkhole.key  - Sinkhole private key (mount into sinkhole)"
echo ""
echo "The sinkhole cert includes SANs for: api.openai.com, api.anthropic.com,"
echo "evil.com, attacker.com, httpbin.org, and other test hostnames."
