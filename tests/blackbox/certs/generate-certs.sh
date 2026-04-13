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
# Generated files (public — in repo, visible to VM):
#   certs/ca.crt          - Test CA certificate
#   certs/sinkhole.crt    - Sinkhole certificate
#
# Generated files (private — outside repo, NOT visible to VM):
#   ~/.safeyolo/test-certs/ca.key          - Test CA private key
#   ~/.safeyolo/test-certs/sinkhole.key    - Sinkhole private key
#
# Why the split:
#   The workspace is mounted into agent VMs via VirtioFS. Private keys in
#   the repo tree would be accessible to the agent — violating the security
#   contract that blackbox tests verify. Keeping keys outside the repo
#   ensures the key isolation test passes for the right reason.
#
# Usage:
#   ./generate-certs.sh           # Generate if missing
#   ./generate-certs.sh --force   # Regenerate all
#

set -e

CERT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEY_DIR="$HOME/.safeyolo/test-certs"
mkdir -p "$KEY_DIR"

cd "$CERT_DIR"

# Check if regeneration requested
if [ "$1" = "--force" ]; then
    rm -f ca.crt sinkhole.crt sinkhole.csr
    rm -f "$KEY_DIR/ca.key" "$KEY_DIR/sinkhole.key"
fi

# Skip if certs already exist
if [ -f ca.crt ] && [ -f sinkhole.crt ] && [ -f "$KEY_DIR/ca.key" ] && [ -f "$KEY_DIR/sinkhole.key" ]; then
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
openssl genrsa -out "$KEY_DIR/ca.key" 4096
openssl req -x509 -new -nodes \
    -key "$KEY_DIR/ca.key" \
    -sha256 \
    -days 3650 \
    -out ca.crt \
    -subj "/CN=SafeYolo Blackbox Test CA/O=SafeYolo Test/C=US"

echo "   Created: ca.crt (public), ~/.safeyolo/test-certs/ca.key (private)"

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
IP.1 = 127.0.0.1
EOF

# Generate key and CSR
openssl genrsa -out "$KEY_DIR/sinkhole.key" 2048
openssl req -new \
    -key "$KEY_DIR/sinkhole.key" \
    -out sinkhole.csr \
    -config sinkhole-openssl.cnf

# Sign with CA
openssl x509 -req \
    -in sinkhole.csr \
    -CA ca.crt \
    -CAkey "$KEY_DIR/ca.key" \
    -CAcreateserial \
    -out sinkhole.crt \
    -days 365 \
    -sha256 \
    -extensions v3_req \
    -extfile sinkhole-openssl.cnf

# Cleanup temporaries
rm -f sinkhole.csr sinkhole-openssl.cnf ca.srl

# Remove any legacy key files from the repo directory
rm -f ca.key sinkhole.key

echo "   Created: sinkhole.crt (public), ~/.safeyolo/test-certs/sinkhole.key (private)"
echo ""
echo "=== Certificate Generation Complete ==="
echo ""
echo "Public (in repo — visible to VM):"
echo "  $CERT_DIR/ca.crt"
echo "  $CERT_DIR/sinkhole.crt"
echo ""
echo "Private (outside repo — NOT visible to VM):"
echo "  $KEY_DIR/ca.key"
echo "  $KEY_DIR/sinkhole.key"
echo ""
echo "The sinkhole cert includes SANs for: api.openai.com, api.anthropic.com,"
echo "evil.com, attacker.com, httpbin.org, localhost, 127.0.0.1, and other test hostnames."
