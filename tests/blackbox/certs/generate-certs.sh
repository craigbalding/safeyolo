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
    rm -f test-ca-b.crt test-ca-b-crosssigned.crt ecc_intermediate.crt ecc_leaf.crt ecc_chain.pem
    rm -f "$KEY_DIR/ca.key" "$KEY_DIR/sinkhole.key"
    rm -f "$KEY_DIR/test-ca-b.key" "$KEY_DIR/ecc_intermediate.key" "$KEY_DIR/ecc_chain.key"
fi

# Skip if ALL certs already exist. If any is missing we fall through and
# regenerate from scratch -- dependent artifacts (ECC chain cross-signed by
# ca.key) must be rebuilt when ca.key gets rolled.
if [ -f ca.crt ] && [ -f sinkhole.crt ] \
   && [ -f ecc_chain.pem ] && [ -f test-ca-b-crosssigned.crt ] \
   && [ -f "$KEY_DIR/ca.key" ] && [ -f "$KEY_DIR/sinkhole.key" ] \
   && [ -f "$KEY_DIR/ecc_chain.key" ]; then
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

# ===========================================================================
# Tricky chain #1 - ECC leaf + cross-signed bridge root
#
# Mirrors real-world example.com's chain (Cloudflare/SSL.com/Comodo-AAA
# cross-sign pattern) so SafeYolo's upstream-cert-validation code gets
# exercised against the same shape that has regressed twice:
#
#   leaf (ECDSA P-256)
#     -> ecc_intermediate (ECC issuing CA, analogous to Cloudflare's)
#       -> test-ca-b (ECC root, analogous to SSL.com TLS ECC Root 2022)
#         -> test-ca-b-crosssigned-by-test-ca (bridge to THE trusted root)
#
# SafeYolo trusts only ca.crt. The chain served to sinkhole clients is:
#   [ leaf, ecc_intermediate, test-ca-b-crosssigned-by-test-ca ]
# Validators find the bridge cert, chain up to test-ca, and validate.
# If the bundle merge breaks or chain-builder regresses, validation fails.
#
# SAN: example-chain-test.test  (reserved .test TLD, routed to sinkhole
#      port 18444 by tests/blackbox/harness/sinkhole_router.py)
# ===========================================================================
if [ ! -f ecc_chain.pem ] || [ ! -f "$KEY_DIR/ecc_chain.key" ]; then
    echo "3. Generating ECC cross-signed chain (example.com shape)..."

    # 3a. Secondary root CA (mimics SSL.com's ECC Root 2022 — normally
    #     not directly in SafeYolo's trust bundle).
    openssl ecparam -name prime256v1 -genkey -noout \
        -out "$KEY_DIR/test-ca-b.key"
    openssl req -x509 -new -nodes \
        -key "$KEY_DIR/test-ca-b.key" \
        -sha256 \
        -days 3650 \
        -out test-ca-b.crt \
        -subj "/CN=SafeYolo Blackbox Test ECC Root B/O=SafeYolo Test/C=US"

    # 3b. Cross-sign test-ca-b with the primary trusted CA so chains
    #     served by sinkhole can reach ca.crt via the bridge.
    #     openssl x509 -req reuses the public key from test-ca-b.crt
    #     but issues a fresh cert signed by ca.key.
    cat > test-ca-b-crosssign.cnf << 'EOF'
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
EOF
    openssl x509 -req \
        -in <(openssl x509 -x509toreq -signkey "$KEY_DIR/test-ca-b.key" -in test-ca-b.crt) \
        -CA ca.crt -CAkey "$KEY_DIR/ca.key" -CAcreateserial \
        -days 3650 -sha256 \
        -extensions v3_ca -extfile test-ca-b-crosssign.cnf \
        -out test-ca-b-crosssigned.crt
    rm -f test-ca-b-crosssign.cnf

    # 3c. ECC issuing intermediate (analogous to Cloudflare's ECC CA),
    #     signed by test-ca-b.
    openssl ecparam -name prime256v1 -genkey -noout \
        -out "$KEY_DIR/ecc_intermediate.key"
    cat > ecc_intermediate.cnf << 'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = SafeYolo Blackbox ECC Issuing CA
O = SafeYolo Test
C = US
[v3_int]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
EOF
    openssl req -new -key "$KEY_DIR/ecc_intermediate.key" \
        -out ecc_intermediate.csr -config ecc_intermediate.cnf
    openssl x509 -req \
        -in ecc_intermediate.csr \
        -CA test-ca-b.crt -CAkey "$KEY_DIR/test-ca-b.key" -CAcreateserial \
        -days 3650 -sha256 \
        -extensions v3_int -extfile ecc_intermediate.cnf \
        -out ecc_intermediate.crt
    rm -f ecc_intermediate.csr ecc_intermediate.cnf

    # 3d. ECDSA P-256 leaf with SAN for example-chain-test.test.
    openssl ecparam -name prime256v1 -genkey -noout \
        -out "$KEY_DIR/ecc_chain.key"
    cat > ecc_leaf.cnf << 'EOF'
[req]
distinguished_name = dn
req_extensions = v3_leaf
prompt = no
[dn]
CN = example-chain-test.test
O = SafeYolo Blackbox Test
C = US
[v3_leaf]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @sans
[sans]
DNS.1 = example-chain-test.test
DNS.2 = *.example-chain-test.test
# IP SAN: the sinkhole_router rewrites flow.request.host to
# 127.0.0.1 before mitmproxy's upstream TLS verify runs, so the
# cert must include 127.0.0.1 as an IP SAN or mitmproxy reports
# "Certificate verify failed: IP address mismatch". Same trick the
# default sinkhole.crt uses.
IP.1 = 127.0.0.1
EOF
    openssl req -new -key "$KEY_DIR/ecc_chain.key" \
        -out ecc_leaf.csr -config ecc_leaf.cnf
    openssl x509 -req \
        -in ecc_leaf.csr \
        -CA ecc_intermediate.crt -CAkey "$KEY_DIR/ecc_intermediate.key" -CAcreateserial \
        -days 365 -sha256 \
        -extensions v3_leaf -extfile ecc_leaf.cnf \
        -out ecc_leaf.crt
    rm -f ecc_leaf.csr ecc_leaf.cnf

    # 3e. Chain PEM served by sinkhole: leaf + intermediate +
    #     cross-signed bridge. Order matters (leaf first).
    cat ecc_leaf.crt ecc_intermediate.crt test-ca-b-crosssigned.crt \
        > ecc_chain.pem

    rm -f ca.srl test-ca-b.srl ecc_intermediate.srl

    echo "   Created: ecc_chain.pem (public, chain: leaf + intermediate + bridge)"
    echo "            ~/.safeyolo/test-certs/ecc_chain.key (private leaf key)"
    echo "   Terminates at ca.crt via cross-signed bridge root."
fi
