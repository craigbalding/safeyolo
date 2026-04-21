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
    rm -f rsa_int_b.crt rsa_int_a.crt rsa_deep_leaf.crt rsa_deep_chain.pem
    rm -f nc_intermediate.crt nc_leaf.crt nc_chain.pem
    rm -f extra_int.crt extra_leaf.crt junk_a.crt junk_b.crt extra_chain.pem
    rm -f expired_leaf.crt expired_chain.pem
    rm -f wrong_san_leaf.crt wrong_san_chain.pem
    rm -f self_signed_chain.pem
    rm -f aia_int.crt aia_leaf.crt aia_chain.pem
    rm -f "$KEY_DIR/ca.key" "$KEY_DIR/sinkhole.key"
    rm -f "$KEY_DIR/test-ca-b.key" "$KEY_DIR/ecc_intermediate.key" "$KEY_DIR/ecc_chain.key"
    rm -f "$KEY_DIR/rsa_int_b.key" "$KEY_DIR/rsa_int_a.key" "$KEY_DIR/rsa_deep_chain.key"
    rm -f "$KEY_DIR/nc_intermediate.key" "$KEY_DIR/nc_chain.key"
    rm -f "$KEY_DIR/extra_int.key" "$KEY_DIR/extra_chain.key" "$KEY_DIR/junk_a.key" "$KEY_DIR/junk_b.key"
    rm -f "$KEY_DIR/expired_chain.key" "$KEY_DIR/wrong_san_chain.key" "$KEY_DIR/self_signed_chain.key"
    rm -f "$KEY_DIR/aia_int.key" "$KEY_DIR/aia_chain.key"
fi

# Skip if ALL certs already exist. If any is missing we fall through and
# regenerate from scratch -- dependent artifacts (ECC chain cross-signed by
# ca.key) must be rebuilt when ca.key gets rolled.
if [ -f ca.crt ] && [ -f sinkhole.crt ] \
   && [ -f ecc_chain.pem ] && [ -f test-ca-b-crosssigned.crt ] \
   && [ -f rsa_deep_chain.pem ] && [ -f nc_chain.pem ] \
   && [ -f extra_chain.pem ] && [ -f expired_chain.pem ] \
   && [ -f wrong_san_chain.pem ] && [ -f self_signed_chain.pem ] \
   && [ -f aia_chain.pem ] \
   && [ -f "$KEY_DIR/ca.key" ] && [ -f "$KEY_DIR/sinkhole.key" ] \
   && [ -f "$KEY_DIR/ecc_chain.key" ] && [ -f "$KEY_DIR/aia_chain.key" ]; then
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

# ===========================================================================
# Helper: emit a leaf .cnf with a standard v3_leaf section. Every leaf we
# generate includes 127.0.0.1 as an IP SAN because the sinkhole_router
# rewrites flow.request.host to 127.0.0.1 before mitmproxy's upstream TLS
# verify runs -- without the IP SAN mitmproxy reports "IP address mismatch"
# even when the DNS SAN is correct. Same trick the default sinkhole.crt uses.
# The `wrong_san` shape below deliberately omits both the test hostname and
# the IP SAN so the hostname-match check fires.
# ===========================================================================
write_leaf_cnf() {
    # $1: output path, $2: CN, $3: extra DNS SAN (primary)
    local out="$1" cn="$2" dns="$3"
    cat > "$out" << EOF
[req]
distinguished_name = dn
req_extensions = v3_leaf
prompt = no
[dn]
CN = $cn
O = SafeYolo Blackbox Test
C = US
[v3_leaf]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @sans
[sans]
DNS.1 = $dns
DNS.2 = *.$dns
IP.1 = 127.0.0.1
EOF
}

# ===========================================================================
# Tricky chain #2 -- RSA 4-deep chain
#
# Pattern: RSA leaf -> RSA intermediate A -> RSA intermediate B -> ca.crt
# Why: 4-deep chains are common in the wild (Amazon CloudFront, Microsoft,
# Akamai). Catches regressions in mitmproxy's / Python ssl's depth handling.
# SAN: rsa-deep-chain.test
# ===========================================================================
if [ ! -f rsa_deep_chain.pem ] || [ ! -f "$KEY_DIR/rsa_deep_chain.key" ]; then
    echo "4. Generating RSA 4-deep chain (CloudFront shape)..."

    # 4a. RSA intermediate B (signed by ca.crt). pathlen:1 so it can issue
    #     intermediate A below, which in turn issues leaves.
    openssl genrsa -out "$KEY_DIR/rsa_int_b.key" 2048
    cat > rsa_int_b.cnf << 'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = SafeYolo RSA Intermediate B
O = SafeYolo Test
C = US
[v3_int]
basicConstraints = critical, CA:TRUE, pathlen:1
keyUsage = critical, keyCertSign, cRLSign
EOF
    openssl req -new -key "$KEY_DIR/rsa_int_b.key" \
        -out rsa_int_b.csr -config rsa_int_b.cnf
    openssl x509 -req -in rsa_int_b.csr \
        -CA ca.crt -CAkey "$KEY_DIR/ca.key" -CAcreateserial \
        -days 3650 -sha256 \
        -extensions v3_int -extfile rsa_int_b.cnf \
        -out rsa_int_b.crt
    rm -f rsa_int_b.csr rsa_int_b.cnf

    # 4b. RSA intermediate A (signed by B). pathlen:0 -- end of CA chain,
    #     issues only leaves.
    openssl genrsa -out "$KEY_DIR/rsa_int_a.key" 2048
    cat > rsa_int_a.cnf << 'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = SafeYolo RSA Intermediate A
O = SafeYolo Test
C = US
[v3_int]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
EOF
    openssl req -new -key "$KEY_DIR/rsa_int_a.key" \
        -out rsa_int_a.csr -config rsa_int_a.cnf
    openssl x509 -req -in rsa_int_a.csr \
        -CA rsa_int_b.crt -CAkey "$KEY_DIR/rsa_int_b.key" -CAcreateserial \
        -days 3650 -sha256 \
        -extensions v3_int -extfile rsa_int_a.cnf \
        -out rsa_int_a.crt
    rm -f rsa_int_a.csr rsa_int_a.cnf

    # 4c. RSA leaf signed by intermediate A.
    openssl genrsa -out "$KEY_DIR/rsa_deep_chain.key" 2048
    write_leaf_cnf rsa_deep_leaf.cnf "rsa-deep-chain.test" "rsa-deep-chain.test"
    openssl req -new -key "$KEY_DIR/rsa_deep_chain.key" \
        -out rsa_deep_leaf.csr -config rsa_deep_leaf.cnf
    openssl x509 -req -in rsa_deep_leaf.csr \
        -CA rsa_int_a.crt -CAkey "$KEY_DIR/rsa_int_a.key" -CAcreateserial \
        -days 365 -sha256 \
        -extensions v3_leaf -extfile rsa_deep_leaf.cnf \
        -out rsa_deep_leaf.crt
    rm -f rsa_deep_leaf.csr rsa_deep_leaf.cnf

    # 4d. Chain PEM: leaf + intA + intB. Verifier chains intB to ca.crt.
    cat rsa_deep_leaf.crt rsa_int_a.crt rsa_int_b.crt > rsa_deep_chain.pem

    rm -f ca.srl rsa_int_b.srl rsa_int_a.srl
    echo "   Created: rsa_deep_chain.pem (leaf + intA + intB, terminates at ca.crt)"
fi

# ===========================================================================
# Tricky chain #3 -- name-constrained intermediate
#
# Pattern: leaf <- intermediate with nameConstraints (permitted DNS = the
# leaf's subtree only) <- ca.crt. Exercises X.509 nameConstraints handling,
# which has historically had bugs in OpenSSL and Python ssl. Permitted
# subtree includes the 127.0.0.1 IP SAN because the sinkhole_router rewrites
# the request host before mitmproxy's TLS verify runs.
# SAN: nc-constrained.test (within the permitted subtree)
# ===========================================================================
if [ ! -f nc_chain.pem ] || [ ! -f "$KEY_DIR/nc_chain.key" ]; then
    echo "5. Generating name-constrained intermediate chain..."

    openssl genrsa -out "$KEY_DIR/nc_intermediate.key" 2048
    cat > nc_intermediate.cnf << 'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = SafeYolo Name-Constrained Intermediate
O = SafeYolo Test
C = US
[v3_nc]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
nameConstraints = critical, permitted;DNS:nc-constrained.test, permitted;IP:127.0.0.1/255.255.255.255
EOF
    openssl req -new -key "$KEY_DIR/nc_intermediate.key" \
        -out nc_intermediate.csr -config nc_intermediate.cnf
    openssl x509 -req -in nc_intermediate.csr \
        -CA ca.crt -CAkey "$KEY_DIR/ca.key" -CAcreateserial \
        -days 3650 -sha256 \
        -extensions v3_nc -extfile nc_intermediate.cnf \
        -out nc_intermediate.crt
    rm -f nc_intermediate.csr nc_intermediate.cnf

    openssl genrsa -out "$KEY_DIR/nc_chain.key" 2048
    write_leaf_cnf nc_leaf.cnf "nc-constrained.test" "nc-constrained.test"
    openssl req -new -key "$KEY_DIR/nc_chain.key" \
        -out nc_leaf.csr -config nc_leaf.cnf
    openssl x509 -req -in nc_leaf.csr \
        -CA nc_intermediate.crt -CAkey "$KEY_DIR/nc_intermediate.key" -CAcreateserial \
        -days 365 -sha256 \
        -extensions v3_leaf -extfile nc_leaf.cnf \
        -out nc_leaf.crt
    rm -f nc_leaf.csr nc_leaf.cnf

    cat nc_leaf.crt nc_intermediate.crt > nc_chain.pem
    rm -f ca.srl nc_intermediate.srl
    echo "   Created: nc_chain.pem (leaf SAN within permitted subtree)"
fi

# ===========================================================================
# Tricky chain #4 -- extra unrelated intermediates in the chain PEM
#
# Pattern: chain = [leaf, used_intermediate, junk_a, junk_b]. The junk
# certs aren't on the verification path; mitmproxy should find the correct
# path (leaf -> used_intermediate -> ca.crt) and ignore the extras.
# Real-world servers sometimes send extras due to misconfiguration
# (Apache SSLCertificateChainFile pointing at a bundle with unrelated CAs).
# SAN: extra-intermediates.test
# ===========================================================================
if [ ! -f extra_chain.pem ] || [ ! -f "$KEY_DIR/extra_chain.key" ]; then
    echo "6. Generating chain with extra unrelated intermediates..."

    # 6a. Used intermediate (signed by ca.crt).
    openssl genrsa -out "$KEY_DIR/extra_int.key" 2048
    cat > extra_int.cnf << 'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = SafeYolo Extra-Chain Intermediate
O = SafeYolo Test
C = US
[v3_int]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
EOF
    openssl req -new -key "$KEY_DIR/extra_int.key" \
        -out extra_int.csr -config extra_int.cnf
    openssl x509 -req -in extra_int.csr \
        -CA ca.crt -CAkey "$KEY_DIR/ca.key" -CAcreateserial \
        -days 3650 -sha256 \
        -extensions v3_int -extfile extra_int.cnf \
        -out extra_int.crt
    rm -f extra_int.csr extra_int.cnf

    # 6b. Two unrelated self-signed "junk" CAs -- not on the verify path.
    openssl genrsa -out "$KEY_DIR/junk_a.key" 2048
    openssl req -x509 -new -nodes -key "$KEY_DIR/junk_a.key" \
        -sha256 -days 3650 -out junk_a.crt \
        -subj "/CN=Unrelated Junk CA A/O=SafeYolo Test/C=US"
    openssl genrsa -out "$KEY_DIR/junk_b.key" 2048
    openssl req -x509 -new -nodes -key "$KEY_DIR/junk_b.key" \
        -sha256 -days 3650 -out junk_b.crt \
        -subj "/CN=Unrelated Junk CA B/O=SafeYolo Test/C=US"

    # 6c. Leaf signed by the used intermediate.
    openssl genrsa -out "$KEY_DIR/extra_chain.key" 2048
    write_leaf_cnf extra_leaf.cnf "extra-intermediates.test" "extra-intermediates.test"
    openssl req -new -key "$KEY_DIR/extra_chain.key" \
        -out extra_leaf.csr -config extra_leaf.cnf
    openssl x509 -req -in extra_leaf.csr \
        -CA extra_int.crt -CAkey "$KEY_DIR/extra_int.key" -CAcreateserial \
        -days 365 -sha256 \
        -extensions v3_leaf -extfile extra_leaf.cnf \
        -out extra_leaf.crt
    rm -f extra_leaf.csr extra_leaf.cnf

    # 6d. Chain PEM: leaf + real intermediate + 2 junk certs.
    cat extra_leaf.crt extra_int.crt junk_a.crt junk_b.crt > extra_chain.pem
    rm -f ca.srl extra_int.srl
    echo "   Created: extra_chain.pem (leaf + int + 2 junk CAs; verify should ignore junk)"
fi

# ===========================================================================
# Tricky chain #5 -- expired leaf (MUST fail upstream verify)
#
# Pattern: valid chain but leaf notAfter is in the past. Generated via
# `openssl ca` (supports -startdate/-enddate; `openssl x509 -req` in 3.0
# does not). Uses the existing trusted intermediate (test-ca-b) to sign.
# SAN: expired-leaf.test
# Expected: mitmproxy 502 -- expired cert must NOT be accepted.
# ===========================================================================
if [ ! -f expired_chain.pem ] || [ ! -f "$KEY_DIR/expired_chain.key" ]; then
    echo "7. Generating expired-leaf chain (MUST fail verify)..."

    # Stand up a minimal CA state so `openssl ca` works. The index/serial
    # files live in a tempdir and are cleaned up after signing.
    EXP_TMP=$(mktemp -d)
    touch "$EXP_TMP/index.txt"
    echo 1000 > "$EXP_TMP/serial"
    cat > "$EXP_TMP/ca.cnf" << EOF
[ca]
default_ca = my_ca
[my_ca]
new_certs_dir = $EXP_TMP
database = $EXP_TMP/index.txt
serial = $EXP_TMP/serial
default_md = sha256
policy = policy_any
x509_extensions = v3_leaf
email_in_dn = no
rand_serial = no
unique_subject = no
[policy_any]
commonName = supplied
organizationName = optional
countryName = optional
[v3_leaf]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @sans
[sans]
DNS.1 = expired-leaf.test
DNS.2 = *.expired-leaf.test
IP.1 = 127.0.0.1
EOF

    openssl genrsa -out "$KEY_DIR/expired_chain.key" 2048
    openssl req -new -key "$KEY_DIR/expired_chain.key" \
        -out "$EXP_TMP/expired_leaf.csr" \
        -subj "/CN=expired-leaf.test/O=SafeYolo Blackbox Test/C=US"

    # Issue via `ecc_intermediate.crt` so the chain is structurally valid
    # apart from the notAfter. Signed 2020-01-01..2021-01-01 -- deep past.
    openssl ca -config "$EXP_TMP/ca.cnf" \
        -cert ecc_intermediate.crt -keyfile "$KEY_DIR/ecc_intermediate.key" \
        -in "$EXP_TMP/expired_leaf.csr" \
        -out expired_leaf.crt \
        -batch -notext \
        -startdate 20200101000000Z -enddate 20210101000000Z

    # Chain: expired leaf + intermediate + cross-signed bridge (same
    # structure as ecc_chain.pem; only the leaf's validity differs).
    cat expired_leaf.crt ecc_intermediate.crt test-ca-b-crosssigned.crt \
        > expired_chain.pem

    rm -rf "$EXP_TMP"
    echo "   Created: expired_chain.pem (leaf notAfter=2021-01-01; upstream verify MUST reject)"
fi

# ===========================================================================
# Tricky chain #6 -- hostname/SAN mismatch (MUST fail upstream verify)
#
# Pattern: valid chain, leaf has SAN `other-name.test` only. Served on the
# port routed to `wrong-san.test`. Neither the requested host nor the
# connection target (127.0.0.1) appears in the cert's SAN, so hostname
# verification must fail.
# SAN: other-name.test (deliberately mismatched)
# Expected: mitmproxy 502 -- hostname mismatch must NOT be accepted.
# ===========================================================================
if [ ! -f wrong_san_chain.pem ] || [ ! -f "$KEY_DIR/wrong_san_chain.key" ]; then
    echo "8. Generating wrong-SAN chain (MUST fail verify)..."

    cat > wrong_san_leaf.cnf << 'EOF'
[req]
distinguished_name = dn
req_extensions = v3_leaf
prompt = no
[dn]
CN = other-name.test
O = SafeYolo Blackbox Test
C = US
[v3_leaf]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
# Deliberately only other-name.test -- NOT wrong-san.test, NOT 127.0.0.1.
subjectAltName = DNS:other-name.test
EOF
    openssl genrsa -out "$KEY_DIR/wrong_san_chain.key" 2048
    openssl req -new -key "$KEY_DIR/wrong_san_chain.key" \
        -out wrong_san_leaf.csr -config wrong_san_leaf.cnf
    openssl x509 -req -in wrong_san_leaf.csr \
        -CA ecc_intermediate.crt -CAkey "$KEY_DIR/ecc_intermediate.key" -CAcreateserial \
        -days 365 -sha256 \
        -extensions v3_leaf -extfile wrong_san_leaf.cnf \
        -out wrong_san_leaf.crt
    rm -f wrong_san_leaf.csr wrong_san_leaf.cnf

    cat wrong_san_leaf.crt ecc_intermediate.crt test-ca-b-crosssigned.crt \
        > wrong_san_chain.pem
    rm -f ecc_intermediate.srl
    echo "   Created: wrong_san_chain.pem (leaf SAN=other-name.test; upstream verify MUST reject)"
fi

# ===========================================================================
# Tricky chain #7 -- self-signed leaf with no trust path (MUST fail)
#
# Pattern: leaf is self-signed; trust bundle has ca.crt (not the leaf's
# issuer). Chain builder finds no path to a trusted root.
# SAN: self-signed.test
# Expected: mitmproxy 502 -- no path to trusted root.
# ===========================================================================
if [ ! -f self_signed_chain.pem ] || [ ! -f "$KEY_DIR/self_signed_chain.key" ]; then
    echo "9. Generating self-signed leaf (MUST fail verify)..."

    write_leaf_cnf self_signed.cnf "self-signed.test" "self-signed.test"
    openssl genrsa -out "$KEY_DIR/self_signed_chain.key" 2048
    # Self-signed: -x509 on the req command, key signs its own cert.
    openssl req -x509 -new -nodes \
        -key "$KEY_DIR/self_signed_chain.key" \
        -sha256 -days 365 \
        -extensions v3_leaf -config self_signed.cnf \
        -out self_signed_chain.pem
    rm -f self_signed.cnf
    echo "   Created: self_signed_chain.pem (no path to ca.crt; upstream verify MUST reject)"
fi

# ===========================================================================
# Tricky chain #8 -- AIA-only (missing intermediate, MUST fail)
#
# Pattern: server presents [leaf] only -- no intermediate. The leaf's AIA
# caIssuers extension points to a local URL that could (conceptually)
# serve the intermediate. OpenSSL / Python ssl do NOT chase AIA by
# default; mitmproxy inherits that. Result: chain cannot be completed
# and upstream verify fails.
#
# Why this matters: if mitmproxy ever flips to AIA-chasing (e.g. someone
# enables a custom X509_STORE_CTX verify callback), an attacker who
# controls the AIA URL or can MITM the HTTP fetch could inject an
# arbitrary intermediate. This test is the canary -- current behavior
# is documented as "fails deterministically", and a 200 would mean
# chain policy changed silently.
#
# SAN: aia-only.test
# Expected: 502 / transport error -- chain cannot be completed.
# ===========================================================================
if [ ! -f aia_chain.pem ] || [ ! -f "$KEY_DIR/aia_chain.key" ]; then
    echo "10. Generating AIA-only chain (leaf presented alone; MUST fail)..."

    # 10a. Dedicated intermediate signed by ca.crt. Kept separate from the
    #      other intermediates so this test's shape is self-contained --
    #      nothing else references aia_int, so regenerating won't ripple.
    openssl genrsa -out "$KEY_DIR/aia_int.key" 2048
    cat > aia_int.cnf << 'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = SafeYolo AIA-Only Intermediate
O = SafeYolo Test
C = US
[v3_int]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
EOF
    openssl req -new -key "$KEY_DIR/aia_int.key" \
        -out aia_int.csr -config aia_int.cnf
    openssl x509 -req -in aia_int.csr \
        -CA ca.crt -CAkey "$KEY_DIR/ca.key" -CAcreateserial \
        -days 3650 -sha256 \
        -extensions v3_int -extfile aia_int.cnf \
        -out aia_int.crt
    rm -f aia_int.csr aia_int.cnf

    # 10b. Leaf signed by aia_int with an AIA caIssuers URL. The URL
    #      targets the sinkhole's HTTP port; it is NOT wired up to
    #      actually serve the intermediate (handlers return JSON), so
    #      even if a future mitmproxy build chased the URL the fetched
    #      bytes would not parse as a cert. The URL exists so the cert
    #      structurally mirrors real-world AIA-only leaves.
    openssl genrsa -out "$KEY_DIR/aia_chain.key" 2048
    cat > aia_leaf.cnf << 'EOF'
[req]
distinguished_name = dn
req_extensions = v3_leaf
prompt = no
[dn]
CN = aia-only.test
O = SafeYolo Blackbox Test
C = US
[v3_leaf]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @sans
authorityInfoAccess = caIssuers;URI:http://127.0.0.1:18080/aia/aia-int.crt
[sans]
DNS.1 = aia-only.test
DNS.2 = *.aia-only.test
IP.1 = 127.0.0.1
EOF
    openssl req -new -key "$KEY_DIR/aia_chain.key" \
        -out aia_leaf.csr -config aia_leaf.cnf
    openssl x509 -req -in aia_leaf.csr \
        -CA aia_int.crt -CAkey "$KEY_DIR/aia_int.key" -CAcreateserial \
        -days 365 -sha256 \
        -extensions v3_leaf -extfile aia_leaf.cnf \
        -out aia_leaf.crt
    rm -f aia_leaf.csr aia_leaf.cnf

    # 10c. Chain PEM: leaf ONLY. Intermediate is deliberately absent --
    #      that is what makes this test a missing-intermediate case.
    cp aia_leaf.crt aia_chain.pem
    rm -f ca.srl aia_int.srl
    echo "   Created: aia_chain.pem (leaf only; intermediate MUST remain absent)"
fi
