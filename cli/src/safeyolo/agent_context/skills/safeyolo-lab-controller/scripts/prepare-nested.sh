#!/usr/bin/env bash
# Prepare the native inner proxy for an owned Lab request experiment.
set -euo pipefail

inputs=/safeyolo/lab-native
instance=${1:-$HOME/.safeyolo/lab-inner}
if (($# > 1)); then echo 'Usage: prepare-nested.sh [NEW_INSTANCE_DIRECTORY]' >&2; exit 2; fi
for binary in safeyolo safeyolo-proxy; do
    if [[ ! -x $inputs/bin/$binary ]]; then
        echo "Prepared native Linux input is missing: $inputs/bin/$binary; select Lab --nested-assets" >&2
        exit 1
    fi
done
cli_identity=$("$inputs/bin/safeyolo" --version)
proxy_identity=$("$inputs/bin/safeyolo-proxy" --version)
if [[ ${cli_identity#* commit=} != "${proxy_identity#* commit=}" ]]; then
    echo 'The inner CLI and proxy have different source/profile identities' >&2
    exit 1
fi
if [[ -e $instance || -L $instance ]]; then
    echo 'The inner directory already exists. Inspect the retained instance or choose a fresh directory; no files were changed.' >&2
    exit 1
fi
if [[ ${HTTP_PROXY:-} != http://127.0.0.1:8080 ]]; then
    echo 'This nested path requires the guest outer proxy at http://127.0.0.1:8080; the outer configuration was not changed.' >&2
    exit 1
fi
if [[ -z ${SSL_CERT_FILE:-} || ! -r $SSL_CERT_FILE ]]; then
    echo 'Readable outer CA trust is required before preparing the inner proxy' >&2
    exit 1
fi
umask 077
mkdir -p -- "$instance/bin"
instance=$(cd -- "$instance" && pwd -P)
for binary in safeyolo safeyolo-proxy; do
    cp -- "$inputs/bin/$binary" "$instance/bin/$binary"
    chmod 0755 "$instance/bin/$binary"
done
"$instance/bin/safeyolo" --root "$instance" init
"$instance/bin/safeyolo" --root "$instance" agent create lab-client --workspace "$HOME"
# This explicit listener is independent of a sandbox launch. The Lab controller
# drives it through a Unix socket; no second model or inner guest is required.
cat > "$instance/config.toml" <<'EOF'
admin_port = 19090
parent_proxy = "http://127.0.0.1:8080"
tls_ca_file = "certs/mitmproxy-ca.pem"
agent_map_file = "data/agent_map.json"
listeners = [{ agent_id = "lab-client", socket_path = "data/lab-client.sock", source_id = "10.80.0.10" }]
EOF
cp -- "$instance/policy.toml" "$instance/policy-original.toml"
"$instance/bin/safeyolo" config check "$instance/config.toml"
printf 'Prepared native inner instance: %s\nRequest identity: lab-client\nRequest socket: %s/data/lab-client.sock\nOriginal policy: %s/policy-original.toml\n' "$instance" "$instance" "$instance"
printf '%s\n' 'Start and change only this inner instance with its native CLI. All external traffic still traverses the outer proxy. This prepares a proxy-only experiment; it does not start an inner sandbox.'
