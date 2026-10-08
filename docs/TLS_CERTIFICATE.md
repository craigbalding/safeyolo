# TLS certificate management

SafeYolo intercepts HTTPS at its mediated proxy. The client trusts the
instance's signing CA; the proxy makes a separate verified TLS connection to
the origin. TLS verification or parsing failure does not select passthrough.

## Instance CA

Native initialization, performed by installation, creates a unique local CA:

```text
ROOT/certs/mitmproxy-ca-cert.pem  # Public certificate for clients
ROOT/certs/mitmproxy-ca.pem       # Private signing key and CA; keep on the host
```

The proxy reuses the configured `tls_ca_file`. The native installer does not
read or convert the earlier Python installation's keys. Keep the private key
out of sandboxes, source control and messages. The public certificate can be
inspected on the host without the retired certificate CLI:

```sh
openssl x509 -in "$SAFEYOLO_CONFIG_DIR/certs/mitmproxy-ca-cert.pem" -noout -subject -dates -fingerprint -sha256
```

## Agent sandboxes

Native lifecycle stages the public CA and proxy environment in the agent's
configuration share. Guest init installs trust and supplies `SSL_CERT_FILE`,
`REQUESTS_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS`. Preserve these variables when
launching tools. Agent traffic uses the configured mediated route; use
`http://_safeyolo.proxy.internal` for the authenticated Agent API. Do not
change that URL to HTTPS or copy the host Admin token into the guest.

A host-owned probe can use an explicitly configured agent Unix listener and
public CA. This example assumes that the proxy is running, `data/alice.sock`
is its configured listener, and the selected policy allows the destination:

```sh
curl --unix-socket "$SAFEYOLO_CONFIG_DIR/data/alice.sock" --proxy http://localhost --cacert "$SAFEYOLO_CONFIG_DIR/certs/mitmproxy-ca-cert.pem" https://httpbin.org/get
```

Per-process trust avoids changing the host's system trust store. Node uses
`NODE_EXTRA_CA_CERTS`; OpenSSL/curl and many Go tools use `SSL_CERT_FILE`;
Python requests uses `REQUESTS_CA_BUNDLE`; Git can use `GIT_SSL_CAINFO`. Java
may require its own keystore. These are client trust inputs, not permission
to disable origin verification.

## Additional upstream trust

For a parent or origin with a private CA or missing intermediate, set
`upstream_ca_file` in `config.toml` to a readable PEM bundle. It augments the
native trust roots while retaining signature, validity and hostname checks.
`parent_proxy` selects an explicit HTTP(S) parent authority. See
[native settings](native-settings.md#runtime-settings) for their defaults and
path resolution. Restart the owned proxy after changing runtime trust:

```sh
safeyolo stop
safeyolo start
```

Keep each agent's lifecycle separate; stopping the proxy leaves its sandbox
running. In a nested sandbox preserve the existing proxy and CA environment.

## Certificate pinning and passthrough

A pinned application can reject interception even when the CA is trusted.
The operator can select exact TLS passthrough entries in `config.toml`:

```toml
ignore_hosts = ["pinned-app.example.test:443", "another-pinned.example.test"]
```

Use the native loader's supported exact host/port, address and CIDR semantics;
do not broaden an exception to unrelated hosts or ports. Restart the proxy
for the runtime setting to take effect. Passthrough retains encrypted bytes
and connection start/error/end metadata; it does not produce inspected payload
or credential-scan claims for that connection. Ordinary traffic remains
inspected. This is an operator policy choice, unavailable through the Agent API.

Disabling pinning in a development application can also make it accept the
proxy CA. Avoid flags that disable all certificate verification: they remove
origin authenticity rather than trusting this CA.

## Troubleshooting

Check the configured public CA path, its readable mode and its dates. Inspect
`SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/`NODE_EXTRA_CA_CERTS` in the actual tool's
environment. A client may use a bundled trust store; configure that client
rather than disabling verification. For a specific pinned domain, review the
exact passthrough choice and its security cost on the host. Use native logs
and [diagnosis](native-operator.md) to distinguish client trust, upstream trust,
network policy and an unavailable endpoint.

Native initialization in [the CLI](../proxy/src/bin/safeyolo.rs) prepares the
signing CA. [The TLS owner](../proxy/src/tls.rs) imports it and signs leaf
certificates. No Python certificate preparation runs on the product path.
