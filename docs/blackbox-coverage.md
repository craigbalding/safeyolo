# SafeYolo Blackbox Test Coverage

Generated from test docstrings in `tests/blackbox/`. Do not edit by hand — run `python3 tests/blackbox/gen_docs.py`.

Each entry states the security property the test asserts and the threat it defends against. The probe (What) describes the specific observation used to confirm the property.

**89 tests across 30 threat categories.**

## Host-side

### `tests/blackbox/host/identity/test_agent_identity.py`

#### TestAgentMap — Agent identity is registered in agent_map.json after start.

**Threat:** Every request the proxy sees is attributed to an agent by
looking up the client IP in agent_map.json. If an agent is not
registered, service_discovery can't name it and downstream addons
(flow_recorder, network_guard scoping) fall back to 'unknown' —
cross-agent isolation collapses.

- **`test_agent_map_has_entry`** — agent_map.json contains an entry for the running agent.
  - *Probe:* Reads ~/.safeyolo/data/agent_map.json and asserts the
agent name is a key.
  - *Consequence if unasserted:* Without the entry, service_discovery can't map the
agent's PROXY-v2 attribution IP back to a name.
- **`test_agent_map_has_attribution_ip`** — Attribution IP is in the 10.200.0.0/16 range.
  - *Probe:* Reads the agent's entry and asserts the 'ip' field
starts with '10.200.'.
  - *Consequence if unasserted:* The attribution IP range is load-bearing — the PROXY-v2
parser and service_discovery both assume this prefix. An IP
outside the range indicates network_guard isolation was
misconfigured and traffic would be unattributable.
- **`test_agent_map_has_socket`** — Bridge socket referenced in the entry exists on disk.
  - *Probe:* Reads the 'socket' field and asserts the path is a
live Unix domain socket (Path.is_socket()).
  - *Consequence if unasserted:* The bridge socket is the only egress path for the agent.
A missing or stale socket means every agent request fails with
ENOENT — effectively a denial of service, not a security
issue, but a strong signal that the identity chain is broken.

### `tests/blackbox/host/lifecycle/test_token_lifecycle.py`

#### TestAgentTokenLifecycle — Agent token survives proxy restart without breaking a running sandbox.

**Threat:** The agent_token authenticates the sandbox's requests to the
agent API. If a proxy restart regenerates the token but the
sandbox still holds the old value, the agent gets 401 on every
diagnostic call — breaking `safeyolo explain`, credential
approval UX, and any other observability feature the agent
exposes to itself. In the Docker stack this worked via bind-mount;
the microVM migration introduced a copy step that is the common
regression point.

- **`test_agent_api_survives_proxy_restart`** — Agent API stays reachable from the sandbox across proxy restart.
  - *Probe:* Verify agent API /health returns 200 from inside the
sandbox; stop + start the test proxy; assert /health still
returns 200 from the same running sandbox.
  - *Consequence if unasserted:* If the sandbox's cached token goes stale on proxy
restart, every agent-originated diagnostic call fails 401.
This regression killed `safeyolo explain` when we first
migrated from Docker bind-mounts to microVM copies.

### `tests/blackbox/host/proxy/test_credential_guard.py`

#### TestCredentialRouting — Credentials reach only their authorised destinations.

**Threat:** An agent with a real OpenAI/Anthropic/GitHub key should be
able to use it against the legitimate provider, but nothing else.
If the credential guard lets a request with a live token reach
an unrelated host, an attacker-in-the-agent can exfiltrate the
credential itself (by observing the token in their own logs).

- **`test_openai_key_to_openai_allowed`** — OpenAI bearer token passes through to api.openai.com.
  - *Probe:* POST to api.openai.com with a test OpenAI key in the
Authorization header; assert 200 and the sinkhole received
the request with the Authorization header intact.
  - *Consequence if unasserted:* Confirms the positive path — a legitimate use of an
OpenAI key actually works. Without this assertion, an overly
strict credential guard could break the primary workflow.
- **`test_openai_key_to_evil_blocked`** — OpenAI key sent to evil.com is blocked before leaving the proxy.
  - *Probe:* POST to evil.com with an OpenAI bearer token; assert
428 (approval required) and the sinkhole received zero
requests on evil.com.
  - *Consequence if unasserted:* A leaked key reaching attacker-controlled infrastructure
is the core threat credential_guard defends against. This is
the primary exfiltration vector — a compromised agent posting
the user's key to any host it can reach.
- **`test_anthropic_key_to_anthropic_allowed`** — Anthropic x-api-key passes through to api.anthropic.com.
  - *Probe:* POST to api.anthropic.com with a test Anthropic key in
x-api-key; assert 200 and the sinkhole received the request
with the x-api-key header preserved.
  - *Consequence if unasserted:* Confirms Anthropic's non-Bearer header is recognised as
a valid credential route — different header scheme from
OpenAI, so credential_guard must support both.
- **`test_anthropic_key_to_attacker_blocked`** — Anthropic key sent to attacker.com is blocked.
  - *Probe:* POST to attacker.com with an Anthropic x-api-key;
assert 428 and sinkhole saw zero requests on attacker.com.
  - *Consequence if unasserted:* Symmetric to the OpenAI case — confirms both credential
formats are scoped to their legitimate hosts.
- **`test_no_credentials_passes_through`** — Requests without credentials are not blocked by credential_guard.
  - *Probe:* GET httpbin.org/get with no Authorization headers;
assert 200 and sinkhole saw the request.
  - *Consequence if unasserted:* credential_guard only triggers on credential presence.
A broken implementation that blocks any request to a
non-allowlisted host would be network_guard's job, not this
addon's — confirm the boundaries are respected.

#### TestCredentialInBody — Credentials embedded in request bodies are blocked.

**Threat:** Agents can put credentials in JSON/form bodies, not just
headers. If the guard only scans headers, an attacker can put
a stolen key in the request body and exfiltrate through any
endpoint that accepts POST data. The body-scanning path exists
behind credguard_scan_bodies=true but isn't wired up yet.

- **`test_key_in_json_body_blocked`** — OpenAI key in a JSON body is blocked when body scanning is on.
  - *Probe:* POST to evil.com with the OpenAI test key inside a JSON
body (not in headers); assert 428/403 and no leak to sinkhole.
  - *Consequence if unasserted:* Closes the header-only evasion — without body scanning,
`{"api_key": "sk-..."}` to an arbitrary host is a straight
exfil path. Requires credguard_scan_bodies=true, which is
not yet default.

#### TestBlockResponseContent — Block responses carry diagnostic data for humans and agents.

**Threat:** When a request is blocked, the agent needs enough information
in the response to understand what happened — and the operator
needs an audit identifier to correlate with logs. A bare 428 with
no body makes both roles fly blind.

- **`test_block_response_includes_event_id`** — Block response body contains event_id or request_id.
  - *Probe:* Trigger a block by sending an OpenAI key to evil.com,
parse the 428 body as JSON, assert either 'event_id' or
'request_id' is present.
  - *Consequence if unasserted:* The ID lets the operator run `safeyolo explain <id>` to
see the full decision chain. Without it, block diagnostics
have to be matched to logs by timestamp — fragile and slow.
- **`test_block_response_indicates_approval_required`** — Block response body mentions 'approval' or 'prompt'.
  - *Probe:* Trigger a block; assert the lowercased response body
contains 'approval' or 'prompt'.
  - *Consequence if unasserted:* The agent reads the block response to decide whether to
surface an approval UX to the user or just fail. Without a
clear signal in the body, agents default to treating 428 as
a permanent failure.

### `tests/blackbox/host/proxy/test_network_guard.py`

#### TestAccessControl — Allowlisted domains pass through; blocked domains are stopped.

**Threat:** network_guard is the coarse-grained "what destinations is
this agent allowed to reach at all" layer. Failure modes here
are either over-permissive (agent reaches a blocked host, data
leaks) or under-permissive (legitimate traffic fails, breaks
real workflows).

- **`test_allowed_domain_passes`** — Allowlisted httpbin.org receives a GET through the proxy.
  - *Probe:* GET httpbin.org/get through the proxy; assert 200 and
the sinkhole saw one request.
  - *Consequence if unasserted:* Positive-path check — if allowlisted hosts don't actually
reach their upstream, the agent loses legitimate connectivity
and users will disable network_guard to get work done.

#### TestRateLimiting — Per-host request budgets are enforced without spurious denies.

**Threat:** network_guard caps total request volume to each host to
contain runaway loops and cost spikes. If the accounting drops
or double-counts, either budgets block legitimate traffic (false
positive) or never fire (the cap is meaningless).

- **`test_multiple_requests_allowed_within_budget`** — Five requests inside the budget all succeed.
  - *Probe:* Reset budgets; issue 5 GETs to httpbin.org; assert all
5 returned 200 and the sinkhole saw 5.
  - *Consequence if unasserted:* Confirms the rate limiter isn't tripping on normal
volumes. A false-positive rate limit at low call counts
would make the proxy useless for any real workload.

#### TestProxyHeaderStripping — Proxy-specific headers are consumed, not forwarded upstream.

**Threat:** `Proxy-Authorization` (RFC 7235) is credentials for the proxy
itself — not for the origin server. Forwarding it upstream leaks
the proxy credential to every destination the agent talks to,
and violates hop-by-hop header semantics.

- **`test_proxy_authorization_not_forwarded`** — Proxy-Authorization header is stripped before reaching upstream.
  - *Probe:* Send GET with Proxy-Authorization: Basic secret123;
assert 200, and the sinkhole's received headers do NOT
contain Proxy-Authorization.
  - *Consequence if unasserted:* Hop-by-hop header leak would expose the proxy credential
to every upstream — a straight credential disclosure bug.

### `tests/blackbox/host/proxy/test_upstream_cert_validation.py`

#### TestEccCrossSignedChain — Upstream validation of an ECC leaf whose chain reaches the

**Threat:** Mirrors example.com's shape. If certifi's bundle lacks a root
the merge was supposed to supply, or the chain builder fails to
traverse the bridge cert, validation drops and the curl hangs
(the failure surfaces as time-out or 502 from mitmproxy).

- **`test_chain_validates_end_to_end`** — GET https://example-chain-test.test/ through the proxy returns 200.
  - *Probe:* Route through SafeYolo's mitmproxy to the sinkhole's
port-18444 HTTPS endpoint. The sinkhole presents the chain
[ECC leaf, ECC intermediate, test-ca-b cross-signed by
test-ca]. mitmproxy validates it against the merged bundle,
accepts, MITMs, and forwards to us.
  - *Consequence if unasserted:* A green 200 confirms the chain-shape regression that
has bitten us twice is not currently present. A red (timeout,
502, or TLS verify error from mitmproxy) means something in
`_merge_system_cas_into_certifi` or the upstream TLS context
is broken.

#### TestRsaDeepChain — Upstream validation of a 4-deep RSA chain (leaf -> intA -> intB -> root).

**Threat:** Many real-world CDN chains (Amazon CloudFront, Microsoft,
some Akamai deployments) are 4-deep. Chain builder regressions
around depth limits, path-length constraints, or intermediate
caching surface here without needing public internet access.

- **`test_four_deep_chain_validates`** — GET https://rsa-deep-chain.test/ through the proxy returns 200.
  - *Probe:* Route through SafeYolo's mitmproxy to the sinkhole's
port-18445 HTTPS endpoint. The sinkhole presents the chain
[RSA leaf, RSA intermediate A (pathlen:0), RSA intermediate B
(pathlen:1)]. mitmproxy walks leaf -> A -> B -> ca.crt and
accepts.
  - *Consequence if unasserted:* A green 200 confirms the chain builder handles 4-deep
chains with path-length-constrained intermediates. A red means
either the depth is being truncated, or the pathlen constraint
is being misinterpreted -- both would break real CDN upstreams.

#### TestNameConstrainedIntermediate — Upstream validation of a leaf under a name-constrained intermediate.

**Threat:** X.509 nameConstraints (RFC 5280 s4.2.1.10) is implemented
inconsistently across TLS stacks -- OpenSSL, Python ssl, and
mitmproxy have each had bugs at various versions. An intermediate
that permits DNS:nc-constrained.test must still validate a leaf
whose SAN is within that subtree.

- **`test_leaf_in_permitted_subtree_validates`** — GET https://nc-constrained.test/ through the proxy returns 200.
  - *Probe:* Route through SafeYolo's mitmproxy to the sinkhole's
port-18446 HTTPS endpoint. The intermediate has critical
nameConstraints permitting DNS:nc-constrained.test and
  - *Consequence if unasserted:* A green 200 confirms mitmproxy honours nameConstraints
correctly when the leaf is within the permitted subtree. A red
502 likely means the validator is rejecting leaves under
name-constrained intermediates outright (a known bug class in
some TLS stacks).

#### TestExtraIntermediatesIgnored — Upstream validation when server presents extra, unrelated intermediates.

**Threat:** Real-world servers sometimes include extras in the chain due
to SSLCertificateChainFile misconfiguration or bundle generation
errors. An over-strict validator that refuses any chain containing
certs outside the verification path would break these upstreams.
mitmproxy should find the correct path and silently ignore the rest.

- **`test_junk_certs_in_chain_dont_break_verify`** — GET https://extra-intermediates.test/ through the proxy returns 200.
  - *Probe:* Route through SafeYolo's mitmproxy to the sinkhole's
port-18447 HTTPS endpoint. The sinkhole presents the chain
[leaf, real intermediate, junk CA A, junk CA B]. Only
`leaf -> real intermediate -> ca.crt` is on the verification
path; the two junk CAs are unrelated self-signed certs.
  - *Consequence if unasserted:* A green 200 confirms the chain builder picks the right
path and ignores extras. A red means either the builder got
confused by the junk, or it rejected the whole chain for
containing unrelated certs -- either would break real upstreams
that ship mis-bundled intermediates.

#### TestExpiredLeafRejected — Must-fail: upstream MUST reject a cert whose notAfter is in the past.

**Threat:** Accepting expired certs has historically regressed in TLS
stacks (most famously GnuTLS CVE-2014-3466, but also ssl stacks
whose expiry check lived in a flag disabled by default). If SafeYolo
ever accepts an expired upstream cert, attackers who compromised an
expired key long after its issuer stopped caring could impersonate
the upstream. This test is the canary.

- **`test_expired_cert_causes_upstream_failure`** — GET https://expired-leaf.test/ through the proxy returns 502 (or errors).
  - *Probe:* Route through SafeYolo's mitmproxy to the sinkhole's
port-18448 HTTPS endpoint, which presents a valid chain whose
leaf has notAfter=2021-01-01 (years in the past). mitmproxy
walks the chain, validates the signatures (all fine), then
checks validity windows and MUST reject.
  - *Consequence if unasserted:* Any response other than an upstream-verify failure
(connection error or 502) means SafeYolo accepted an expired
cert -- a regression that would silently weaken upstream
authentication across the board.

#### TestWrongSanRejected — Must-fail: upstream MUST reject a cert whose SAN doesn't match the host.

**Threat:** Hostname verification is the most basic TLS invariant after
chain trust. A bug that accepts any valid-chained cert regardless
of hostname would let anyone with ANY cert signed by a trusted CA
impersonate ANY upstream. This test ensures the SAN-match check
still fires.

- **`test_cert_with_mismatched_san_causes_failure`** — GET https://wrong-san.test/ through the proxy returns 502 (or errors).
  - *Probe:* Route through SafeYolo's mitmproxy to the sinkhole's
port-18449 HTTPS endpoint. The leaf has SAN=DNS:other-name.test
only -- neither the requested hostname (wrong-san.test) nor the
connection target IP (127.0.0.1) appears. The chain itself is
valid, so the only reason to reject is the hostname mismatch.
  - *Consequence if unasserted:* Any response other than an upstream-verify failure means
SafeYolo is accepting certs without checking SAN -- a
catastrophic regression that breaks TLS authentication entirely.

#### TestSelfSignedLeafRejected — Must-fail: upstream MUST reject a self-signed leaf with no trust path.

**Threat:** A self-signed leaf whose issuer isn't in the trust store has
no path to a trusted root. Accepting it would mean anyone with a
key can generate a cert for any hostname and pass verification.
This test ensures SafeYolo's trust store isn't being bypassed.

- **`test_self_signed_cert_causes_failure`** — GET https://self-signed.test/ through the proxy returns 502 (or errors).
  - *Probe:* Route through SafeYolo's mitmproxy to the sinkhole's
port-18450 HTTPS endpoint, which presents a single self-signed
leaf (SAN=self-signed.test, 127.0.0.1). The leaf signs itself;
no trusted issuer is present in the chain.
  - *Consequence if unasserted:* Any response other than an upstream-verify failure means
SafeYolo is accepting untrusted roots -- TLS trust is broken.

#### TestAiaOnlyRejected — Must-fail: upstream MUST reject a chain that presents only the leaf.

**Threat:** When the server omits intermediates, the verifier has no path
to a trusted root unless it chases the AIA caIssuers URL. Python
ssl / OpenSSL default to NOT chasing AIA -- servers are expected
to ship the full chain. mitmproxy inherits that. If it ever flips
to AIA-chasing (custom verify callback, new OpenSSL flag), an
attacker who controls the AIA URL or can MITM the HTTP fetch
could inject arbitrary intermediates -- a silent widening of the
trust surface. This test documents current "fails deterministically"
behavior; a 200 here means chain-building policy changed and the
assertion needs an explicit update.

- **`test_missing_intermediate_causes_failure`** — GET https://aia-only.test/ through the proxy returns 502 (or errors).
  - *Probe:* Route through SafeYolo's mitmproxy to the sinkhole's
port-18451 HTTPS endpoint, which presents ONLY the leaf --
the intermediate is deliberately absent from the chain PEM.
The leaf's AIA caIssuers extension points at a local URL
that a future AIA-chaser could hit, but today nothing fetches
it; chain-building halts at the missing issuer.
  - *Consequence if unasserted:* Any response other than an upstream-verify failure means
mitmproxy started AIA-chasing without an explicit policy
decision -- a silent, auditable change to what SafeYolo
accepts as a valid upstream chain.

### `tests/blackbox/host/security/test_firewall_structural.py`

#### TestProcessSecrecy — Proxy process doesn't leak SafeYolo tokens via its cmdline.

**Threat:** Process command lines are readable by any local user via
`ps aux` or `/proc/PID/cmdline`. If SafeYolo tokens appear in
the mitmdump invocation, a non-root user on the host (or a
process that escaped the sandbox) can read them and gain full
admin control. Tokens must be passed via file or env var instead.

- **`test_no_tokens_in_process_cmdline`** — Admin and agent tokens do not appear in the mitmdump cmdline.
  - *Probe:* `pgrep -a -f mitmdump` to get the cmdline string; assert
the admin and agent token contents are not substrings of it.
  - *Consequence if unasserted:* A token in the cmdline is readable by any local user —
full admin access leaks to anyone with shell on the host.

## In-sandbox (isolation)

### `tests/blackbox/isolation/test_agent_api_scope.py`

#### TestAgentAPIAuth — Agent API rejects every unauthenticated request.

**Threat:** The agent API exposes proxy diagnostics and a small mutation
surface. Any bypass of the bearer-token gate means any local
process on the VM (or a LAN attacker if the endpoint ever leaks)
can read policy, flow contents, and credentials metadata, or
mutate agent gateway state.

- **`test_health_with_valid_token`** — Valid token returns 200.
  - *Probe:* GET /health with the agent token from /app/agent_token;
assert 200.
  - *Consequence if unasserted:* Baseline positive case — if this fails, every other
auth test is meaningless because auth is entirely broken.
- **`test_health_without_token`** — No Authorization header returns 401/403.
  - *Probe:* GET /health with no Authorization header.
  - *Consequence if unasserted:* Default-deny — any bypass here means the whole API is
open to unauthenticated callers.
- **`test_health_with_wrong_token`** — Bogus bearer value returns 401/403.
  - *Probe:* GET /health with Authorization: Bearer wrong-token-value.
  - *Consequence if unasserted:* Confirms the auth check actually compares the full token,
not just its presence. A check that accepts 'any non-empty
value' is effectively unauthenticated.
- **`test_health_with_empty_bearer`** — Empty Bearer token returns 401/403.
  - *Probe:* GET /health with Authorization: Bearer  (empty value).
  - *Consequence if unasserted:* An empty string passes a naive truthiness check in some
implementations. Closes that specific evasion.
- **`test_every_get_route_requires_auth`** — Every documented GET route rejects unauthenticated callers.
  - *Probe:* GET each of /health, /status, /policy, /budgets,
/config, /memory, /agents, /circuits with no token;
assert 401/403 each time.
  - *Consequence if unasserted:* Individual auth decorators could be forgotten when new
routes are added. Coverage across the route set catches
per-route auth bypasses.

#### TestAgentAPIMethodRestriction — Each route accepts only its documented HTTP methods.

**Threat:** A route that silently accepts any method can become a
mutation endpoint by accident. PUT/PATCH/DELETE on a GET-only
route must not succeed — if they do, someone has forgotten a
method allowlist and mutations can happen unintentionally.

- **`test_put_rejected`** — PUT on /health returns 405.
  - *Probe:* PUT /health with a valid token; assert 405.
  - *Consequence if unasserted:* PUT is a mutation method. /health is read-only. A 200
or 2xx here would indicate the route accepts arbitrary
methods — potential mutation surface.
- **`test_patch_rejected`** — PATCH on /health returns 405.
  - *Probe:* PATCH /health; assert 405.
  - *Consequence if unasserted:* Same property as PUT — mutation method on a read route.
- **`test_delete_on_nonexistent_route`** — DELETE on /nonexistent returns 404 or 405.
  - *Probe:* DELETE /nonexistent; assert status is 404 or 405.
  - *Consequence if unasserted:* A 200 on an unrecognised path indicates a catch-all
handler that silently accepts any method — a route-matching
bug that could eat valid requests or accept unintended ones.

#### TestAgentAPIMutationSurface — Mutation endpoints are auth-gated; non-mutation routes reject writes.

**Threat:** The agent API's mutation surface is deliberately narrow:
flow tagging plus gateway request/binding. Bypasses here let
an unauthenticated caller mark flows or trigger capability
grants — higher-blast-radius than read-only diagnostic access.

- **`test_tag_post_requires_auth`** — POST /api/flows/.../tag without token returns 401/403.
  - *Probe:* POST to the tag endpoint with a JSON body but no
Authorization header; assert 401/403.
  - *Consequence if unasserted:* Tag mutation is part of the audit trail. Unauthenticated
tagging corrupts flow metadata — someone could add misleading
tags that throw off post-incident analysis.
- **`test_tag_delete_requires_auth`** — DELETE /api/flows/.../tag/... without token returns 401/403.
  - *Probe:* DELETE the tag endpoint with no Authorization header;
assert 401/403.
  - *Consequence if unasserted:* Tag deletion is also mutation. An attacker who can
delete tags can wipe evidence tying flows to a test run or
investigation context.
- **`test_gateway_request_access_requires_auth`** — POST /gateway/request-access without token returns 401/403.
  - *Probe:* POST to /gateway/request-access with a JSON body but
no Authorization header; assert 401/403.
  - *Consequence if unasserted:* request-access triggers the human-in-the-loop approval
flow for capability grants. An unauthenticated caller
spamming this endpoint could social-engineer approvals or
exhaust operator attention.
- **`test_post_on_get_only_route_rejected`** — POST on /policy returns 405, not 200.
  - *Probe:* POST /policy with a valid token; assert 405.
  - *Consequence if unasserted:* /policy is a read-only diagnostic endpoint. A 200 would
indicate method-router confusion — another mutation surface
silently opened.

#### TestAgentAPICrossAgentIsolation — Agent API returns only the calling agent's data.

**Threat:** Multiple agents share the same proxy and flow store. If the
API returns flows belonging to other agents, one agent can read
another's request bodies (credentials, PII, contents). The scope
is enforced by resolving the caller's source IP through
service_discovery; this tests the end-to-end isolation, not the
mechanism.

- **`test_flow_search_scoped_to_calling_agent`** — Flow search returns only flows from the caller's subnet.
  - *Probe:* Emit a tagged probe through the proxy, then query
/api/flows/search. For each returned flow, assert the
client address is in this agent's subnet (not another
agent's).
  - *Consequence if unasserted:* A cross-agent leak here is a full information
disclosure — one agent reads another's request contents,
including credentials and response bodies.
- **`test_gateway_services_scoped`** — GET /gateway/services responds without error as this agent.
  - *Probe:* GET /gateway/services with the agent token; assert 200
and the response body parses as JSON without an 'error' key.
  - *Consequence if unasserted:* A smoke test for the scoping mechanism — the response
shape varies, so we verify the endpoint functions for the
calling agent. Cross-agent leakage in the detailed contents
is covered by test_flow_search_scoped_to_calling_agent.

### `tests/blackbox/isolation/test_key_isolation.py`

#### TestPublicCertPresent — Public CA cert is installed in the agent's trust store.

**Threat:** The agent validates HTTPS traffic against this CA. Without
it, every HTTPS request through the proxy fails with certificate
errors and the agent can't do useful work — or it's tempted to
use --insecure flags that undermine interception security.

- **`test_public_cert_exists`** — Public CA cert file is present in /usr/local/share/ca-certificates.
  - *Probe:* Check `PUBLIC_CERT.exists()` for safeyolo.crt.
  - *Consequence if unasserted:* Missing file means update-ca-certificates never added
it — the agent can't verify proxy-signed certs.
- **`test_public_cert_readable`** — Public CA cert file is readable and contains a PEM certificate.
  - *Probe:* Read safeyolo.crt; assert contents include 'BEGIN
CERTIFICATE'.
  - *Consequence if unasserted:* A zero-byte or non-PEM file would pass the existence
check but still break TLS. Confirms the file is actually a
usable cert, not a stub.
- **`test_public_cert_has_no_private_key`** — Public CA cert file contains no PRIVATE KEY block.
  - *Probe:* Read safeyolo.crt; assert 'PRIVATE KEY' is not in
the content.
  - *Consequence if unasserted:* If the install script accidentally concatenates the
public cert with the private key, shipping both to every
sandbox, the agent has root of trust on arbitrary domains —
complete interception bypass.

#### TestPrivateKeyAbsent — CA private key never enters the sandbox, anywhere.

**Threat:** The CA private key is the root of trust for mitmproxy's
TLS interception. An agent that obtains it can sign certificates
for any domain and impersonate any service — defeating every
network/credential guard that depends on TLS inspection. This
class probes multiple filesystem locations from the adversary's
perspective to prove the key is structurally absent.

- **`test_no_key_files_in_cert_store`** — No .key files in /usr/local/share/ca-certificates.
  - *Probe:* List the trust store dir; assert no file has suffix .key.
  - *Consequence if unasserted:* The trust store is the obvious place to accidentally
drop a private key alongside its cert. A .key file here is
the simplest possible leak pattern.
- **`test_no_key_files_in_config_share`** — No .key files in /safeyolo (the config share).
  - *Probe:* List files in /safeyolo; assert no .key suffix.
  - *Consequence if unasserted:* The config share is mounted from the host and could
accidentally include key material if prepare_config_share
is too greedy about what it copies.
- **`test_no_private_key_content_in_pem_files`** — No .pem/.crt file in cert directories contains PRIVATE KEY.
  - *Probe:* Walk the trust store, config share, and /etc/ssl/certs;
read every .pem/.crt; assert none contain 'PRIVATE KEY'.
  - *Consequence if unasserted:* Catches the naming-convention dodge — even if the file
is called .crt (public), it could carry private key content.
Tests the content, not the name.
- **`test_full_filesystem_scan_for_private_keys`** — Whole-filesystem scan finds no PRIVATE KEY content.
  - *Probe:* os.walk from / (skipping /proc, /sys, /dev, /run and
third-party site-packages); read the first 1 KiB of each
regular file; assert 'PRIVATE KEY' doesn't appear.
  - *Consequence if unasserted:* The targeted tests above check known-critical paths.
This is the catch-all: if the key leaked to a surprising
location (/tmp, /var/log, an agent workspace subdir), the
targeted tests would miss it but this scan would catch it.

### `tests/blackbox/isolation/test_vm_isolation.py`

#### TestNetworkEscape — Sandbox cannot reach external networks except through the proxy.

**Threat:** The proxy is the sole authorised egress path. Every other
network-layer route — direct IP, raw sockets, alternate ports,
IPv6, DNS, cloud metadata IPs — must be unreachable. A gap here
means data exfiltrates outside the credential/network guards
entirely, and the agent operates with no policy enforcement.

- **`test_direct_http_blocked`** — Direct HTTP to an external IP (bypassing proxy) fails.
  - *Probe:* curl --noproxy to http://1.1.1.1; assert non-zero exit.
  - *Consequence if unasserted:* The most basic egress escape — if the agent can just
curl any IP directly, the proxy is decorative.
- **`test_direct_https_blocked`** — Direct HTTPS to an external IP (bypassing proxy) fails.
  - *Probe:* curl -k --noproxy to https://8.8.8.8; assert non-zero exit.
  - *Consequence if unasserted:* A firewall that only blocks port 80 would let port 443
traffic through. TLS at the IP layer bypasses URL-based
inspection entirely.
- **`test_dns_udp_blocked`** — Raw UDP to 8.8.8.8:53 fails.
  - *Probe:* Craft a DNS query, sendto() a UDP socket pointed at
8.8.8.8:53; assert the receive times out.
  - *Consequence if unasserted:* DNS is a classic covert-channel egress. If UDP/53 is
open, an agent can stream data via DNS tunnelling, which
never touches the HTTP proxy.
- **`test_raw_socket_blocked`** — AF_INET raw socket creation fails (no CAP_NET_RAW in sandbox).
  - *Probe:* socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) then sendto a
crafted ICMP echo to 1.1.1.1; assert PermissionError/OSError.
  - *Consequence if unasserted:* ICMP tunnelling and ping-based exfiltration rely on raw
sockets. Without CAP_NET_RAW the syscall fails at creation.
- **`test_direct_alt_port_blocked`** — Direct TCP to 1.1.1.1 on 8443, 22, 6667, 25 all fail.
  - *Probe:* curl --noproxy to 1.1.1.1 on each non-standard port;
assert non-zero exit for every port.
  - *Consequence if unasserted:* A firewall that only blocked :80 and :443 would leave
every other port open. Alt-HTTPS (:8443), SSH (:22), IRC
(:6667, historical C2), SMTP (:25) are all realistic C2/
exfil channels the agent might attempt.
- **`test_libc_resolver_blocked`** — getaddrinfo() on an external name raises gaierror.
  - *Probe:* socket.getaddrinfo("blackbox-probe-should-not-resolve.
example", 80, ...); assert gaierror.
  - *Consequence if unasserted:* Raw UDP/53 blocking alone doesn't cover the libc
resolver path. If /etc/resolv.conf points at a reachable
nameserver, getaddrinfo quietly succeeds — agents using
the system resolver bypass the proxy for lookups and can
DNS-tunnel data.
- **`test_non_icmp_raw_protocols_blocked`** — Raw sockets for SCTP/GRE/IPIP also fail.
  - *Probe:* socket(AF_INET, SOCK_RAW, proto) for proto in
[132=SCTP, 47=GRE, 4=IPIP]; assert PermissionError/OSError
for each.
  - *Consequence if unasserted:* If the sandbox filter scopes raw sockets only by
IPPROTO_ICMP, tunnelling protocols (GRE, IPIP, SCTP) leak
through and provide alternate exfil paths invisible to
TCP/UDP observers.
- **`test_ipv6_egress_blocked`** — IPv6 egress via curl -6 and AF_INET6 socket both fail.
  - *Probe:* curl -6 to a literal v6 address; AF_INET6 socket
connect to the same; both must fail/timeout.
  - *Consequence if unasserted:* mitmproxy binds to IPv4 only. If the sandbox has v6
connectivity, the agent can reach any v6-capable destination
outside the proxy's view entirely — a complete bypass.
- **`test_metadata_ips_unreachable`** — Cloud metadata IPs (169.254.169.254, 169.254.170.2) are unreachable.
  - *Probe:* curl --noproxy to each metadata IP; assert non-zero exit.
  - *Consequence if unasserted:* On a cloud VM host, link-local metadata endpoints expose
instance IAM credentials and user-data. A sandbox that can
reach them SSRFs the host's IAM role — often full access to
the cloud account.
- **`test_af_packet_blocked`** — AF_PACKET socket creation fails.
  - *Probe:* socket(17 /* AF_PACKET */, SOCK_RAW, 0); assert
PermissionError/OSError.
  - *Consequence if unasserted:* AF_PACKET lets the process craft Ethernet frames
directly. With it, an agent can ARP-spoof, forge source
IPs (bypassing L3 firewall rules by appearing to be the
host), or probe the L2 neighbourhood.
- **`test_dns_tunnel_subdomain_blocked`** — Arbitrary subdomain under a real TLD does not resolve.
  - *Probe:* getaddrinfo("exfil-data-here.tunnel-probe.httpbin.org",
...); assert gaierror. If it resolves, fail.
  - *Consequence if unasserted:* DNS tunnelling encodes data in subdomain labels
(<base64>.exfil.attacker.com) — every query leaks ~60 bytes
to a nameserver the attacker controls. The proxy never sees
it because it's DNS, not HTTP. The only safe posture is no
external name resolution at all.
- **`test_host_header_mismatch_routes_by_url`** — Host-header mismatch with URL routes by URL (200, not 4xx).
  - *Probe:* Send a proxy'd GET with URL=httpbin.org and
Host=evil.com; assert 200 (URL is authoritative; Host is
advisory per RFC 7230 §5.4).
  - *Consequence if unasserted:* An agent must not be able to smuggle a blocked
destination by putting it in the Host header while keeping
an allowed URL. The URL is what gets evaluated and where the
traffic goes; confirming that guarantees no Host-based
domain-fronting evasion.
- **`test_proxy_reachable`** — HTTP via the proxy to an allowlisted host succeeds (200).
  - *Probe:* curl through HTTP_PROXY to an allowlisted host with
an X-Test-Context header; assert 200.
  - *Consequence if unasserted:* Positive control for the entire isolation suite. If
this fails, the agent has no connectivity at all — all
other "reachability blocked" assertions become meaningless
("everything is blocked including what should work").

#### TestHostAdjacentReachability — Sandbox cannot reach host-side services other than the proxy.

**Threat:** The agent is meant to reach only the proxy, and everything
else on the host (admin API, SSH, arbitrary local services,
other agents' subnets) must be off-limits. A pass-by-default
configuration (whatever isn't explicitly blocked is reachable)
would let an agent pivot to local-only services assumed safe
because they're bound to loopback or LAN.

- **`test_admin_api_unreachable`** — SafeYolo admin API ports (9090, 9190) are unreachable.
  - *Probe:* TCP connect to host:9090 and host:9190 from inside the
sandbox; assert both fail.
  - *Consequence if unasserted:* The admin API can change policy modes (block → warn),
add allowlist entries, or approve credentials. Agent access
to it would defeat every other control SafeYolo enforces —
a single-request sandbox escape.
- **`test_host_ssh_unreachable`** — Port 22 reachable from sandbox is its own sshd, not the host's.
  - *Probe:* Connect to port 22 on the resolved proxy host; if a
banner comes back, the connection terminated to the
sandbox-internal sshd (or nothing at all). Pass if
timeout/refused.
  - *Consequence if unasserted:* If the agent can reach the host's SSH, it can try
password brute force or probe for authorized_keys leaks.
The sandbox-internal sshd is a separate service that
doesn't run against host keys.
- **`test_host_listener_unreachable`** — A live TCP listener on the host is unreachable.
  - *Probe:* Read the marker file /safeyolo/host-listener-port
(harness starts a real TCP listener on 127.0.0.1:<port>
before booting the VM); assert the sandbox cannot connect.
  - *Consequence if unasserted:* Distinguishes "blocked by isolation" from "nothing
listening." The listener test guards against future
implementation changes — a regression that gave the sandbox
routable paths to the host would silently break isolation
but pass the arbitrary-port test.
- **`test_arbitrary_host_port_unreachable`** — An unused port (44444) on the host is unreachable.
  - *Probe:* TCP connect to host:44444; assert fail.
  - *Consequence if unasserted:* Together with test_host_listener_unreachable, confirms
block-by-default — an arbitrary port nothing listens on
should still be unreachable (not just refused by the
kernel because no service is bound). Complements the
live-listener test for full coverage.
- **`test_cross_agent_ip_unreachable`** — Adjacent agents' attribution IPs are unreachable.
  - *Probe:* Derive this agent's attribution IP (10.200.x.y) from
loopback; probe TCP on the neighbouring ±1 offsets; assert
both unreachable.
  - *Consequence if unasserted:* Each agent runs in an isolated netns with its own
loopback. If one agent could reach another's attribution
IP, cross-agent lateral movement would be possible — an
agent compromised by the user's content could pivot to a
neighbouring agent's workspace.
- **`test_sinkhole_direct_unreachable`** — Sinkhole ports 18080/18443/19999 unreachable direct from sandbox.
  - *Probe:* TCP connect to host:18080, :18443, :19999 (sinkhole
HTTP, HTTPS, control API); assert all fail.
  - *Consequence if unasserted:* Sinkhole ports bind 0.0.0.0 during test runs, so they
ARE listening — unlike the 44444 test. A direct sandbox →
sinkhole connect succeeding here would mean the isolation
boundary has a real hole, not just absence of services.

#### TestPrivilegeEscalation — Agent cannot gain root, load modules, or poke kernel memory.

**Threat:** Every local privilege-escalation vector — running as root,
setuid(0), kernel module loading, /dev/mem, eBPF — is a path
to full sandbox escape. The agent must run unprivileged and be
unable to acquire privileges through any of these mechanisms.

- **`test_runs_as_nonroot`** — Agent process uid is not 0.
  - *Probe:* os.getuid() != 0.
  - *Consequence if unasserted:* Running as root in the sandbox elevates the impact of
every subsequent bug. Even with namespaces, root-inside-a-
container is one kernel vuln away from host root.
- **`test_expected_uid`** — Agent process runs as uid 1000.
  - *Probe:* os.getuid() == 1000.
  - *Consequence if unasserted:* The attribution chain (service_discovery, bind-mount
ownership, userns mapping) all assume uid 1000 inside the
sandbox. A different uid means ownership mismatches and
identity confusion.
- **`test_cannot_gain_root`** — setuid(0) raises PermissionError.
  - *Probe:* os.setuid(0) under pytest.raises(PermissionError).
  - *Consequence if unasserted:* If setuid to root works, the agent is 'nonroot' only
by convention. Any suid binary or kernel bug that bypasses
normal checks could elevate. Must fail at the syscall level.
- **`test_kernel_modules_disabled`** — init_module(2) syscall returns non-success.
  - *Probe:* Direct syscall to init_module with null args; assert
return value is -1 and errno non-zero.
  - *Consequence if unasserted:* Loading a kernel module is immediate, total compromise
— the module runs in ring 0. Blocked either by
CONFIG_MODULES=n in the guest kernel, or by gVisor's
user-space kernel rejecting the syscall.
- **`test_no_dev_mem`** — /dev/mem does not exist in the sandbox.
  - *Probe:* os.path.exists("/dev/mem") is False.
  - *Consequence if unasserted:* /dev/mem is a direct view of physical RAM. If present
and readable, the agent can dump kernel data structures and
potentially extract secrets from other processes.
- **`test_no_dev_kmem`** — /dev/kmem does not exist in the sandbox.
  - *Probe:* os.path.exists("/dev/kmem") is False.
  - *Consequence if unasserted:* /dev/kmem exposes kernel virtual memory directly —
easier to parse than /dev/mem and equally dangerous for
secret extraction.
- **`test_ebpf_blocked`** — bpf(2) syscall fails.
  - *Probe:* Invoke syscall numbers 321 (x86_64) and 280 (aarch64)
for SYS_bpf with zero args; if any returns 0, fail.
  - *Consequence if unasserted:* eBPF programs run in kernel context with wide access —
network introspection, kprobe instrumentation, cgroup
hooks. Even with verifier constraints, eBPF has been a
recurring privilege-escalation vector.

#### TestFilesystemIsolation — Config share mount is read-only and holds no private keys.

**Threat:** /safeyolo contains configuration and agent metadata from
the host. It is mounted read-only so a compromised agent can't
write back to the host's config, and must never contain private
key material that a TLS-intercept attack would benefit from.

- **`test_config_share_readonly`** — Writes to /safeyolo raise OSError.
  - *Probe:* open("/safeyolo/test-write-attempt", "w") under
pytest.raises(OSError).
  - *Consequence if unasserted:* A writable config share would let the agent modify
its own configuration (proxy settings, policy files) and
potentially affect the host's view of agent state. Must
be read-only.
- **`test_no_private_key_in_config_share`** — No file in /safeyolo contains PRIVATE KEY markers or has .key suffix.
  - *Probe:* List /safeyolo files; reject any whose name contains
'private' or ends in '.key', or whose first 500 bytes
contain 'PRIVATE KEY'.
  - *Consequence if unasserted:* The CA private key is the root of trust for TLS
interception. A stray copy on the config share is
game-over for cert verification.

#### TestSandboxExposure — Sandbox surfaces (/dev, /proc, PID namespace) expose nothing useful.

**Threat:** A hardened sandbox minimises what the adversary can inspect
or manipulate. Each leaked surface — an unexpected device node,
a readable /proc/kcore, a full host process list — is a rung on
the escalation ladder. These probes test the reduction, not the
mechanism (which varies between gVisor and VZ).

- **`test_dev_whitelist`** — Every /dev entry is on the expected whitelist.
  - *Probe:* Enumerate /dev; compare against the expected set
(plus prefixed exceptions for microVMs); assert no
unexpected entries.
  - *Consequence if unasserted:* Novel device entries are attack surface. This test is
deliberately allowlist-based rather than blocklist-based —
if the runtime adds a new device, the test fails until a
human evaluates whether it should be there.
- **`test_proc_kcore_unreadable`** — /proc/kcore is absent or unreadable.
  - *Probe:* Skip if /proc/kcore doesn't exist; otherwise, open
it under pytest.raises(PermissionError/OSError).
  - *Consequence if unasserted:* /proc/kcore is a live view of kernel memory as an ELF
core dump. Reading it leaks kernel data structures and
credentials from other processes.
- **`test_proc_kallsyms_redacted`** — /proc/kallsyms (if readable) shows addresses redacted to zero.
  - *Probe:* Read first 50 lines of /proc/kallsyms; assert every
line starts with '0000000000000000'.
  - *Consequence if unasserted:* Unredacted kernel symbol addresses give attackers
exact offsets for ROP/JOP gadgets — a major leg-up for
kernel-exploit chains. Modern kernels redact to zero for
unprivileged readers; this test catches regressions.
- **`test_sys_kernel_debug_inaccessible`** — /sys/kernel/debug is absent or unreadable.
  - *Probe:* Skip if /sys/kernel/debug doesn't exist; else, call
os.listdir() under pytest.raises(PermissionError/OSError).
  - *Consequence if unasserted:* debugfs/tracefs expose kernel internals (probes, event
tracers, module lists). A listable /sys/kernel/debug is a
broad surface for kernel introspection and — via tracefs —
a privilege-escalation vector.
- **`test_pid_namespace_isolated`** — PID 1's cmdline is the sandbox init, not the host's.
  - *Probe:* Read /proc/1/cmdline; assert it does NOT contain
'systemd', '/sbin/init', or 'launchd'.
  - *Consequence if unasserted:* If PID 1 is the host's init, the PID namespace is
leaking through and the agent can read the full host
process table — every running service's cmdline, including
argv secrets and parent hierarchies.
- **`test_firewall_rules_not_readable`** — iptables/pfctl don't emit rules from inside the sandbox.
  - *Probe:* Run `iptables -L`, `iptables-save`, `pfctl` if present;
fail if any exits 0 with non-empty output.
  - *Consequence if unasserted:* An agent that can enumerate host firewall rules learns
exactly which ports/IPs are reachable via which path — a
map of the egress surface to probe. Also implies CAP_NET_ADMIN,
which the sandbox must not have.
- **`test_host_ssh_not_reachable_via_sandbox_sshd`** — No SSH private keys are present in the sandbox filesystem.
  - *Probe:* Check /root/.ssh/ and /home/agent/.ssh/ for id_ed25519
or id_rsa; fail if any exists.
  - *Consequence if unasserted:* Defence-in-depth. The sandbox runs sshd for inbound
operator access, but must not possess client private keys
that could be used to ssh OUT to the host or another agent.
A leaked private key turns the sandbox into a lateral-
movement pivot.

#### TestFilesystemBoundary — Workspace mount is contained; no setuid, mknod, or traversal escape.

**Threat:** /workspace is a shared surface between agent and host. If
the agent can create setuid binaries, device nodes, or symlinks
that leak outside the mount, it can either escalate inside the
sandbox or trick the host into touching files outside /workspace.

- **`test_workspace_symlink_traversal`** — Symlink to /etc/shadow inside /workspace doesn't reach host files.
  - *Probe:* Create /workspace/.../shadow-link → /etc/shadow; try
to read it. If readable, assert the content does NOT look
like the host's real shadow file (which would have many
colon-separated fields and 'root:' entries).
  - *Consequence if unasserted:* virtiofs/lisafs gofer mounts are supposed to contain
traversal within the sandbox rootfs. A bug that followed
symlinks on the host side would let the agent read any host
file the mount process can see — /etc/shadow, SSH keys,
cloud credentials.
- **`test_workspace_no_setuid`** — setuid bit on a /workspace binary doesn't execute as root.
  - *Probe:* Create a script in /workspace, chmod 4755 (setuid
root), execute it; if it reports 'root', fail. Bit present
on disk but not effective at exec is acceptable.
  - *Consequence if unasserted:* /workspace should be mounted `nosuid`. Otherwise the
agent (uid 1000) could make a suid-root shell and
immediately gain root inside the sandbox — the first step
of most escape paths.
- **`test_workspace_no_mknod`** — mknod on /workspace fails with PermissionError/OSError.
  - *Probe:* os.mknod('/workspace/.../testdev', S_IFCHR, makedev(1,3));
assert the call fails.
  - *Consequence if unasserted:* /workspace should be mounted `nodev` and the sandbox
should lack CAP_MKNOD. Device nodes on a shared mount let
the agent access arbitrary devices (raw block devices like
/dev/sda, tty, etc.) once the host views the file.
- **`test_ca_trust_store_immutable`** — Writes to /usr/local/share/ca-certificates fail.
  - *Probe:* Attempt to write a fake-CA PEM to the trust store
directory; expect PermissionError/OSError.
  - *Consequence if unasserted:* If the agent can add a CA to its own trust store, it
can stand up a local MITM for its own traffic — TLS-
inspecting requests that should have gone through SafeYolo.
The trust store must be read-only to uid 1000.

#### TestSyscallSeccompEquivalents — Dangerous syscalls (keyring, pivot_root, unshare, ptrace) are blocked or contained.

**Threat:** Docker's default seccomp profile drops ~44 syscalls that
are rarely legitimate and historically exploited — kernel
keyring injection (CVE-2017-6074), pivot_root filesystem
escape, user-namespace creation as escalation vehicle, ptrace
process introspection. Blackbox checks confirm the same
exposures are closed on the current runtime (gVisor or VZ).

- **`test_keyctl_blocked`** — keyctl(2) returns -1 with non-zero errno.
  - *Probe:* Call SYS_keyctl with KEYCTL_GET_KEYRING_ID=0 and zero
args; assert ret == -1 and errno != 0.
  - *Consequence if unasserted:* The kernel keyring is a shared store across processes.
CVE-2017-6074 and several related issues exploited keyctl
to escalate privileges. Blocked in Docker's default seccomp
for exactly this reason.
- **`test_add_key_blocked`** — add_key(2) returns -1 with non-zero errno.
  - *Probe:* Call SYS_add_key with zero args; assert ret == -1 and
errno != 0.
  - *Consequence if unasserted:* Companion to keyctl — adds keys to the kernel keyring.
Same privilege-escalation exposure. Blocked in Docker's
default seccomp.
- **`test_pivot_root_blocked`** — pivot_root(2) returns -1 with non-zero errno.
  - *Probe:* Call SYS_pivot_root with zero args; assert ret == -1
and errno != 0.
  - *Consequence if unasserted:* pivot_root moves the root filesystem — combined with
a mount from an attacker-controlled directory, it's a
classic container escape. Must not be callable from the
sandbox.
- **`test_unshare_user_ns_contained`** — unshare(CLONE_NEWUSER) grants no new access even if it succeeds.
  - *Probe:* Call unshare with CLONE_NEWUSER. If it fails, pass
(strongest outcome). If it succeeds, verify /etc/shadow is
still unreadable, PID 1's cmdline still doesn't reveal host
init, and /safeyolo is still read-only.
  - *Consequence if unasserted:* gVisor's sentry emulates namespaces, and VZ microVMs
run real kernels — both allow the syscall. The property
that matters is that the new namespace doesn't grant
privileges the agent didn't already have. Tests the
escape, not the syscall.
- **`test_ptrace_init_blocked`** — ptrace(PTRACE_ATTACH, 1, ...) returns -1.
  - *Probe:* Call SYS_ptrace with PTRACE_ATTACH on pid 1; assert
ret == -1 and errno != 0.
  - *Consequence if unasserted:* Attaching to init lets the agent read memory (keys,
tokens) from the most privileged process in the sandbox
and potentially inject code. Docker drops ptrace entirely
in its default seccomp.
