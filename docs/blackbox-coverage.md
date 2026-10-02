# SafeYolo Blackbox Test Coverage

Generated from native pytest selections and installed procedures in `tests/blackbox/`. Do not edit by hand — run `python3 tests/blackbox/gen_docs.py`.

Each entry states the security property the test asserts and the threat it defends against. The probe (What) describes the specific observation used to confirm the property.

**82 distinct pytest methods across 23 threat categories.**

This is a source inventory, not a passing execution receipt. The ordinary guest selection excludes root containment; the root selection runs root containment and private-key isolation. Private-key scans run under both identities; public-cert checks run as the ordinary user. Parameterization and platform/fixture skips affect executed nodes. The retired host/proxy selection is excluded.

## Installed procedural selections

`run-installed.sh` prepares once and runs these independent sections:

| Actual lane | Selected sections |
|---|---|
| `systrap` | isolation, workloads, access, lifecycle, continuity |
| `kvm` | isolation, ingress, workloads |
| `vz` | isolation, access, lifecycle, continuity |

### `tests/blackbox/installed_access.py`

Exercise installed access through two live systrap or VZ guests.

Retain service and contract binding/risk approvals, exact credential injection
and live peer denial, populated owner-positive/peer-negative guest flow search
and detail, test-context/trace evidence, real NATS Coord and attention, operator
Plumb approval/exchange/closure, WebSocket peer effects and traffic-inspector
filter/transcript/export. These observations stay in one installed composition.

### `tests/blackbox/installed_state_transition.py`

Check installed native state through restart, replacement and recovery.

Use the current installed CLI and its exact --install-commit.
No agent is booted: this is installed host composition, not guest isolation.
Each return process must read durable state, reset process-local task policy,
and enforce revocations before deliberately restoring access.

The procedure uses four native process lifetimes. Historical cross-backend
receipts remain recorded in the issue; they are not a current execution mode.

### `tests/blackbox/installed_ingress.py`

Check installed native ingress through one real gVisor/KVM guest.

Require the selected wheel and packaged executable, authenticated runtime and
actual KVM runsc argv/UID mapping. Bind guest localhost requests to its mounted
agent UDS. Observe an exact allowed HTTP marker at the owned origin, a denied
request with no origin delivery, and protected local API boundaries.

### `tests/blackbox/installed_lifecycle.py`

Exercise installed lifecycle through systrap or physical VZ guests.

Retain live listener add/remove, policy changes during admitted SSE, all five
default guest-trust TLS cases (valid, wrong SAN, self-signed, future, expired)
with origin/no-passthrough checks, scoped ignore_hosts removal across held and
new connections, stable CA/upstream trust/policy and recovery. Keep mixed
HTTP/SSE/WS/CONNECT drain, three subject cycles and a separate live owner whose
process, policy and controls survive those cycles. Observe owned stop/cleanup.

### `tests/blackbox/installed_workloads.py`

Exercise installed Linux workloads through one systrap or KVM guest.

Retain package fetch/hash/query/install/payload/purge, read-only Git clone and
exact commit/marker, held SSE first-event/control/release ordering, WSS echo
and peer-close state, denied-upgrade canary with no origin delivery, and pinned
SSH host-key/command through CONNECT. Each selected run owns its fixtures,
disposable key, SSH server and guest writable state.
Installed access owns the plain-WS exchange and inspector observations through
the same guest handshake, payload and close helper.

### Installed host package

`run-installed-package.sh` runs installed_host_smoke.py in smoke mode: current installed launcher, exact wheel/native executable, authenticated runtime identity, owned HTTP allow/deny origins and verified stop. It boots no guest and proves no guest isolation.

The package also selects `tests/proxy_contracts/test_https_contract.py::test_https_origin_verification` against its packaged executable.

The complete native process/protocol family is separately maintained in `tests/proxy_contracts/`, run once per supported host platform overnight. installed_state_transition.py checks installed durable state through four native process lifetimes on Linux and the hosted Mac. Historical cross-backend receipts remain in the accepted issues. Runner selection describes intended execution, not a passing receipt.

## Installed native ingress

### `tests/blackbox/host/native/test_installed_native.py`

#### TestInstalledNative — The installed native listener serves real host requests during the guest run.

**Threat:** An isolation pass cannot name a native proxy if its host requests ran
through a different process or never reached an origin.

- **`test_controlled_origin_and_protected_admin`** — The selected agent reaches an owned origin and cannot proxy to admin.
  - *Probe:* Send one ordinary request to the controlled sinkhole, then one
to the protected management listener through the same agent socket.
  - *Consequence if unasserted:* A response alone cannot show origin delivery or admin containment.

## Host process security

### `tests/blackbox/host/security/test_firewall_structural.py`

#### TestProcessSecrecy — Proxy process doesn't leak SafeYolo tokens via its cmdline.

**Threat:** Process command lines are readable by any local user via
`ps aux` or `/proc/PID/cmdline`. If SafeYolo tokens appear in
the mitmdump invocation, a non-root user on the host (or a
process that escaped the sandbox) can read them and gain full
admin control. Tokens must be passed via file or env var instead.

- **`test_no_tokens_in_process_cmdline`** — Admin and agent tokens do not appear in the selected proxy cmdline.
  - *Probe:* Inspect the native receipt's PID or the retained mitmdump
process command line; assert neither token is a substring.
  - *Consequence if unasserted:* A token in the cmdline is readable by any local user —
full admin access leaks to anyone with shell on the host.

## Installed agent identity

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
- **`test_agent_map_has_socket`** — Per-agent proxy socket referenced in the entry exists on disk.
  - *Probe:* Reads the 'socket' field and asserts the path is a
live Unix domain socket (Path.is_socket()).
  - *Consequence if unasserted:* The per-agent UDS (bound by mitmproxy's
UnixInstance) is the only egress path for the agent. A missing or
stale socket means every agent request fails with ENOENT —
effectively a denial of service, not a security issue, but a strong
signal that the identity chain is broken.

#### TestRootlessUidMapping — Linux sandbox identities map to non-root host identities.

**Threat:** SafeYolo intentionally permits namespace-root for package
installation. Its host safety depends on the enclosing user
namespace mapping sandbox uid 0 to a subordinate uid while mapping
sandbox uid 1000 to the operator for workspace access.

- **`test_sandbox_root_maps_to_subordinate_host_uid`** — Sandbox uid 0 maps to uid 100000 rather than host root.
  - *Probe:* On Linux, read the live user-namespace holder's uid_map
and assert sandbox uid 0 maps to host uid 100000, while uid
1000 maps only to the current host operator uid.
  - *Consequence if unasserted:* If sandbox uid 0 mapped to host uid 0, setpriv or a package
maintainer script would gain real host root. If uid 1000 did
not map to the operator, normal workspace ownership would fail.

## Installed agent persistence and restart

### `tests/blackbox/host/lifecycle/test_home_persistence.py`

#### TestAgentHomePersistence — Writes to /home/agent persist across `agent stop` and `agent run`.

**Threat:** The persistent home is where mise installs, shell history,
host-script-staged auth (e.g. ~/.claude.json), and any user state
live. If it doesn't survive a sandbox restart, every `agent run`
is effectively a fresh install — no auth, no cached tools, no
shell history. On Linux the memory-backed overlay silently
discarded those writes before the OCI bind-mount landed; this
test guards against a regression to that behavior.

- **`test_home_persists_across_restart`** — Marker written to /home/agent is still there after stop/start.
  - *Probe:* Write a random-token marker file to /home/agent from
inside the running agent, stop the sandbox, start it again,
read the marker back from the fresh sandbox, assert the
content is identical.
  - *Consequence if unasserted:* A missing file or mismatched content means writes to
/home/agent landed somewhere ephemeral (the memory overlay
on Linux, or an un-mounted location on either platform) —
the OCI bind-mount is broken or was never wired. Host-script
auth staging, mise installs, and shell history all rely on
this invariant.

### `tests/blackbox/host/lifecycle/test_token_lifecycle.py`

#### TestLiveAgentLifecycle — Agent egress survives proxy restart without restarting its sandbox.

**Threat:** The agent_token authenticates the sandbox's requests to the
agent API. If a proxy restart regenerates the token but the
sandbox still holds the old value, the agent gets 401 on every
diagnostic call — breaking `safeyolo explain`, credential
approval UX, and any other observability feature the agent
exposes to itself. Token- and UDS-inode refresh across a proxy
restart is the common regression point this test catches.

- **`test_agent_api_survives_proxy_restart`** — Agent API stays reachable from the sandbox across proxy restart.
  - *Probe:* Verify agent API /health returns 200 from inside the
sandbox; stop + start the test proxy; assert /health still
returns 200 from the same running sandbox.
  - *Consequence if unasserted:* A recreated token or Unix socket must remain reachable from
the same sandbox. File-binding the old socket inode made every
reconnect fail even though the host pathname had been recreated.

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
- **`test_full_filesystem_scan_for_private_keys`** — Whole-filesystem scan finds no unexpected private-key material.
  - *Probe:* os.walk from / (skipping /proc, /sys, /dev, /run and
third-party site-packages); inspect private-key markers and allow only
the three exact guest sshd host-key paths.
  - *Consequence if unasserted:* The targeted tests above check known-critical paths.
This is the catch-all: if any private key leaked to a surprising
location (/tmp, /var/log, an agent workspace subdir), the
targeted tests would miss it but this scan would catch it. Guest-local
SSH host keys are expected only at their standard paths.

### `tests/blackbox/isolation/test_root_containment.py`

#### TestGuestRootCapability — Guest root is available and useful inside the isolated environment.

**Threat:** Agents need to install distro packages and repair their own guest
environment. A test suite which only proves non-root operation can miss a
broken sudo/root path even though that path is a supported feature.

- **`test_root_shell_has_uid_zero`** — The operator-selected root shell really runs as guest UID 0.
  - *Probe:* Read the effective and real process UIDs and require both to be
zero when the suite is launched with ``agent shell --root``.
  - *Consequence if unasserted:* Merely accepting the CLI flag is not useful acceptance evidence;
package installation and guest repair require actual guest-root
privileges.
- **`test_root_shell_and_pid1_have_nofile_limit`** — The root SSH login and its PID 1 view have the required limit.
  - *Probe:* Inspect this process through the dedicated ``agent shell --root``
lane and read the open-file limit for PID 1 from proc.
  - *Consequence if unasserted:* SSH can produce identity-specific limits. A sudo transition
inside the normal agent session does not exercise the root login path
that the CLI creates.
- **`test_root_can_install_local_apt_package`** — Guest root can install and remove a local package with apt/dpkg.
  - *Probe:* Build a minimal local Debian package, install it through apt,
verify its payload under /usr/local, then purge it without network
downloads.
  - *Consequence if unasserted:* This exercises the filesystem overlay and package database that
real ``apt`` installs depend on, while keeping acceptance deterministic
and independent of an external mirror.

#### TestGuestRootTrustIsolation — Guest trust changes cannot widen the host proxy's upstream trust.

**Threat:** Guest root can install packages and local trust anchors. That
supported capability must remain inside the sandbox. The host proxy must
continue to authenticate upstream TLS with its own trust store.

- **`test_guest_ca_change_does_not_change_proxy_validation`** — A guest-only trust anchor remains untrusted by the host proxy.
  - *Probe:* Install the sinkhole's self-signed leaf into the writable guest
trust store, prove the guest bundle accepts it, then request that
upstream through SafeYolo and require the host proxy to return 502.
  - *Consequence if unasserted:* A successful upstream request would show that guest-controlled
trust changed the proxy's host-side certificate validation boundary.

#### TestGuestRootContainment — Guest root cannot cross the SafeYolo isolation boundary.

**Threat:** UID 0 is intentionally powerful inside the guest. It must still be
unable to bypass proxy-only egress, reach host listeners, modify the
host-backed SafeYolo share, or access a host virtualization device.

- **`test_root_direct_egress_blocked`** — Guest root cannot bypass the proxy with a direct connection.
  - *Probe:* Use curl with all proxy handling disabled against a public IP
and require the connection to fail.
  - *Consequence if unasserted:* Package-management privilege must not also grant an unobserved
network path around SafeYolo's policy and credential controls.
- **`test_root_proxy_path_works`** — Guest root retains the authorised proxy egress path.
  - *Probe:* Send an HTTP request through HTTP_PROXY to the allowlisted test
host and require a 200 response.
  - *Consequence if unasserted:* A direct-egress failure is only meaningful when the intended
proxy path is a working positive control for the same root process.
- **`test_root_cannot_reach_live_host_listener`** — Guest root cannot connect to a known-live host TCP service.
  - *Probe:* Read the harness listener port from the read-only config share
and attempt a direct TCP connection to the host address.
  - *Consequence if unasserted:* Testing a live listener distinguishes real host isolation from a
connection failure caused only by choosing an unused port.
- **`test_root_cannot_modify_host_config_share`** — Guest root cannot write the host-backed SafeYolo config share.
  - *Probe:* Attempt to create a probe beneath /safeyolo and require an
operating-system error with no file left behind.
  - *Consequence if unasserted:* A writable share would let a root package maintainer script
mutate host-side proxy or agent configuration across the boundary.
- **`test_gvisor_root_cannot_access_host_kvm_device`** — The host KVM device is not exposed inside a gVisor sandbox.
  - *Probe:* In a gVisor lane, assert /dev/kvm is absent even in a
guest-root shell; hardware microVMs use their own device boundary.
  - *Consequence if unasserted:* The Linux KVM lane gives gVisor's sentry host-side access to KVM;
passing that device through to the agent would expose a powerful host
virtualization interface outside the intended boundary.

### `tests/blackbox/isolation/test_runtime_capabilities.py`

#### TestOpenFileLimit — Every supported sandbox exposes the same open-file headroom.

**Threat:** A lower hard limit on the VZ normal-session path makes agent
workloads depend on the operator's host platform. The session must repair
that limit before it runs the requested workload.

- **`test_pid1_shell_and_child_inherit_nofile_limit`** — PID 1 and all later descendants have a 65536 soft/hard limit.
  - *Probe:* Read PID 1's proc limit, inspect the running test process that
was launched through the normal agent-shell path, and spawn one more
child.
  - *Consequence if unasserted:* Checking only the final agent process can hide a child-only
workaround. The normal SSH entry path must establish the session and
its visible PID 1 limit before it launches the requested workload.

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
an X-SafeYolo-Test-Context header; assert 200.
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

- **`test_admin_api_unreachable`** — The host admin API listeners are unreachable from the sandbox.
  - *Probe:* TCP connect to the admin ports named by the harness. The
default Linux lane checks both production 9090 and test 9190;
the physical VZ lane checks its assigned live test port.
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
- **`test_sinkhole_direct_unreachable`** — The live sinkhole HTTP, HTTPS, and control paths are unreachable.
  - *Probe:* TCP connect to each harness origin and control path. On VZ,
HTTP and control share one listener; both probes use that port.
  - *Consequence if unasserted:* Sinkhole ports bind 0.0.0.0 during test runs, so they
ARE listening — unlike the 44444 test. A direct sandbox →
sinkhole connect succeeding here would mean the isolation
boundary has a real hole, not just absence of services.

#### TestGuestPrivilegeBoundary — Guest privilege remains inside the sandbox boundary.

**Threat:** Agents start as uid 1000 but may need guest root to install
packages. On Linux that root is deliberately namespace-root,
mapped to an unprivileged subordinate host uid. Kernel modules,
host memory, and eBPF remain unavailable regardless of guest uid.

- **`test_expected_uid`** — Agent process runs as uid 1000.
  - *Probe:* os.getuid() == 1000.
  - *Consequence if unasserted:* The attribution chain (service_discovery, bind-mount
ownership, userns mapping) all assume uid 1000 inside the
sandbox. A different uid means ownership mismatches and
identity confusion.
- **`test_privilege_transition_matches_platform_contract`** — Guest-root transition follows the platform's isolation model.
  - *Probe:* On a hardware microVM, direct setuid(0) must fail. On
Linux gVisor, setpriv must reach uid 0 inside the sandbox;
the host-side uid-map test separately proves this maps to a
subordinate uid rather than host root.
  - *Consequence if unasserted:* Package installation needs an intentional guest-root
path, while treating namespace-root as host root would both
break that feature and test the wrong security boundary.
- **`test_sudo_reaches_guest_root`** — The standard sudo command reaches root only inside the guest.
  - *Probe:* Run `sudo -n id -u` as the agent and require uid 0. On
gVisor the SafeYolo shim uses namespace capabilities; on a
hardware microVM the distro's normal sudo transition applies.
  - *Consequence if unasserted:* Agents need a familiar, non-operator-mediated way to
install native packages without confusing host root with
sandbox or VM root.
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

#### TestSandboxRootContainment — Linux namespace-root cannot cross SafeYolo's host boundary.

**Threat:** Allowing agents to install distro packages intentionally
grants root inside gVisor. The security property is therefore
containment: namespace-root must still be unable to modify the
host config share, reach host listeners, inspect host processes,
or access host devices.

- **`test_config_share_stays_readonly_as_sandbox_root`** — Sandbox root cannot write the host-backed config share.
  - *Probe:* Elevate with setpriv and attempt to create a file under
/safeyolo; require the write to fail and the path to remain
absent.
  - *Consequence if unasserted:* If namespace-root can modify this host bind mount it can
tamper with proxy configuration or guest bootstrap state,
turning guest package installation into host-state mutation.
- **`test_host_listener_stays_unreachable_as_sandbox_root`** — Sandbox root cannot connect to a live host TCP listener.
  - *Probe:* Elevate with setpriv, parse the host endpoint from the
configured proxy URL, and attempt a direct TCP connection to
the harness's known-live host listener; require failure.
  - *Consequence if unasserted:* Guest root must not turn the loopback-only network
namespace into a path to host services or the admin API.
- **`test_host_kernel_surfaces_stay_absent_as_sandbox_root`** — Sandbox root sees neither host devices nor the host PID 1.
  - *Probe:* Elevate with setpriv, assert /dev/kvm, /dev/mem and
/dev/kmem are absent, then assert PID 1's command line is not
a host init such as systemd or launchd.
  - *Consequence if unasserted:* Exposing a host device or process namespace to guest root
would convert an intentionally useful guest capability into a
direct host-compromise primitive.

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

#### TestFilesystemBoundary — Workspace mount cannot expose host files or host devices.

**Threat:** /workspace is a shared surface between agent and host. If
the agent can create usable device nodes or symlinks that leak
outside the mount, it can trick the host mount implementation into
exposing resources beyond /workspace. Guest-root access itself is
tested as an intended capability in test_root_containment.py.

- **`test_workspace_symlink_traversal`** — Symlink to /etc/shadow inside /workspace doesn't reach host files.
  - *Probe:* Create /workspace/.../shadow-link → /etc/shadow; try
to read it. If readable, assert it resolves to the same guest
inode and bytes as opening /etc/shadow directly.
  - *Consequence if unasserted:* virtiofs/lisafs gofer mounts are supposed to contain
traversal within the sandbox rootfs. A bug that followed
symlinks on the host side would let the agent read any host
file the mount process can see — /etc/shadow, SSH keys,
cloud credentials.
- **`test_workspace_no_mknod`** — mknod on /workspace fails with PermissionError/OSError.
  - *Probe:* os.mknod('/workspace/.../testdev', S_IFCHR, makedev(1,3));
assert the call fails.
  - *Consequence if unasserted:* /workspace should be mounted `nodev` and the sandbox
should lack CAP_MKNOD. Device nodes on a shared mount let
the agent access arbitrary devices (raw block devices like
/dev/sda, tty, etc.) once the host views the file.

#### TestSyscallSeccompEquivalents — Dangerous syscalls (keyring, pivot_root, unshare, ptrace) are blocked or contained.

**Threat:** A conservative container seccomp baseline drops ~44
syscalls that are rarely legitimate and historically exploited
— kernel keyring injection (CVE-2017-6074), pivot_root
filesystem escape, user-namespace creation as escalation
vehicle, ptrace process introspection. Blackbox checks confirm
the same
exposures are closed on the current runtime (gVisor or VZ).

- **`test_keyctl_blocked`** — keyctl(2) returns -1 with non-zero errno.
  - *Probe:* Call SYS_keyctl with KEYCTL_GET_KEYRING_ID=0 and zero
args; assert ret == -1 and errno != 0.
  - *Consequence if unasserted:* The kernel keyring is a shared store across processes.
CVE-2017-6074 and several related issues exploited keyctl
to escalate privileges — a standard target of conservative
container seccomp profiles.
- **`test_add_key_blocked`** — add_key(2) returns -1 with non-zero errno.
  - *Probe:* Call SYS_add_key with zero args; assert ret == -1 and
errno != 0.
  - *Consequence if unasserted:* Companion to keyctl — adds keys to the kernel keyring.
Same privilege-escalation exposure; a conservative container
seccomp baseline drops both.
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
and potentially inject code. Conservative container seccomp
baselines drop ptrace entirely.
