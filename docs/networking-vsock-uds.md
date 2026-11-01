# Agent networking: vsock and Unix sockets

This is the current request path for the Rust proxy. It describes the host
transport used by Linux gVisor sandboxes and macOS Virtualization.framework
microVMs. Release acceptance is recorded in
[issue #640](https://github.com/craigbalding/safeyolo/issues/640).

## Request and shell paths

Each sandbox has no direct external network interface. Agent HTTP clients use
the guest forwarder at `127.0.0.1:8080`. The host gives each agent a private
Unix domain socket (UDS) at
`~/.safeyolo/agents/<agent>/proxy/proxy.sock`. The Rust proxy binds
that socket. By default, traffic enters through these private sockets.
The native [external-ingress prototype](#operator-bound-external-ingress-prototype)
also accepts explicitly configured TCP bindings.

```text
Agent HTTP client -> guest forwarder -> per-agent host UDS -> Rust proxy -> upstream
                       Linux: /safeyolo/proxy/proxy.sock through gVisor --host-uds=open
                       macOS: vsock port 1080 -> safeyolo-vm VSockProxyRelay -> host UDS
```

On Linux, gVisor mounts only that agent's socket directory into the guest and
allows the host UDS connection. On macOS, the Swift `VSockProxyRelay` connects
each guest vsock stream to that agent's host UDS. The relay transports bytes;
the Rust listener supplies the trusted agent identity.

`safeyolo agent shell <name>` uses a separate route. Linux runs the command
through `runsc exec`. On macOS, the host SSH client uses the agent's shell UDS;
`VSockShellBridge` forwards it through vsock port 2220 to the guest shell
bridge and `sshd`. The shell socket is
`~/.safeyolo/data/shell-sockets/<agent>.sock`. It is separate from the proxy
socket.

## Agent identity and listener updates

The host command-line interface (CLI) assigns each running agent an
attribution Internet Protocol (IP) address from
`10.200.0.0/16`. The CLI reserves a stable `network_slot` in the agent's
configuration. It uses the lowest free slot for a new agent and preserves a
running legacy agent's address when possible. For network slot `N`, the
address is `10.200.{(N+1) / 256}.{(N+1) % 256}`, using integer division.
Slot 0 has `10.200.0.1`. The CLI creates a listener entry with
`agent_id`, `source_id`, and `socket_path` in the host configuration. The
listener supplies the request owner and source IP. The proxy does not consult
an agent map, guest metadata, or request headers to identify the caller.

The Rust proxy binds each configured path with `tokio::net::UnixListener`.
On accept, it attaches the configured agent and source identity to the
connection. An HTTP header cannot choose another agent. The private mount or
vsock relay also prevents a guest from addressing a different agent's host
socket. The socket directory is a host-controlled convention for the CLI;
Rust uses the listener entry for identity. Host-local Admin application
programming interface (API) traffic uses a separate listener.

When the CLI starts or stops an agent sandbox, it reconciles its managed
listener entries with the Rust proxy. Startup uses the existing backend
observation and matching host-owned run or boot record to restore a live
attachment. A prepared start adds its listener before boot. A failed boot
removes that listener while preserving any uncertain backend record. A proven
stop removes the attachment. If the backend is unknown, the existing listener
remains available for recovery. The host does not scan socket directories to
discover identities.
After writing the updated configuration, the CLI signals a running
proxy with SIGHUP. It waits up to five seconds for the matching `reload_id`
in the readiness marker. Listener synchronization fails if the proxy does not
acknowledge the update. If the proxy is unavailable, the CLI saves the
configuration for its next start. Operator-defined listener entries remain intact.
A running guest can retain its earlier
`data/sockets/<ip>_<agent>/proxy.sock` directory mount until stop. New starts
use the dedicated directory under `agents/<agent>/proxy/`. Linux mounts only
that directory, so other host agent state stays outside the guest share.
A stale socket file does not establish an identity. The proxy binds the
configured listener and removes a stale socket only after the existing
connection and inode checks. Removed or replaced listeners stop accepting
with their old configuration. In-flight requests keep the identity fixed at
accept while their connections drain.

Authenticated `/agents` reports configured listener names, source IPs and
request activity. It does not expose host socket paths. Operator `/stats`
retains that information under `agents`; obsolete map-file statistics and
service-discovery events are removed.

There is no `PUT /admin/proxy/mode` route or mitmproxy mode list in the current
package.
The external-ingress exploration in
[issue #580](https://github.com/craigbalding/safeyolo/issues/580) uses the same
native request driver and configured listener owners.

## Operator-bound external ingress prototype

This source prototype lets an operator name a TCP HTTP-proxy ingress and
select an existing agent listener's policy and evidence partition. It does not
create an agent or a sandbox. Configure the binding on the trusted host in
the selected instance's `config.toml`. The example selects an existing agent
named `mobile` and exposes the proxy only on IPv4 loopback:

```toml
[[ingress_bindings]]
name = "mobile-test"
listen = "127.0.0.1:18080"
agent = "mobile"
```

`listen` is a required numeric socket address. Port zero selects an ephemeral
port. The operator can explicitly choose a wider address, including a wildcard.
The TCP ingress has no client authentication or encryption. Any client that
can reach it can submit traffic under the selected agent's network policy.
Existing Agent API authentication and credential controls still apply.
Binding creation and removal remain host configuration operations; there is no
agent-created listener or approval route.

Use a source-built `safeyolo-proxy` with the prepared instance configuration.
If another proxy owns that instance, stop that proxy before this foreground
launch. Do not run two proxy processes against the same instance:

```sh
safeyolo-proxy --config "$HOME/.safeyolo/config.toml"
```

For an already running matching proxy, edit its configuration and send SIGHUP
to that proxy process. Set the top-level `reload_id` to a fresh value before
sending the signal. The existing readiness file, normally
`data/ready.json` under the instance root, must show that value before the
reload is treated as accepted. Its `ingress_bindings` array reports each name,
requested `listen`, actual `address`, selected `agent`, `target_socket`, and
`state`. A binding with no matching configured target reports `target_unavailable` and has
no TCP listener. Multiple configured UDS listeners with the same selected
agent name are ambiguous and reject the configuration.

From an external proxy-capable client that can reach the selected address,
configure that address as its HTTP proxy. For HTTPS interception, trust the
selected instance's public CA certificate on the client; keep the private CA
key on the host. For example, on the same host, with an operator-approved
destination in `TARGET_URL`:

```sh
curl --proxy http://127.0.0.1:18080 "$TARGET_URL"
```

The configuration persists; listening sockets belong to the proxy process.
Remove a binding's table and reload to close only that ingress. If the host
removes the target listener, the binding suspends. It resumes when a reload
restores one matching listener. Replacing the selected socket's owner with a
different agent does not transfer the binding to that owner. Accepted
connections retain their captured provenance. Removal closes their bridges;
the existing connection owner cancels and joins their transport tasks, with its
ten-second transport grace. Removal waits for the
accept task to release its socket, so the address can be reused while old
transports finish cleanup. UDS listeners and unrelated TCP listeners remain
independent. Ctrl-C or SIGTERM shuts down the foreground proxy and its bindings.

An occupied address rejects startup or reload with the binding name and
address. Failed preparation releases staged sockets and preserves an accepted
configuration and its readiness marker. A listener accept failure removes
readiness and reports the error. A failed accept-task stop reports a reload
error without publishing readiness. Transport task failures use the existing
proxy shutdown diagnostics.
`listening` describes the TCP acceptor, not a target health probe. If the actual
UDS is missing or replaced, the connection closes and the proxy reports a named
target/relay error. Failures before UDS acknowledgment create no attributed flow.

### Trusted identity and observation

Raw forwarding into the ordinary UDS cannot distinguish an external client
from sandbox bytes. The native TCP binding therefore creates a bound UDS client
socket in a private host temporary directory. A process-local pending note
associates that endpoint with the selected listener configuration, binding name
and actual TCP endpoints. Both UDS peers must have this proxy process's kernel
credentials. The existing UDS acceptor claims the note only if its own listener
configuration matches the selected target. That acceptor assigns the evidence
owner and acknowledges the connection through a private in-process channel.
Only then does the bridge copy external bytes unchanged through the UDS.

The note is transport provenance, not an identity authority: it cannot assign
an owner that differs from the accepting UDS listener. HTTP headers cannot
create a note. A missing or replaced target cannot acknowledge the transfer;
the bridge closes without sending client bytes to the replacement. Every
terminal path removes the pending note and attempts to delete its owned
temporary socket directory. A deletion failure is reported.
If cancellation has already removed a host-bound peer's note, the UDS acceptor
rejects that peer instead of assigning ordinary sandbox attribution.
External traffic then uses the same `ConnectionIdentity`, HTTP/CONNECT driver,
policy evaluator, credential controls, budgets, audit writer and flow store.
No request header carries trusted ingress identity, and no parallel policy or
event store is introduced.
Budgets keep their existing action/destination keys; binding names do not
create separate counters.

External records use the selected agent as `evidence_owner` and
`trusted_transport_identity`, with `initiator=external`. Attribution provenance
contains `transport_source=uds`, `ingress_transport=tcp`, `uds_agent`,
`binding`, `selected_agent`, and
`ingress=switchboard/<name>`. Connection records retain the actual TCP
endpoints. Observation streams use `external_ingress` as their ingress point.
External connections carry neither a sandbox run nor a sandbox source slot.
They cannot inherit a live sandbox's run-scoped authority or automatically
borrow its declared test context. An explicit test-context header remains an
untrusted annotation. It cannot change the evidence owner.

The existing operator-port shield also protects actual ingress endpoints,
including ephemeral ports, numeric aliases and local interfaces reached through
wildcard binds. Proxy egress cannot enter another partition through a binding.
An unrelated remote destination on the same port remains subject to its normal
policy.

The selected agent can query retained flows through its existing authenticated,
scoped Agent API. Existing capture eligibility and retention settings still
apply: flow-store rows require applied test context, and body retention can be
disabled or bounded. Sparse NSM metadata is not a retained request or response
body. External ingress does not enable content capture or a new analysis API.

The focused native tests use real curl HTTP and CONNECT/TLS clients with owned
origins and ephemeral trust material. This is equivalent-client source proof.
It does not establish Android, remote exposure, installed-release, macOS or
whole-sandbox acceptance.

### Smallest useful live mutation follow-up

The current native `traffic_view` supports live observations, per-read agent
scope, existing filter expressions and retained-body reads. The flow store
supports historical agent-scoped queries. These readers do not own transport
tasks. Live HTTP observation routes are operator Admin API routes. An agent
route would need authentication and a fixed caller evidence-owner scope;
it must not reuse the operator's mutable shared scope as agent authority.
`ConnectionTasks` already owns cancellation, upgrades and joined cleanup.
There is no production agent API for holding, editing, replaying or installing
temporary mutation rules. The retired mitmproxy runtime is not needed for this
ingress prototype and is not restored.

The smallest useful next capability is cancellation of one selected live
client connection. It can delegate to the existing connection cancellation
sender. The operation affects every exchange on that connection, including
multiplexed requests; it must not be presented as cancellation of only one
HTTP/2 stream. Exact request editing or a hold/release operation needs additional
request-driver ownership and remains separate work.

An operator would grant that cancellation capability to one controlling agent
for a bounded session, scoped to the selected evidence owner and, when chosen,
one ingress binding. Authentication alone would not grant mutation authority.
Each call would check that grant and the current proxy runtime, then resolve
the connection ID through a private live connection handle whose owner was
captured at accept. Caller filters and agent-name parameters could narrow the
selection but could not expand it. The missing work is this grant binding,
private handle lookup and agent API operation; the observation view alone
cannot implement cancellation.

Completed connections must leave that lookup. Revoking or expiring a grant,
stopping its controlling agent run, removing or retargeting its binding, or
restarting the proxy must invalidate the capability. A cancellation already
started uses the existing joined cleanup. No held flow or temporary rule is
created by this proposed operation. This exploration records the design
boundary; it does not implement the mutation interface or a rule language.

## Diagnose a broken path

On the host, use the installed CLI for the selected instance and named
agent. These observations remain available when the proxy or listener is absent:

```sh
safeyolo agent diagnostics syone
```

The diagnostic reports runtime, control, coding-agent, terminal, and
proxy attachment state separately. On macOS, it also queries private helper
control and tests the shell bridge for an SSH banner. On Linux, shell readiness
uses exec control in the recorded namespaces. Inspect the failed dimension and
its next action; a missing proxy attachment does not mean that the runtime stopped.

A ready proxy attachment confirms that the host can connect to the configured
UDS. It does not verify guest egress or Agent API health. From inside the agent
guest, use the authenticated [first health check](AGENTS.md#first-health-check)
and require `"agent_api": "ok"` in the response. A generic HTTP response does
not prove API health. See [agent debugging](agent-debugging.md) for the failed-shell workflow.

For decision and audit events on the host, run:

```sh
safeyolo logs --lines 50
```

`safeyolo logs` reads the JSON Lines file selected by `audit_log_path` in the
configuration. The default is `logs/audit.jsonl` under the instance root.
It is not a complete packet capture or a substitute for the diagnostic probes.
On macOS, the VM helper's guest console and relay messages are in
`~/.safeyolo/agents/<name>/serial.log`. On Linux, guest boot output is in
`~/.safeyolo/agents/<name>/status/boot.log`. Setting `SAFEYOLO_VM_DEBUG=1`
before starting the macOS helper enables its extra relay debug messages;
it does not enable tracing across every proxy stage.

| Symptom | First check |
| --- | --- |
| Agent cannot connect to the proxy | Run `safeyolo agent diagnostics <name>`; inspect proxy state and the agent's proxy attachment separately from runtime state. |
| Proxy transport passes but Agent API fails | Run the authenticated [first health check](AGENTS.md#first-health-check) inside the agent guest and require `"agent_api": "ok"`. Socket reachability or a generic HTTP response does not prove API health. |
| Agent request is attributed to the wrong identity | Compare the host listener entry and source IP with the named socket and `agent diagnostics` attachment. Do not rely on a guest-supplied header. |
| macOS shell hangs | Run `safeyolo agent diagnostics <name>`; inspect private control and the shell SSH-banner result before choosing recovery. |

## Platform and configuration notes

| | Linux | macOS |
| --- | --- | --- |
| Sandbox | Rootless gVisor with systrap or KVM | Apple Virtualization.framework microVM |
| Guest egress bridge | Bind-mounted UDS via `--host-uds=open` | vsock port 1080 through `VSockProxyRelay` |
| Operator shell | `runsc exec` | SSH through `VSockShellBridge` and vsock port 2220 |
| Agent identity at proxy | Configured Rust listener for the private UDS | Configured Rust listener for the private UDS |

`SAFEYOLO_CONFIG_DIR` selects a separate instance root, including its agent
state, listener configuration, and socket directories. `SAFEYOLO_VM_HELPER` can select a macOS helper
binary for a development run. `SAFEYOLO_VM_DEBUG` controls the helper's
extra relay logging.

For the current component overview, see
[architecture](ARCHITECTURE.md#sandbox-runtime-and-networking) and
[developer architecture](DEVELOPERS.md#architecture-overview). For isolation
checks, see [security verification](security-verification.md). Relevant
sources are [instance paths](../proxy/src/host_platform.rs),
[listener reconciliation](../proxy/src/host_lifecycle.rs),
[Rust listener ownership](../proxy/src/lib.rs), and the
[macOS proxy relay](../vm/Sources/SafeYoloVM/VSockProxyRelay.swift).
