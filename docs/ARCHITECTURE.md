# SafeYOLO architecture overview

This is the map of the system: what runs where, who owns which decision, and
where to find each piece in the source tree. Detailed behaviour stays in the
linked reference documents; this page should only change when a boundary,
process or owner changes.

## What SafeYOLO is

SafeYOLO runs coding agents (Claude Code, Codex, Pi and others) in isolated
Linux sandboxes on an operator's host. The sandbox has no external network
interface. Every outbound request goes through a host-owned, per-agent socket
into one Rust proxy, which applies the operator's policy, keeps credentials on
the host, records evidence and asks the operator when a request is outside
policy.

Around that core, SafeYOLO has grown:

- **Operator tooling**: a CLI, the macOS Command Centre, traffic inspection
  and exports, diagnostics and a Lab for controlled experiments.
- **Coord**: rooms, targeted attention and durable work claims for
  coordinating agents, plus supervised **factories** built on Coord.
- **Multi-instance features**: federation between instances, delegated peer
  support and approvals, operational notices and signal feeds.
- **Execution beyond the sandbox**: disposable jobs (gVisor, VZ, Hyperlight)
  and a signed host-execution contract for named targets.

## Trust model

| Zone | Trust | Owns |
|---|---|---|
| Host and operator | Trusted root | `config.toml`, `policy.toml`, credentials, approvals, sandbox runtime |
| SafeYOLO proxy | Enforcement point, runs as the operator's UID (not root) | Policy evaluation, credential protection, evidence, Agent and Admin application programming interfaces (APIs) |
| Agent sandboxes | Untrusted; may be prompt-injected or malicious | Nothing outside their mounts; guest `sudo` is not host privilege |
| External services | Reachable only through policy | Their own authentication |

Two rules recur throughout the code:

1. **Identity comes from the listener, never from the request.** The socket a
   connection arrives on fixes the agent. Headers, JSON fields and bearer
   tokens cannot select another agent.
2. **Fail closed.** Unknown credentials and out-of-policy requests get
   HTTP 428 (approval required) or 403 (denied), never silent passthrough.
   Policy is loaded and validated before any agent listener binds.

See [SECURITY.md](../SECURITY.md) for the full security model.

## System context

```text
 Operator
   │  safeyolo CLI ─────────────┐        Command Centre (macOS app)
   │                            │          │  Admin API + live events
   ▼                            ▼          ▼
┌─────────────────────────── Host ─────────────────────────────────────┐
│                                                                      │
│  safeyolo-proxy  (one process per instance, Rust, operator UID)      │
│   ├─ per-agent UDS listeners ◄──────────── agent sandboxes           │
│   ├─ Admin API  127.0.0.1 + bearer token                             │
│   ├─ Agent API  virtual host _safeyolo.proxy.internal (via proxy)    │
│   ├─ policy, approvals, grants, credential vault, service gateway   │
│   ├─ evidence: audit JSONL, FlowStore (SQLite), observations/PCAP   │
│   └─ Coord control state: SQLite kernel                              │
│                                                                      │
│  nats-server (JetStream): separate process managed by the host CLI    │
│                                                                      │
│  Sandboxes                                                           │
│   ├─ Linux: rootless gVisor (runsc) in a user namespace              │
│   └─ macOS: Virtualization.framework microVM via safeyolo-vm         │
│        guest: safeyolo-guest (PID 1 / supervisor), safeyolo-coord,   │
│               guest forwarder 127.0.0.1:8080, staged skills          │
│                                                                      │
│  Optional: Hyperlight job helper · safeyolo-host-executor targets    │
└──────────────────────────────────────────────────────────────────────┘
         │ upstream HTTPS (policy-gated)          │ NATS (TLS / Tailscale)
         ▼                                        ▼
   External services                      Other SafeYolo instances
```

## Deployable pieces

| Artifact | Language | Source | Role |
|---|---|---|---|
| `safeyolo` | Rust | `proxy/src/bin/safeyolo.rs` + `proxy/src/host_*`, `operator_commands*` | Host CLI: install/start/stop, agent lifecycle, policy, credentials, operator evidence, Coord, configure |
| `safeyolo-proxy` | Rust | `proxy/src/main.rs`, `proxy/src/lib.rs` | The enforcement process. Reloads on SIGHUP and on watched policy/service changes |
| `safeyolo-coord` | Rust | `proxy/src/bin/safeyolo-coord.rs` | Guest-side Coord tools, MCP stdio server, bounded harness supervision, staging helpers |
| `safeyolo-guest` | Rust | `guest/command/` | Guest PID 1 and command supervisor, probes, clock, desktop bridge, Lab evidence |
| `safeyolo-vm` | Swift | `vm/` | macOS microVM helper: VZ configuration, vsock proxy relay and shell bridge |
| Command Centre | Swift | `command-centre/macos/` | Optional macOS GUI over the Admin API and live events; approvals and agent state |
| `safeyolo-host-executor` | Rust | `host-executor/` | Standalone target for the `safeyolo.host-execution/v1` contract (Linux, macOS, Windows) |
| Guest image | Shell + OCI | `guest/`, `contrib/*/build-*-rootfs.sh` | Debian trixie rootfs (tree for gVisor, ext4 for VZ), kernel and initramfs for macOS; published to GitHub Container Registry (GHCR) as `safeyolo-guest` |
| Hyperlight jobs | Rust | `jobs/hyperlight-host`, `jobs/hyperlight-guest` | Micro-VM runtime for disposable checker jobs |

Python is no longer shipped. It remains only in repository tests, black-box
instruments, reference implementations under `tests/reference/` and some
skill scripts.

The `proxy` crate is one library (about 280k lines) with three binaries. Its
top-level modules fall into the groups used in the rest of this document.

## Instance layout

One instance is one directory (default `~/.safeyolo`) and one proxy process.
Several instances can share a host.

```text
ROOT/
├── config.toml   runtime settings: paths, listeners, observation limits
├── policy.toml   hosts, agents, grants, budgets, lists, controls
├── bin/          host executables
├── assets/       helpers, guest scripts, skills, launchers, service YAML
├── share/        prepared guest images / Linux rootfs-tree
├── agents/<name>/  persistent home, overlay, runtime.json, proxy/proxy.sock
├── certs/        instance CA (public) and signing key
├── data/         tokens, instance identity, durable state (Coord, grants…)
└── logs/         canonical audit log and flow storage
```

`config.toml` owns *how the proxy runs*; `policy.toml` owns *what agents may
do*. See [CONFIGURATION.md](CONFIGURATION.md) and [settings.md](settings.md).

## Sandbox runtime and networking

Each agent runs in an isolated Linux sandbox without an external network
interface. Requests go through the guest forwarder and a host-owned,
per-agent Unix domain socket (UDS) to the Rust proxy:

```text
Agent sandbox -> guest forwarder -> per-agent UDS -> Rust proxy -> upstream
```

The host-owned Unix domain socket listener establishes request identity. A
request header cannot select another agent. The proxy applies the configured
network, credential, and inspection controls at their respective request
stages; streamed bodies and TLS passthrough have narrower inspection and
capture coverage. The [networking reference](networking-vsock-uds.md)
describes the platform bridges and their limits.

On macOS, the sandbox is a hardware-backed microVM using Apple
Virtualization.framework and virtual sockets. On Linux, it is a rootless
gVisor sandbox using `runsc` in an unprivileged user namespace. The guest has
no direct external interface; removing proxy environment variables does not
create an external network route. See [security verification](security-verification.md)
for tests of the isolation boundary.

Agents have full pseudo-terminals (PTYs): a virtual-socket PTY bridge on macOS
and `runsc exec` on Linux. Guest init is served from a writable status share
and a read-only configuration share.

The host CLI owns sandbox lifecycle (`host_lifecycle`, `host_launch`,
`host_platform`, `host_runs`, `linux_host`).

### Platform comparison

| | Linux | macOS (Apple silicon) |
|---|---|---|
| Isolation | gVisor `runsc`, rootless in an unprivileged user namespace; KVM platform if available, else systrap | Virtualization.framework microVM |
| Rootfs | Shared `share/rootfs-tree/` with a per-agent tmpfs overlay | Read-only ext4 base with a separate writable overlay |
| Network | None; only the agent's socket directory is mounted (`--host-uds=open`) | No virtio-net; vsock only |
| Proxy path | guest forwarder → `/safeyolo/proxy/proxy.sock` | guest forwarder → vsock 1080 → `VSockProxyRelay` → host UDS |
| Shell | `runsc exec` | host SSH → shell UDS → vsock 2220 → guest `sshd` |
| Persistent | home, package caches, cron spool | home, workspace and config shares (VirtioFS) |

### Agent names, durable IDs and runs

Each agent has three identities that must not be confused:

- **Name**: a configuration handle; it authenticates nothing.
- **Durable ID** (`ag-…` in `policy.toml`): minted at creation; re-creating a
  name gives a new identity.
- **Run ID**: minted per sandbox generation. "Current-run authority" requires
  matching name, durable ID, generation, state and verified backend process.
  Grants, delegation and support operations check it.

The CLI reconciles listener entries with the proxy on start/stop, signals
SIGHUP and waits for the matching `reload_id`. An unknown backend keeps its
records for recovery; it must not be reported as successfully stopped.

### Linux runtime and storage

- **Rootless host operation**: runsc runs in an unprivileged user namespace (`unshare -Un` + `newuidmap`/`newgidmap`) and launching agents requires no host sudo. Agents start as uid 1000; in-guest `sudo` may enter sandbox uid 0 for ephemeral package installs. That identity maps to the installation's selected subordinate host UID, while container UID 1000 maps to the operator. GIDs use their separately selected range. The installer reuses safe existing allocations or prepares unused ranges through the host account tools; the original archive base remains 100000.
- **Rootfs**: a single shared directory tree at
  `~/.safeyolo/share/rootfs-tree/` is the gVisor OCI `root.path`; Linux does
  not package it as an image. By default, writes go to a per-agent file-backed
  tmpfs overlay. Those rootfs writes disappear on stop; the backing file is
  temporary. `rootfs_overlay = "memory"` selects a memory-backed upper instead.
  Home and package-cache bind mounts persist separately. The native cron/at
  spool has a per-agent bind under `agents/<name>/overlay/var/spool/cron` in
  default mode; memory mode uses a fresh spool. Per-agent package caches keep
  reinstalls cheap.
- **Isolation platform**: KVM (hardware-enforced) if available; systrap (seccomp-BPF) fallback otherwise. `safeyolo doctor` reports the selected runtime.
- **Host preparation**: New source installers prepare missing tools and safe subordinate UID/GID allocations. Where Ubuntu restricts user namespaces, they prepare an installation-scoped namespace entry and install profiles for that entry and the selected runtime path. Explicit KVM preparation grants the mapped root GID device access and repairs a selected root UID denial if required. The group grant survives a named-user ACL reset. If the device or its group permissions reset, run `SAFEYOLO_RUNSC_PLATFORM=kvm safeyolo host prepare` before the next sandbox creation. See [host preparation](installation.md#linux-host-preparation-in-new-source-bundles). The published release still needs [manual host preparation](installation.md#guest-prerequisites).

See the [macOS microVM architecture](microvm-architecture.md) and
[historical Linux port design](linux-port-design.md) for platform design context.

## Request path

```text
agent client ─► guest forwarder ─► per-agent UDS ─► safeyolo-proxy ─► upstream
                                   (identity fixed at accept)
```

The proxy terminates Transport Layer Security (TLS) with the instance certificate authority (CA) (`tls`, `tls_identity`), parses
HTTP/1.1 and HTTP/2 (`http`, `upstream_h2`), and handles CONNECT tunnels
(`tunnels`) and WebSockets (`websocket`, `websocket_relay`). Selection of
opaque forwarding happens once, before parsing; a timeout or parse failure does
not grant passthrough.

The main request driver is `http::forward`. Its controls have the following
responsibilities. This table is not an execution order: ordinary HTTP and
CONNECT use different check sites, and some controls run at more than one site.

| Control | Module(s) | Effect |
|---|---|---|
| Admin shield | `admin_shield` | Agents cannot reach the Admin API |
| Agent API virtual host | `agent_api`, `http::local_agent_api` | `_safeyolo.proxy.internal` is answered locally, before network checks; never resolved upstream |
| Loop guard | `http::loop_detected` | Breaks proxy loops |
| Network guard | `network_guard`, `policy` | Host/agent egress policy, rate budgets, homoglyphs, lists; may raise an approval (428) |
| Named checks | `http::policy_checks`, `policy::checks` | Operator-authored checks over request facts |
| Circuit breaker | `circuits`, `circuit_runtime` | Fail fast for unhealthy upstreams |
| Credential guard | `credential_guard`, `credentials`, `credential_hmac` | Detects credentials and checks their destination; unknown → 428; HMAC fingerprints only |
| Service gateway | `services`, `credential_injection`, `grants`, `contracts`, `oauth` | Swaps gateway tokens for host-held credentials; enforces capabilities, risky-route grants and request contracts |
| Content inspection | `inspection`, `prompt_injection` | Pattern scanning of URL, headers and bodies; prompt-injection signals on model traffic |
| Specialised paths | `services::docker`, `http::codex_routing`, `ssh_proxy` | Docker API mediation, coding-client routing, SSH |
| Test context | `test_context` | Requires/records `X-SafeYolo-Test-Context` for designated target hosts |
| Response scan | `http::scan_response_with_lifetime` | Response-side inspection and decisions |

Streamed bodies and TLS passthrough get narrower inspection and capture. See
the [capability inventory](proxy-parity.md) for current protocol and inspection
limits.

## Policy and decisions

- **Source of truth**: `policy.toml`. `safeyolo policy check FILE` validates a
  candidate without activating it. `safeyolo policy apply FILE` validates the
  candidate, requests activation through the Admin API and checks that the
  result is active. `safeyolo policy show` reads active policy state; if the
  Admin API is unavailable, it identifies the saved-policy fallback instead.
  The running proxy watches policy and the service catalogue and reloads on
  change; `config.toml` reloads on SIGHUP.
- **Snapshots and assessment**: `policy::snapshot`, `policy_runtime`,
  [policy-snapshots.md](policy-snapshots.md),
  [policy-assessment.md](policy-assessment.md).
- **Maintained lists**: `policy_feeds` downloads named host lists on the host;
  rules in `policy.toml` assign their effect.
  [policy-feeds.md](policy-feeds.md).
- **Signals**: `signals` follows NATS Key Value (KV) keys, keeps evidence and reconciles
  operator-selected responses. Receipt never grants authority.
  [signals.md](signals.md).
- **Approvals**: `approvals` records pending network, credential, service,
  contract, route, room and desktop requests. The operator decides through the
  CLI, Command Centre or delegated reviewers
  ([delegated-approvals.md](delegated-approvals.md)).
- **Grants**: `grants` holds service-risk grants (`once`, `session`,
  `remembered`) and contract bindings. Grants never widen a capability.

Network permission, credential permission, service authorization, contract
binding and risky-route approval are separate decisions by design.

## Credentials and services

Credentials live on the host (local encrypted store or 1Password references,
`credentials`, `credential_resolver`). Service definitions are YAML
(`cli/src/safeyolo/services/*.yaml`, schema in
[service-gateway-v2-yaml-spec.md](service-gateway-v2-yaml-spec.md)). The
operator authorizes an agent for a named capability of a service with a named
credential. The gateway injects the real credential upstream, so the agent never
holds it. Host scripts that copy logins into a guest are a separate, weaker
boundary. See [credentials.md](credentials.md) and
[coding-client-gateway.md](coding-client-gateway.md).

## Evidence and observability

| Store | Module | Contents |
|---|---|---|
| Audit log | `audit` (writer, envelope, explain, network security monitoring (NSM), disclosure) | Canonical JSONL events with rotation; the integration surface for other tools |
| FlowStore | `flow_store`, `flow_writer`, `flow_recorder` | SQLite store of recorded flows; read by `traffic` and exports (raw, curl, httpie, HAR, zHAR) |
| Observations | `observations`, `packet_capture` | Transport metadata before HTTP reassembly; optional capture and classic packet capture (PCAP) export (file, pipe, TCP, WSS) |
| Live view | `traffic_view`, `http::live_view` | Read-only terminal inspector and filters |
| Metrics/stats | `metrics`, `operator_stats`, `memory_monitor` | Per-agent and per-domain counters, memory accounting |

Metadata observation is on by default without payloads; capture is opt-in and
bounded. [native-observations.md](native-observations.md),
[operator-guide.md](operator-guide.md).

## Control surfaces

| Surface | Who | Transport | Module |
|---|---|---|---|
| CLI | Operator | Local files + Admin API | `bin/safeyolo.rs`, `host_commands`, `operator_commands` |
| Admin API | Operator tools, Command Centre | `127.0.0.1`, bearer token (constant-time check) | `admin_api`, `admin_listener` |
| Operator events | Command Centre | Local listener | `operator_events`, `command_centre` |
| Agent API | Agents | Virtual host through the agent's own proxy socket | `agent_api` |
| Model Context Protocol (MCP) | Agent harnesses | `safeyolo-coord mcp` (stdio) → Agent API | `bin/safeyolo-coord.rs`, `coord_tools` |
| Skills | Agents | Staged into guests at launch | `cli/src/safeyolo/agent_context/skills/` |

The Agent API is how agents explain blocks, request access, read their own
flows, declare test contexts and use Coord. The skills teach agents to use it.

## Coord and factories

Coord is SafeYOLO's coordination kernel.

- **Storage split**: SQLite owns control state (identity, membership, brief,
  work ownership, claims, attestations). NATS JetStream owns conversation
  history. The host CLI starts and stops the separate managed `nats-server`
  process alongside the proxy. Proxy readiness does not establish Coord
  readiness.
- **Invariants**: addressing affects *attention, not visibility*; work claims
  are not resource locks; envelope attribution is authoritative and message
  bodies are untrusted.
- **Modules**: `coord_rooms` (rooms, membership, work, signals, federation),
  `coord_timeline`, `coord_operator`, attention adapters per harness
  (`coord_claude_attention`, `coord_codex_attention`, `coord_acp_attention`),
  `coord_supervisor` (bounded harness turns from checkpoints), `coord_setup`.
- **Factories** (`factory`, `factory_proposals`): small TOML bindings of
  approved agents to Markdown role contracts and one room. There is no runtime
  interpretation of role prose.
- **Adapters**: Mattermost (`mattermost`), Dispatch public digest
  (`dispatch`, `site/`).

[coord-kernel-capabilities.md](coord-kernel-capabilities.md),
[coord-trust-boundary.md](coord-trust-boundary.md),
[factories.md](factories.md).

## Multiple instances

Instances connect over authenticated NATS (TLS with a selected CA, or verified
Tailscale). Broker credentials and Admin tokens stay on hosts. Guests always
use their own local Agent API.

- **Federation**: exchanged public identity files; `safeyolo configure`
  guides setup ([federation-setup.md](federation-setup.md)).
- **Peer support** (`peer_support`): an operator grants a support agent
  inspection, guest logs, guest administration or lifecycle actions over named
  durable targets ([peer-support.md](peer-support.md)).
- **Delegated approvals**: named reviewers decide selected request types for
  named workers without gaining policy administration.
- **Operational notices**: selected lifecycle and `needs_operator` events
  delivered to an authorized recipient
  ([operational-events.md](operational-events.md)).

## Execution outside the agent sandbox

- **Jobs** (`jobs`): host-only disposable execution from trusted job
  definitions, with captured-stream evidence. Engines are gVisor, VZ and
  Hyperlight (core Rust guests or Unikraft Python). `JobSpec` never carries a
  host mount path. [hyperlight-jobs.md](hyperlight-jobs.md).
- **Host execution** (`host_execution`, `host-executor/`): the
  `safeyolo.host-execution/v1` contract lets an issuing instance invoke adopted,
  versioned operations on a named target. The target enrols issuer keys,
  bounds scope and budgets, and keeps a ledger. Execution binds to an
  authenticated agent run and an activated operator task.
  [host-execution-contract.md](host-execution-contract.md).

## Other subsystems

| Subsystem | Modules | Notes |
|---|---|---|
| Desktop and preview | `desktop_preview`, `desktop_present`, `desktop_session` | Guest desktop/browser presented to the operator |
| Web sharing | `tailnet`, `external_ingress` | One Tailscale Serve mapping; operator-bound TCP ingress prototype |
| Guest distribution | `guest_oci`, `guest_acquisition` | OCI index is the guest release catalogue; upgrade and rollback |
| Lab and demo | `lab`, `demo` | Controlled-fault experiments; disposable demo |
| Repo map | `repo_map`, `repo-map.toml` | Contextual hints for agents working on a repository |

## Build, release and assurance

- **CI** (`.github/workflows/`): Rust proxy, CI, CodeQL, Scorecard,
  ClusterFuzzLite (`fuzz/`, `.clusterfuzzlite/`), black-box lanes, guest OCI
  publication, installed arm64 checks, proxy assurance and Pages.
- **Tests**: unit tests beside the Rust modules; process and protocol
  contracts in `proxy/tests/` and `tests/proxy_contracts/`; installed host and
  sandbox probes in `tests/blackbox/`; nested-Linux lanes.
- **Assurance**: `docs/assurance-map.toml` and `tests/assurance.toml` map claims
  to evidence. Documentation drift checks live in `scripts/check_doc_*.py`
  ([DEVELOPERS.md](DEVELOPERS.md#documentation-drift-protection)).
- **Acceptance graph**: `…/skills/safeyolo/references/graph/accept-safeyolo.yaml`
  chooses the smallest lane that exercises a boundary.

## Where to start reading

| Question | Start at |
|---|---|
| How does a request get allowed or blocked? | `proxy/src/http.rs` (`forward`, `decide`), `network_guard.rs`, `policy.rs` |
| Why was an agent attributed this way? | `config.rs` (`AgentListener`), `host_runs.rs`, [networking-vsock-uds.md](networking-vsock-uds.md) |
| How does an agent start? | `host_lifecycle.rs`, `host_launch.rs`, `host_platform.rs`, `guest/command/src/main.rs` |
| Where are credentials swapped in? | `services.rs`, `credential_injection.rs`, `grants.rs` |
| What does an agent see and call? | `agent_api.rs`, `cli/src/safeyolo/agent_context/skills/safeyolo/` |
| How does Coord work? | `coord_rooms.rs`, `coord_supervisor.rs`, `bin/safeyolo-coord.rs` |
