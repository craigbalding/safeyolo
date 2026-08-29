# Agent identity and run-lifecycle implementation plan

Status: planning note for issue #391, checked against
`master@a037f5f1da6d6ede35da6520b102a05bc69308e3`.

This note plans only Steps 1–3 from the issue: trace today's agent lifecycle,
make the durable `agent_id` available at trusted ingress, and add one minimal
current-run identity. It does not implement a generic lifecycle framework.
It refines the earlier [`AgentPrincipal` design note](../agent-principal-identity.md):
the trusted-boundary rule remains, but the repository now has an
`AgentIdentity` result type and durable agent IDs, so growing that type is the
smallest coherent implementation.

## Decisions in brief

- `[agents.<name>].agent_id` in `policy.toml` remains the durable agent
  identity. The table key remains the operator-facing config name.
- Grow the existing resolved `AgentIdentity` with `agent_id`; do not add a
  second `AgentPrincipal` wrapper yet. `AgentIdentity` already carries the
  resolved/unavailable/conflict result and proves that a value crossed the
  trusted UDS/IP-map boundary. A second type would duplicate that distinction
  without supplying another invariant.
- Add `agent_id` to each live `agent_map.json` entry. Resolve it from the
  policy registry when the entry is created, then recover it from the map on a
  proxy restart. Name stays in the map key and UDS path for config/display and
  diagnostics; it stops being sufficient authority.
- Persist exactly one current/most-recent run record at
  `agents/<name>/current-run.json`. Do not add a run database or historical
  run rows. Existing audit events are the transition history.
- A run record is authoritative only when its embedded `agent_id`, `name`,
  `run_id`, platform handle, runtime probe, map entry and guest readiness marker
  agree. A PID, socket, map entry or filename alone is never enough.
- A full copy of `~/.safeyolo` is a restore/move of the same SafeYolo
  authority and therefore preserves its `sy-...` ID. Using two such copies
  independently at the same time is unsupported. Creating a distinct
  installation must omit/rekey all coord state as one operation; deleting only
  `data/coord/instance_id` is not a supported clone procedure.

## Step 1: current lifecycle, from code

### Sources of truth today

| Fact | Current source and writers | Current readers / deletion |
|---|---|---|
| Agent name | `commands/agent.py:add()` validates the CLI string, then uses it both as the `[agents.<name>]` TOML key and `agents/<name>/` directory. There is no separate stored canonical-name field. | Every agent CLI command, policy compilation, platform code and display path looks up by name. `remove()` deletes both locations, but they can be temporarily inconsistent because disk setup happens before `save_agent()` on add. |
| Durable `agent_id` | `add()` calls `_new_agent_id()` and writes `[agents.<name>].agent_id`; `agents_store.get_or_mint_agent_id()` backfills legacy records under the policy lock. | Coord resolves name to ID in `AgentAPI._handle_coord()`. `remove_agent()` deletes it with the whole TOML entry. Stop/run preserves it; remove/re-add mints another. |
| Stable network slot | `agents_store.reserve_agent_network_slot()` writes `[agents.<name>].network_slot`, considering saved slots plus live entries in `agent_map.json`. | `LinuxPlatform.setup_networking()` and `DarwinPlatform.setup_networking()` deterministically derive `10.200/16` attribution from the slot. Removal drops it with the agent config. It is a subordinate allocation, not a principal. |
| Attribution IP | `_run_agent()` gets `fw_alloc["attribution_ip"]` from the platform and writes it through `vm._update_agent_map()`. It is also written to the per-run config share. | `ServiceDiscovery` reverses IP to name; `UnixMode` obtains the same IP from the socket directory. `status()` displays the map value. Platform stop normally removes the map entry. |
| UDS/proxy mode | `sockets.path_for(name, ip)` derives `data/sockets/<ip>_<name>/proxy.sock`; `_update_agent_map()` stores a diagnostic copy of the path. `_initial_mode_specs()` derives mitmproxy modes from the map. | `UnixMode` parses name and IP from the directory and stamps a synthetic peer address. `resolve_agent_identity()` reconciles that UDS name with the IP-map name. `UnixInstance` owns the socket inode; proxy stop/restart removes/recreates it. |
| Runtime PID/handle | macOS `vm.start_vm()` writes `agents/<name>/vm.pid` for the `safeyolo-vm` helper. Linux uses fixed runsc container ID `safeyolo-<name>`, runsc state under `~/.safeyolo/run`, `agents/<name>/userns.pid`, and diagnostic `container.pid`. | `DarwinPlatform.is_sandbox_running()` ultimately probes the PID; Linux asks `runsc state` through the recorded user namespace. Stop removes the PID files and runsc state. No artifact identifies an incarnation. |
| `agent_map.json` | `vm._update_agent_map()` read-modify-writes a top-level object keyed by name with `ip`, `started`, and optional `socket`. | Service discovery and proxy listener startup treat it as the current runtime projection. It is durable on disk but intended to describe live agents. It currently has neither `agent_id` nor an incarnation ID. |
| Guest status | `vm.prepare_config_share()` removes old `status/{static-init-done,per-run-started,vm-status}` files. Guest init recreates them; `_run_agent()` waits for `per-run-started`. | The marker's existence, not its contents, identifies readiness. It is name-directory scoped and cannot prove which run wrote it. |
| Per-agent config/disk | `agents/<name>/config-share`, `status`, `home`, `cache`, custom rootfs, Linux `overlay`, macOS `overlay.img`, logs, and macOS snapshot files. `policy.toml` holds folder, scripts, mounts, ports, services, grants, bindings and allocations. | Stop/run deliberately retains these. `platform.remove_agent_dir()` deletes the whole directory on remove. The ephemeral option discards rootfs writes only; `/home/agent` remains persistent. |
| SafeYolo instance | `coord.identity.get_or_create_instance_id()` atomically creates `data/coord/instance_id`; `coord.api.bootstrap()` also inserts it into coord SQLite. | Coord envelopes use it as `origin_instance_id`. The file and DB survive all proxy/agent lifecycle operations and a host reboot. |

### `add -> run -> stop -> run -> remove -> re-add`

1. `commands/agent.py:add()` validates name and config, creates or prepares
   rootfs/home state, optionally runs host setup, then finally writes the agent
   TOML record and newly minted ID. A setup failure can therefore leave an
   agent directory with no registry record. More importantly, `add --force`
   currently reuses the existing directory but unconditionally mints a new
   `agent_id`; this is an undocumented identity rotation over retained disk
   state. Step 2 must preserve the existing ID for a config overwrite, or make
   replacement an explicit stop/remove/add operation. Preserving it is the
   smaller and safer interpretation of "overwrite configuration".
2. `_run_agent()` loads config by name, starts the shared proxy if needed,
   rejects a platform probe that says the name is already running, reserves the
   stable network slot, derives the attribution IP/UDS path, and writes
   `agent_map.json` **before** `start_sandbox()`. It then prepares the config and
   status shares and emits `agent.started` before a sandbox has successfully
   started. Linux creates a fixed name-derived runsc container and writes
   `container.pid`; macOS starts a helper and writes `vm.pid`. Readiness is a
   fresh `per-run-started` file. There is no transaction tying these facts
   together.
3. `commands/agent.py:stop()` first calls `is_sandbox_running(name)`. If false,
   it returns without invoking platform cleanup, so a stale map/socket/PID can
   remain. Otherwise platform stop removes runtime state and the map entry,
   then the CLI reconciles proxy modes. Linux's foreground run path also calls
   platform stop. A naturally exited macOS foreground run only unlinks
   `vm.pid` in `_run_agent()` and can leave its map entry. Exceptions after the
   pre-launch map write can do the same.
4. The next run repeats runtime allocation. `agent_id`, network slot, config,
   home, persistent rootfs overlay, caches and snapshots survive. PID/status/map
   artifacts are intended to be replaced, but none carries a generation. A
   reused name normally gets the same attribution IP and UDS path.
5. `remove()` calls `platform.stop_sandbox(name)` unconditionally, tears down
   the saved slot, deletes `agents/<name>/`, deletes `[agents.<name>]`, and asks
   mitmproxy to drop the mode. It does not delete name-keyed historical flows,
   audit events or legacy plumb rows. It also does not explicitly purge every
   name-keyed in-memory gateway object from a still-running proxy.
6. Re-add creates a new directory/record and new `agent_id`, but may reuse the
   old slot, IP, UDS path and every external or historical name key. Thus the
   durable ID invariant exists in coord but is not yet enforced elsewhere.

### Name-keyed inventory after trusted ingress

The distinction in the last column is intentional: not every use of a name is
an identity bug.

| Surface | Name-keyed state or API today | Classification / required direction |
|---|---|---|
| Agent registry and policy | `[agents.<name>]`, `load_agent(name)`, agent host/egress rules, services, mounts and CLI mutations | Name is the correct human/config lookup key. The embedded `agent_id` is authority for durable grants and ownership. Policy matching may continue to receive name as explicit config context. |
| Agent filesystem and platform | All `agents/<name>/...` paths, Linux container/userns names, macOS PID/shell socket, snapshot paths | Name may remain a locator. Any security-sensitive state read from it must embed and match `agent_id` and, when runtime-owned, `run_id`. Locks may use the validated name as a local mutex namespace. |
| Runtime ingress | `agent_map.json`, `ServiceDiscovery._ip_to_name`, `UnixMode.agent`, `AgentIdentity.agent`, and `flow.metadata["agent"]` | Security authority today. Add `agent_id` at map production and carry it in `AgentIdentity`/flow metadata; keep name only alongside it for config/display. UDS and map disagreement remains fail-closed. |
| PDP/security addons | `SecurityAddon`, network guard, credential guard, loop/transport guards and sensor events consume the resolved name. Network guard's PDP `principal_id` is currently `client:<attribution-ip>`; credential guard uses `project:<name>`. | Principal/ownership fields must use `agent_id`; policy context continues to use name. Do not make policy files use opaque IDs. |
| Agent API | `_resolve_agent_id()` is misnamed: it returns the trusted **name**. Flow search/read, audit lookup, trace ownership, test-context, plumb and service access use it. Coord immediately performs an extra policy lookup to obtain the real ID. | Return the typed `AgentIdentity`; use its ID for ownership and coord, and its name only for config/rendering. Never accept either `str` or `AgentIdentity` in the same trusted internal API. |
| Flow evidence and trace | `flow_recorder` assigns the name to `flows.agent_id` and `engagement_id`; `TraceStore.agent_id` is also populated from `flow.metadata["agent"]`. Agent API ownership compares those name values. | These columns/fields are security ownership despite their misleading names. New records must use the durable ID. Historic name-only rows cannot safely be relabelled after possible remove/re-add; retain them as legacy/operator-visible, not agent-readable authority. |
| Audit/watch/approvals | `AuditEvent.agent`, JSONL lookup, approval dedup keys and watch actions carry/display name. | Keep `agent` as display/config context, add `agent_id` and later `run_id` to new security/runtime events. Historic events are facts, never authorization records. Watch must resolve a displayed name to the current record at mutation time. |
| Test-context declarations | `TestContext._declarations` is keyed by attribution IP and stores trusted name. The claimed slot-reuse guard compares name, so remove/re-add of the same name passes it. | In-memory and intentionally lost on proxy restart, but security-sensitive. Key/compare `agent_id`; add `run_id` in Step 3 if a declaration must not cross an agent restart. |
| Service gateway | `TokenBinding`, `GrantEntry`, `ContractBindingState`, in-memory dict keys, PDP principal strings and nested TOML grants/bindings use name. Session grants disappear on proxy restart but can survive agent stop/run while the proxy lives. | Inventory only here. Issue #391 Step 4 must bind durable authority to `agent_id` and decide whether session means `run_id`. Do not widen the first identity PR into the grant redesign. |
| Legacy plumb | SQLite grant/pending/message participants and service membership APIs use names. | Durable authorization by name. Keep frozen or migrate in its own compatibility decision; coord already uses `agent_id` and is the current pattern. Do not silently bind old rows to a re-added name. |
| Preview/desktop | `PreviewConfig`, host server, relays, tailnet reservation and audit use name; each request can open a new relay to whatever run currently has that name. | Tailnet port remains a config allocation by name. Step 3 must capture the active `run_id` and reject/close before a relay can attach to another run; no exposure registry is required yet. |
| Coord agents | Memberships, attention, envelopes, inventory and leases use `agent_id`; names in envelopes/inventory are display snapshots. | Already the desired split. The ingress lookup is the remaining ad-hoc name-to-ID join. |
| Coord operator | `LOCAL_OPERATOR_ID = "operator"`; coord CLI/API pass the same literal as principal and actor ID. Envelope `sender_kind="operator"` is separately disambiguated and carries `origin_instance_id`. | Scope the local sentinel to `operator@<sy-id>` before federation relies on it. Gateway `account="operator"` and `operator_provenance.ORIGIN` are persona/provenance labels, not this principal, and should not be changed. |

### What survives which restart

| Boundary | Survives | Rebuilt/lost and current caveat |
|---|---|---|
| Proxy restart while agent lives | Policy record/`agent_id`, per-agent disk, platform process/PIDs, network slot, attribution map and socket **directory** survive. Linux bind-mounts the directory rather than the socket inode; macOS relay reconnects per flow. | Socket inode, UnixInstance, discovery caches, trace/test-context memory and session grants are lost. `_initial_mode_specs()` recreates listeners from the map, so traffic resumes with the same name/IP but today still has no durable/run identity in ingress. |
| Agent stop then run | Policy/ID/slot/tailnet port, workspace config, home, caches, persistent overlay and snapshot survive. | Sandbox handle, PID, guest markers, map entry and socket are meant to be replaced. The same slot recreates the same IP/path. Session grants in a live proxy currently survive, demonstrating why `run_id` is needed. |
| Host restart | All files above, including policy, per-agent disk, PID files, `agent_map.json`, coord DB and instance ID survive. | Processes and socket inodes do not. Proxy startup removes stale sockets but trusts the persisted map and may recreate a listener for a dead sandbox. Linux cleans old runsc state on the next start; Darwin's PID-only probe has PID-reuse ambiguity. There is no general reconciliation pass. |
| Remove/re-add same name | Historical JSONL, flow SQLite and legacy plumb state survive outside the deleted agent directory. The SafeYolo instance ID survives. | Agent policy/disk, nested grants/config and runtime artifacts are deleted; re-add mints a new ID/run-to-be and may reuse the old slot/path. Any surviving name-only ownership is therefore unsafe for the new principal. |
| Copied/cloned `~/.safeyolo` | Everything is copied, including `sy-...`, agent IDs, coord DB/NATS credentials, proxy/agent tokens, CA/vault material and name-keyed disk. | Current code neither detects a clone nor defines rekeying. `bootstrap()` can even insert another instance row if only the ID file is deleted. Treat a full copy as restore/move of the same authority, forbid concurrent independent use, and require a future atomic clone/rekey command for a new authority. |

### Local operator scoping

The smallest coherent change is a `coord.identity.local_operator_id()` helper
that returns `f"operator@{get_or_create_instance_id()}"`. Use it everywhere the
coord control plane currently uses the literal principal/actor ID:

- `coord/kernel.py` operation keys, conflict IDs and outbox actors;
- `coord/api.py` grants, room access and operator sends;
- `coord/brief.py` and `coord/inventory.py` actor fields; and
- `commands/coord.py` local operator join/read/send/wait calls.

Increment `coord/store.py`'s schema version and transactionally rewrite local
`memberships`, `coord_operations`, brief actors and any other operator-ID
columns from `operator` to the one ID derived from the database's single
instance identity. Reject a DB containing multiple different `instance` rows
instead of guessing. `sender_kind` and `actor_kind` remain `operator`, and the
terminal can still render "operator". This is instance authority scoping only:
no human row, login, authentication, `run_id`, or lifecycle subsystem.

## Step 2: narrow `agent_id` propagation

### Representation and authoritative resolution

Extend `core.identity.AgentIdentity` with `agent_id: str | None` and
`attribution_ip: str | None`. Enforce that a `RESOLVED` result has a valid
`ag-...` ID and name, while unavailable/conflict results expose neither as an
authority. Keep diagnostic UDS/map/metadata names for conflict reporting.

Do not add `AgentPrincipal` now. The existing result type is already the
trusted boundary, and it must be checked for `is_resolved` before use. Internal
security APIs should receive the resolved `AgentIdentity` (or an explicitly
extracted `agent_id` when the domain store is ID-keyed), never an overload that
also accepts a bare name. Name-taking APIs remain only at CLI/JSON/config
boundaries and policy/display lookup.

The authoritative name-to-ID mapping remains the locked `[agents]` snapshot in
`agents_store.py`. `_run_agent()` resolves/backfills the ID before publishing
runtime state, then `_update_agent_map()` writes it into the host-owned map:

```json
{
  "cody": {
    "agent_id": "ag-0123456789abcdef0123456789abcdef",
    "ip": "10.200.0.1",
    "socket": ".../10.200.0.1_cody/proxy.sock",
    "started": "2026-08-29T00:00:00Z"
  }
}
```

`ServiceDiscovery` should index one immutable runtime binding containing name,
ID and IP, and `resolve_agent_identity()` should use that binding for both IP
fallback and the ID paired with a UDS name. UDS name vs map name, stamped name
vs trusted name, duplicate IP/ID, absent ID, and map ID vs the current registry
record all fail closed. Stamp `flow.metadata["agent_id"]` alongside the
existing display/config name.

The early transport backstop is not an exception. Today
`request_id.recover_trusted_agent()` calls `resolve_agent_identity(flow)`
without discovery so it can recover the UDS name before normal request hooks.
Replace it with `recover_trusted_identity() -> AgentIdentity`. That helper
obtains the live `service-discovery` addon from the authoritative mitmproxy
addon registry (using the module singleton only when no master exists in unit
tests), then resolves the UDS tuple against its already-loaded runtime binding.
It returns and stamps both name and ID; `transport_guard` consumes the typed
result rather than copying a returned string. The discovery request hook does
not need to have run for its map lookup to be callable. If the addon/binding is
absent or disagrees, the early path remains unavailable/conflict: the
transport denial still happens, but evidence is not falsely assigned to an
agent. There is no UDS-name-only `RESOLVED` compatibility case.

Make map mutation locked and atomic while touching this schema; concurrent
starts currently perform an unlocked JSON read-modify-write. Proxy restart
loads the same ID from the map, validates it against the registry, and recovers
the same `AgentIdentity` for still-running agents.

### Migration and compatibility

- On first proxy/run access, backfill a missing policy `agent_id` with the
  existing locked helper. Normalize a legacy live map entry by adding that ID
  only when its configured name exists and platform liveness agrees; otherwise
  remove/quarantine the stale runtime entry. Never mint an ID for an
  unregistered map name.
- Preserve the ID across `add --force`; do not treat config overwrite as
  removal. A deliberate remove/re-add remains the only ordinary ID rotation.
- Map consumers that only need name/IP/display ignore the additive field. An
  older SafeYolo binary can read the map, which makes rollback operational,
  though it naturally loses the new identity guarantee.
- Do not rewrite historic `flows.agent_id` values or name-only audit/plumb
  records to the current ID. Their original incarnation is unknowable. New
  ownership queries exclude legacy rows from agent access; operator tools may
  still show them as legacy evidence.
- Keep name available as policy context. Changing user-authored policy keys to
  opaque IDs is explicitly out of scope.

### Smallest independently reviewable first PR

The first implementation PR should stop at the trusted boundary:

1. add/validate `agent_id` in `AgentIdentity` and flow metadata;
2. atomically add it to `agent_map.json`, including legacy normalization and
   registry mismatch rejection;
3. change early request/transport recovery to return the same typed identity
   from the live runtime binding, before service-discovery's request hook;
4. make `AgentAPI._handle_coord()` consume the resolved ID directly instead of
   repeating name lookup/mint; and
5. preserve ID through `add --force`.

Exact production files: `agents_store.py`, `vm.py:_update_agent_map`,
`commands/agent.py:add/_run_agent`, `proxy.py:_initial_mode_specs`,
`mitm_addons/service_discovery.py`, `core/identity.py`,
`mitm_addons/request_id.py`, `mitm_addons/transport_guard.py`, and
`mitm_addons/agent_api.py`. Exact focused tests:
`cli/tests/test_agents_store.py`, `cli/tests/test_vm.py`,
`cli/tests/test_commands_vm.py`, `cli/tests/test_proxy.py`,
`tests/test_service_discovery_file.py`,
`tests/test_agent_identity_resolution.py`, `tests/test_request_id.py`,
`tests/test_transport_guard.py`, and `tests/test_agent_api_coord.py`.

Acceptance: UDS and IP resolution return the same ID; proxy restart recovers
it; missing/malformed/duplicate/mismatched IDs fail closed; legacy live state
backfills once; unregistered stale state is not adopted; force preserves ID;
remove/re-add changes it; coord performs no post-ingress name lookup; and an
early UDS-attributed transport error resolves the same ID before ordinary
request hooks, while missing/conflicting bindings fail closed. This PR does
not migrate gateway grants or introduce `run_id`.

A following mechanical identity-consumer PR should change PDP principal IDs,
flow/trace ownership, audit spine, test-context declarations and other
security-sensitive consumers to use `agent_id`, while retaining name only as
policy/display context. That bounded sequence prevents a permanent ecosystem
of APIs that accept either names or typed identities.

## Step 3: minimal runtime incarnation

### Current-run record

Add `agent_runs.py` and `config.get_agent_current_run_path(name)`. Store one
atomic JSON record at `agents/<name>/current-run.json`:

```json
{
  "schema_version": 1,
  "run_id": "run-0123456789abcdef0123456789abcdef",
  "agent_id": "ag-0123456789abcdef0123456789abcdef",
  "name": "cody",
  "state": "running",
  "started_at": "2026-08-29T00:00:00Z",
  "ended_at": null,
  "pid": 12345,
  "runtime_handle": {
    "kind": "runsc",
    "container_id": "safeyolo-cody"
  },
  "attribution_ip": "10.200.0.1",
  "uds_path": ".../10.200.0.1_cody/proxy.sock",
  "exit_reason": null
}
```

`runtime_handle` is a small tagged object rather than an opaque string so each
platform can prove the handle without parsing prose. Linux keeps the existing
name-derived container ID for rollback compatibility, but writes `agent_id`
and `run_id` as OCI annotations and verifies them in `runsc state`. macOS adds
a diagnostic `--runtime-id <run_id>` helper argument; liveness verifies PID,
executable and that exact argument, avoiding PID reuse. Existing `vm.pid`,
`container.pid` and `userns.pid` remain platform projections, not authority.
In schema version 1, `pid` and `runtime_handle` are explicitly nullable while
`starting` has not spawned and when a pre-spawn failure is recorded. A
`running` or `stopping` record requires a provable `runtime_handle`; a
`failed` record claiming a live runtime requires one too. `pid` stays a
nullable platform projection rather than becoming the cross-platform key.

Use only these states and transitions:

```text
starting -> running -> stopping -> exited
    |          |           |
    +----------+-----------+-> failed
```

`exited` means the runtime ended, whether requested or unexpected;
`exit_reason` distinguishes those cases. `failed` means this start/stop attempt
could not establish, clean up, or reconcile the promised runtime. It is a
terminal state transition, but it is not safe to overwrite while its exact
handle is still alive. `ended_at` is set only once death is proven. A failed
record with `ended_at = null` therefore blocks replacement and ingress while
exact cleanup is retried; a dead failed record may be overwritten by the next
start after its event is emitted. No transition table, revision counter,
operation ID or historical run database is needed; a per-agent lifecycle lock
plus compare-current-`run_id` atomic writes handles the actual concurrency.

Place lifecycle locks under `data/agent-locks/<name>.lock`, outside the deleted
agent directory, so remove/re-add cannot create a second lock inode while an
old operation holds the first. Name is acceptable here as a validated mutex
namespace; the record itself must match the current ID. Every operation that
can create, mutate, run, stop or delete that name participates: `add`,
`add --force`, `run`, `stop`, and `remove`. `add` takes the lock before it
inspects or creates the agent directory and holds it through the policy save,
so it cannot race the current pre-save disk/host-script phase against removal.
`add --force` first reconciles and refuses an exact live or failed-live run;
configuration overwrite is a stopped-agent operation, not live mutation.

### Mint, transitions and cleanup ordering

1. `run` acquires the per-name lock, reconciles any record and platform state,
   refuses a verified live run, and completes all ordinary preflight. It mints
   `run_id` immediately before committing runtime artifacts. A failed warm
   restore and its cold-boot fallback are two actual sandbox starts and must
   therefore receive different IDs.
2. Write `starting` with ID/name/IP/UDS, then publish an `agent_map.json` entry
   containing both IDs. Pass `run_id` into `prepare_config_share()` and
   `start_sandbox()`. The guest reads `config-share/run-id` and writes that
   exact value into `status/per-run-started`; the host compares contents rather
   than file existence.
3. Attach the PID/platform handle to the same `starting` record immediately
   after spawn. Change to `running` only after the matching readiness marker
   and exact platform probe succeed. Emit `agent.started` here, not before
   spawn.
4. Any failure compare-and-updates that run to `failed`, removes the map entry
   only if its `run_id` still matches, reconciles proxy modes, and cleans the
   exact runtime handle. If exact cleanup fails and the handle remains live,
   retain `failed` with `ended_at = null`, fail ingress closed, close runtime
   children, and block a new start while later reconciliation retries cleanup.
   Cleanup from an old run must never remove a newer run's map/socket.
5. `stop` acquires the same lock and reconciles even when the current
   name-based liveness probe says false. For a live matching run it writes
   `stopping`, stops the exact handle, conditionally removes map/modes, then
   writes `exited`. A stop failure follows the same failed-live rule. Repeated
   stop is idempotent and retries cleanup. `remove` holds the lock through
   proven runtime death, disk deletion and registry deletion; it must fail
   without deleting identity/disk when exact cleanup cannot prove death.
6. A plain `add` or `add --force` releases the lock after its config/identity
   commit. If it requests auto-run, it then calls the ordinary run entry point,
   which reacquires the lock and revalidates the committed agent. This is an
   explicit release/reacquire handoff, not a recursive lock or ownership
   transfer; a concurrent remove may win between phases, in which case run
   fails cleanly as unregistered.
7. Once a run reaches `running`, release the lifecycle lock before waiting on
   a foreground terminal/process so `stop` remains usable. Natural-exit and
   exception cleanup reacquire the lock and compare the current `run_id`
   before any state/map/socket mutation. If stop or a later run already changed
   the record, old foreground cleanup is a no-op for shared state.

### Reconciliation and restart behavior

`agent_runs.reconcile(name, platform)` should apply these rules at `run`,
`stop`, `remove`, status inspection and before proxy startup builds modes:

- record ID differs from `[agents.<name>].agent_id`: never adopt; remove the
  stale map/listener and report cleanup needed;
- `starting` plus exact live handle and matching readiness: promote to
  `running`; live without readiness remains `starting` only within the startup
  deadline, otherwise stop and mark `failed`;
- `running` plus exact live handle: retain the same `run_id`, including across
  proxy restart;
- `starting` without a live handle: `failed`; `running` or `stopping` without a
  live handle: `exited` with a reconciliation reason;
- `failed` with its exact handle still live: keep `ended_at = null`, fail
  ingress closed, close children, retry stop of that exact handle and block
  overwrite/remove; `failed` with no exact live handle: conditionally purge
  its map/socket, set `ended_at` and allow a later start to overwrite it;
- PID alive but executable/run annotation mismatches: stale/PID reuse, never
  signal or adopt it;
- map/socket entry missing or mismatched while the exact runtime is live:
  rebuild it from the run record; map entry present for no exact runtime:
  remove it;
- host restart leaves no live platform handle, so old running records become
  terminal and no stale listener is created;
- remove/re-add deletes the old record; even a recovered stray record fails
  the embedded-ID check against the newly minted agent.

On upgrade, a live pre-`run_id` sandbox may be adopted once only if the policy
ID, name, map IP/path and platform-specific process/container proof all agree.
Mint an `adopted` run ID, persist it, annotate/rewrite only what can be proven,
and audit the adoption. If the platform cannot prove the live handle (notably
an ambiguous Darwin PID), fail closed for ingress and require stop/run. A
stopped legacy agent gets no record until its next start.

The additive map fields/current-run file/OCI annotations are ignored by older
binaries. Retaining the Linux container name and legacy PID projections keeps
rollback able to stop a runtime. Rollback loses run-aware enforcement, so it
must first close preview/desktop children; it never rewrites IDs or records.

### Runtime children without an exposure registry

Step 3 need not implement the issue's future `ExposureSession`. Add
`agent_id`/`run_id` to `preview.PreviewConfig`, capture them when preview or
desktop opens, and require `agent_runs.require_active()` before every new port
forward. If the current record changes or becomes terminal, shut down the host
preview and Tailnet child. Include both IDs in open/close audit details. This
prevents a long-lived preview process from attaching by name to a later run.

### Exact code and tests

Production changes:

- new `cli/src/safeyolo/agent_runs.py`: schema validation, atomic record
  mutation, lifecycle lock, mint/transition/reconcile/require-active;
- `config.py`: current-run and lock paths;
- `commands/agent.py`: add/force-add/auto-run locking and
  run/restore-fallback/foreground-handoff/stop/remove transitions, event
  timing, preview capture;
- `commands/lifecycle.py` and `proxy.py`: reconcile before status/mode startup;
- `vm.py`, `platform/__init__.py`, `platform/linux.py`,
  `platform/darwin.py`, and `vm/Sources/SafeYoloVM/main.swift`: carry and prove
  the runtime handle;
- `guest-init-per-run.sh` and `vm.prepare_config_share()`: run-tagged readiness;
- `agent_map.json` producer/consumer and `ServiceDiscovery`: carry/validate
  `run_id`; and
- `preview.py`: compare captured run before relaying.

Focused tests belong in a new `cli/tests/test_agent_runs.py` plus the existing
command, VM, Linux/Darwin platform, proxy, identity, preview and blackbox
lifecycle suites. Acceptance cases:

- two starts preserve `agent_id` and produce different `run_id` values;
- a failed restore attempt and cold fallback have different runs;
- proxy restart with a live sandbox recovers the same run;
- host restart/stale PID, PID reuse, stale runsc state, stale map, stale socket
  and stale readiness content are not adopted;
- crash between each `starting`/spawn/map/running boundary reconciles safely;
- start cleanup failure, stop failure and host restart with a failed-live
  record retain ownership, fail ingress closed and retry exact cleanup until
  runtime death is proven;
- concurrent add/add, add/remove, add/run, force-add/stop, run/run, run/stop and
  stop/remove serialize or use the specified auto-run/foreground handoff;
- remove/re-add same name yields different agent and run IDs;
- old cleanup cannot delete a new run's map/listener;
- a preview captured on run A closes or fails after run B starts; and
- legacy live adoption is exact or fail-closed, never name-only.

Run focused identity/lifecycle tests first, both platform unit suites, doc/link
checks and pre-commit, then the full Python suite. Exercise the existing Linux
and macOS lifecycle blackbox lanes for platform-handle behavior; unit mocks
alone cannot prove PID/runsc reconciliation.

## Implementation order and non-goals

Recommended order is: Step 2 boundary PR; Step 2 consumer migration; Step 3
current-run core and reconciliation; Step 3 preview binding; then separately
scope the coord operator sentinel once clone/rekey behavior is documented in
operator-facing backup guidance.

Defer gateway grant states/binding, exposure registry/list/close, credential
providers, external-vault references, generic revisions/outbox, and historical
run event sourcing to their dedicated follow-ups. Network slots, tailnet ports,
policy definitions, audit facts, messages, flows, snapshots and approval
requests remain allocations/config/facts/subordinate artifacts, not new
lifecycle-managed objects.
