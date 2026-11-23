# Host execution contract

The `safeyolo.host-execution/v1` contract connects an issuing SafeYolo instance
to a named execution target. The target can run independently or alongside
SafeYolo. The maintained types and validators are in
[`host-executor`](../host-executor/src/lib.rs). The proxy's
[`host_execution`](../proxy/src/host_execution.rs) module reuses those types and
owns the service projections. `schemas()` derives the JSON schemas from the
shared types. The shared fixtures and authenticated HTTP witness
are in [`host_execution.rs`](../proxy/tests/host_execution.rs).

Loading types does not enrol an issuer or grant invocation permission. The
standalone executor enforces adopted native operations. Catalogue adoption
uses the target configuration and the issuer's existing native policy owner.
The local Service Gateway adapter binds these operations to an authenticated
agent run and an activated operator task. The
[deployment guide](host-operations.md) covers standalone preparation, remote
HTTPS and starter workflows. Integrated platform qualification remains part of
[#1669](https://github.com/craigbalding/safeyolo/issues/1669).

## Ownership and trust

| Owner | Authoritative inputs and decisions |
|---|---|
| Issuing SafeYolo instance | Durable instance/agent identities; current host-observed agent run and selected task; policy, grants, checks, assessments and approvals; issuer signing credential. |
| Target operator | Durable target identity; enrolled issuers and public keys; adopted package bytes; maximum operation scope and budgets; maximum authority age. |
| Target executor | Fresh authenticated issuer-authority observations; atomic admission/usage and replay records; job lifecycle, output and actual native enforcement. |
| Calling agent | Typed argument choices and untrusted rationale. Agent labels and prose establish no identity or scope. |

The issuer is identified by its durable instance ID. The target operator binds
each issuer to named Ed25519 public keys using the existing credential and
configuration owners. The private signing key stays outside agent sandboxes.
No certificate authority or new approval protocol is required. A standalone
target keeps its operator-owned trust, adoption and ceiling configuration; it
does not become a second SafeYolo policy owner.

An issuer adapter must derive the principal from trusted ingress and current
run state, using the existing `AgentRun` identity. It must bind the selected task
or explicitly use `task_id: null` when there is no task. It must obtain current
policy, grant and assessment inputs before signing. A signing helper is not a
policy check. Signing arbitrary agent-supplied principal or scope fields would
violate this contract.

The target accepts `IssuerAuthority` only from an authenticated issuer owner.
That value is an expiring projection of the issuer's current authority, not a
request-supplied grant or another policy store. Its revision changes when an
underlying grant/run/task or authority changes. Its assessment revision names
the exact policy/check/approval inputs used by the issuer. Target operators own
the ceiling revision; it changes when the ceiling changes. Trust revisions
change on issuer/key enrolment, rotation or removal. These revision obligations
and delivery of fresh authority are required consumer dependencies. The witness
uses fixed trusted inputs and does not implement their production adapters.
`Target::revisions()` also hashes the actual trusted key set, grants and ceiling
with their owner revision references. Reusing a label cannot conceal changed
inputs from a client that supplied expected revisions. Proposals and invocations
use `request_revisions()` to bind the selected operation and grant. Discovery
returns those revisions per operation. Changes to another operation do not
invalidate an unchanged prepared invocation.

## Client and target journey

For an already enrolled issuer and adopted target, the client uses these steps:

1. Discover the selected target's adopted operations and current revisions.
   An operation can be present without an invocation scope. Discovery is an
   authenticated disclosure, not permission to execute.
2. Select a literal operation/resource ID and typed arguments. Carry the
   discovered operation, implementation and authority revisions into a proposal.
3. Inspect the proposal's normalized arguments, effective budgets, expiry and
   assessment digest. A proposal reserves no budget and grants no approval.
4. Invoke using that exact assessment digest and the same validity inputs.
   The target rechecks authority and budgets at admission. Changed inputs need
   another proposal. Retain the returned job and original request ID.
5. Read the job or a bounded output range. To cancel, supply the observed job
   revision. Inspect the subsequent receipt to determine whether execution
   actually stopped.

All routes use `POST` with a JSON `SignedRequest`. The catalogue can change
without changing the routes:

| Action | Route | Result |
|---|---|---|
| `discover` | `/v1/host-execution/discover` | Catalogue, operation scope indicators, features, revisions and authority validity. |
| `propose` | `/v1/host-execution/propose` | Normalized invocation, effective limits and assessment digest. |
| `invoke` | `/v1/host-execution/invoke` | Retained admission receipt. |
| `job` | `/v1/host-execution/job` | Current lifecycle receipt for the selected job. |
| `output` | `/v1/host-execution/output` | Offset, base64 bytes, end indicator and retained-output digest. |
| `cancel` | `/v1/host-execution/cancel` | Current receipt with cancellation requested. |

Timestamps are UTC Unix seconds. Time budgets are seconds, byte budgets are
bytes, and concurrency/process limits are counts. Output offsets count bytes
in the retained stream, including bytes inside a multibyte text character.

Adapters must bound request/response sizes and use authenticated HTTPS or an
explicitly adopted protected local transport. The client's configured endpoint
must authenticate the selected target; matching a target label in JSON is
insufficient. Redirects must not disclose signed requests to another target.
The witness uses owned loopback TCP connections and proves issuer signature
validation; it does not qualify an HTTPS deployment.

## Agent gateway entry point

On a running Unix SafeYolo host, the operator uses the existing policy owner to
adopt a `host_bindings` table. Each value is an encoded JSON binding document.
Installed capability discovery exposes `host_execution_binding` and its actual
validator. A binding selects the target's adopted `Target`, issuer, native
grant, key ID, vault credential reference, service name, an authenticated
endpoint and finite request/response/deadline limits. A `unix` endpoint selects a canonical absolute socket and executor UID.
An `https` endpoint selects a host, port and adopted certificate PEM. Endpoint
name and certificate validation precede signed-request dispatch. The
credential value is base64 Ed25519 PKCS#8 in the existing encrypted store.
Neither the value nor a signed request is returned to the agent.

The issuer ID must match the selected instance's durable identity. The native
grant's principal selects the agent, run and task. The operator registers and
activates that task through the existing task owner. `task_revision` is the
shared canonical JSON digest of its registered document. A different task ID,
changed active document, stopped run or changed durable agent identity cannot
reuse the binding. The service must also have current `gateway:request` policy
permission for each selected native protocol path. A binding does not override
an existing gateway or task denial.

The agent uses its ordinary Agent API bearer through
`http://_safeyolo.proxy.internal`:

1. Read `GET /gateway/host` to find bindings for its current run and task.
2. Send a discovery action to `POST /gateway/host/{binding}`. The request below
   uses a previously discovered binding name and an agent-retained request ID.
3. Propose a literal invocation with the discovered operation revisions. Read
   the normalized arguments, limits, validity and assessment digest. Supply
   that preparation to the invocation action.
4. Retain the invocation's request ID and job ID. Use the same binding for job,
   output and cancellation actions. A changed payload needs a new proposal.

```json
{"request_id":"discover-1","expected":null,"action":{"kind":"discover"}}
```

Inputs contain only `request_id`, `expected`, `action`, optional
`untrusted_rationale` and optional `challenge_id`. The gateway supplies target,
issuer, grant, principal and expiry from the approved binding. Unknown fields,
definition-management actions and issuer enrolment are refused. Discovery
filters operations and catalogue changes to the selected grant. Proposals have
no separate retained object or cross-agent readback route. The exposed API has
no job-listing or definition-management route. Job, output and cancellation
always require the target's exact issuer, principal and grant ownership.

The existing `route_challenges` owner can select native invocations by agent,
binding service, operation ID as `capability`, method `POST` and path
`/v1/host-execution/invoke`. Its adopted checks run even when gateway policy
already permits that route. An absent required finding or an unmet question
prevents target dispatch. A positive deny finding remains a denial. A private
challenge creates no operator attention. The agent can abandon or revise the
operation, or explicitly use the existing eligible challenge escalation with
task, source and alternative context. An operator's `exact` decision permits
only that invocation and request ID; native grants and target checks still
apply. It creates no new standing grant and never executes or retries a request.
Routine permitted invocations with satisfied checks need no approval.

Private policy assessment and operator policy review include complete native
grants, target ceilings and future-family bounds through the existing host
effect assessor. The result distinguishes represented effects from unknown
behavior. A favorable assessment creates no permission.

The gateway checks Unix socket peer UID and protected path ownership, or
verifies the configured HTTPS certificate and endpoint name. It rechecks current
policy, task, run and vault selection before sending. The target then
independently authenticates and admits the signed request. Target input changes
can therefore refuse a request after issuer admission. The adapter supports the
executor's protected Unix socket and authenticated HTTPS on all target platforms. Windows named pipes remain a protected local
transport. Target configuration is not implicitly synchronized, and saved
inputs do not establish running-target readiness. The deployment guide shows
configuration, rotation and current-revision inspection.

The gateway sends each request once. A missing or mismatched invocation or
cancellation reply returns an uncertain outcome with the original request ID
and possible job ID. Cancellation retains the selected job's ID. An unavailable
read or proposal reports `execution_outcome: unavailable`; it sent no invocation.
Mismatched discovery also reports the expected and observed package digests.
Inspect an uncertain job under current read authority before retrying. An exact
duplicate mutation uses the target's durable receipt; changed content with the
same ID conflicts. After revocation removes read authority, the target operator
must inspect the retained result. Gateway or credential revocation stops new
admissions and reads; an admitted job retains its target execution deadline and
limits. Revocation does not undo effects or prove process termination.
`gateway.host_admission`, `gateway.host_result`, `gateway.host_refused` and
`gateway.host_result_unavailable` distinguish reached issuer, target and
uncertain outcomes in the existing audit. A missing audit event is not proof
that no effect occurred.

`SignedRequest` contains `request`, `key_id` and a base64 Ed25519 signature.
The signing message is UTF-8: protocol version, newline, key ID, newline, then
the lowercase SHA-256 digest of the canonical request. Canonical JSON uses the
existing approval/report digest owner: recursively sorted object keys, retained
array order and native JSON value semantics. The version is also inside the
signed request. Verifiers reject unknown fields, versions, actions and required
features. They also compare the HTTP method/path with the signed action.
Required v1 validation remains mandatory when `required_features` is empty.

The request binds target, issuer, principal/run/task, grant, request ID, expiry,
action, arguments, expected revisions and rationale. All fields are covered by
the signature; rationale remains untrusted after authentication. Key IDs are
scoped to their issuer. Job/replay identities include both target and issuer,
so equal agent, key, grant or request IDs at separate issuers confer no access.

## Effective authority and package projections

Invocation requires all of these conditions:

- The operation and resource belong to the adopted package.
- The issuer's current grant matches the exact principal, run and task, permits
  the protocol action, and has not expired or been revoked. The target's
  `allowed_verbs` ceiling must also permit that protocol action.
- Both the delegated operation scope and the target's local ceiling permit the
  implementation, resource and every supplied or defaulted argument.
- Expected trust, authority, ceiling, assessment, operation and implementation
  revisions still match. The proposal digest binds normalized arguments,
  revisions, intersected budgets and validity; changing an allowed argument
  still requires reassessment.
- The target atomically reserves usage within the effective call/concurrency
  budgets before dispatch. Time/output budgets are the minimum of issuer,
  ceiling and adopted implementation limits.

Selectors are literal ASCII IDs containing letters, digits, `_`, `.`, `:` or
`-`. Selectors are neither paths nor patterns. Unknown arguments and wrong
types are refused. Argument types reuse the existing native request-contract
binding types: string, integer, boolean, string list and enum. Scope choices are
complete JSON values. A string list is one choice, not independently combinable
permissions for its entries. An omitted optional argument with no default is
absent. A default is normalized before scope comparison.

One `Package` holds the stable operations/resources, typed arguments and
defaults, execution specifications, native effect declarations and enforcement
disclosures. Optional `semantics` carries reviewed resource identity,
conditional effects, composition rules, alternatives, evidence and limitations.
Missing identity and consequence annotations remain explicit assessment gaps.
`Package::projections()` derives the target material, native gateway definitions
and shared effect-assessment definition. They carry the common package version
and digest. `verify_projections()` checks them against regeneration. The target and
gateway adoption owners must verify those projections against the approved
package; a caller-supplied digest alone is not adoption authority.

The current native effect model identifies operations by method/path. The
generator therefore emits one service projection per package operation, each
with the same stable invocation route and its own selector/argument contract.
These are ordinary native service definitions, not another route matcher.
The existing route analyser cannot prove identity through the nested signed
body. Route projections retain unresolved native identities and no unsupported
effect-enforcement mapping. They reuse the adopted explanations and narrower
alternatives in private assessment, challenge and operator review. They do not
claim that route access authorizes the payload. The target's independent checks
remain mandatory.

The [host authoring workflow](service-authoring.md#author-host-operation-packages)
also assesses complete native operation scopes through the existing effect
evaluator. Target-owned grants and ceiling values supply target/resource
identity, typed argument choices, execution principal and validity. The
assessment composes current/proposed authority with supplied retained-effect
observations. Expiry does not remove earlier writes, disclosures or persistence.
Unobserved historical state and ambient dependency/alias relationships remain
explicit limitations. This read-only assessment does not replace issuer policy,
target admission or the agent/task gateway adapter.

Discovery includes separate semantic revisions for implementation, enforceable
authority, adopted understanding and description. The existing
`implementation_sha256` remains the exact complete-operation admission pin.
Its change alone is not a claim that executable bytes changed. A description
edit leaves the semantic implementation revision unchanged. A changed recipe
or executable hash changes that revision even when the description is unchanged.
A shared model correction changes understanding, the operation pin and prepared
assessment inputs. A stale prepared invocation is refused even when executable
bytes remain identical. Catalogue review records that model change separately
from the enforceable authority comparison. Catalogue review records
description-only changes as equivalent. Existing exact grant pins and standing
update rules still apply.

Direct target discovery discloses the full adopted definitions, including
literal environment values, to a grant with the discovery action. The agent
gateway filters that catalogue to the selected grant. Adoption must account for
the relevant disclosure. Host-held service credentials remain with their existing owners;
the package's delegated service references do not contain those credential values.

## Catalogue adoption and revision changes

`CatalogueAdoption` records publisher trust, an active signed catalogue, its
previous signed revision, observed candidate input and standing update bounds.
The target's `Configuration.catalogue` owns target adoption. A native issuer
stores the same type as a JSON string under
`[host_catalogues] PACKAGE_NAME = 'ADOPTION_JSON'` in `policy.toml`. Use the
existing policy adoption/apply interface to adopt that initial authority. The
derived `catalogue_adoption` schema describes every field. These records do
not add an approval queue, endpoint grant or agent/task permission.

`observed_file = { path, max_bytes }` can name an absolute local discovery file.
An authorised publisher or the existing artifact/signal consumer supplies its
`SignedCatalogue`. The configured byte ceiling bounds decoding. The target reads
actual candidate bytes before invocation and dispatch. The issuer's existing
policy watcher reads actual bytes on its ordinary control pass. Size and
modification time do not establish identity. A signature authenticates the
publisher and full source; it does not permit execution or qualification code.
The signed `announcement_revision` is a positive increasing publisher revision,
separate from the package's implementation version. The existing adoption
records retain the last verified announcement, including withdrawal and pending
revisions. Older announcements and different content reusing a revision refuse
adoption. Duplicate announcements are idempotent; reconnect cannot undo a
recorded withdrawal or select an older update.

An `UpdateRule` carries the complete operation ceiling, declared effects,
required checks and enforcement assumptions. `allow_narrower` permits a
conservative inclusion proof against that standing ceiling.
`allow_implementation_updates` separately permits trusted executable or pinned
dependency byte updates within the ceiling. This can cover changes between
adjacent revisions that are not tightening, provided both remain within the
original assessed ceiling. It does not establish general program equivalence.
Recipes, argument/default semantics, environment, identity, service-manager
authority, persistence declarations and required enforcement remain represented.
Unknown comparisons and unresolved enforcement remain visible.

Comparison reports contain deterministic `equivalent`, `narrower`, `broader`,
`incompatible` or `unknown` results and field differences. Only fields with set
semantics are sorted; argument lists, defaults, native command words and adopted
effect explanations retain their meaning. Canonical-equivalent edits preserve
source provenance without replacing adopted explanations with publisher prose.
New selectors stay discoverable while awaiting authority. A family explicitly
names a literal prefix ending in `:`, exclusions, a complete operation ceiling
and invocation scope. The issuer and target each authorise membership through
their selected exact-operation or family scope. Their family prefixes need not
match. An exact operation grant never gains future membership implicitly. The
whole potential family authority and its compositions must be assessed at
initial adoption. Each selected scope's call and concurrency budgets aggregate
its members independently. Target ceilings apply across issuers and grants.
Call usage belongs to the current grant or selected target-scope revision;
active reservations, including uncertain jobs, survive revision changes.

An operation's implementation, represented authority, effect/assessment and
complete operation identities are distinct. The implementation digest retains
the complete operation definition; executable and dependency digests identify
file bytes. Discovery also retains the full
package digest and source. `Invocation.operation_sha256` binds the full selected
operation and package identity, independently of unrelated operations or package
metadata. A changed operation still needs fresh assessment. Required check names
must be present in both current trusted scopes; the issuer must derive this
evidence from its existing check owners, never from caller-supplied names.

The native policy transaction activates generated gateway definitions with their
adoption record. The same transaction advances the package and catalogue status
in gateway bindings that match the previous active package snapshot. It preserves
each binding's target identity, grants, ceilings, endpoint, signing credential
reference and task binding. Bindings with other package snapshots keep their
definitions. The transaction retains the last qualified revision and restores
the saved source and runtime if activation fails. The target validates the entire selected
native catalogue before saving its adopted revision in the existing protected
configuration. The executor must be able to replace that configuration. An
external edit detected during qualification refuses the save. Target and issuer
can update separately: mismatched changed operations refuse invocation; unchanged
operation identities remain usable. Neither side claims that the other is live.

Discovery, target checking and `policy show` expose observed, proposed, qualified
and active identities with the automatic, refused or awaiting-review reason.
Quiet updates use ordinary retained configuration and policy/executor audit
output. No routine approval request is generated inside standing authority.
The configuration keeps the previous signed revision for inspection and rollback.

Pending proposals, findings and approvals retain their exact inputs. An admitted
job revalidates its original request before entering `running`. A changed input
prevents that launch. A running job retains its original implementation and
limits; updates do not relaunch it or reverse its effects. Exact replay returns
the retained admission without dispatching again. The ordinary job/output and
cancellation routes retain their current ownership and revocation checks.

For a known stale preparation, a trusted issuer can use `refresh_preparation()`
with authenticated discovery and the real proposal route. It revalidates current
scope and normalized arguments and returns freshly signed invocation authority.
It never sends an invocation. Reconcile the original request/job after an
uncertain reply before selecting another effect; a stale reply alone cannot
establish that an earlier request never executed.

Withdrawal either retains the active revision or selects the identified retained
previous revision under `on_withdraw`. An explicit `pin` selects retained bytes.
An older announcement alone cannot select rollback. Duplicate observations and
reconnects preserve the selected identities. Announcement expiry prevents a new
adoption from stale discovery; it does not revoke an already adopted package.
Current publisher trust, invocation grants, issuer freshness and target ceilings
still apply. Rollback never recreates a removed grant or erases job history.

`execution.dependencies` can pin canonical input files by content digest and
finite byte ceiling. Linux validates and mounts sealed snapshots of these files
at their declared paths before launch. It detects changed bytes even when size
and modification time remain equal, and subsequent replacement cannot change the
held snapshots. Native executable snapshots retain the same protection. macOS
and Windows explicitly refuse declared dependency snapshots because those
backends cannot yet supply this guarantee. Ambient runtime dependencies and
alternate access paths remain outside the declared pin set; no closure over
arbitrary program dependencies or aliases is claimed. Existing broader native
profiles and their disclosure remain unchanged.

## Standalone binary and build dependencies

The standalone executable is `safeyolo-host-executor` (`.exe` on Windows).
It does not require Python, Rust, WSL, a container runtime or a full SafeYolo
installation on the target. Its `--version` output identifies the source commit,
build profile and Rust target. A local build without a supplied source revision
reports `commit=unknown`; this is not a release identity.

| Target | Required runtime components and current native profile |
|---|---|
| Linux x86-64 / ARM64 | Compatible C runtime; a pinned bubblewrap with the options used by the backend; kernel user namespaces, seccomp and delegated cgroup v2 memory/pids controls. The executor must run where it can migrate its own jobs into that delegation. Ordinary programs receive read paths with no writes, network or IPC. The fixed service profile below separately admits its trusted OS client. |
| macOS ARM64 | Native Seatbelt through the OS `sandbox-exec`, system libraries and process-observation APIs. Ordinary programs receive no fork, writes, sockets or Mach access. The profile requires explicit `memory` and `executor_restart` exceptions. The fixed service profile adds disclosed Mach lookup authority and, for restart, signal permission for its trusted OS client. |
| Windows x86-64 | Native Windows security, Credential Manager, local named pipes, Job Objects, the Service Control Manager and the Universal C Runtime supplied by current Windows. The GNU package statically links its compiler runtime. Its remaining imports are Windows system DLLs. No MinGW installation is required on the target. |

SQLite is bundled into the executable. Operation definitions separately declare
their runtime libraries, tools, interpreters and service permissions. A server
binary that loads does not establish that an adopted operation's dependencies
or native guarantees are available. The required native starter operations
must not hide a Python dependency.

The native proxy workflow retains an executor archive for each target below,
named `host-executor-TARGET-COMMIT`. Download the archive for the selected source
from that workflow's artifacts. The separate `packages_only` dispatch continues
to select full SafeYolo packages. The executor job runs during ordinary pull
request, push, scheduled and manual contract runs. Windows binaries are built
with the GNU cross compiler; compiling Windows tests does not run them.

| Archive target | Native component evidence and deployment scope |
|---|---|
| `x86_64-unknown-linux-gnu` | Ubuntu 24.04, ordinary user, delegated cgroup v2 and pinned bubblewrap; observation, fixed user-service control and lifecycle fixtures. |
| `aarch64-unknown-linux-gnu` | Linux ARM64 executable and contract checks. Native namespace/cgroup fixture results use x86-64; ARM64 enforcement remains unqualified. |
| `aarch64-apple-darwin` | macOS ARM64; observation, fixed user-service control and lifecycle fixtures with the explicit broader bounds below. |
| `x86_64-pc-windows-gnu` | Native Windows 11 foreground and Service component fixtures, with a separate ordinary workload account. Other Windows versions and Windows ARM64 remain unqualified. |

The GNU Linux packages need a compatible glibc; the workflow builds them on
Ubuntu 24.04. A package's executable identity and metadata identify its exact
source and target. This component evidence does not establish integrated
gateway or starter-catalogue release qualification; those consumers have their
own acceptance.

On Linux or macOS, extract the selected ZIP into an operator-owned directory,
make `safeyolo-host-executor` executable if the extraction tool omitted its
mode, then run `./safeyolo-host-executor --version`. On Windows, use
`Expand-Archive` in an operator-owned directory and run
`.\safeyolo-host-executor.exe --version`. Compare the binary's SHA-256 with
`host-executor.json` and its reported commit with the selected workflow source.
Extraction and a version result do not create configuration, accounts, service
permissions or an isolation delegation. Then use `check` with the explicitly
adopted configuration and private state directory before starting `serve`.

For a release producer, run the following from a clean, committed source
checkout with the repository's Rust toolchain, native linker/C build tools,
Bash and Python 3.11 or later. The build uses the existing Cargo reserve guard and inherits
its configured reserve, target directory and one-job settings. It can download
locked build dependencies. Choose a new archive path outside the checkout;
replace `/release/executor.zip` below with that path before running the command.

```sh
python3 scripts/build_host_executor.py --output /release/executor.zip
```

The command builds a production executable for the build host and writes a ZIP
archive with the binary, licence, `host-executor.json`, deployment guide,
authoring source and agent helper. The target bundles rustls TLS and rcgen
certificate preparation; the helper uses the agent sandbox's Python 3, not a
target-side interpreter.
It prints the archive and binary SHA-256 digests. The metadata records the
source, target, compiler, selected build flags and a link to this contract at
the built source revision. `--target` selects an
installed Rust cross-compilation target and its linker; otherwise
`CARGO_BUILD_TARGET`, when set, selects the target. Python and build tools are
not included or needed when running the extracted binary. The archive does not
install accounts, service-manager configuration, bubblewrap or cgroup delegation.
Build completion does not establish native enforcement or release qualification.

## Execution scope and enforcement limits

Each implementation digest covers its arguments, effects, enforcement
disclosure and the complete execution specification:

- A fixed executable path and content digest, argument words, exact environment
  and working directory. `Operation::command()` renders words without a shell.
  Strings stay literal; booleans/integers use JSON scalar text; a list expands
  into argument words. Environment values must produce exactly one word. Native
  NUL bytes and invalid environment names are refused. No ambient environment
  is inherited. Optional arguments used by command words need a default.
- An explicit target-native principal and supplementary groups. A user/group
  label is an adoption input, not proof that the runtime uses that identity.
- Target-native filesystem read/write paths. Empty lists permit no application
  access in that category. Required runtime files must be included by adoption.
- Explicit network hosts, ports and TCP/UDP transport; Unix sockets or named
  pipes; finite time, output, memory and process limits.
- Named delegated service capabilities/resources, using the existing service
  owners' semantics. A declaration creates no credential, route or service
  grant. Those owners must recheck current access during execution.

Platform adapters must resolve and enforce these scopes using their maintained
native boundaries, verify executable identity against replacement races, and
refuse a required scope they cannot enforce. Absolute path and identity syntax,
path alias/symlink handling, resolver/IP binding and platform-specific isolation
are native executor dependencies, not guarantees supplied by this validator.
An operator may explicitly adopt implementation semantics that containment
cannot establish. The package must distinguish those adopted declarations from
enforced properties and unresolved dependencies. Generation or a valid
signature does not prove that arbitrary code obeys its effect description.

Invocations have no deployment, enrolment, trust or ceiling mutation action.
Those operations use their existing operator-owned adoption/configuration
paths. A fixed-service restart cannot replace its executable, unit, environment
or configuration. An operation that declares broader executable or writable
scope needs explicit adoption and matching authority; the word “restart” adds
no restriction or guarantee by itself.

The `execution.broader` set identifies explicitly adopted exceptions to required
native guarantees. It is part of the implementation digest, issuer grant and
target ceiling binding. An empty set requires every declared bound. The current
`memory` exception permits the macOS backend to poll resident memory without
claiming a hard kernel memory cap. The `executor_restart` exception permits a
process to remain running beyond its deadline if the controller crashes. Restart
retains uncertain cleanup and concurrency until the recorded process birth is
absent; it does not signal a recovered PID. The macOS backend requires both
exceptions. An enforcement label cannot select either exception. The Linux and
macOS adapters refuse unsupported filesystem, network and IPC profiles.
An ordinary adopted program cannot receive a service-manager channel: under
the executor account that channel could launch code outside the sandbox and
modify executor inputs. A service name or executable digest alone does not
make an arbitrary program a trusted service client.

The fixed service profile admits only the native, root-owned OS client and
protected parents, pinned by content digest. It checks literal action/resource
arguments and an exact native environment; callers cannot substitute a program,
unit, loader variable or interpreter. This client and its system libraries are
part of the trusted executor boundary. The selected unit definition, executable,
dependencies and service-manager permissions remain adopted external trust
dependencies. Linux and macOS support `start`, `stop`, `restart` and `status`
for one existing user service. Neither profile creates or replaces units or
their configuration.

For Linux, the delegated service owner is `systemd-user`, with capability
`start`, `stop`, `restart` or `status` and one literal `.service` resource. The executable is
`/usr/bin/systemctl`. Its literal arguments begin with `--user --no-pager
--no-ask-password`, followed by `start -- UNIT`, `stop -- UNIT`,
`restart -- UNIT` or `show --property=ActiveState --property=MainPID -- UNIT`. Its exact environment is
`XDG_RUNTIME_DIR=/run/user/UID` and `SYSTEMD_OFFLINE=0`; the latter prevents
systemctl from skipping the requested operation inside the filesystem sandbox.
The declared Unix socket is
`/run/user/UID/systemd/private`. Only AF_UNIX sockets and that mounted manager
channel are available. This profile requires `delegated_services` and
`process_visibility` in `execution.broader`. The trusted client shares the
host process namespace so systemd can verify peer credentials. It receives no
host proc filesystem, and the seccomp filter denies signals, foreign-process
limit changes, ptrace, cross-process memory access and file-descriptor copying. Cgroup limits
and descendant cleanup still apply to the client job.

For macOS, the owner is `launchd-user`, with one literal `gui/UID/LABEL` or
`user/UID/LABEL` resource. The executable is `/bin/launchctl` with literal
`print RESOURCE` for status, `kickstart RESOURCE` for start,
`kill SIGTERM RESOURCE` for stop or `kickstart -k RESOURCE` for restart, with
an empty environment. The trusted client receives Mach lookup permission.
Stop and restart also permit the signal permission that launchd checks for
those actions. A stop sends SIGTERM; it does not disable the adopted service
or prevent launchd from starting it again under its existing definition.
The profile requires `network_ipc` and
`delegated_services` exceptions in addition to `memory` and `executor_restart`.
For both profiles the working directory is `/`; UID is the executor's adopted
numeric identity. The complete client specification remains bound by the
operation digest and both authority ceilings.

Service processes and persistent effects are outside helper-process memory,
task, deadline and cleanup controls. A receipt's `processes_stopped` describes
the helper, not the selected service. Restart can intentionally leave a service
running. The native receipt discloses these limits; transport completion or
helper cleanup does not establish a service's final state.

The Windows adapter requires explicit `filesystem`, `registry`, `network_ipc`
and `delegated_services` exceptions. Job Objects bound aggregate process memory,
active processes and direct descendant lifetime. Job Objects do not confine
files, disk writes, registry access, network destinations or service-manager
effects. Those permissions come from the selected workload account's operating
system (OS) access. Declared paths, destinations and services are assessments in
that profile. Delegated service, Windows Management Instrumentation and task
scheduler effects can continue outside the Job Object. A receipt's
`processes_stopped` observation covers associated Job processes only.

The Windows executor uses a separate, non-administrative workload account.
The executor rejects workload privileges that can bypass protected ACLs or
impersonate the executor. Configuration, state, executables and their ancestors
must prevent workload replacement. The adapter checks native access control
lists (ACLs), refuses reparse points and holds executable/ancestor handles
against replacement. Local drive paths are supported; UNC/device paths,
alternate data streams and trailing-dot/space aliases are refused. Host-owned
DLLs and OS tool dependencies remain unpinned and must be assessed. The native
launcher does not load the workload's user profile or current-user registry
hive automatically. Event Log and registry commands need the corresponding OS
read permission. Fixed service commands need an explicit service ACL; a signed
request does not create one.

`native.credential` selects a generic Windows Credential Manager entry owned by
the executor account. `credential-store --name NAME --account DOMAIN\user`
reads a UTF-8 password from private stdin. The password is not a configuration
field or command argument. A PowerShell/.NET caller must write UTF-8 bytes
without a byte-order mark to the child input pipe; a writer's preamble otherwise
becomes part of the password. `identity --credential NAME` reports the workload SID
and stable token groups. The changing logon-session SID is excluded from that
stable list. Native launch requires `SeImpersonatePrivilege`, or the appropriate
assign-primary-token and quota privileges. Windows Service installation selects
the executor account explicitly; credential provisioning must use that same
account. `service --name SCM_NAME --config ABSOLUTE_JSON --state ABSOLUTE_DIRECTORY`
uses the same validation, admission and execution code as `serve`. Service stop
requests native Job cleanup before reporting `SERVICE_STOPPED`.

The local Windows transport is `\\.\pipe\safeyolo-host-TARGET_ID`. The server
uses a private DACL, rejects remote clients and refuses a pre-existing pipe name
at startup. A client must verify the pipe server's OS account before sending a
signed request; a pipe name or target label alone does not authenticate the
server. Clients should open with identification-level security quality of
service to prevent server impersonation. The component fixture verifies the
server process token against its selected executor account. Connections,
pending instances and whole request/response deadlines are bounded. Native
command lines use Windows CRT quoting with an explicit application path and
exact case-insensitive environment names. Native command lines are limited to
32767 UTF-16 units, including the terminating NUL. If the selected executor lacks
assign-primary-token/quota privileges, the token-launch fallback has a shorter
1024-unit limit. A longer command then fails before process creation and names
the required executor privilege; no shell is implicit.

The Windows launcher supplies the Job Object in the process-creation attribute
list and verifies membership before resuming the suspended workload. This closes
the controller-crash gap between creating a process and assigning it to its Job.
The required creation-time Job attribute is available on Windows 10 and newer
and Windows Server 2016 and newer. See Microsoft's
[creation-time Job assignment explanation](https://devblogs.microsoft.com/oldnewthing/20230209-00/?p=107812/).

## Lifecycle, replay and revocation

`Receipt.native` contains native observations when the executor has retained
them. The observations identify the backend, enforced properties, dependencies,
exit code or signal, process cleanup, output truncation and termination reason.
A missing native observation or exit value stays unknown. A retained admission
or successful transport reply does not establish native execution or cleanup.
The executor records native completion facts and concurrency release in the
same transaction. `Receipt.process`, when present, retains the process ID and
start time used by native restart reconciliation. A PID alone does not prove
that a current process is the recorded job.

The target retains admission before dispatch and returns a revisioned `Receipt`.
States are `admitted`, `running`, `completed`, `failed`, `cancelled` and
`uncertain`. An admitted job can start or terminate; a running job can terminate.
Terminal records cannot return to running. Only the executor records observed
state. `completed` reports the operation result, not proof of all containment
guarantees. A timeout needs native termination/observation; it is not itself
proof that effects stopped.

The standalone executor allocates the admitted output buffer, lifecycle receipt
and first cancellation reply inside the admission transaction. It updates those
allocations in place. Reaching `ledger.database_bytes` therefore refuses new
work before dispatch without spending an admission or disabling an existing
job's cancellation, output or recovery writes. The limit covers SQLite database
pages. The target operator must separately reserve disk for the rollback journal,
including its page checksums and headers, filesystem overhead and executable snapshots. Host
storage loss or an input/output error can still prevent persistence.

Native enforcement and lifecycle facts retain their reserved fields. Free-text
receipt diagnostics retain at most 4096 UTF-8 bytes plus an explicit
`[diagnostic truncated]` marker. This diagnostic bound does not truncate the
operation's retained output stream or impose a rationale limit.

A cancellation request sets `cancellation_requested` and advances the receipt
revision. It leaves the state active. Only confirmed termination can produce
`cancelled`; an unobservable outcome is `uncertain`. Cancellation cannot undo
earlier effects. Output is a bounded retained byte stream with offsets and a
digest of the complete retained bytes. Disclosure always rechecks current
issuer/principal/grant ownership; knowing a job ID grants no output access.
The separate job/output/cancel verbs cover retained jobs of that exact
principal and grant. Removing invocation scope alone does not remove those
permissions. Remove the corresponding verbs or revoke the grant to stop
subsequent disclosure/cancellation through that grant. The target's action
ceiling can independently refuse each of those verbs.

The target's durable admission transaction must cover the namespaced request
ID, exact request digest, job receipt and budget reservation. Exact replay
returns the retained mutation result without reserving or dispatching again.
Reusing an ID with different content conflicts. Current authentication is still
required before returning a replay result. Inspect the existing job with a fresh
read request after authority changes; do not change the original mutation and
reuse its ID. If current disclosure authority is gone, the target operator must
inspect it. The contract claims no exactly-once external effects. A crash
between admission and observable completion can leave an uncertain job.
Call usage is keyed by issuer, grant ID, `Authorized::grant_revision()` and
operation. Unrelated authority-snapshot changes do not reset that usage.
Concurrency includes still-active jobs from prior revisions of the same
issuer/grant/operation, so a grant edit does not hide running work.

After target restart, restore receipts and usage before accepting requests.
Reconcile previously active work against actual native processes/effects.
If reconciliation cannot prove the outcome, retain `uncertain` and inspect the
original operation before another attempt. Never start a second command solely
because an HTTP reply, process connection or gateway disappeared. The minimal
witness keeps an in-memory reference ledger; production durability and native
reconciliation remain executor obligations.

Every request needs authority observed no later than the target's configured
maximum age and before the issuer snapshot, grant and request expiry. The
effective validity ends at their earliest bound. While the issuer/gateway is
disconnected, new admission and subsequent reads stop when that bound is reached.
An issuer revocation takes effect when the target receives the authenticated
replacement snapshot, and in all cases by the prior freshness/expiry bound,
assuming the target's trusted clock and freshness enforcement. Thus the maximum
new-request revocation latency is the configured maximum authority age; a
shorter snapshot or grant expiry can reduce it. This is a consumer-enforced
bound, not evidence of production feed delivery from the witness.

Admission fixes the execution deadline and limits. A job may continue after
grant expiry/revocation within those admitted limits. Starting an admitted job
requires reauthentication/reassessment against current authority as well as
the receipt's validity and deadline. Native revocation can stop it sooner, but
transport loss or credential rotation does not by itself establish termination.
Delegated service use always follows that service owner's current authority.
New reads/cancellation requests still need current authorization. Operator
recovery remains available through the target's protected management path.

Rotation replaces the target's issuer-scoped key selection and trust revision.
Removed keys reject subsequent requests. A changed revision requires discovery
and reassessment; a still-enrolled old key has only its explicitly retained
authority. Rotation must not silently reissue a stopped/recreated agent's run
or grant. Target operators choose any overlap through their existing trust
configuration. No request enrols a key or changes a ceiling.

## Focused witness

From a repository checkout on Linux or macOS with the pinned Rust toolchain and
locked dependencies available, run the following focused integration test.
Use the repository Cargo reserve wrapper and the environment's existing reserve
settings. The test creates owned loopback endpoints and a temporary isolated
SafeYolo proxy. It starts no native operation or virtual machine:

```sh
scripts/cargo_with_space.sh test --locked --manifest-path proxy/Cargo.toml --test host_execution -- --nocapture
```

The same signed client discovers, proposes, invokes, recovers a simulated lost
reply, reads output and requests cancellation first on a standalone target,
then on a target alongside an actual isolated SafeYolo proxy. Shared negative
fixtures exercise identity, freshness, selectors and protocol refusals. Other
controls cover typed/default scope, package projection correspondence,
replacement refusal, issuer collisions, budgets and terminal transitions.
This proves the shared contract boundary. It does not establish native platform
containment, a durable production ledger, issuer-feed revocation delivery or
integrated gateway deployment.
