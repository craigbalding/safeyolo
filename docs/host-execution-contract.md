# Host execution contract

The `safeyolo.host-execution/v1` contract connects an issuing SafeYolo instance
to a named execution target. The target can run independently or alongside
SafeYolo. The maintained types and validators are in
[`host_execution`](../proxy/src/host_execution.rs). `schemas()` derives the JSON
schemas from those types. The shared fixtures and authenticated HTTP witness
are in [`host_execution.rs`](../proxy/tests/host_execution.rs).

This increment supplies the protocol, package projections and contract witness.
It does not install a native executor, enrol an issuer, change policy, or add a
gateway route to a running instance. The platform executor, adoption, effect
authoring and gateway consumers are the separate children of
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
inputs from a client that supplied expected revisions.

## Client and target journey

For an already enrolled issuer and adopted target, the client uses these steps:

1. Discover the selected target's adopted operations and current revisions.
   An operation can be present without an invocation scope. Discovery is an
   authenticated disclosure, not permission to execute.
2. Select a literal operation/resource ID and typed arguments. Carry the
   discovered package, implementation and authority revisions into a proposal.
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
- Expected trust, authority, ceiling, assessment, package and implementation
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
disclosures. `Package::projections()` derives the target material and native
gateway service/effect material. Both carry the common package version and
digest. `verify_projections()` checks them against regeneration. The target and
gateway adoption owners must verify those projections against the approved
package; a caller-supplied digest alone is not adoption authority.

The current native effect model identifies operations by method/path. The
generator therefore emits one service projection per package operation, each
with the same stable invocation route and its own selector/argument contract.
These are ordinary native service definitions, not another route matcher.
The existing effect analyser cannot prove identity through the nested signed
body. Projections retain an unresolved resource identity and no unsupported
effect-enforcement mapping. They do not claim that route access authorizes the
payload. The target's independent checks remain mandatory.
Discovery discloses the full adopted definitions, including literal environment
values, to a grant with the discovery action. Adoption must account for that
disclosure. Host-held service credentials remain with their existing owners;
the package's delegated service references do not contain those credential values.

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

## Lifecycle, replay and revocation

The target retains admission before dispatch and returns a revisioned `Receipt`.
States are `admitted`, `running`, `completed`, `failed`, `cancelled` and
`uncertain`. An admitted job can start or terminate; a running job can terminate.
Terminal records cannot return to running. Only the executor records observed
state. `completed` reports the operation result, not proof of all containment
guarantees. A timeout needs native termination/observation; it is not itself
proof that effects stopped.

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
