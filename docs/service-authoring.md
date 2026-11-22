# Author service effect models

Use this workflow on an operator host or in a repository checkout to prepare
service definitions before access is requested. The input is a maintained local
OpenAPI specification with reviewed semantic annotations. Generation uses no
network or model request. It produces a proposal; the operator controls adoption.
The requesting agent cannot change adopted operator service definitions.

The [controlled job fixture](../proxy/tests/fixtures/service-authoring/job.openapi.json)
and its [semantic documentation](../proxy/tests/fixtures/service-authoring/job-semantics.md)
provide a complete example. They define an illustrative API, not verified
Rundeck behavior. No upstream service or credential is needed for this example.

## Generate and validate

In a checkout with the supported Rust toolchain and locked dependencies, build
the native CLI. These commands run from the repository root. They write one
generated definition to `/tmp` and do not activate it or grant service access.
Use a disk-backed output path for large specifications.

```sh
cargo build --manifest-path proxy/Cargo.toml --locked --release --bin safeyolo
proxy/target/release/safeyolo services generate proxy/tests/fixtures/service-authoring/job.openapi.json > /tmp/job-proposal.yaml
proxy/target/release/safeyolo services check /tmp/job-proposal.yaml
cargo test --manifest-path proxy/Cargo.toml --locked --release --test service_authoring --test service_effects
```

Generation prints JavaScript Object Notation (JSON), which is also valid YAML.
`services check` uses the current `ServiceDefinition` loader and prints the
service name when validation succeeds. The tests compare generated output with
the maintained [definition](../proxy/tests/fixtures/service-authoring/job.generated.yaml),
load it through the current catalogue, and exercise native request enforcement.
When you intentionally change the fixture, regenerate that file with
`services generate` and rerun the tests.

Installed native CLIs provide the same `services generate OPENAPI_FILE` and
`services check DEFINITION_FILE` commands without a running proxy. A failed
generation returns an error and no definition. Checking a file does not fetch its
sources, test an upstream API or establish exhaustive semantic correctness.

## Author host-operation packages

The same commands accept a maintained `safeyolo.host-execution/v1` package.
The [Windows starter](../host-executor/examples/windows-starter.json) contains
the common operation definitions, fixed command recipes and reviewed semantics.
It includes separate service enumeration, status, start, stop and restart;
bounded Event Log queries; machine and workload-user registry queries;
process, system, software, update and file inspection; network diagnostics;
scheduled-task inspection; and a fixed executable with typed arguments.
Explicit broader write, transmission and reviewer-control examples exercise
the composition rules. They are separate operations, with no implicit authority
from the query operations.

From the repository root, use a built native CLI and a disk-backed output
directory. The following commands validate and generate the example. They do
not contact a target, adopt a catalogue, change policy or execute a command:

```sh
mkdir -p data/authoring
proxy/target/release/safeyolo services check host-executor/examples/windows-starter.json
proxy/target/release/safeyolo services generate host-executor/examples/windows-starter.json > data/authoring/windows-projections.json
proxy/target/release/safeyolo services check host-executor/examples/windows-starter.json data/authoring/windows-projections.json
```

The generated object contains the exact target definitions, gateway definitions
and a shared `assessment` service definition. Logical `/operations/ID` paths in
the assessment inventory identify modeled operations; they are not additional
HTTP endpoints. Each gateway projection uses the existing signed invocation
route. The current `ServiceDefinition` loader checks the generated effect
references and rules. The native package owner checks argument, evidence,
identity and alternative references. Correspondence checking regenerates the
entire output from the common source.

Before target adoption, replace the example executable hashes and workload
identity with the selected target's actual inputs. Use the executor's
`identity --credential NAME` command to obtain its Windows workload SID and
groups. Bind the selected PowerShell and `whoami.exe` content hashes, local
paths, service names and operating-system access. Review the inbox modules,
service executable/configuration and other ambient dependencies. The example
hashes identify no installed executable. Source validation cannot establish
these target facts.

The Windows commands require Windows PowerShell 5.1 and the named inbox
modules. Fixed PowerShell command text is part of the execution recipe.
Typed argument values enter through environment variables and are consumed
as data. The commands accept no caller-supplied program or script text.
Broader explicitly authorized operations can use different recipes.
The Windows executor requires the disclosed broader filesystem, registry,
network/interprocess communication (IPC) and delegated-service permissions of
the workload account. Job Objects do not confine those effects. A query recipe
does not turn those broader account permissions into a confinement guarantee.

### Host identities and prepared assessment

`Package.semantics` holds sources, resource identity keys, composition rules,
narrower alternatives and coverage gaps. Each operation's `semantics` maps
resource keys to the target ID, resource selector, actual execution principal,
typed argument, fixed value or explicit unresolved identity. An optional alias
map names reviewed canonical values. The model does not discover filesystem
links, registry links, service dependencies or arbitrary selector equivalence.
An unreviewed value in an alias map remains unresolved; alias chains are refused.

The registry examples retain the selected view. The machine `SOFTWARE` key
has distinct 32/64-bit views. The example workload-user key is shared across
those views. `HKCU` identifies the actual workload account, using its execution
SID; it does not identify the operator or requesting agent. Different registry
keys can have different view and alias behavior. Review those identities when
adapting the example, using Microsoft's
[registry view rules](https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys).

On an authorized operator host with a current executor configuration, inspect a
selected issuer/grant through the existing native CLI. In the following
example, `target.json` is that executor configuration, `issuer` is its enrolled
issuer ID and `grant` is its retained grant ID. `proposed.json`, when supplied,
contains one complete proposed native grant. `known-effects.json`, when
supplied, contains trusted retained-effect observations with recorded scopes,
observation times and evidence. The command reads those files and prints JSON;
it grants, adopts and executes nothing:

```sh
safeyolo services assess-host target.json issuer grant
safeyolo services assess-host target.json issuer grant --proposed-grant proposed.json --known-effects known-effects.json
```

The result identifies the target, issuer, run/task principal, current grant
lifetimes and authority revisions. It separates the full proposed scope from
the intersection with the current target ceiling. Assessment covers every
permitted argument value, including authorized defaults; an example invocation
cannot narrow the grant. Missing or stale authority is reported as unavailable.
Exact-operation authority grants no future catalogue membership. To assess an
adopted future-operation class, the adoption owner must supply its complete
ceiling and retain uncharacterised future behavior as uncertainty.

The native projection uses the existing service effect evaluator. It composes
write plus execution/restart on the same target/resource, data access plus
transmission, and control plus reliance on the same reviewer. Retained effects
can still contribute after access expiry. An observation is not a current
state probe; absent observations do not prove that earlier changes were undone.
Alternative recipes show complete arguments, resource choices, current access,
proposed access, prerequisites, limitations and source references. An alternative
within a proposal is not reported as currently available authority.

Route-only challenge, private policy assessment and operator review reuse the
same adopted effects and prepared alternatives. They explicitly retain unknown
native target/argument authority until a caller has verified that authority.
The prepared native assessment API is
[`host_execution::semantics`](../proxy/src/host_execution/semantics.rs).
Complete agent/task gateway integration remains a separate consumer; loading
the model does not supply it.

Discovery reports separate implementation, authority, understanding and
description revisions. The existing exact operation pin still binds the complete
definition for admission. A description-only edit does not imply a changed
execution recipe. A changed executable hash or recipe changes implementation
identity even when prose is unchanged. Corrected effects, rules or evidence
change adopted understanding and invalidate affected prepared inputs without
requiring executable bytes to change. Existing authored allow/deny/approval
policy continues to decide acceptable risk. The model makes no completeness
claim and grants no access.

## Review the source before adding annotations

1. Record the API version, specification, authoritative documentation and any
   supplied test evidence. Preserve each source's location and revision in
   `effect_model.sources`. Label unverified upstream assumptions in gaps or
   prerequisites. Test only an API and account authorized for that purpose.
2. Inventory every supplied operation with a stable `operationId`, method and
   path. Record affected resources and the identity fields that distinguish
   them. Treat an unresolved account, alias or execution identity explicitly as
   unresolved. Do not infer undocumented behavior coverage from the inventory.
3. For each modeled operation, review possible effects, execution authority and
   persistence after access expiry. Record inputs, omissions and defaults that
   change effects. Separate executable changes from descriptive changes, even
   when they share an endpoint. Do not assert that an operation occurred.
4. Map available enforcement to current capability contracts. Route-wide grants
   remain unrestricted by example arguments. Path bindings can narrow an identity;
   query and body equality checks apply only when their fields are supplied.
   Review omissions before claiming that a constraint excludes an effect.
5. Compose reusable named effects through a declared resource relationship.
   Record prerequisites, consequence, explanation and evidence. Keep severity
   and allow/deny/approval policy out of the effect model. Absence of a rule does
   not establish safety.
6. Describe diagnostic alternatives with operation references, required arguments
   and access, modeled prerequisites, expected effects, unverified upstream
   prerequisites and explicit limitations. Limit comparisons to represented
   evidence. An alternative can disclose information or leave persistent effects.
7. Generate and check the definition. Review the generated diff and expected
   regressions independently before operator adoption. For adoption and activation,
   follow the [existing service-definition workflow](service-gateway-v2-yaml-spec.md#minimum-viable-service-file).

## Input and model fields

The generator accepts flat OpenAPI 3.0 and 3.1 documents in YAML or JSON. It reads
path/query parameters and flat `application/json` object bodies. Resolve Swagger
or referenced/composed schemas into a reviewed flat input first. The generator
rejects `$ref`, `allOf`, `oneOf` and `anyOf`; it does not fetch or infer their
meaning. Unsupported parameter locations and body formats return errors.
Webhook and callback operations need a separate reviewed paths inventory.
The generator also rejects an optional body with required properties because
the current argument model does not represent that body-presence condition.

`x-safeyolo-service` contains the ordinary service fields and `effect_model`.
Each operation's optional `x-safeyolo` supplies its semantic annotation.
The generator obtains method, path and argument locations from OpenAPI. It
derives required flags and defaults from the specification. An annotation can
describe an otherwise unspecified omission, but cannot override a declared
default or requirement. An operation without an annotation becomes
`uncharacterised` with an explicit gap. Generated contract operations refer to
OpenAPI `operationId` by `name`; their method and path come from that operation.

The [native model types](../proxy/src/services/effects.rs) define the exact
accepted fields. Unknown model fields and expression variants fail loading.

| Field | Meaning |
|---|---|
| `sources` | Named evidence locations and versions. References identify evidence; the loader does not verify source contents. |
| `resources` | Resource descriptions and complete identity keys, such as project and job. |
| `effects` | Named possible effects, descriptions, evidence and `persists_after_access`. |
| `operations` | Generated inventory with coverage, method/path, arguments, resource identity mappings, conditional effects, execution authority, evidence and gaps. |
| `operations[].arguments` | Location, field, upstream required flag, evidence and omission: `invalid`, `unchanged`, `default` with value, or `unresolved` with reason. Operation and argument tables are mappings keyed by stable reference. |
| `operations[].resources` | Each identity component comes from an argument, a documented fixed value, a known unrestricted set or an unresolved source with reason. |
| `operations[].effects[].when` | `always`, `present` with argument, or `equals` with argument/value. Equality uses the declared omission default when the argument is absent; an unresolved omission stays unresolved. |
| `enforcement` | Named references to a capability and one supported contract operation. The loader checks the method/path and supported request checks. |
| `rules` | `all_effects_same_scope` with one resource and distinct named effects; prerequisites, consequence, explanation, evidence and gaps. |
| `alternatives` | Ordered steps with operation, enforcement reference, arguments and expected effects; recipe prerequisites, unverified prerequisites, limitations and evidence. |
| `regressions` | Ordered grant additions, approved bindings and observed arguments; expected possible/observed/excluded effects, identity scopes, rule overlap and evidence. |
| `gaps` | Explicit coverage limits, unresolved behavior and assumptions. |

## What validation establishes

The loader resolves operation, effect, resource, rule, recipe and evidence
references. It checks each complete resource identity mapping and each expected
scope against the current approved path bindings. Expected scopes distinguish
known values, known unrestricted scope and unresolved identity. Observed
arguments do not narrow a modeled grant. Optional query/body bindings alone do
not establish identity presence.

A semantic enforcement reference rejects unsupported request fields, state or
response requirements, body ranges, type-only checks and unresolved binding
references. These declarations cannot silently claim enforcement in this model.
The reference also checks operation selection across overlapping path templates.
If another grantable operation can replace the named operation in the executor,
the mapping is unsupported and validation fails. This check includes operations
absent from the approved selection list and paths from future bindings. Disjoint
operations, lower-priority matches and later ties remain supported. The validator
checks full path templates. It does not prove that binding-value domains or
equivalent checks make an overlap harmless.
Existing contract declarations without an effect model retain their documented
[request-check limits](service-gateway-v2-yaml-spec.md#request-checks-and-limits).

The fixture includes both permission-addition orders, shared and disjoint jobs,
description-only and executable edits, omitted defaults and unresolved identity.
Its regression effects and rule outcomes are authored expectations. Loading
checks structure, references and scope claims. The `service_effects` tests execute
every shared regression through the runtime evaluator and compare possible,
observed and excluded effects, scopes and rule outcomes. Native authoring tests
separately demonstrate the enforcement facts stated in the fixture documentation.

## Runtime assessment

For a temporary route request, SafeYolo projects the agent's current baseline
and temporary gateway permissions, bindings and explicit denials into the adopted
model. The candidate adds its exact method and literal path. The assessment covers
all permitted arguments. Submitted payloads and agent explanations cannot narrow
that authority. For example, a description-only sample does not exclude executable
editing when `steps` remains allowed. An enforced description-only allowlist can
exclude that effect. A preview equality binding still permits an omitted query
argument, including its declared execution default.

The evaluator reports direct effects, persistent effects, scoped combinations,
contributing permission identifiers, rule identifiers, evidence, prerequisites and
gaps. Each conditional effect retains its resource and evaluated status; an effect
on one resource cannot satisfy a rule about another. Rule results are `match`,
`non_match` or `unresolved`. A known unrestricted
job scope includes a concrete job. Unresolved alias identity stays unknown.
Composite identities retain their namespace: equal job identifiers in different
projects do not establish a same-job combination. Path policy partitions can also
report `except` with excluded literal values. Complex path patterns outside the
supported literal, whole-segment and tail-wildcard partition remain unresolved.
For a known candidate resource, the ordinary policy decision on that exact
resource can still establish overlap. Whole-segment stars retain the native
policy's ability to span slashes; unknown remainder regions remain explicit.
This limit affects assessment certainty; it does not change request admission.

Reviewed alternative recipes use the same evaluator. Their required operations,
methods, paths, bindings and access availability remain separate from suitability
for the operator's goal. Upstream existence, credentials, runner state and other
unverified prerequisites remain explicit. A recipe that uses another endpoint
still receives the policy decision for its modeled effects.
An unspecified recipe binding is reported as an unverified binding condition.
An uninstantiated constraint cannot exclude effects from the proposed access.

The current route's possible effects and the matching rule combinations it
contributes to enter the existing risk policy's `enables` conditions. Unrelated
permissions remain visible in the assessment without changing that route's risk
decision. Access denied by current risk policy is excluded from baseline authority;
the candidate remains visible so its own prohibited effects can be explained.
The model supplies semantics; operator policy
supplies allow, approval or denial decisions. An unresolved combination is not
asserted as a matching rule. Missing coverage, absent rules and uncertainty do not
create automatic denial. The intentionally partial model does not certify current
upstream state. Expired edit permission does not prove that an earlier edit was
undone, and expiry does not cancel an admitted operation.

The [route-approval workflow](service-route-approval.md) presents this assessment
before operator work, rechecks it at escalation and approval, and requires an
explicit retry after a current approval. No runtime model call, arbitrary-script
interpretation or upstream behavior probe contributes to the assessment.

Definitions grant no access. Generated annotations remain proposals until the
operator adopts them through the existing catalogue workflow. Loading a model with
uncharacterised operations or unresolved behavior introduces no automatic denial
or new operator policy.
