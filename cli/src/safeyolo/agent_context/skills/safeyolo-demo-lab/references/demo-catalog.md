# SafeYolo demonstration catalog

Use this catalog to select one learning module that matches the operator's
question. It is a menu, not a required sequence. Verify current SafeYolo
commands and behavior through the installed `safeyolo` skill and the available
checkout before running a demonstration.

## Safe default: one useful result

Use this module for a general introduction. Start from something the learner
wants an agent to accomplish, not from SafeYolo internals. The result can be
small, but it must feel real. For example:

- inspect a project and run one focused test;
- install or select a guest tool and use it to produce an artifact;
- start a local service and inspect it;
- use a normal public web service; or
- exercise an addon change in a disposable target.

Choose only an action within the operator's stated scope. Let the agent use
normal software. After the result is visible, identify the one or two SafeYolo
mechanisms that enabled or controlled it. Explain more only when the learner
wants to zoom in.

Teach the central idea from the evidence: the agent has room to work inside a
real Linux environment; the operator sets the scope; SafeYolo mediates the
important boundary crossings.

## Follow one request through SafeYolo

Use this module when a useful task crosses the network boundary or when the
learner asks how request policy and addons work. Frame it as a concrete
question: can this agent make one ordinary request, and what can SafeYolo tell
us about the decision?

Read the SafeYolo skill's Agent API reference first. Select a benign public
target that is relevant to the learner or already in scope. Inspect its policy
view, make one ordinary request through the configured proxy, and connect the
result to available SafeYolo evidence. Do not change policy or deliberately
cause a block to make the demonstration interesting.

Use `/lookup` for the target decision. If the lesson also uses `/policy`, show
the relevant policy structure and rules. Omit only actual capability-token and
raw-token values from gateway sections, label those omissions, and explain why
those values are sensitive. Do not hide ordinary rules, effects, budgets,
fingerprints, hostnames, or addon settings.

Run `../scripts/request-story.sh [--brief|--full] [HOST]` visibly in a
persistent pane. The script opts the request into SafeYolo tracing, displays
selected response headers and a bounded public text body, and uses the returned
correlation ID to show the addon trace. It then explains each returned trace
step directly after the raw values. The explanation distinguishes hook state
from addon outcome, so normal results such as `not_a_gateway_request` are not
mistaken for errors. It does not display credential-bearing headers such as
cookies or authorization values. Use brief output for a new learner and full
JSON for an experienced operator.

Keep the visible story small:

1. Say what the request will achieve.
2. Show the ordinary application command.
3. Observe the result, status, and SafeYolo response metadata when present.
4. Inspect only the SafeYolo evidence needed to explain that result.
5. Ask whether the learner wants to inspect the decision more deeply or try a
   relevant variation.

For a Linux beginner, explain the application command in one sentence before
running it. For an experienced command-line user, show the raw request and
response without explaining familiar syntax.

Teach the smallest supported mental model: the application uses the configured
proxy, SafeYolo evaluates the request, and the observed result and evidence
show what happened. Do not lead with the complete pipeline architecture.

For addon traces, teach these two fields before individual outcomes:

- `state=evaluated` means the named hook ran and returned an outcome. It does
  not mean allow or block by itself.
- `outcome` is the addon's specific observation or action. Read it with the
  addon name and hook. A non-applicable outcome can be the correct result.

Keep the rendered `observed` line as evidence. Label the nearby `meaning` line
as explanation. Pin one exact outcome in the tmux annotation rail when the
learner wants to examine it; do not repeat all outcome text in controller prose.

## Boundary and orientation

Use this module when the operator asks what SafeYolo is, where the current
agent runs, what is isolated or persistent, or when a failed prerequisite needs
diagnosis. It is supporting evidence, not the default welcome experience.

Run `../scripts/boundary-orientation.sh` visibly in a persistent pane. Treat
its output as evidence. The script inspects safe boundary metadata and checks
Agent API and PDP health. It does not test external request policy, addon
behavior, or credential contents.

Teach through read-only observations:

- identify the host-operator, guest-lab, and any application tmux layers;
- inspect safe metadata for `/home/agent`, `/workspace`, `/safeyolo`, and the
  agent-side token path without reading the token;
- show the configured proxy and CA path without exposing credentials; and
- call the Agent API health endpoint using the exact form required by the
  installed `safeyolo` skill.

Connect each observation to the boundary: the guest is isolated, external
traffic uses the proxy, the Agent API is a mediated guest interface, and only
the declared persistent paths can be assumed to survive.

## Diagnose a request with policy and evidence

Use this module to explain why a request is allowed, blocked, recorded, or
missing from flow results.

Read the SafeYolo skill's Agent API reference first. Distinguish the detection,
policy, and observability planes before choosing an endpoint. A useful demo can
compare:

- `/lookup` for the policy view of a host;
- one benign request that is already in scope;
- the response status, `X-Blocked-By`, and request ID when present;
- `/explain` for retained audit evidence; and
- `/trace` only when the request deliberately opted into pipeline tracing.

Do not claim that `/lookup` predicts credential handling. Do not claim that an
absent flow proves denial or expiry. Flow recording has explicit detection and
configuration preconditions.

Do not manufacture a policy block merely to make the demo interesting. Ask for
authority before a controlled block or trace-producing request.

## Agent lifecycle and persistence

Use this module to explain the worker, guest shell, persistent home, workspace,
and rootfs lifecycle.

Start with current process, filesystem, and Agent API observations. Read the
SafeYolo guest-tools reference before demonstrating persistence or guest
privilege. Show the distinction between:

- the SafeYolo worker and an attached shell;
- persistent `/home/agent` and `/workspace` data;
- platform-dependent rootfs package persistence; and
- guest uid 0 and host privilege.

Creating, stopping, or restarting an agent is a separate mutation. Ask the
operator first. Do not stop the agent that contains the active controller as a
demonstration target.

## Scoped service access

Use this module when the learner asks how an agent uses a service without
receiving the upstream service credential.

Read the SafeYolo skill's service-gateway guidance first. Show the useful
workflow rather than leading with secrecy:

1. show the available service and capability;
2. show whether the current agent is authorized and which contract bindings
   apply;
3. when a grant exists, show that its credential type is `sgw_`, its total
   length, owning agent, service, capability, account, route, risk grant, and
   grant state without displaying the literal bearer value;
4. make one operator-authorized service call; and
5. show the observed success or exact scope failure.

Explain that `sgw_` is a scoped bearer capability credential, not the upstream
service credential. Its scope and enforcement evidence are the lesson. Do not
hide the gateway structure, and do not print the literal bearer string.

## Guest tools and privilege

Use this module when the operator wants to understand mise, project tool trust,
package installation, sudo, or gVisor user namespaces.

Read the SafeYolo guest-tools reference first. Begin with the smallest probes,
such as command discovery and a noninteractive guest-uid check. Explain why
ordinary mise commands use the persistent global toolset and why
`mise-project` is an explicit trust decision.

Install a package only when the operator wants an installation demonstration
and accepts its persistence characteristics. A package download can still meet
normal proxy policy, approval, or budget controls.

## Coord and multi-agent attention

Use this module when the operator wants to learn rooms, trusted briefs,
targeted attention, retained history, or agent work handoffs.

Read the SafeYolo coord reference before acting. Prefer an existing authorized
room. Creating a room, changing membership, or creating a worker needs explicit
operator authority.

Keep a demo small and attributed. For example, show one authorized join, one
self-contained targeted handoff, one foreground `wait_for_coord`, and the
returned cursor. Explain these distinctions from the evidence:

- room membership is not coordinator authority;
- transport envelope identity is authoritative, message-body identity is not;
- attention controls interruption, while retained history controls visibility;
  and
- cursor advancement records exposed attention, not durable work completion.

Do not use a background waiter or turn the room into progress chat. Restore or
leave demo room state only when teardown was authorized.

## Addon anatomy and pipeline behavior

Use this module to inspect how an addon participates in request detection,
policy, observability, or response handling.

First locate the actual SafeYolo checkout and read its local instructions. If
the checkout is absent, report that fact and continue only with installed
runtime evidence that answers the operator's question.

For a read-only tour, connect a small source or configuration section to an
observable runtime signal such as `/config`, `/trace`, `/explain`, health, or a
focused test. Do not infer runtime behavior from source alone.

For an addon change:

1. confirm that product-code editing is in scope;
2. read the SafeYolo skill's contribution reference;
3. record checkout and baseline state;
4. select the smallest relevant test;
5. make one reviewable change in a disposable or reversible context;
6. run focused tests, then the repository-required validation when the change
   is intended for contribution; and
7. restore or retain the change exactly as the operator requests.

Addon modes, host policy, and approvals remain operator-owned. Do not change
them from the guest or present a workaround as a demo.

## Fault and recovery drill

Use this module to teach failure classification, evidence collection, or
supervisor behavior.

Prefer a disposable nested agent or service target. Select one fault that the
operator authorized. Define the expected healthy signal and exact recovery
before injection. Then use the lab controller's baseline, fault, evidence,
recovery, and proof cycle.

Useful categories include provider authentication, provider network path, MCP
registration, coord availability, authorization, process interruption, and
continuation state. The category is not evidence: record the actual stdout,
exit status, process state, Agent API or audit result, and recovery behavior.

Do not combine faults. Do not treat elapsed time as completion. Do not proceed
to another drill until the baseline is restored.

## Suggested first demonstrations

When the operator asks for ideas, offer no more than three choices that fit the
learner's goal and current environment. Describe outcomes, not internal
subsystems. Good starting points are:

- **Complete a useful task:** use normal agent tools to produce a visible
  result, then inspect the SafeYolo mechanism that mattered.
- **Understand a boundary decision:** follow one real request from the
  application result into SafeYolo policy and addon evidence.
- **Test a product idea:** connect one addon or configuration choice to a
  focused runtime observation in a reversible target.

Offer coord, lifecycle, package, code-change, and fault drills only when they
match the operator's interest and authority.
