---
name: safeyolo
description: Help the operator use SafeYolo and complete product tasks, including creating or launching agents, granting peer support, configuring workers, sharing guest services with agents or operators, connecting services, discovering capabilities, changing policy through its approval owner, and coordinating work. Also use for proxy/TLS failures; non-HTTP transports, UDP media, relays or gateways; policy or credential blocks; HTTP 403/428/429/503/508 or X-Blocked-By responses; surprising guest package, sudo, setpriv, apt, apk, pip, or mise behavior; debugger/profiler denials; recovery shells; guest-browser and desktop use; Agent API flows, budgets, circuit breakers and approvals; and sandbox introspection. Do not invoke merely because the repository is SafeYolo, or for ordinary healthy sandbox commands, routine factory handoffs, or GitHub App Connector work already specified by injected instructions.
---

# Help the operator use SafeYolo

Help the operator reach the requested result through SafeYolo's existing
interfaces and authority. Treat SafeYolo as the outer security boundary;
do not try to bypass or weaken it.

## Carry the task through

1. Recover the operator's goal and known host, instance, agent, workspace and
   harness choices. Preserve the selected executable and instance in every
   command or handoff. Ask only for missing choices that change the result.
2. Select the relevant workflow below. For a capability question, use
   [capability discovery](references/agent-api.md#discover-the-right-capability)
   and the relevant owner's current grants. Separate what the installed product
   supports, what this agent may do, and what is ready now. A missing host CLI,
   an empty grant list or a failed read does not establish an unsupported feature.
3. Do the permitted work within the user's request and existing authority.
   Read-only discovery within current access needs no new confirmation. Use an
   existing grant when it covers the task; do not turn routine authorized work
   into another approval request.
4. When an operator step is necessary, finish the preparation you can do and
   give the smallest concrete next step for the selected target. Include a
   verified command or the existing approval reference, what it enables, and
   what you will do afterward. Explain new access, scope and lifetime before
   the decision. Do not end at "I cannot do that from here" or make the human
   discover a supported workflow. Do not invent a command or request Admin
   credentials to fill an access gap.
5. After the operator acts, re-read effective access and target state, then
   continue and verify the requested result. Report partial completion when
   needed. Reconcile an uncertain operation by its original identity before
   retrying; a submitted request or saved setting alone does not prove success.

Keep the human response short: the outcome or blocker, the next useful action
and any material decision. Read only the relevant reference section. Do not
send raw capability catalogues, JSON, tokens or exhaustive internal options
when the operator needs a recommendation or a command.

## Keep your execution context clear

Use known context first. Inside a guest, if your own identity is unclear, read
`/safeyolo/agent-name`. Select `agent_id`, `generation` and `workspace` from
`/safeyolo/host-launch-context.json` when the durable identity, run or host
workspace matters. These are host-staged files in the read-only per-run share.
They provide context, not additional authority. Do not infer identity from a
hostname, the shared Linux username `agent`, a repository name or another
agent's message. `/health` and `/status` do not identify the caller.

Distinguish your own guest, another agent, the owning host and the operator's
computer. `127.0.0.1` belongs to the machine or network namespace using it.
Your own workspace and running processes do not require a peer-support grant.
Choose access from the intended consumer and where its browser or client runs.
Guest browsing, gateway service access, host loopback and tailnet publication
serve different uses; a task can need more than one. Check installed support
for the selected path.

## Choose the product workflow

| Operator goal | Start here |
|---|---|
| Create, launch, resume or service another agent | [Agent creation, launch and support](references/agent-launchers.md). Creation and delegated servicing use different existing owners; prepare the host step and continue through a support grant. |
| Use a guest browser or share a guest service | [Guest browsers and service access](references/web-services.md). Choose guest-browser use, service-gateway access for agents, host loopback with optional SSH, or tailnet publication from the intended use. |
| Set up a task worker, change its task or resume unfinished setup | [Worker commissioning](../safeyolo-commission/SKILL.md). Reuse intent, saved choices and completed work; prepare only the next useful increment. |
| Discover or change network, credential, support or other policy rights | [Policy authoring](../policy-authoring/SKILL.md). Discover installed forms, prepare and assess a proposal, then use the existing human approval. |
| Connect or use a service, including one hosted by another agent | [Service gateway](references/agent-api.md#service-gateway). Discover the service, request offered access or a binding, and prepare missing definitions or policy through their existing owners. |
| Perform a task on a host | [Host operations](references/host-operations.md). Discover adopted targets and task bindings; prepare missing capability through the existing setup and policy owners. |
| Add or qualify a coding harness | [Harness authoring](../harness-authoring/SKILL.md). Check installed capabilities and qualification before host activation. Ordinary launch uses the agent guide above. |
| Build an automated check or action | [Job authoring](../job-authoring/SKILL.md). Choose the execution engine and prepare the check; activation belongs to the selected instance's existing operator authority. |
| Delegate work, coordinate agents or follow up a result | [Coord work coordination](references/coord.md). Use the selected native or message contract and current membership; a shared room does not grant peer administration. |
| Share an app running in the current guest | [Operator actions](references/agent-api.md#operator-actions). Keep the current guest and HTTP port; use `web.publish` and the existing preview authority owner without starting a desktop. Verify access from the intended operator device. |

For a failed request or boundary problem, use the evidence workflow below and
its matched troubleshooting reference. Product setup does not require running
every diagnostic first.

## Keep task files durable

Keep authored code and retained task data under the assigned workspace folder,
including working scripts and their inputs and outputs. `/tmp` is ephemeral and
may be RAM-backed, so it is not a recovery location for scripts, downloads,
evidence or build artifacts.
Persistent home remains appropriate for installed tools and runtime caches. See
[what persists](references/guest-tools.md#know-what-persists) when choosing paths.

## Routine supervised factory fast path

When injected developer instructions already contain the role's Coord and
GitHub rules, follow those instructions without loading this skill merely for
confidence. If this skill was required for a real setup, failure, ambiguity,
or non-routine operation, read only the reference needed for that condition;
do not reload Coord or GitHub references already supplied by the role contract.

## Start with evidence

1. For a failed native Coord tool, read its `structuredContent` and text result.
   The failure retains available `http_status`, validated response `request_id`,
   `blocked_by`, `retry_after`, bounded `error_details` and `body_state`.
   `isError: true` still means the original operation failed or is uncertain.
   Missing correlation and incomplete bodies remain explicit.
   For an identified failure, `diagnostic_reference` names its own-request
   `/explain` read. The reference grants no access; automatic collection is
   limited to local Agent API 503s.
2. For a local Agent API 503, consume the attached `diagnostic` first. It uses
   your current identity to read `/explain` for the original request. Collection
   adds at most two seconds and two reads, with only one refresh for `pending`.
   Read `collection_state`, `evidence.status`, `evidence_limited` and `limits`.
   Diagnostic reads have their own IDs in `reads`; use `original_request_id`
   and `reference` for the failed operation. For other clients, capture the
   status, response headers and JSON body. Read `X-Blocked-By`, `type`, `action`,
   `reflection`, `reason` and `Retry-After` when present.
3. Check the Agent API before changing the request:

   ```sh
   (
     agent_token=$(cat /app/agent_token) || exit
     printf 'Authorization: Bearer %s\n' "$agent_token" |
       curl -sS --header @- http://_safeyolo.proxy.internal/health
   )
   ```

4. Continue permitted read-only investigation through the existing Agent API.
   Use `/lookup?host=...`, `/budgets` or `/circuits` when the returned evidence
   supports a policy, quota or upstream-health hypothesis. A recorded
   `agent.api_response` refusal or `blocked_by: agent-api` does not identify a
   network-policy cause. A `complete` search does not establish a root cause;
   empty, pending, incomplete, refused and unavailable evidence have limits.
5. Separate diagnosis from recovery and replay. Diagnosis never retries the
   original operation, approves recovery or advances an attention cursor.
   Before repeating an uncertain send, inspect canonical retained history.
   Preserve the last safe attention position if any object resolution fails.
   Follow an endpoint's supported approval path for missing scope; when no
   such path is available, report the exact unmet evidence need. An approval
   notification alone grants no permission. Read the canonical approval and
   effective access before deciding or retrying. Do not loop on a 428 or 429.

For an investigation that needs more retained evidence, use
`diagnostic_evidence` to discover current local disclosure. Use
`request_diagnostic_access` to request explicit subjects, sources, history and
a fixed snapshot, selected expiry, or until-revoked lifetime. Read the canonical
approval before `query_diagnostic_evidence`. Inspect completeness and source
limitations on every result. The operator can narrow or revoke access through
the existing support grant controls. Observation grants no repair or publication.
See [diagnostic disclosure](references/agent-api.md#approved-diagnostic-evidence)
for filters, pagination, retention and attribution limits.

## Select the needed reference

- Read [GitHub composite checks](references/github-checks.md) before using the
  optional intake or exact-candidate helper through a configured GitHub App
  connector. It defines explicit inputs, normalized evidence, and failure
  diagnostics without making either helper a factory policy.
- Read [Relay Dispatch generation](references/dispatch-generation.md) before
  consuming completion-note nominations for public engineering content or
  rendering a Dispatch or living topic page.
- Read [Agent API and workflows](references/agent-api.md) before querying
  policy, flows, approvals, service capabilities, contract bindings or approved
  collaboration rooms. Use its contents to select the current routes and
  request shapes; do not load the whole reference for one operation.
- Read [Troubleshooting and escalation](references/troubleshooting.md) for
  blocked responses, proxy/TLS failures, logs, request correlation, and exact
  host commands to ask the operator to run.
- Read [Non-HTTP clients](references/non-http-clients.md) for protocol-specific
  transports, UDP media, external relays, loopback adapters, and verification
  inside agent sandboxes. It includes a baresip/TURN example and an agent runbook.
- For a client-selected destination IP, read [Select a target IP](references/troubleshooting.md#select-a-target-ip).
  It covers ordinary curl syntax, the CONNECT response ID and linked evidence
  after a TLS failure. Address acquisition is separate from target selection.
- Read [Guest tools and privilege](references/guest-tools.md) before installing
  native packages, restoring retained guest prerequisites, changing configuration
  capture coverage, diagnosing `sudo`, using Linux `setpriv`, or deciding
  whether an operator root shell is actually necessary.
- Read [Desktop and operator preview](references/desktop.md) before starting a
  graphical guest program, exposing the optional desktop to the operator, or
  diagnosing Xvfb, VNC, noVNC, and browser startup.
  Guest browsers are supported for webapp security testing and other browser
  tasks. For sharing a service, use the
  [access choices](references/web-services.md#choose-the-consumer-and-access-path).
  Offer the normal typed `desktop.present` operator action when a preview
  helps the task. Use `GET /operator-actions` to discover its availability.
  Agent reasons remain untrusted; SafeYolo owns the consequences and approval.
  After a typed action is denied or unavailable, do not automatically substitute
  an equivalent privileged host command or retry with different reasons to get
  another prompt. Read the canonical result and report the unmet need. This
  does not prevent commands explicitly requested by the operator or genuine
  administration when the typed action cannot provide the required operation.
- Read [Schedule guest shell work](references/scheduling.md) for cron/at,
  current execution environment, Coord and exact tmux-pane examples, job state,
  diagnostics and image rollout.
- Read [Contributing to the SafeYolo repo](references/contributing-to-safeyolo.md)
  when editing files in the SafeYolo checkout itself: any pre-commit or CI
  drift check firing (`check_skill_markers`, `check_doc_cli_flags`,
  `check_doc_constants`, `check_doc_links`, `check_doc_forbidden`); adding
  claims to user-facing docs (`README.md`, `SECURITY.md`, `docs/*`, `guest/README.md`,
  `cli/README.md`, `contrib/*.md`); or generally "why is CI red after I only
  changed docs / do I need `pre-commit install` here". Not for unrelated
  project work — SafeYolo being the sandbox boundary does not make every
  in-sandbox task SafeYolo development.

Read only the reference needed for the current task.

## Troubleshooting and acceptance graphs

Use the graphs in [`references/graph/`](references/graph/) as decision aids
rather than re-deriving SafeYolo's plane and acceptance stories every time.
Each `.yaml` is the source of truth; the sibling `.mmd` is a mermaid render
for a human operator watching over my shoulder. Every symptom node carries a
`keywords:` list so binding an observation or claim to an entry can be
keyword-matched, not eye-matched.

**Manifest** — pick the graph whose entry-question fits, then bind a symptom
inside it:

| Graph | Entry question |
|---|---|
| [`triage-request-failing.yaml`](references/graph/triage-request-failing.yaml) | "A request through SafeYolo failed / was blocked / behaved weirdly" |
| [`triage-credential-guard.yaml`](references/graph/triage-credential-guard.yaml) | "Why is credential-guard questioning my credential?" |
| [`triage-approval-required.yaml`](references/graph/triage-approval-required.yaml) | "The proxy said `wait_for_approval` — what now?" |
| [`triage-flow-inspection.yaml`](references/graph/triage-flow-inspection.yaml) | "Why isn't `/api/flows/search` returning what I expect?" |
| [`triage-service-gateway.yaml`](references/graph/triage-service-gateway.yaml) | "How do I use a gated service (Gmail, Jira, etc.)?" |
| [`triage-tls-and-ca.yaml`](references/graph/triage-tls-and-ca.yaml) | "TLS handshake failing / cert not trusted" |
| [`triage-guest-tools-and-sudo.yaml`](references/graph/triage-guest-tools-and-sudo.yaml) | "sudo / apt / mise / package install failing" |
| [`triage-kernel-observability.yaml`](references/graph/triage-kernel-observability.yaml) | "perf / eBPF / bpftrace / ftrace / kprobe / uprobe doesn't work inside the guest" |
| [`triage-desktop-preview.yaml`](references/graph/triage-desktop-preview.yaml) | "The graphical guest desktop or its browser is not working" |
| [`accept-safeyolo.yaml`](references/graph/accept-safeyolo.yaml) | "Which trusted tool proves this SafeYolo acceptance claim?" |

Graphs cross-reference each other via a top-level `see_also:` block when a
symptom overlaps concerns — check the target graph before authoring a new
edge in the current one.

**Traversal protocol I follow when using a graph in-context:**

1. State the entry-node match out loud so the reader can see the bind.
2. At each `evidence` node, state which endpoint, probe, or operator command
   yields the value I'm reading. For executable acceptance evidence, obey its
   `tool` trust and invocation annotation.
3. Follow `implies` / `rules_out` edges by the evidence value.
4. At a `conclusion` or `operator_ask`, stop graph traversal. Carry any required
   operator step into the task handoff above; continue after it is resolved.
5. **Graph gap:** if the evidence is not covered by an outgoing edge,
   report `Graph gap`, the node id, the observed evidence and the missing
   relationship to the operator. Keep the result unproved. Continue only
   checks supported by the available evidence and existing authority.

An installed skill does not include the repository's graph renderer. In a
SafeYolo source checkout, an agent may contribute a missing node or edge to
the YAML and regenerate its `.mmd` with `scripts/render_skill_graph.py`.
Repository maintenance is optional and is not a prerequisite for diagnosis.

## Preserve the boundary

- Use `http://_safeyolo.proxy.internal`, never HTTPS, for the virtual Agent API.
- Read `/app/agent_token` at call time and keep it out of output and files.
- Treat `sgw_` gateway tokens as credentials even though they are not upstream
  secrets.
- From a guest, never request the Admin token or access port 9090, directly
  edit host policy, or bypass network controls. Use the supported proposal and
  approval paths for policy changes. An agent running on the owning host uses
  only its actual host authority; this skill grants none.
- Guest `sudo` is an intended capability, not host elevation. Keep its effects
  inside the declared writable mounts and do not confuse it with permission to
  alter host policy or SafeYolo's security boundary.
- When operator action is needed, explain why and carry the goal through the
  concrete handoff and subsequent verification.
