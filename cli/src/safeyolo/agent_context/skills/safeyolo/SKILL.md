---
name: safeyolo
description: Operate and troubleshoot from inside a SafeYolo sandbox. Use for SafeYolo proxy or TLS failures, policy and credential blocks, HTTP 403/428/429/503/508 responses, guest package installation and sudo/setpriv behavior, optional desktop and operator preview access, X-Blocked-By responses, Agent API queries, flow inspection, budgets, circuit breakers, service-gateway access, approvals through safeyolo watch, and approved agent-to-agent plumb collaboration.
---

# Operate inside SafeYolo

Treat SafeYolo as the outer security boundary. Diagnose through its agent-side
interfaces; do not try to bypass or weaken it.

## Start with evidence

1. Capture the failing request's status, response headers, and JSON body.
2. Read `X-Blocked-By`, `type`, `action`, `reflection`, `reason`, and
   `Retry-After` when present.
3. Check the Agent API before changing the request:

   ```sh
   curl -sS http://_safeyolo.proxy.internal/health \
     -H "Authorization: Bearer $(cat /app/agent_token)"
   ```

4. Use `/lookup?host=...`, `/budgets`, or `/circuits` to test the relevant
   policy, quota, or upstream-health hypothesis.
5. Retry only after self-correcting the request, waiting for backoff, or
   receiving operator approval. Do not loop on a 428 or 429.

## Select the needed reference

- Read [Agent API and workflows](references/agent-api.md) before querying
  policy, flows, service capabilities, contract bindings, or `plumb`
  conversations. It contains the current routes and request shapes.
- Read [Troubleshooting and escalation](references/troubleshooting.md) for
  blocked responses, proxy/TLS failures, logs, request correlation, and exact
  host commands to ask the operator to run.
- Read [Guest tools and privilege](references/guest-tools.md) before installing
  native packages, diagnosing `sudo`, using Linux `setpriv`, or deciding
  whether an operator root shell is actually necessary.
- Read [Desktop and operator preview](references/desktop.md) before starting a
  graphical guest program, exposing the optional desktop to the operator, or
  diagnosing Xvfb, VNC, noVNC, and browser startup.

Read only the reference needed for the current task.

## Triage graphs

For fast-turn triage, use the graphs in [`references/graph/`](references/graph/)
as decision aids rather than re-deriving SafeYolo's plane story every time.
Each `.yaml` is the source of truth; the sibling `.mmd` is a mermaid render
for a human operator watching over my shoulder. Every symptom node carries
a `keywords:` list so binding an observed symptom to an entry can be
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
| [`triage-desktop-preview.yaml`](references/graph/triage-desktop-preview.yaml) | "The operator can't see what I'm showing / desktop isn't working" |

Graphs cross-reference each other via a top-level `see_also:` block when a
symptom overlaps concerns — check the target graph before authoring a new
edge in the current one.

**Traversal protocol I follow when using a graph in-context:**

1. State the entry-node match out loud so the reader can see the bind.
2. At each `evidence` node, state which endpoint or operator command
   yields the value I'm reading.
3. Follow `implies` / `rules_out` edges by the evidence value.
4. Land on a `conclusion` or `operator_ask` and stop.
5. **Graph gap:** if the evidence I have is not covered by an outgoing
   edge, say `Graph gap` explicitly, name the node id, edit the YAML
   with a new node/edge, run `scripts/render_skill_graph.py`, and only
   then continue. Do not guess and continue with an unwritten edge.

The graphs are mine to maintain. When I add a new symptom or find a
missing edge during real triage, I update the YAML in the same turn.

## Preserve the boundary

- Use `http://_safeyolo.proxy.internal`, never HTTPS, for the virtual Agent API.
- Read `/app/agent_token` at call time and keep it out of output and files.
- Treat `sgw_` gateway tokens as credentials even though they are not upstream
  secrets.
- Never request the admin token or port 9090, change addon modes, edit host
  policy, or suggest direct network bypasses.
- Guest `sudo` is an intended capability, not host elevation. Keep its effects
  inside the declared writable mounts and do not confuse it with permission to
  alter host policy or SafeYolo's security boundary.
- Ask for narrow operator action and explain why it is needed.
