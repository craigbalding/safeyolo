---
name: safeyolo
description: Operate and troubleshoot from inside a SafeYolo sandbox. Use for SafeYolo proxy or TLS failures, policy and credential blocks, HTTP 403/428/429/503/508 responses, guest package installation and sudo/setpriv behavior, X-Blocked-By responses, Agent API queries, flow inspection, budgets, circuit breakers, service-gateway access, approvals through safeyolo watch, and approved agent-to-agent plumb collaboration.
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

Read only the reference needed for the current task.

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
