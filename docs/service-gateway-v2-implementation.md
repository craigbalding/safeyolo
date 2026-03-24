# Service Gateway v2 — Implementation Plan

Companion to [Service Gateway v2 Design](service-gateway-v2-design.md) and
[Service YAML Spec](service-gateway-v2-yaml-spec.md).

## Staging

The implementation is staged. Each stage is independently shippable.

### v2.0 — Core (capabilities + risky routes + request flow)

1. **Service YAML schema** — new format with `capabilities`, `risky_routes`,
   service-level `auth`. Update `service_loader.py`:
   - `ServiceRole` → `Capability`
   - `RouteRule.effect` removed
   - New `RiskyRoute` and `RiskyRouteGroup` dataclasses
   - `ServiceDefinition` gains `risky_routes` and top-level `auth`

2. **Gateway route evaluation** — replace deny-first/allow-second with
   capability route matching + risky route detection in
   `service_gateway.py`.

3. **Agent API updates** — `GET /gateway/services` returns capabilities
   (not roles). `POST /gateway/request-access` accepts `capability` field.

4. **PDP risky route evaluation** — new `gateway.risky_route` event type.
   Policy rules for risk appetite (`tactics`, `enables`, `irreversible`).
   PDP returns `immediate_response` with reflection.

5. **Watch: service + risky route approval** — `handle_service_approval()`
   handles capability requests with reasons. New
   `handle_risky_route_approval()` for risky route prompts with group
   display, drill-in, and "type yes" for `irreversible`.

6. **Passive fallback** — gateway 428 with reflection when agent hits
   risky route without access request. Watch shows informational event
   (not approval prompt). Two-phase: reflect → request → approve.

7. **Migration** — convert v1 service YAML files. Update existing tests.

### v2.1 — Safety features

8. **Once-grant semantics** — `response()` hook in gateway. 2xx consumes,
   everything else releases. In-flight serialisation per grant.

9. **Redirect policy** — default deny in gateway. Route pair + same-host
   overrides in policy. Time-bound expiry with watch re-prompt.

### v2.2 — Credential lifecycle

10. **Capability-level credential binding** — optional per-capability
    credentials in agents.yaml. Gateway uses most specific available.

11. **Unknown service credential detection** — credential guard triggers
    428 for first-time authenticated requests to unknown services. Watch
    prompts: "Did you provide this credential?" with vault/block/allow
    options. (Design in v2 design doc, Future Work section.)

12. **Security maturity nudges** — suggest credential scoping based on
    observed usage. Posture dashboard in `safeyolo status`.

## Files Modified (v2.0)

| File | Change |
|------|--------|
| `addons/service_loader.py` | New schema: `Capability`, `RiskyRoute`, `RiskyRouteGroup`, remove `effect` |
| `addons/service_gateway.py` | Capability route matching, risky route detection → PDP, passive fallback |
| `addons/agent_api.py` | Return capabilities in `/gateway/services`, capability in request-access |
| `addons/admin_api.py` | No changes expected |
| `pdp/core.py` | Handle `gateway.risky_route` event type |
| `pdp/schemas.py` | Risk appetite policy schema |
| `cli/.../commands/watch.py` | Service approval, risky route approval, group display, passive fallback info |
| `cli/.../commands/agent.py` | Update authorize to use capabilities |
| `config/services/*.yaml` | Convert to v2 format |
| `tests/test_service_gateway.py` | Update for capabilities, add risky route tests |
| `tests/test_service_loader.py` | Update for new schema |

## Files Modified (v2.1)

| File | Change |
|------|--------|
| `addons/service_gateway.py` | `response()` hook, in-flight tracking, redirect blocking |
| `cli/.../commands/watch.py` | Redirect expiry re-prompts |
| Policy schema | Redirect overrides (route pair, same-host + expiry) |

## Files Modified (v2.2)

| File | Change |
|------|--------|
| `addons/service_gateway.py` | Capability-level credential lookup |
| `addons/credential_guard.py` | Unknown service detection heuristics |
| `cli/.../commands/watch.py` | "Did you provide this?" prompt, vault flow |
| `cli/.../agents_store.py` | Capability-level bindings in agents.yaml |

## Build Order (v2.0)

```
service_loader.py          (no deps — schema only)
     │
     ├──► service_gateway.py   (depends on loader)
     │         │
     │         └──► agent_api.py  (depends on gateway)
     │
     └──► pdp/core.py + schemas    (depends on loader for types)
               │
               └──► watch.py        (depends on PDP response shape)
```

Steps 1-4 can largely be parallelised. Step 5 (watch) depends on the PDP
response shape. Step 6 (passive fallback) depends on both gateway and
watch. Step 7 (migration) is last.
