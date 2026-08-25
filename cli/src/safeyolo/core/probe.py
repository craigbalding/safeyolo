"""Shared constants for the reserved doctor pipeline-probe path (issue #213).

The probe destination is referenced by several structurally-independent
components:

- `PDPCore._evaluate_inner` — grants an intrinsic ALLOW below user policy,
  so `network_guard` still evaluates normally but always sees the probe
  as allowed. User `deny "*"` and budget state must not defeat doctor.
  (Circuit-breaker is deliberately outside the PDP path and executes
  normally as its own trace-participating addon.)
- `probe_sink` addon — early-marks the flow, then synthesises a local 200
  after every security addon has evaluated.
- A transport-boundary guard — refuses any upstream connect for this host
  so a missing/broken sink cannot leak the probe onto the network.
- `flow_recorder` — suppresses probe flows from the FlowStore.
- `doctor` — sends the probe and reads `/trace` for the resulting request.

Kept in `safeyolo.core` (rather than in `pdp/` or `mitm_addons/`) so both
sides of the pdp/addons split can import without circular dependencies.
"""

from __future__ import annotations

# Reserved internal destination. Must never resolve or reach the network.
# Chosen under `.internal` to be RFC 6761-adjacent and to match the sibling
# `_safeyolo.proxy.internal` virtual host used by the Agent API.
PROBE_HOST: str = "_safeyolo.probe.internal"

# Reason code returned by the intrinsic PDP allow. The stable string is
# the DAG's evidence that the probe traversed policy_engine via the
# reserved path rather than via user configuration.
PROBE_ALLOW_REASON_CODE: str = "INTERNAL_PIPELINE_PROBE"

# Trace error-reason values for the reserved probe path. Aliases to the
# canonical constants in `safeyolo.core.trace` so both `probe.PROBE_*_REASON`
# (probe-domain) and `trace.REASON_PROBE_*` (trace-vocab) name the same
# strings. Split by capture stage (issue #213 seventh-pass review):
#   - PROBE_SINK_FAILED_REASON: the request-hook failsafe caught a missing
#     sink BEFORE transport was attempted (client got a correlated 5xx).
#   - PROBE_REACHED_UPSTREAM_REASON: the server_connect backstop fired —
#     transport was actually attempted (audit-only diagnostic).
# Distinguishing lets operator triage answer "did doctor's request even
# leave the proxy" without ambiguity.
# Self-aliased imports (`x as x`) so ruff recognises them as intentional
# re-exports rather than unused imports.
from safeyolo.core.trace import REASON_PROBE_REACHED_UPSTREAM as PROBE_REACHED_UPSTREAM_REASON  # noqa: E402
from safeyolo.core.trace import REASON_PROBE_SINK_FAILED as PROBE_SINK_FAILED_REASON  # noqa: E402

__all__ = [
    "PROBE_ALLOW_REASON_CODE",
    "PROBE_HOST",
    "PROBE_PATH",
    "PROBE_REACHED_UPSTREAM_REASON",
    "PROBE_SINK_FAILED_REASON",
    "is_probe_host",
]

# Fixed path used by doctor when sending the probe. Not load-bearing for
# routing (the host alone triggers everything) — kept constant so trace
# entries and audit events include a recognisable marker.
PROBE_PATH: str = "/__pipeline_probe"


def is_probe_host(host: str | None) -> bool:
    """True iff `host` is the reserved pipeline-probe destination.

    Case-insensitive by convention (DNS names). Callers use this instead
    of hardcoding the string so any future rename lands in one place.
    """
    if not host:
        return False
    return host.lower() == PROBE_HOST
