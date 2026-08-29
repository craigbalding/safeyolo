"""One-shot registration for SafeYolo's production mitmproxy addons."""

import logging
from importlib import import_module

log = logging.getLogger("safeyolo.production-addons")

# Canonical production addon load order.
ADDON_CHAIN = [
    # UDS ingress is imported by traffic_master before mitmproxy parses its
    # options. Initial modes are supplied by the custom entry point, so no
    # bootstrap addon or transient TCP listener is needed here.
    # Layer 0: Infrastructure
    "pid_writer.py",     # writes SAFEYOLO_PROXY_PID_FILE on `running`
    "file_logging.py",
    "memory_monitor.py",
    "admin_shield.py",
    # The normal handler is the sole recoverable production import. Its
    # adjacent independent guard still has to load when this import fails.
    "agent_api.py",
    "agent_api_guard.py",
    "loop_guard.py",
    "request_id.py",
    "operator_provenance.py",
    "service_discovery.py",
    "sse_streaming.py",
    "policy_engine.py",
    # Layer 0.5: Service Gateway
    "service_gateway.py",
    # Layer 1: Network Policy
    "network_guard.py",
    "circuit_breaker.py",
    # Layer 2: Security Inspection
    "credential_guard.py",
    "pattern_scanner.py",
    "test_context.py",
    # Layer 3: Observability
    "flow_recorder.py",
    "request_logger.py",
    "ignored_host_logger.py",
    "metrics.py",
    "traffic_scope.py",
    "flow_pruner.py",
    "admin_api.py",
    # Layer 4: Reserved diagnostic destinations (issue #213 PR B).
    # probe_sink is the normal terminator (early marker in requestheaders,
    # local 200 in request). transport_guard is the correlated late
    # request-hook failsafe (client-correlatable) + the structural
    # server_connect no-egress backstop (audit-only for catastrophic
    # chain failures). Agent API request containment is handled much earlier
    # by agent_api_guard, immediately after its normal handler and before any
    # policy/security/observability addon. Load order here still matters:
    # transport_guard's probe request hook must run AFTER probe_sink so a
    # normally-terminated probe bypasses its failsafe.
    "probe_sink.py",
    "transport_guard.py",
]


class ProductionAddons:
    """Import and expose the production chain once for this process.

    This container deliberately has no configure hook or filesystem watcher.
    Python's normal module cache therefore keeps the addon modules and their
    imported ``safeyolo.*`` dependencies on one consistent generation until
    the traffic process is restarted.
    """

    name = "safeyolo-production-addons"

    def __init__(self) -> None:
        self.addons = []
        for addon_file in ADDON_CHAIN:
            module_name = addon_file.removesuffix(".py")
            try:
                module = import_module(f"{__name__}.{module_name}")
                self.addons.extend(module.addons)
            except Exception as exc:
                if addon_file != "agent_api.py":
                    raise
                # The virtual host is safer and more diagnosable with the
                # independent guard alive than with the whole proxy aborted.
                # Do not interpolate exception text: import errors may embed
                # checkout paths or other operator-only values.
                log.error(
                    "Agent API handler import/registration failed (%s); "
                    "continuing with independent local containment",
                    type(exc).__name__,
                )
