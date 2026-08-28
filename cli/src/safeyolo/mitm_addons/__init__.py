"""One-shot registration for SafeYolo's production mitmproxy addons."""

from importlib import import_module

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
    "agent_api.py",
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
    # chain failures). Load order matters: transport_guard's request
    # hook must run AFTER probe_sink so a normally-terminated probe
    # bypasses the failsafe entirely.
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
            module = import_module(f"{__name__}.{module_name}")
            self.addons.extend(module.addons)
