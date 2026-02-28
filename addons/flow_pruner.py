"""
flow_pruner.py - Prevent unbounded flow accumulation in TUI mode

mitmproxy's TUI keeps every flow object in memory for the scrollable list.
With no built-in limit, this grows until the process is OOM-killed.
See: https://github.com/mitmproxy/mitmproxy/issues/6398

This addon periodically removes old completed flows from the view,
keeping the most recent N flows. Only active in TUI mode (mitmproxy,
not mitmdump - mitmdump doesn't retain flows).

Loading order: Layer 3 (observability), after request_logger.
"""

import logging
import time

from mitmproxy import ctx

log = logging.getLogger("safeyolo.flow-pruner")

DEFAULT_MAX_FLOWS = 500
PRUNE_INTERVAL_SECONDS = 30


class FlowPruner:
    """Prune old flows from mitmproxy's view to cap memory usage."""

    name = "flow-pruner"

    def __init__(self):
        self._last_prune: float = 0.0
        self._total_pruned: int = 0

    def load(self, loader):
        loader.add_option(
            name="flow_pruner_max",
            typespec=int,
            default=DEFAULT_MAX_FLOWS,
            help=f"Maximum flows to retain in TUI view (default: {DEFAULT_MAX_FLOWS})",
        )

    def running(self):
        max_flows = ctx.options.flow_pruner_max
        log.info(f"Flow pruner active (max {max_flows} flows)")

    def response(self, flow):
        """Check flow count after each response and prune if needed."""
        now = time.time()
        if now - self._last_prune < PRUNE_INTERVAL_SECONDS:
            return

        self._last_prune = now
        self._prune()

    def _prune(self):
        """Remove oldest completed flows if over the limit."""
        try:
            view = ctx.master.view
        except AttributeError:
            # mitmdump has no view - nothing to prune
            return

        max_flows = ctx.options.flow_pruner_max
        current = len(view)
        if current <= max_flows:
            return

        # Remove oldest flows (they're at the start of the view)
        to_remove = current - max_flows
        removed = 0
        # Collect flows to remove first (can't modify during iteration)
        removable = []
        for flow in view:
            if removed >= to_remove:
                break
            # Only remove completed flows (have a response or error)
            if flow.response or flow.error:
                removable.append(flow)
                removed += 1

        for flow in removable:
            ctx.master.view.remove(flow)

        if removed > 0:
            self._total_pruned += removed
            log.debug(f"Pruned {removed} flows (total pruned: {self._total_pruned}, retained: {len(view)})")


addons = [FlowPruner()]
