"""policy_engine — mitmproxy addon that configures the global PolicyClient.

The addon is tiny; the real PolicyEngine + pydantic-model implementation
lives in `safeyolo.policy.engine`. This module only owns the mitmproxy
hook surface: option registration, `configure()` reconfiguration on
option change, and shutdown cleanup.
"""
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger("safeyolo.policy-engine")


class PolicyClientConfigurator:
    """
    Mitmproxy addon that configures the global PolicyClient.

    Must be loaded first in the addon chain. Other addons use get_policy_client()
    to get the configured client.
    """

    name = "policy-engine"  # Keep name for backwards compat with existing configs

    def __init__(self):
        self._configured_baseline: str | None = None
        self._configured_budget: str | None = None
        self._configured_services_dir: str | None = None

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="policy_file",
            typespec=Optional[str],
            default=None,
            help="Path to baseline policy YAML file",
        )
        loader.add_option(
            name="policy_budget_state",
            typespec=Optional[str],
            default=None,
            help="Path to budget state JSON file",
        )

    def configure(self, updates):
        """Configure PolicyClient when options change.

        Reconfigures on policy_file, policy_budget_state, or gateway_services_dir
        changes. The gateway_services_dir option is registered by ServiceGateway
        (loaded after us), so it may not be available on the first configure() call.
        When it becomes available, we reconfigure to pick up the services dir.
        """
        from mitmproxy import ctx

        from pdp import PolicyClientConfig, configure_policy_client

        baseline_path = ctx.options.policy_file
        budget_path = ctx.options.policy_budget_state

        # Derive services_dir: prefer gateway_services_dir option, fall back to
        # sibling "services" directory next to policy file
        services_dir = None
        try:
            gw_svc_dir = ctx.options.gateway_services_dir
            if gw_svc_dir and Path(gw_svc_dir).is_dir():
                services_dir = Path(gw_svc_dir)
        except (AttributeError, KeyError):
            pass  # Option not registered yet (gateway addon loads after us)
        if services_dir is None and baseline_path:
            candidate = Path(baseline_path).parent / "services"
            if candidate.is_dir():
                services_dir = candidate

        services_dir_str = str(services_dir) if services_dir else None

        # Skip if nothing changed (smart reconfigure)
        if (
            baseline_path == self._configured_baseline
            and budget_path == self._configured_budget
            and services_dir_str == self._configured_services_dir
        ):
            return

        # Build config with paths from mitmproxy options
        config = PolicyClientConfig(
            mode="local",
            baseline_path=Path(baseline_path) if baseline_path else None,
            budget_state_path=Path(budget_path) if budget_path else None,
            services_dir=services_dir,
        )

        configure_policy_client(config)

        self._configured_baseline = baseline_path
        self._configured_budget = budget_path
        self._configured_services_dir = services_dir_str

        log.info(
            "PolicyClient configured",
            extra={
                "baseline_path": baseline_path,
                "budget_state_path": budget_path,
            },
        )

    def done(self):
        """Cleanup on shutdown."""
        from pdp import reset_policy_client

        reset_policy_client()

    def get_stats(self) -> dict:
        """Get engine statistics via PolicyClient.get_stats()."""
        from pdp import get_policy_client, is_policy_client_configured

        if is_policy_client_configured():
            try:
                client = get_policy_client()
                return client.get_stats()
            except Exception:
                log.debug("Failed to get policy stats", exc_info=True)
        return {}


# Mitmproxy addon instance
policy_engine_addon = PolicyClientConfigurator()
addons = [policy_engine_addon]
