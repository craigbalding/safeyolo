"""
admin_client.py - PDPAdminClient interface for management operations

This module provides the abstraction between management addons and PDP.
Separates "enforcement evaluate" (PolicyClient) from "management mutate state" (PDPAdminClient).

Implementations:
- LocalPDPAdminClient: Direct call to pdp/core.py (default)
- HttpPDPAdminClient: HTTP call to FastAPI service (for split-process mode)

Usage:
    from pdp.admin_client import get_admin_client

    client = get_admin_client()
    baseline = client.get_baseline()
    client.update_baseline(new_policy)
"""

import logging
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

log = logging.getLogger("safeyolo.pdp.admin_client")


@dataclass
class AdminClientConfig:
    """Configuration for PDPAdminClient."""
    mode: Literal["local", "http"] = "local"

    # For local mode: paths to policy files
    baseline_path: Path | None = None
    budget_state_path: Path | None = None

    # For http mode: PDP service endpoint
    endpoint: str = "http://127.0.0.1:8080"
    timeout_ms: int = 5000  # Longer timeout for admin ops


class PDPAdminClient(ABC):
    """Abstract interface for PDP management operations.

    Management addons depend on this interface, not PDPCore directly.
    """

    # -------------------------------------------------------------------------
    # Baseline Policy
    # -------------------------------------------------------------------------

    @abstractmethod
    def get_baseline(self) -> dict | None:
        """Get the current baseline policy."""
        pass

    @abstractmethod
    def get_baseline_path(self) -> str | None:
        """Get the path to the baseline policy file."""
        pass

    @abstractmethod
    def update_baseline(self, policy_data: dict) -> dict:
        """Update the baseline policy.

        Returns:
            Status dict with permission count or error
        """
        pass

    # -------------------------------------------------------------------------
    # Credential Approvals
    # -------------------------------------------------------------------------

    @abstractmethod
    def add_credential_approval(
        self,
        destination: str,
        credential: str,
        tier: str = "explicit",
    ) -> dict:
        """Add a credential approval to the baseline."""
        pass

    # -------------------------------------------------------------------------
    # Budget Management
    # -------------------------------------------------------------------------

    @abstractmethod
    def get_budget_stats(self) -> dict:
        """Get current budget usage statistics."""
        pass

    @abstractmethod
    def reset_budgets(self, resource: str | None = None) -> dict:
        """Reset budget counters."""
        pass

    # -------------------------------------------------------------------------
    # Task Policy Management
    # -------------------------------------------------------------------------

    @abstractmethod
    def upsert_task_policy(self, task_id: str, policy_data: dict) -> dict:
        """Upsert a task policy."""
        pass

    @abstractmethod
    def delete_task_policy(self, task_id: str) -> dict:
        """Delete a task policy."""
        pass

    @abstractmethod
    def get_task_policy(self, task_id: str) -> dict | None:
        """Get task policy data if it exists."""
        pass

    # -------------------------------------------------------------------------
    # Stats
    # -------------------------------------------------------------------------

    @abstractmethod
    def get_stats(self) -> dict:
        """Get PDP statistics."""
        pass


class LocalPDPAdminClient(PDPAdminClient):
    """In-process admin client - calls PDPCore directly."""

    def __init__(self, config: AdminClientConfig):
        from .core import get_pdp

        self._pdp = get_pdp(
            baseline_path=config.baseline_path,
            budget_state_path=config.budget_state_path,
        )
        log.info("LocalPDPAdminClient initialized")

    def get_baseline(self) -> dict | None:
        return self._pdp.get_baseline()

    def get_baseline_path(self) -> str | None:
        return self._pdp.get_baseline_path()

    def update_baseline(self, policy_data: dict) -> dict:
        return self._pdp.update_baseline(policy_data)

    def add_credential_approval(
        self,
        destination: str,
        credential: str,
        tier: str = "explicit",
    ) -> dict:
        return self._pdp.add_credential_approval(destination, credential, tier)

    def get_budget_stats(self) -> dict:
        return self._pdp.get_budget_stats()

    def reset_budgets(self, resource: str | None = None) -> dict:
        return self._pdp.reset_budgets(resource)

    def upsert_task_policy(self, task_id: str, policy_data: dict) -> dict:
        return self._pdp.upsert_task_policy(task_id, policy_data)

    def delete_task_policy(self, task_id: str) -> dict:
        return self._pdp.delete_task_policy(task_id)

    def get_task_policy(self, task_id: str) -> dict | None:
        return self._pdp.get_task_policy(task_id)

    def get_stats(self) -> dict:
        return self._pdp.get_stats()


class HttpPDPAdminClient(PDPAdminClient):
    """HTTP-based admin client - calls PDP via REST API."""

    def __init__(self, config: AdminClientConfig):
        try:
            import httpx
        except ImportError:
            raise ImportError(
                "httpx is required for HttpPDPAdminClient. "
                "Install with: pip install httpx"
            )

        self._endpoint = config.endpoint.rstrip("/")
        self._timeout = config.timeout_ms / 1000.0

        self._client = httpx.Client(
            base_url=self._endpoint,
            timeout=httpx.Timeout(self._timeout),
        )
        log.info("HttpPDPAdminClient initialized", extra={"endpoint": self._endpoint})

    def get_baseline(self) -> dict | None:
        response = self._client.get("/v1/baseline")
        if response.status_code == 200:
            data = response.json()
            return data.get("baseline")
        return None

    def get_baseline_path(self) -> str | None:
        response = self._client.get("/v1/baseline")
        if response.status_code == 200:
            data = response.json()
            return data.get("path")
        return None

    def update_baseline(self, policy_data: dict) -> dict:
        response = self._client.put("/v1/baseline", json=policy_data)
        return response.json()

    def add_credential_approval(
        self,
        destination: str,
        credential: str,
        tier: str = "explicit",
    ) -> dict:
        response = self._client.post(
            "/v1/approvals/credentials",
            json={"destination": destination, "credential": credential, "tier": tier},
        )
        return response.json()

    def get_budget_stats(self) -> dict:
        response = self._client.get("/v1/budgets")
        return response.json()

    def reset_budgets(self, resource: str | None = None) -> dict:
        payload = {"resource": resource} if resource else {}
        response = self._client.post("/v1/budgets/reset", json=payload)
        return response.json()

    def upsert_task_policy(self, task_id: str, policy_data: dict) -> dict:
        response = self._client.put(f"/v1/tasks/{task_id}/policy", json=policy_data)
        return response.json()

    def delete_task_policy(self, task_id: str) -> dict:
        response = self._client.delete(f"/v1/tasks/{task_id}/policy")
        return response.json()

    def get_task_policy(self, task_id: str) -> dict | None:
        response = self._client.get(f"/v1/tasks/{task_id}/policy")
        if response.status_code == 200:
            return response.json().get("policy")
        return None

    def get_stats(self) -> dict:
        response = self._client.get("/v1/stats")
        if response.status_code == 200:
            return response.json()
        return {}


# =============================================================================
# Factory Function
# =============================================================================

_admin_client_instance: PDPAdminClient | None = None
_admin_client_lock = threading.Lock()


def get_admin_client(config: AdminClientConfig | None = None) -> PDPAdminClient:
    """Get or create a PDPAdminClient based on configuration.

    First call with config initializes the client.
    Subsequent calls return the same instance.
    """
    global _admin_client_instance

    with _admin_client_lock:
        if _admin_client_instance is None:
            if config is None:
                config = AdminClientConfig()

            if config.mode == "http":
                _admin_client_instance = HttpPDPAdminClient(config)
            else:
                _admin_client_instance = LocalPDPAdminClient(config)

        return _admin_client_instance


def reset_admin_client() -> None:
    """Reset the global admin client (for testing)."""
    global _admin_client_instance
    with _admin_client_lock:
        _admin_client_instance = None
