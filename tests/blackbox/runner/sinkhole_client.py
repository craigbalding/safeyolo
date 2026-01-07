"""Client for sinkhole control API."""

import time
from dataclasses import dataclass
from typing import Optional

import httpx


@dataclass
class CapturedRequest:
    """Mirrored from sinkhole for type safety."""

    timestamp: float
    host: str
    method: str
    path: str
    headers: dict[str, str]
    body: str
    client_ip: str
    query_params: dict[str, list[str]]


class SinkholeClient:
    """Client for querying and controlling the sinkhole server."""

    def __init__(self, base_url: str = "http://sinkhole:9999"):
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(timeout=10.0)

    def health(self) -> bool:
        """Check if sinkhole is healthy."""
        try:
            resp = self._client.get(f"{self.base_url}/health")
            return resp.status_code == 200
        except httpx.RequestError:
            return False

    def clear_requests(self):
        """Clear all captured requests."""
        resp = self._client.post(f"{self.base_url}/requests/clear")
        resp.raise_for_status()

    def get_requests(
        self,
        host: Optional[str] = None,
        since: Optional[float] = None,
    ) -> list[CapturedRequest]:
        """Get captured requests with optional filtering."""
        params = {}
        if host:
            params["host"] = host
        if since:
            params["since"] = str(since)

        resp = self._client.get(f"{self.base_url}/requests", params=params)
        resp.raise_for_status()

        data = resp.json()
        return [
            CapturedRequest(
                timestamp=r["timestamp"],
                host=r["host"],
                method=r["method"],
                path=r["path"],
                headers=r["headers"],
                body=r["body"],
                client_ip=r["client_ip"],
                query_params=r.get("query_params", {}),
            )
            for r in data["requests"]
        ]

    def get_request_count(self, host: Optional[str] = None) -> int:
        """Get count of captured requests."""
        params = {}
        if host:
            params["host"] = host
        resp = self._client.get(f"{self.base_url}/requests/count", params=params)
        resp.raise_for_status()
        return resp.json()["count"]

    def wait_for_ready(self, timeout: float = 30.0):
        """Wait for sinkhole to be ready."""
        start = time.time()
        while time.time() - start < timeout:
            if self.health():
                return
            time.sleep(0.5)
        raise TimeoutError(f"Sinkhole not ready after {timeout}s")

    def close(self):
        """Close the HTTP client."""
        self._client.close()
