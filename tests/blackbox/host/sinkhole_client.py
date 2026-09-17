"""Client for sinkhole control API."""

import time
import uuid
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
    body_hex: str | None = None
    raw_target: str | None = None
    raw_query: str | None = None
    header_items: list[tuple[str, str]] | None = None
    body_expected_bytes: int | None = None
    body_received_bytes: int | None = None
    body_complete: bool | None = None
    connection_accepted: bool | None = None
    connection_closed: bool | None = None
    connection_id: str | None = None

    @property
    def body_bytes(self) -> bytes:
        """Return the exact body captured by the sinkhole.

        Older sinkhole servers did not publish ``body_hex``.  Keep those
        responses readable through the historical text field while making
        current observer responses lossless.
        """
        if self.body_hex is None:
            return self.body.encode("utf-8")
        return bytes.fromhex(self.body_hex)


@dataclass
class ConnectionObservation:
    """Lifecycle observation mirrored from the sinkhole control API."""

    connection_id: str
    client_ip: str
    accepted_at: float
    state: str
    request_state: str
    request_count: int
    closed_at: float | None = None


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
                body_hex=r.get("body_hex"),
                raw_target=r.get("raw_target"),
                raw_query=r.get("raw_query"),
                header_items=(
                    [tuple(pair) for pair in r["header_items"]]
                    if r.get("header_items") is not None
                    else None
                ),
                body_expected_bytes=r.get("body_expected_bytes"),
                body_received_bytes=r.get("body_received_bytes"),
                body_complete=r.get("body_complete"),
                connection_accepted=r.get("connection_accepted"),
                connection_closed=r.get("connection_closed"),
                connection_id=r.get("connection_id"),
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

    def get_connections(self) -> list[ConnectionObservation]:
        """Get accepted sinkhole connection lifecycle observations."""
        resp = self._client.get(f"{self.base_url}/connections")
        resp.raise_for_status()
        return [ConnectionObservation(**connection) for connection in resp.json()["connections"]]

    def wait_for_ready(self, timeout: float = 30.0):
        """Wait for sinkhole to be ready."""
        start = time.time()
        while time.time() - start < timeout:
            if self.health():
                return
            time.sleep(0.5)
        raise TimeoutError(f"Sinkhole not ready after {timeout}s")

    def wait_for_receiver_ready(
        self,
        receiver_url: str = "http://127.0.0.1:18080",
        *,
        probe_host: str = "__sinkhole_receiver_ready__.test",
        timeout: float = 30.0,
    ):
        """Wait for the HTTP receiver and its capture path to be usable."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            nonce = uuid.uuid4().hex
            probe_path = f"/__sinkhole_receiver_ready__/{nonce}"
            probe_url = f"{receiver_url.rstrip('/')}{probe_path}"
            try:
                response = self._client.get(probe_url, headers={"Host": probe_host})
                if response.status_code == 200:
                    if any(
                        request.method == "GET"
                        and request.path == probe_path
                        and (
                            request.raw_target is None
                            or request.raw_target == probe_path
                        )
                        for request in self.get_requests(host=probe_host)
                    ):
                        return
            except httpx.RequestError:
                pass
            time.sleep(min(0.5, max(0, deadline - time.monotonic())))
        raise TimeoutError(f"Sinkhole receiver not ready after {timeout}s: {receiver_url}")

    def close(self):
        """Close the HTTP client."""
        self._client.close()
