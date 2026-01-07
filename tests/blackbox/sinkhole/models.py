"""Data models for captured HTTP requests."""

from dataclasses import dataclass, field


@dataclass
class CapturedRequest:
    """A captured HTTP request for later inspection."""

    timestamp: float
    host: str  # From Host header / SNI
    method: str
    path: str
    headers: dict[str, str]
    body: bytes
    client_ip: str
    query_params: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        return {
            "timestamp": self.timestamp,
            "host": self.host,
            "method": self.method,
            "path": self.path,
            "headers": self.headers,
            "body": self.body.decode("utf-8", errors="replace"),
            "client_ip": self.client_ip,
            "query_params": self.query_params,
        }
