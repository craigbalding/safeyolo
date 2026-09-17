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
    raw_target: str | None = None
    raw_query: str | None = None
    header_items: list[tuple[str, str]] | None = None
    body_expected_bytes: int | None = None
    body_received_bytes: int | None = None
    body_complete: bool | None = None
    connection_accepted: bool | None = None
    connection_closed: bool | None = None

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        return {
            "timestamp": self.timestamp,
            "host": self.host,
            "method": self.method,
            "path": self.path,
            "headers": self.headers,
            "body": self.body.decode("utf-8", errors="replace"),
            # Keep the historical text field for existing callers while
            # exposing a lossless representation for binary/exact-body
            # acceptance scenarios.
            "body_hex": self.body.hex(),
            "client_ip": self.client_ip,
            "query_params": self.query_params,
            # ``path`` and ``query_params`` are retained normalized views.
            # These fields preserve the original request-target spelling and
            # query order/encoding for signed and repeated-parameter tests.
            "raw_target": self.raw_target if self.raw_target is not None else self.path,
            "raw_query": self.raw_query,
            # Keep the historical mapping while exposing duplicate field order.
            "header_items": self.header_items
            if self.header_items is not None
            else list(self.headers.items()),
            "body_expected_bytes": self.body_expected_bytes,
            "body_received_bytes": self.body_received_bytes,
            "body_complete": self.body_complete,
            "connection_accepted": self.connection_accepted,
            "connection_closed": self.connection_closed,
        }
