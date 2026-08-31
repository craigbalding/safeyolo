"""Typed legacy-attachment actions and narrow loopback callback ingress.

This is intentionally not a generic card or forms system.  A small fixed
SafeYolo operator-request schema selects a fixed action vocabulary, and the
listener accepts only bounded JSON at one callback path plus one health path.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import ipaddress
import json
import re
import unicodedata
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit

OPERATOR_REQUEST_SCHEMA = "safeyolo.coord.operator-request/v1"
ACTION_CALLBACK_SUFFIX = "mattermost/actions"
ACTION_HEALTH_SUFFIX = "mattermost/healthz"
MAX_REQUEST_BODY_BYTES = 64 * 1024
MAX_REQUEST_HEADERS_BYTES = 16 * 1024
MAX_CONCURRENT_REQUESTS = 32
MAX_RESPONSE_BODY_BYTES = 16 * 1024
REQUEST_TIMEOUT_SECONDS = 5.0

_AGENT_ID_RE = re.compile(r"^ag-[0-9a-f]{32}$")
_MSG_ID_RE = re.compile(r"^msg-[0-9a-f]{32}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._~-]+$")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_CONTENT_LENGTH_RE = re.compile(r"^(0|[1-9][0-9]*)$")
_DNS_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")
_MARKDOWN_LINK_RE = re.compile(r"(!?)\[([^\]\n]*)\]\(([^)\n]*)\)")
_CHANNEL_LINK_RE = re.compile(r"(?<![\w~])~(?=[A-Za-z0-9_-])")
_UNSAFE_SCHEME_RE = re.compile(
    r"(?i)\b(?:javascript|data|file|vbscript|mattermost|mmaction):(?://)?|"
    r"\b(?!https://)[a-z][a-z0-9+.-]*://"
)
_PROVENANCE_CLAIM_RE = re.compile(r"(?i)canonical\s+provenance")
_HORIZONTAL_RULE_RE = re.compile(r"^[ \t]{0,3}(?:[-*_][ \t]*){3,}$")
_TASK_ACCEPTED_RE = re.compile(r"^ACCEPTED(?=\s|$)")


class OperatorAction(StrEnum):
    ACKNOWLEDGE = "acknowledge"
    APPROVE = "approve"
    REJECT = "reject"
    DEFER = "defer"
    REVISE = "revise"
    PUBLISH = "publish"
    OPEN_ISSUE = "open-issue"


class SemanticKind(StrEnum):
    STATUS = "status"
    DECISION = "decision"
    FACTORY_PROPOSAL = "factory-proposal"
    DISPATCH_PUBLICATION = "dispatch-publication"


_KIND_ACTIONS: Mapping[SemanticKind, frozenset[OperatorAction]] = {
    SemanticKind.STATUS: frozenset(),
    SemanticKind.DECISION: frozenset(
        {
            OperatorAction.ACKNOWLEDGE,
            OperatorAction.APPROVE,
            OperatorAction.REJECT,
            OperatorAction.DEFER,
            OperatorAction.REVISE,
        }
    ),
    SemanticKind.FACTORY_PROPOSAL: frozenset(
        {
            OperatorAction.OPEN_ISSUE,
            OperatorAction.REVISE,
            OperatorAction.DEFER,
            OperatorAction.REJECT,
        }
    ),
    SemanticKind.DISPATCH_PUBLICATION: frozenset(
        {
            OperatorAction.PUBLISH,
            OperatorAction.REVISE,
            OperatorAction.DEFER,
        }
    ),
}


@dataclass(frozen=True)
class SemanticRequest:
    kind: SemanticKind
    title: str
    summary: str
    reference: str
    details: tuple[str, ...]
    allowed_actions: tuple[OperatorAction, ...]


@dataclass(frozen=True)
class ActionIngressConfig:
    bind_host: str
    bind_port: int
    public_base_url: str
    capability_ttl_seconds: int
    trusted_agent_ids: tuple[str, ...]

    @property
    def callback_url(self) -> str:
        return _append_url_path(self.public_base_url, ACTION_CALLBACK_SUFFIX)

    @property
    def callback_path(self) -> str:
        return urlsplit(self.callback_url).path

    @property
    def health_path(self) -> str:
        return urlsplit(_append_url_path(self.public_base_url, ACTION_HEALTH_SUFFIX)).path


@dataclass(frozen=True)
class CallbackHTTPResponse:
    status: int
    body: Mapping[str, Any]


CallbackHandler = Callable[[Mapping[str, Any]], Awaitable[CallbackHTTPResponse]]
HealthProvider = Callable[[], Mapping[str, Any]]


def _append_url_path(base: str, suffix: str) -> str:
    parsed = urlsplit(base)
    path = parsed.path.rstrip("/") + "/" + suffix
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def canonical_public_base_url(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("public_callback_base_url must be a non-empty HTTPS URL")
    raw_value = value.strip()
    try:
        parsed = urlsplit(raw_value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("public_callback_base_url is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "?" in raw_value
        or "#" in raw_value
        or parsed.netloc.endswith(":")
        or "%" in parsed.path
        or "//" in parsed.path
    ):
        raise ValueError("public_callback_base_url must be HTTPS without credentials, query, or fragment")
    segments = [segment for segment in parsed.path.split("/") if segment]
    if any(segment in {".", ".."} or not _PATH_SEGMENT_RE.fullmatch(segment) for segment in segments):
        raise ValueError("public_callback_base_url has an unsafe path")
    if port == 0:
        raise ValueError("public_callback_base_url has an invalid port")
    hostname = parsed.hostname.lower()
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("public_callback_base_url host must be publicly routable")
    if ":" in hostname:
        try:
            address = ipaddress.IPv6Address(hostname)
        except ValueError as exc:
            raise ValueError("public_callback_base_url has an invalid host") from exc
        if not address.is_global:
            raise ValueError("public_callback_base_url host must be publicly routable")
        hostname = f"[{address}]"
    else:
        labels = hostname.split(".")
        if (
            len(hostname) > 253
            or not _DNS_HOST_RE.fullmatch(hostname)
            or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels)
        ):
            raise ValueError("public_callback_base_url has an invalid host")
        if all(char.isdigit() or char == "." for char in hostname):
            try:
                address = ipaddress.IPv4Address(hostname)
            except ValueError as exc:
                raise ValueError("public_callback_base_url has an invalid host") from exc
            if not address.is_global:
                raise ValueError("public_callback_base_url host must be publicly routable")
            hostname = str(address)
    netloc = hostname if port is None else f"{hostname}:{port}"
    normalized = SplitResult("https", netloc, "/" + "/".join(segments) if segments else "", "", "")
    return urlunsplit(normalized)


def validate_trusted_agent_ids(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError("trusted_action_agent_ids must be a non-empty array")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not _AGENT_ID_RE.fullmatch(item):
            raise ValueError("trusted_action_agent_ids contains an invalid canonical agent ID")
        if item in result:
            raise ValueError("trusted_action_agent_ids contains a duplicate")
        result.append(item)
    return tuple(result)


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _bounded_text(value: Any, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("invalid text")
    result = value.strip()
    if len(result.encode("utf-8")) > maximum:
        raise ValueError("oversized text")
    if "\n" in result or "\r" in result or any(ord(char) < 0x20 for char in result):
        raise ValueError("invalid text controls")
    return result


def parse_semantic_request(envelope: Mapping[str, Any], trusted_agent_ids: Sequence[str]) -> SemanticRequest | None:
    """Return a request only for exact canonical identity plus the fixed schema."""

    if (
        not isinstance(envelope, dict)
        or envelope.get("sender_kind") != "agent"
        or envelope.get("sender_agent_id") not in trusted_agent_ids
        or envelope.get("content_type") != "text/plain"
        or not isinstance(envelope.get("msg_id"), str)
        or not _MSG_ID_RE.fullmatch(envelope["msg_id"])
    ):
        return None
    body = envelope.get("body")
    if not isinstance(body, str) or len(body.encode("utf-8")) > 32 * 1024:
        return None
    try:
        raw = json.loads(body, object_pairs_hook=_strict_pairs)
        if not isinstance(raw, dict) or set(raw) != {
            "schema",
            "kind",
            "title",
            "summary",
            "reference",
            "details",
            "allowed_actions",
        }:
            return None
        if raw["schema"] != OPERATOR_REQUEST_SCHEMA:
            return None
        kind = SemanticKind(raw["kind"])
        title = _bounded_text(raw["title"], 256)
        summary = _bounded_text(raw["summary"], 2 * 1024)
        reference = _bounded_text(raw["reference"], 256)
        details_raw = raw["details"]
        actions_raw = raw["allowed_actions"]
        if not isinstance(details_raw, list) or len(details_raw) > 8:
            return None
        details = tuple(_bounded_text(item, 512) for item in details_raw)
        if not isinstance(actions_raw, list) or len(actions_raw) > 7:
            return None
        actions = tuple(OperatorAction(item) for item in actions_raw)
        if len(actions) != len(set(actions)) or not set(actions).issubset(_KIND_ACTIONS[kind]):
            return None
        if kind is SemanticKind.STATUS and actions:
            return None
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError, RecursionError):
        return None
    return SemanticRequest(kind, title, summary, reference, details, actions)


def operator_request_body(request: SemanticRequest) -> str:
    """Serialize a typed request for the canonical coord body."""

    if (
        len(request.details) > 8
        or len(request.allowed_actions) > 7
        or len(request.allowed_actions) != len(set(request.allowed_actions))
        or not set(request.allowed_actions).issubset(_KIND_ACTIONS[request.kind])
        or (request.kind is SemanticKind.STATUS and request.allowed_actions)
    ):
        raise ValueError("actions are not allowed for this semantic kind")
    value = {
        "schema": OPERATOR_REQUEST_SCHEMA,
        "kind": request.kind.value,
        "title": _bounded_text(request.title, 256),
        "summary": _bounded_text(request.summary, 2 * 1024),
        "reference": _bounded_text(request.reference, 256),
        "details": [_bounded_text(item, 512) for item in request.details],
        "allowed_actions": [action.value for action in request.allowed_actions],
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _strict_single_line(value: str, *, maximum: int) -> str:
    """Render untrusted metadata as one non-active Markdown line."""

    encoded = value.encode("utf-8")
    if len(encoded) > maximum:
        digest = hashlib.sha256(encoded).hexdigest()[:16]
        allowance = max(0, maximum - 80)
        value = value.encode("utf-8")[:allowance].decode("utf-8", errors="ignore")
        value += f"… [truncated; sha256 {digest}]"
    result: list[str] = []
    for char in value:
        code = ord(char)
        if char == "\n":
            result.append(" ")
        elif code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F or unicodedata.category(char).startswith("C"):
            result.append(f"\\u{code:04x}")
        elif char == "@":
            result.append(r"\u0040")
        elif char in "\\`*_[]()<>~#+=|{}!":
            result.append("\\" + char)
        else:
            result.append(char)
    return "".join(result)


def _safe_https_destination(value: str) -> str | None:
    destination = value.strip()
    if not destination or any(char.isspace() for char in destination):
        return None
    try:
        parsed = urlsplit(destination)
    except ValueError:
        return None
    if (
        parsed.scheme.lower() != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or any(unicodedata.category(char).startswith("C") for char in destination)
    ):
        return None
    return destination


def _sanitize_markdown_link(match: re.Match[str]) -> str:
    image, label, raw_destination = match.groups()
    destination = _safe_https_destination(raw_destination)
    safe_label = label.replace("@", "＠")
    safe_label = _CHANNEL_LINK_RE.sub("～", safe_label)
    if destination is None:
        return f"{safe_label} [blocked link]"
    if image:
        return f"[image: {safe_label}]({destination})"
    return f"[{safe_label}]({destination})"


def _truncate_markdown_source(value: str, maximum: int) -> tuple[str, str | None]:
    encoded = value.encode("utf-8")
    if len(encoded) <= maximum:
        return value, None
    digest = hashlib.sha256(encoded).hexdigest()[:16]
    allowance = max(0, maximum - 96)
    prefix = encoded[:allowance].decode("utf-8", errors="ignore")
    # Prefer a complete line. A single very long line is made inert below if
    # it leaves an unmatched inline-code or link delimiter.
    if "\n" in prefix:
        prefix = prefix.rsplit("\n", 1)[0]
    return prefix, f"[truncated; sha256 {digest}]"


def _close_truncated_markdown(rendered: str, maximum: int | None = None) -> str:
    """Close active tail syntax, optionally within an exact character bound."""

    def close(prefix: str) -> str:
        # Do not leave half of a visible control escape at the cut point.
        prefix = re.sub(r"\\u[0-9a-fA-F]{0,3}$", "", prefix)
        if prefix.endswith("\\"):
            prefix = prefix[:-1]
        tail_lines = prefix.split("\n")
        tail = tail_lines[-1]
        if tail.count("[") != tail.count("]") or tail.count("(") != tail.count(")"):
            tail_lines[-1] = re.sub(r"([!\[\]()])", r"\\\1", tail)
            prefix = "\n".join(tail_lines)
        fence_count = sum(1 for line in prefix.splitlines() if re.match(r"^[ \t]*```", line))
        if fence_count % 2:
            prefix += "\n```"
        if prefix.count("`") % 2:
            prefix += "`"
        return prefix

    if maximum is None:
        return close(rendered)
    prefix = rendered[:maximum]
    for _ in range(32):
        closed = close(prefix)
        if len(closed) <= maximum:
            return closed
        overflow = len(closed) - maximum
        prefix = prefix[: max(0, len(prefix) - max(1, (overflow + 1) // 2))]
    return ""


def _finish_truncated_markdown(rendered: str, marker: str, *, maximum: int | None = None) -> str:
    suffix = f"\n\n{marker}"
    if maximum is None:
        return _close_truncated_markdown(rendered) + suffix
    prefix_limit = max(0, maximum - len(suffix))
    return _close_truncated_markdown(rendered[:prefix_limit], prefix_limit) + suffix


def sanitize_mattermost_markdown(
    value: str,
    *,
    maximum: int = 8 * 1024,
    output_maximum: int | None = None,
) -> str:
    """Keep useful Markdown while removing Mattermost side-effect syntax.

    Newlines, headings, lists, code, and ordinary HTTPS links survive. The
    result cannot mention users/channels, embed an image, select an unsafe
    scheme, register a Mattermost action, or counterfeit the final canonical
    provenance boundary added by :func:`compact_fallback`.
    """

    original = value
    value, truncation = _truncate_markdown_source(value, maximum)
    # Mattermost/CommonMark decodes character references before rendering.
    # Normalize them before every syntax and provenance check so an entity
    # cannot recreate active syntax after this sanitizer has inspected it.
    value = html.unescape(value)
    value = value.replace("\r\n", "\n")
    result: list[str] = []
    for char in value:
        code = ord(char)
        if char == "\n":
            result.append(char)
        elif code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F or unicodedata.category(char).startswith("C"):
            result.append(f"\\u{code:04x}")
        elif char == "@":
            result.append("＠")
        elif char == "<":
            result.append(r"\<")
        elif char == ">":
            result.append(r"\>")
        else:
            result.append(char)
    rendered = "".join(result)
    # Every CommonMark image form starts with this opener: inline, full
    # reference, collapsed reference, and shortcut reference. Demoting the
    # opener before link handling preserves readable alt text and references
    # while making an image token structurally impossible.
    rendered = rendered.replace("![", "[image: ")
    rendered = _MARKDOWN_LINK_RE.sub(_sanitize_markdown_link, rendered)
    rendered = _CHANNEL_LINK_RE.sub("～", rendered)
    rendered = _UNSAFE_SCHEME_RE.sub(lambda match: match.group(0).replace(":", r"\:"), rendered)
    rendered = _PROVENANCE_CLAIM_RE.sub("[sender provenance claim]", rendered)

    lines = rendered.split("\n")
    for index, line in enumerate(lines):
        if _HORIZONTAL_RULE_RE.fullmatch(line):
            lines[index] = "\\" + line
    rendered = "\n".join(lines)
    rendered = _TASK_ACCEPTED_RE.sub("TASK ACCEPTED", rendered, count=1)

    if truncation is not None:
        rendered = _finish_truncated_markdown(rendered, truncation)
    if output_maximum is not None and len(rendered) > output_maximum:
        digest = hashlib.sha256(original.encode("utf-8")).hexdigest()[:16]
        rendered = _finish_truncated_markdown(
            rendered,
            f"[truncated; sha256 {digest}]",
            maximum=output_maximum,
        )
    return rendered


def compact_fallback(envelope: Mapping[str, Any], room: str) -> str:
    body = envelope.get("body")
    if not isinstance(body, str):
        body = "[invalid sender body]"
    name = envelope.get("sender_agent_name")
    sender = name if isinstance(name, str) and name else str(envelope.get("sender_kind", "unknown"))
    agent_id = envelope.get("sender_agent_id")
    msg_id = envelope.get("msg_id")
    provenance = (
        "Canonical provenance · "
        f"sender {_strict_single_line(sender, maximum=128)} · "
        f"agent `{_strict_single_line(str(agent_id), maximum=64)}` · "
        f"kind `{_strict_single_line(str(envelope.get('sender_kind', 'unknown')), maximum=32)}` · "
        f"room `{_strict_single_line(room, maximum=128)}` · "
        f"message `{_strict_single_line(str(msg_id), maximum=96)}`"
    )
    separator = "\n\n---\n"
    maximum = 13_500
    body_maximum = maximum - len(separator) - len(provenance)
    projected_body = sanitize_mattermost_markdown(body, output_maximum=body_maximum)
    return f"{projected_body}{separator}{provenance}"


def semantic_attachment(
    request: SemanticRequest,
    *,
    sender_name: str,
    sender_agent_id: str,
    room: str,
    callback_url: str | None,
    capability: str | None,
    adapter_id: str,
    projection_key: str,
    ttl_seconds: int,
) -> dict[str, Any]:
    kind_label = {
        SemanticKind.STATUS: "SafeYolo status",
        SemanticKind.DECISION: "SafeYolo decision",
        SemanticKind.FACTORY_PROPOSAL: "Factory improvement proposal",
        SemanticKind.DISPATCH_PUBLICATION: "Dispatch publication candidate",
    }[request.kind]
    detail_lines = [
        f"**Reference:** {_strict_single_line(request.reference, maximum=256)}",
        *(f"• {_strict_single_line(detail, maximum=512)}" for detail in request.details),
    ]
    actions: list[dict[str, Any]] = []
    if callback_url is not None and capability is not None:
        for action in request.allowed_actions:
            button: dict[str, Any] = {
                "id": action.value,
                "type": "button",
                "name": action.value.replace("-", " ").title(),
                "integration": {
                    "url": callback_url,
                    "context": {
                        "adapter_id": adapter_id,
                        "projection_key": projection_key,
                        "capability": capability,
                        "action": action.value,
                    },
                },
            }
            if action in {
                OperatorAction.ACKNOWLEDGE,
                OperatorAction.APPROVE,
                OperatorAction.PUBLISH,
                OperatorAction.OPEN_ISSUE,
            }:
                button["style"] = "primary"
            elif action is OperatorAction.REJECT:
                button["style"] = "danger"
            actions.append(button)
    footer = (
        f"{sender_name} ({sender_agent_id}) · canonical trusted agent · {room} · "
        f"actions expire in {ttl_seconds // 60} minutes"
        if actions
        else (f"{sender_name} ({sender_agent_id}) · canonical provenance · {room} · no interactive actions")
    )
    return {
        "fallback": _strict_single_line(f"{kind_label}: {request.title}", maximum=512),
        "color": "#3d85c6" if request.kind is not SemanticKind.STATUS else "#6a737d",
        "pretext": kind_label,
        "title": _strict_single_line(request.title, maximum=256),
        "text": "\n\n".join(
            [
                _strict_single_line(request.summary, maximum=2 * 1024),
                "\n".join(detail_lines),
            ]
        ),
        "footer": _strict_single_line(footer, maximum=512),
        "actions": actions,
    }


def semantic_post_message(
    request: SemanticRequest,
    *,
    sender_name: str,
    sender_agent_id: str,
    room: str,
) -> str:
    """Short top-level text for clients that collapse legacy attachments."""

    return (
        f"{_strict_single_line(request.title, maximum=256)}\n"
        f"{_strict_single_line(sender_name, maximum=128)} "
        f"({_strict_single_line(sender_agent_id, maximum=64)}) · canonical trusted agent · "
        f"room {_strict_single_line(room, maximum=128)} · "
        f"{_strict_single_line(request.reference, maximum=256)}"
    )


class MattermostActionListener:
    """One bounded loopback HTTP listener for legacy action callbacks."""

    def __init__(
        self,
        config: ActionIngressConfig,
        handler: CallbackHandler,
        health_provider: HealthProvider,
    ) -> None:
        self.config = config
        self._handler = handler
        self._health_provider = health_provider
        self._server: asyncio.AbstractServer | None = None
        self._tasks: set[asyncio.Task[Any]] = set()
        self.state = "stopped"
        self.last_error: str | None = None

    @property
    def healthy(self) -> bool:
        return self.state == "healthy" and self._server is not None and self._server.is_serving()

    @property
    def bound_port(self) -> int | None:
        if self._server is None or not self._server.sockets:
            return None
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self) -> bool:
        if self._server is not None:
            raise RuntimeError("Mattermost action listener is already started")
        self.state = "starting"
        self.last_error = None
        try:
            self._server = await asyncio.start_server(
                self._serve_connection,
                host=self.config.bind_host,
                port=self.config.bind_port,
                limit=MAX_REQUEST_HEADERS_BYTES + MAX_REQUEST_BODY_BYTES + 1024,
            )
        except OSError as exc:
            self.state = "failed"
            self.last_error = f"listener bind failed: {type(exc).__name__}"
            return False
        self.state = "healthy"
        return True

    async def close(self) -> None:
        server, self._server = self._server, None
        if server is not None:
            server.close()
            await server.wait_closed()
        tasks = [task for task in self._tasks if not task.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self.state = "stopped"

    async def _serve_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        try:
            if len(self._tasks) > MAX_CONCURRENT_REQUESTS:
                response = CallbackHTTPResponse(503, {"error": "listener is busy"})
            else:
                response = await asyncio.wait_for(
                    self._read_and_dispatch(reader),
                    timeout=REQUEST_TIMEOUT_SECONDS,
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            response = CallbackHTTPResponse(400, {"error": "invalid request"})
        try:
            status = response.status
            if status not in {200, 400, 403, 404, 409, 410, 503}:
                raise ValueError("unsupported response status")
            body = json.dumps(dict(response.body), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
                "ascii"
            )
            if len(body) > MAX_RESPONSE_BODY_BYTES:
                raise ValueError("oversized response")
        except (TypeError, ValueError, UnicodeError):
            status = 503
            body = b'{"error":"service unavailable"}'
        try:
            reason = {
                200: "OK",
                400: "Bad Request",
                403: "Forbidden",
                404: "Not Found",
                409: "Conflict",
                410: "Gone",
                503: "Service Unavailable",
            }[status]
            writer.write(
                f"HTTP/1.1 {status} {reason}\r\n".encode("ascii")
                + b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n".encode("ascii")
                + b"Connection: close\r\nCache-Control: no-store\r\n\r\n"
                + body
            )
            await asyncio.wait_for(writer.drain(), timeout=REQUEST_TIMEOUT_SECONDS)
        except (ConnectionError, TimeoutError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            if task is not None:
                self._tasks.discard(task)

    async def _readline(self, reader: asyncio.StreamReader) -> bytes:
        line = await asyncio.wait_for(reader.readline(), timeout=REQUEST_TIMEOUT_SECONDS)
        if not line.endswith(b"\r\n") or len(line) > MAX_REQUEST_HEADERS_BYTES:
            raise ValueError("invalid HTTP line")
        return line

    async def _read_and_dispatch(self, reader: asyncio.StreamReader) -> CallbackHTTPResponse:
        request_line = (await self._readline(reader)).decode("ascii", errors="strict")
        parts = request_line[:-2].split(" ")
        if len(parts) != 3 or parts[2] not in {"HTTP/1.0", "HTTP/1.1"}:
            return CallbackHTTPResponse(400, {"error": "invalid request"})
        method, target, _version = parts
        if "?" in target or "#" in target:
            return CallbackHTTPResponse(404, {"error": "not found"})
        headers: dict[str, str] = {}
        total = len(request_line)
        while True:
            raw = await self._readline(reader)
            total += len(raw)
            if total > MAX_REQUEST_HEADERS_BYTES:
                return CallbackHTTPResponse(400, {"error": "invalid request"})
            if raw == b"\r\n":
                break
            try:
                name, value = raw.decode("ascii", errors="strict")[:-2].split(":", 1)
            except ValueError:
                return CallbackHTTPResponse(400, {"error": "invalid request"})
            if name != name.strip():
                return CallbackHTTPResponse(400, {"error": "invalid request"})
            name = name.lower()
            value = value.strip()
            if (
                not _HEADER_NAME_RE.fullmatch(name)
                or name in headers
                or any(ord(char) < 0x20 or ord(char) > 0x7E for char in value)
            ):
                return CallbackHTTPResponse(400, {"error": "invalid request"})
            headers[name] = value
        if method == "GET" and target == self.config.health_path:
            health = dict(self._health_provider())
            health["listener"] = "healthy" if self.healthy else "failed"
            return CallbackHTTPResponse(200, health)
        if method != "POST" or target != self.config.callback_path:
            return CallbackHTTPResponse(404, {"error": "not found"})
        if "transfer-encoding" in headers:
            return CallbackHTTPResponse(400, {"error": "invalid request"})
        if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            return CallbackHTTPResponse(400, {"error": "invalid request"})
        raw_length = headers.get("content-length")
        if raw_length is None or not _CONTENT_LENGTH_RE.fullmatch(raw_length):
            return CallbackHTTPResponse(400, {"error": "invalid request"})
        length = int(raw_length)
        if length < 2 or length > MAX_REQUEST_BODY_BYTES:
            return CallbackHTTPResponse(400, {"error": "invalid request"})
        try:
            body = await asyncio.wait_for(reader.readexactly(length), timeout=REQUEST_TIMEOUT_SECONDS)
            payload = json.loads(body, object_pairs_hook=_strict_pairs)
        except (
            asyncio.IncompleteReadError,
            TimeoutError,
            UnicodeError,
            ValueError,
            RecursionError,
            json.JSONDecodeError,
        ):
            return CallbackHTTPResponse(400, {"error": "invalid request"})
        if not isinstance(payload, dict):
            return CallbackHTTPResponse(400, {"error": "invalid request"})
        return await self._handler(payload)


def validate_capability_token(value: Any) -> str:
    if not isinstance(value, str) or not _TOKEN_RE.fullmatch(value):
        raise ValueError("invalid capability")
    return value
