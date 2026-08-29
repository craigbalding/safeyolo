"""Deterministic, evidence-backed Markdown for Relay's public Dispatch."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 256 * 1024
MAX_SECTIONS = 4
MAX_ITEMS_PER_SECTION = 32
MAX_EVIDENCE_PER_ITEM = 12
MAX_TOPIC_UPDATES = 16
MAX_TOPIC_STATE_ITEMS = 24
MAX_TEXT_BYTES = 4 * 1024
MAX_SNIPPET_BYTES = 8 * 1024
MAX_OUTPUT_BYTES = 512 * 1024

_TOKEN_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_TOPIC_STATE_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
_DEFINITION_TERM_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:+/-]{0,63}$")
_LANGUAGE_RE = re.compile(r"^[a-z0-9_+-]{1,32}$")
_AUTHORED_LINK_RE = re.compile(
    r"(?:\b(?:https?|mailto):|\bwww\.|\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b)",
    re.I,
)
_UNSAFE_EVIDENCE_URL_RE = re.compile(r'[\s<>()\[\]{}\\"]')
_GITHUB_REPOSITORY_PATH = r"/[^/]+/[^/]+"
_GITHUB_KIND_PATHS = {
    "issue": re.compile(rf"^{_GITHUB_REPOSITORY_PATH}/issues/\d+/?$"),
    "pr": re.compile(rf"^{_GITHUB_REPOSITORY_PATH}/pull/\d+/?$"),
    "commit": re.compile(rf"^{_GITHUB_REPOSITORY_PATH}/commit/[0-9a-f]{{40}}/?$"),
    "document": re.compile(rf"^{_GITHUB_REPOSITORY_PATH}/blob/[^/]+/.+$"),
    "test": re.compile(rf"^{_GITHUB_REPOSITORY_PATH}/blob/[^/]+/.+$"),
}

_SECRET_PATTERNS = (  # DOC: docs/dispatch-generation.md, cli/src/safeyolo/agent_context/skills/safeyolo/references/dispatch-generation.md
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsgw_[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b", re.I),
    re.compile(r"\b(?:sk|xox[baprs])-[A-Za-z0-9-]{16,}\b"),
)
_PRIVATE_PATTERNS = (
    re.compile(r"\b(?:msg|ag|sy|rm|attn)-[0-9a-f]{32}\b", re.I),
    re.compile(
        r"\b(?:coord(?:ination)?[\s_-]*)?(?:seq(?:uence)?)[\s:=#_-]*\d+\b",
        re.I,
    ),
    re.compile(r"\b(?:sender_agent_id|origin_instance_id|mattermost_channel_id|adapter_id)\b", re.I),
    re.compile(r"SAFEYOLO_COMPLETION_NOTES|DISPATCH_CANDIDATE|FACTORY_CANDIDATE"),
    re.compile(r"\b(?:chain[- ]of[- ]thought|private reasoning|raw reasoning|scratchpad)\b", re.I),
    re.compile(r"(?:/Users/|/home/agent/|/app/agent_token)"),
)
class DispatchError(ValueError):
    """A source, evidence, hygiene, or output-boundary check failed."""


class PeriodKind(StrEnum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class SectionKind(StrEnum):
    SHIPPED = "shipped"
    LENS_CAUGHT = "lens_caught"
    WORTH_KNOWING = "worth_knowing"
    FACTORY_PULSE = "factory_pulse"


class PublicAttribution(StrEnum):
    LENS_REVIEW_FINDING = "lens_review_finding"
    FORGE_IMPLEMENTATION_DISCOVERY = "forge_implementation_discovery"
    PREEXISTING_BUG_EXPOSED_BY_TESTING = "preexisting_bug_exposed_by_testing"
    INFRASTRUCTURE_ENVIRONMENT_PROBLEM = "infrastructure_environment_problem"
    FACTORY_PROCESS_OBSERVATION = "factory_process_observation"
    RELAY_SYNTHESIS = "relay_synthesis"


class PublicEvidenceKind(StrEnum):
    ISSUE = "issue"
    PR = "pr"
    COMMIT = "commit"
    DOCUMENT = "document"
    TEST = "test"
    RUNTIME = "runtime"


@dataclass(frozen=True)
class Period:
    kind: PeriodKind
    start: date
    end: date

    @property
    def relative_path(self) -> Path:
        if self.kind is PeriodKind.DAILY:
            return Path("dispatch") / f"{self.start.isoformat()}.md"
        if self.kind is PeriodKind.WEEKLY:
            iso = self.start.isocalendar()
            return Path("snapshots") / f"{iso.year}-W{iso.week:02d}.md"
        return Path("snapshots") / f"{self.start:%Y-%m}.md"

    @property
    def heading(self) -> str:
        if self.kind is PeriodKind.DAILY:
            return f"{self.start:%B} {self.start.day}, {self.start.year}"
        if self.kind is PeriodKind.WEEKLY:
            iso = self.start.isocalendar()
            return f"{iso.year}-W{iso.week:02d}"
        return self.start.strftime("%B %Y")


@dataclass(frozen=True)
class PublicEvidence:
    kind: PublicEvidenceKind
    label: str
    url: str


@dataclass(frozen=True)
class Snippet:
    language: str
    code: str


@dataclass(frozen=True)
class ContentItem:
    title: str
    body: str
    attribution: PublicAttribution
    evidence: tuple[PublicEvidence, ...]
    theme: str | None = None
    snippet: Snippet | None = None
    lesson: str | None = None


@dataclass(frozen=True)
class Section:
    kind: SectionKind
    items: tuple[ContentItem, ...]


@dataclass(frozen=True)
class TopicUpdate:
    slug: str
    title: str
    state_key: str
    summary: str
    current_state: tuple[str, ...]
    evidence: tuple[PublicEvidence, ...]

    @property
    def relative_path(self) -> Path:
        return Path("topics") / f"{self.slug}.md"


@dataclass(frozen=True)
class DispatchManifest:
    period: Period
    definitions: tuple[tuple[str, str], ...]
    sections: tuple[Section, ...]
    topic_updates: tuple[TopicUpdate, ...]


@dataclass(frozen=True)
class GeneratedFile:
    relative_path: Path
    content: str

def _pairs_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DispatchError("dispatch source contains a duplicate JSON key")
        result[key] = value
    return result


def _bounded_json_int(raw: str) -> int:
    if len(raw) > 12:
        raise DispatchError("dispatch source integer is unreasonably large")
    return int(raw)


def _strict_object(
    value: Any,
    field: str,
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise DispatchError(f"{field} must be an object")
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        raise DispatchError(f"{field} is missing required fields")
    if unknown:
        raise DispatchError(f"{field} contains unknown fields")
    return value


def _hygiene(text: str, field: str) -> None:
    for pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            raise DispatchError(f"{field} contains an apparent credential or secret")
    for pattern in _PRIVATE_PATTERNS:
        if pattern.search(text):
            raise DispatchError(f"{field} contains private coordination or reasoning material")


def _text(
    value: Any,
    field: str,
    *,
    maximum: int = MAX_TEXT_BYTES,
    multiline: bool = False,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DispatchError(f"{field} must be a non-empty string")
    result = value.strip()
    try:
        encoded = result.encode("utf-8")
    except UnicodeError as exc:
        raise DispatchError(f"{field} must be valid UTF-8") from exc
    if len(encoded) > maximum:
        raise DispatchError(f"{field} exceeds {maximum} UTF-8 bytes")
    if any(ord(char) < 0x20 and (not multiline or char not in {"\n", "\t"}) for char in result):
        raise DispatchError(f"{field} contains disallowed controls")
    if not multiline and ("\n" in result or "\r" in result):
        raise DispatchError(f"{field} must be one line")
    _hygiene(result, field)
    return result


def _token(value: Any, field: str) -> str:
    result = _text(value, field, maximum=64)
    if not _TOKEN_RE.fullmatch(result):
        raise DispatchError(f"{field} must be a stable lowercase token")
    return result


def _state_key(value: Any, field: str) -> str:
    result = _text(value, field, maximum=128)
    if not _TOPIC_STATE_RE.fullmatch(result):
        raise DispatchError(f"{field} must be a stable semantic state key")
    return result


def _definition_term(value: Any, field: str) -> str:
    result = _text(value, field, maximum=64)
    if not _DEFINITION_TERM_RE.fullmatch(result):
        raise DispatchError(f"{field} must be a concise public term")
    return result


def _list(value: Any, field: str, maximum: int) -> Sequence[Any]:
    if not isinstance(value, list):
        raise DispatchError(f"{field} must be an array")
    if len(value) > maximum:
        raise DispatchError(f"{field} exceeds {maximum} entries")
    return value


def _normalized_hostname(hostname: str) -> str | None:
    try:
        return hostname.encode("idna").decode("ascii").rstrip(".").lower()
    except UnicodeError:
        return None


def _is_public_hostname(host: str) -> bool:
    if not host or host == "localhost":
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        if host[0].isdigit() and re.fullmatch(r"[0-9a-fx.]+", host, re.I):
            return False
        labels = host.split(".")
        if len(labels) < 2 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label, re.I) for label in labels
        ):
            return False
        return not host.endswith(
            (
                ".internal",
                ".local",
                ".localhost",
                ".localdomain",
                ".test",
                ".invalid",
                ".lan",
                ".home",
                ".home.arpa",
                ".corp",
                ".intranet",
                ".private",
            )
        )


def _public_evidence(value: Any, field: str) -> PublicEvidence:
    obj = _strict_object(
        value,
        field,
        required=frozenset({"kind", "label", "url"}),
    )
    try:
        kind = PublicEvidenceKind(obj["kind"])
    except (TypeError, ValueError) as exc:
        raise DispatchError(f"{field}.kind is invalid") from exc
    label = _text(obj["label"], f"{field}.label", maximum=256)
    url = _text(obj["url"], f"{field}.url", maximum=512)
    parsed = urlsplit(url)
    hostname = _normalized_hostname(parsed.hostname) if parsed.hostname is not None else None
    try:
        port = parsed.port
    except ValueError as exc:
        raise DispatchError(f"{field}.url has an invalid port") from exc
    if (
        parsed.scheme != "https"
        or hostname is None
        or not _is_public_hostname(hostname)
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or _UNSAFE_EVIDENCE_URL_RE.search(url)
    ):
        raise DispatchError(f"{field}.url must be public HTTPS evidence without credentials or query data")
    github_pattern = _GITHUB_KIND_PATHS.get(kind.value)
    if hostname == "github.com" and github_pattern is not None and not github_pattern.fullmatch(parsed.path):
        raise DispatchError(f"{field}.kind does not match its GitHub URL")
    return PublicEvidence(kind=kind, label=label, url=url)


def _evidence_list(value: Any, field: str) -> tuple[PublicEvidence, ...]:
    items = _list(value, field, MAX_EVIDENCE_PER_ITEM)
    if not items:
        raise DispatchError(f"{field} must cite at least one public source")
    result = tuple(_public_evidence(item, f"{field}[{index}]") for index, item in enumerate(items))
    urls = [item.url for item in result]
    if len(urls) != len(set(urls)):
        raise DispatchError(f"{field} contains duplicate public sources")
    return result


def _snippet(value: Any, field: str) -> Snippet:
    obj = _strict_object(
        value,
        field,
        required=frozenset({"language", "code"}),
    )
    language = _text(obj["language"], f"{field}.language", maximum=32)
    if not _LANGUAGE_RE.fullmatch(language):
        raise DispatchError(f"{field}.language is invalid")
    code = _text(
        obj["code"],
        f"{field}.code",
        maximum=MAX_SNIPPET_BYTES,
        multiline=True,
    )
    return Snippet(language=language, code=code)


def _content_item(value: Any, field: str, section: SectionKind) -> ContentItem:
    obj = _strict_object(
        value,
        field,
        required=frozenset({"title", "body", "attribution", "evidence"}),
        optional=frozenset({"theme", "snippet", "lesson"}),
    )
    try:
        attribution = PublicAttribution(obj["attribution"])
    except (TypeError, ValueError) as exc:
        raise DispatchError(f"{field}.attribution is invalid") from exc
    theme = _text(obj["theme"], f"{field}.theme", maximum=256) if "theme" in obj else None
    snippet = _snippet(obj["snippet"], f"{field}.snippet") if "snippet" in obj else None
    lesson = _text(obj["lesson"], f"{field}.lesson") if "lesson" in obj else None
    if section is SectionKind.SHIPPED:
        if theme is None:
            raise DispatchError(f"{field}.theme is required for thematic Shipped grouping")
        if snippet is not None or lesson is not None:
            raise DispatchError(f"{field} cannot put a review example in Shipped")
    elif section is SectionKind.LENS_CAUGHT:
        if attribution is not PublicAttribution.LENS_REVIEW_FINDING:
            raise DispatchError(f"{field} must be attributed to a Lens review finding")
        if snippet is None or lesson is None:
            raise DispatchError(f"{field} requires a snippet and lesson")
        if theme is not None:
            raise DispatchError(f"{field}.theme is not used in Lens caught this")
    elif theme is not None or snippet is not None or lesson is not None:
        raise DispatchError(f"{field} contains fields not used by {section.value}")
    return ContentItem(
        title=_text(obj["title"], f"{field}.title", maximum=256),
        body=_text(obj["body"], f"{field}.body"),
        attribution=attribution,
        evidence=_evidence_list(obj["evidence"], f"{field}.evidence"),
        theme=theme,
        snippet=snippet,
        lesson=lesson,
    )


def _section(value: Any, field: str) -> Section:
    obj = _strict_object(
        value,
        field,
        required=frozenset({"kind", "items"}),
    )
    try:
        kind = SectionKind(obj["kind"])
    except (TypeError, ValueError) as exc:
        raise DispatchError(f"{field}.kind is invalid") from exc
    raw_items = _list(obj["items"], f"{field}.items", MAX_ITEMS_PER_SECTION)
    if not raw_items:
        raise DispatchError(f"{field}.items cannot be empty; omit the section")
    return Section(
        kind=kind,
        items=tuple(_content_item(item, f"{field}.items[{index}]", kind) for index, item in enumerate(raw_items)),
    )


def _period(value: Any) -> Period:
    obj = _strict_object(
        value,
        "period",
        required=frozenset({"kind", "start", "end"}),
    )
    try:
        kind = PeriodKind(obj["kind"])
        start = date.fromisoformat(_text(obj["start"], "period.start", maximum=10))
        end = date.fromisoformat(_text(obj["end"], "period.end", maximum=10))
    except (TypeError, ValueError) as exc:
        raise DispatchError("period kind or dates are invalid") from exc
    if end < start:
        raise DispatchError("period.end cannot precede period.start")
    if kind is PeriodKind.DAILY and end != start:
        raise DispatchError("a daily Dispatch must cover exactly one day")
    if kind is PeriodKind.WEEKLY and (start.weekday() != 0 or end != start + timedelta(days=6)):
        raise DispatchError("a weekly snapshot must cover Monday through Sunday")
    if kind is PeriodKind.MONTHLY:
        next_month = date(start.year + 1, 1, 1) if start.month == 12 else date(start.year, start.month + 1, 1)
        if start.day != 1 or end != next_month - timedelta(days=1):
            raise DispatchError("a monthly snapshot must cover one complete month")
    return Period(kind=kind, start=start, end=end)


def _topic_update(value: Any, field: str) -> TopicUpdate:
    obj = _strict_object(
        value,
        field,
        required=frozenset(
            {
                "slug",
                "title",
                "state_key",
                "summary",
                "current_state",
                "evidence",
            }
        ),
    )
    current = _list(obj["current_state"], f"{field}.current_state", MAX_TOPIC_STATE_ITEMS)
    if not current:
        raise DispatchError(f"{field}.current_state cannot be empty")
    return TopicUpdate(
        slug=_token(obj["slug"], f"{field}.slug"),
        title=_text(obj["title"], f"{field}.title", maximum=256),
        state_key=_state_key(obj["state_key"], f"{field}.state_key"),
        summary=_text(obj["summary"], f"{field}.summary"),
        current_state=tuple(_text(item, f"{field}.current_state[{index}]") for index, item in enumerate(current)),
        evidence=_evidence_list(obj["evidence"], f"{field}.evidence"),
    )


def _content_texts(manifest: DispatchManifest) -> tuple[str, ...]:
    result: list[str] = []
    for section in manifest.sections:
        for item in section.items:
            result.extend([item.title, item.body, *(evidence.label for evidence in item.evidence)])
            for optional in (item.theme, item.lesson):
                if optional is not None:
                    result.append(optional)
            if item.snippet is not None:
                result.append(item.snippet.code)
    for topic in manifest.topic_updates:
        result.extend(
            [
                topic.title,
                topic.summary,
                *topic.current_state,
                *(evidence.label for evidence in topic.evidence),
            ]
        )
    return tuple(result)


def _manifest_public_texts(manifest: DispatchManifest) -> tuple[str, ...]:
    return (*_content_texts(manifest), *(explanation for _term, explanation in manifest.definitions))


def _validate_authored_links(manifest: DispatchManifest) -> None:
    if any(_AUTHORED_LINK_RE.search(text) for text in _manifest_public_texts(manifest)):
        raise DispatchError("Relay-authored text cannot contain links; use validated public evidence")


def _validate_definitions(manifest: DispatchManifest) -> None:
    definitions = dict(manifest.definitions)
    used = {term for term, _explanation in _used_definitions(_content_texts(manifest), definitions)}
    if used != set(definitions):
        raise DispatchError("unused public definitions would add filler")


def parse_manifest_text(text: str) -> DispatchManifest:
    try:
        encoded = text.encode("utf-8")
    except UnicodeError as exc:
        raise DispatchError("dispatch source must be valid UTF-8") from exc
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise DispatchError(f"dispatch source exceeds {MAX_MANIFEST_BYTES} bytes")
    try:
        raw = json.loads(
            text,
            object_pairs_hook=_pairs_object,
            parse_int=_bounded_json_int,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                DispatchError("dispatch source contains a non-finite number")
            ),
        )
    except DispatchError:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError, ValueError) as exc:
        raise DispatchError("dispatch source is not bounded valid JSON") from exc
    root = _strict_object(
        raw,
        "dispatch source",
        required=frozenset({"version", "period", "sections"}),
        optional=frozenset({"definitions", "topic_updates"}),
    )
    if type(root["version"]) is not int or root["version"] != SCHEMA_VERSION:
        raise DispatchError(f"dispatch source version must be {SCHEMA_VERSION}")
    raw_definitions = root.get("definitions", {})
    if not isinstance(raw_definitions, dict):
        raise DispatchError("definitions must be an object")
    definitions: list[tuple[str, str]] = []
    for term, explanation in raw_definitions.items():
        public_term = _definition_term(term, "definitions term")
        definitions.append((public_term, _text(explanation, f"definitions.{public_term}", maximum=512)))
    raw_sections = _list(root["sections"], "sections", MAX_SECTIONS)
    sections = tuple(_section(item, f"sections[{index}]") for index, item in enumerate(raw_sections))
    order = [
        SectionKind.SHIPPED,
        SectionKind.LENS_CAUGHT,
        SectionKind.WORTH_KNOWING,
        SectionKind.FACTORY_PULSE,
    ]
    indices = [order.index(section.kind) for section in sections]
    if indices != sorted(indices) or len(indices) != len(set(indices)):
        raise DispatchError("sections must be unique and in editorial order")
    raw_topics = _list(root.get("topic_updates", []), "topic_updates", MAX_TOPIC_UPDATES)
    topics = tuple(_topic_update(item, f"topic_updates[{index}]") for index, item in enumerate(raw_topics))
    slugs = [topic.slug for topic in topics]
    if len(slugs) != len(set(slugs)):
        raise DispatchError("topic_updates contains duplicate slugs")
    manifest = DispatchManifest(
        period=_period(root["period"]),
        definitions=tuple(sorted(definitions)),
        sections=sections,
        topic_updates=topics,
    )
    _validate_definitions(manifest)
    _validate_authored_links(manifest)
    return manifest


def load_manifest(path: Path) -> DispatchManifest:
    try:
        if path.is_symlink():
            raise DispatchError("dispatch source must be a regular non-symlink file")
        source = path.resolve(strict=True)
        if not source.is_file():
            raise DispatchError("dispatch source must be a regular non-symlink file")
        if source.stat().st_size > MAX_MANIFEST_BYTES:
            raise DispatchError(f"dispatch source exceeds {MAX_MANIFEST_BYTES} bytes")
        content = source.read_bytes()
        if len(content) > MAX_MANIFEST_BYTES:
            raise DispatchError(f"dispatch source exceeds {MAX_MANIFEST_BYTES} bytes")
        text = content.decode("utf-8")
    except DispatchError:
        raise
    except UnicodeError as exc:
        raise DispatchError("dispatch source must be valid UTF-8") from exc
    except (OSError, RuntimeError) as exc:
        raise DispatchError(f"cannot read dispatch source: {type(exc).__name__}") from exc
    return parse_manifest_text(text)


def _markdown_text(text: str) -> str:
    result = text.replace("\\", "\\\\")
    for character in ("`", "*", "_", "[", "]", "<", ">", "#"):
        result = result.replace(character, f"\\{character}")
    if re.match(r"^(?:[-+=]|\d+[.)])\s", result):
        result = "\\" + result
    return result


def _markdown_link_label(text: str) -> str:
    # A hash is inert inside a link label and keeping it literal makes issue and
    # pull-request labels readable without weakening the surrounding escaping.
    return _markdown_text(text).replace(r"\#", "#")


def _attribution_label(attribution: PublicAttribution) -> str:
    return {
        PublicAttribution.LENS_REVIEW_FINDING: "Independent review finding (Lens)",
        PublicAttribution.FORGE_IMPLEMENTATION_DISCOVERY: "Implementation discovery (Forge issue owner)",
        PublicAttribution.PREEXISTING_BUG_EXPOSED_BY_TESTING: "Pre-existing bug exposed by testing",
        PublicAttribution.INFRASTRUCTURE_ENVIRONMENT_PROBLEM: "Infrastructure or environment finding",
        PublicAttribution.FACTORY_PROCESS_OBSERVATION: "Software-factory process observation",
        PublicAttribution.RELAY_SYNTHESIS: "Editorial synthesis (Relay coordinator)",
    }[attribution]


def _evidence_markdown(evidence: Sequence[PublicEvidence]) -> str:
    return ", ".join(f"[{_markdown_link_label(item.label)}]({item.url})" for item in evidence)


def _code_fence(snippet: Snippet) -> str:
    longest = max((len(run) for run in re.findall(r"`+", snippet.code)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{snippet.language}\n{snippet.code}\n{fence}"


def _used_definitions(texts: Sequence[str], definitions: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    expanded_texts = list(texts)
    used: set[str] = set()
    while True:
        newly_used = {
            term
            for term in definitions
            if term not in used
            and any(re.search(rf"(?<!\w){re.escape(term)}(?!\w)", text, re.I) for text in expanded_texts)
        }
        if not newly_used:
            break
        used.update(newly_used)
        expanded_texts.extend(definitions[term] for term in newly_used)
    return tuple((term, explanation) for term, explanation in definitions.items() if term in used)


def _render_definitions(definitions: Sequence[tuple[str, str]]) -> list[str]:
    if not definitions:
        return []
    lines = ["**SafeYolo terms used here:**"]
    lines.extend(f"- `{term}` — {_markdown_text(explanation)}" for term, explanation in definitions)
    return [*lines, ""]


def render_dispatch(manifest: DispatchManifest) -> str | None:
    if not manifest.sections:
        return None
    definitions = dict(manifest.definitions)
    texts: list[str] = []
    for section in manifest.sections:
        for item in section.items:
            texts.extend([item.title, item.body, *(evidence.label for evidence in item.evidence)])
            texts.extend(value for value in (item.theme, item.lesson) if value is not None)
            if item.snippet is not None:
                texts.append(item.snippet.code)
    lines = [
        "---",
        "dispatch_schema: safeyolo.dispatch/v1",
        f"period: {manifest.period.kind.value}",
        f"start: {manifest.period.start.isoformat()}",
        f"end: {manifest.period.end.isoformat()}",
        "editor: Relay",
        "---",
        "",
        f"# SafeYolo Dispatch — {manifest.period.heading}",
        "",
        "_Relay, SafeYolo's coordinator and editor, selected and synthesized this material from linked public evidence. Worker notes were treated as nominations, not publication copy._",
        "",
        *_render_definitions(_used_definitions(texts, definitions)),
    ]
    section_headings = {
        SectionKind.SHIPPED: "Shipped",
        SectionKind.LENS_CAUGHT: "Lens caught this",
        SectionKind.WORTH_KNOWING: "Worth knowing",
        SectionKind.FACTORY_PULSE: "Factory pulse",
    }
    for section in manifest.sections:
        lines.extend([f"## {section_headings[section.kind]}", ""])
        if section.kind is SectionKind.SHIPPED:
            themes: dict[str, list[ContentItem]] = {}
            for item in section.items:
                assert item.theme is not None
                themes.setdefault(item.theme, []).append(item)
            for theme, items in themes.items():
                lines.extend([f"### {_markdown_text(theme)}", ""])
                for item in items:
                    lines.extend(_render_item(item, heading_level=4))
        else:
            for item in section.items:
                lines.extend(_render_item(item, heading_level=3))
    result = "\n".join(lines).rstrip() + "\n"
    if len(result.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise DispatchError("rendered Dispatch exceeds the output bound")
    _hygiene(result, "rendered Dispatch")
    return result


def _render_item(item: ContentItem, *, heading_level: int) -> list[str]:
    lines = [
        f"{'#' * heading_level} {_markdown_text(item.title)}",
        "",
        f"**Attribution:** {_attribution_label(item.attribution)}",
        "",
    ]
    if item.snippet is not None:
        lines.extend([_code_fence(item.snippet), ""])
    lines.extend([_markdown_text(item.body), ""])
    if item.lesson is not None:
        lines.extend([f"**Lesson:** {_markdown_text(item.lesson)}", ""])
    lines.extend([f"**Evidence:** {_evidence_markdown(item.evidence)}", ""])
    return lines


def render_topic(topic: TopicUpdate, manifest: DispatchManifest) -> str:
    definitions = dict(manifest.definitions)
    texts = [
        topic.title,
        topic.summary,
        *topic.current_state,
        *(evidence.label for evidence in topic.evidence),
    ]
    lines = [
        f"<!-- safeyolo-topic-state: {topic.state_key} -->",
        f"# {_markdown_text(topic.title)}",
        "",
        f"_Last materially updated through {manifest.period.end.isoformat()}. Relay editorial synthesis._",
        "",
        *_render_definitions(_used_definitions(texts, definitions)),
        _markdown_text(topic.summary),
        "",
        "## Current state",
        "",
        *(f"- {_markdown_text(item)}" for item in topic.current_state),
        "",
        "## Public evidence",
        "",
        *(f"- [{_markdown_link_label(item.label)}]({item.url})" for item in topic.evidence),
        "",
    ]
    result = "\n".join(lines).rstrip() + "\n"
    if len(result.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise DispatchError("rendered topic exceeds the output bound")
    _hygiene(result, f"rendered topic {topic.slug}")
    return result


def generate_files(
    manifest: DispatchManifest,
) -> tuple[GeneratedFile, ...]:
    """Build public files only; no network, policy, factory, or publish action."""

    files: list[GeneratedFile] = []
    dispatch = render_dispatch(manifest)
    if dispatch is not None:
        files.append(GeneratedFile(manifest.period.relative_path, dispatch))
    for topic in manifest.topic_updates:
        rendered = render_topic(topic, manifest)
        files.append(GeneratedFile(topic.relative_path, rendered))
    return tuple(files)


def _validate_output_path(relative: Path) -> None:
    if relative.is_absolute() or ".." in relative.parts:
        raise DispatchError("generated output path escapes the publication tree")
    if (
        len(relative.parts) != 2
        or relative.parts[0]
        not in {  # DOC: docs/dispatch-generation.md
            "dispatch",
            "snapshots",
            "topics",
        }
        or relative.suffix != ".md"
    ):
        raise DispatchError("generated output path is outside the publication tree")


def _output_root(path: Path, *, create: bool) -> Path:
    try:
        if path.is_symlink():
            raise DispatchError("output root cannot be a symlink")
        if not path.exists():
            if not create:
                raise DispatchError("generated output root or directory is missing")
            path.mkdir(parents=True, mode=0o755)
        root = path.resolve(strict=True)
    except DispatchError:
        raise
    except (OSError, RuntimeError) as exc:
        raise DispatchError("output root must be a real directory") from exc
    if not root.is_dir():
        raise DispatchError("output root must be a real directory")
    return root


def _output_target(root: Path, relative: Path, *, create: bool) -> Path:
    parent = root / relative.parent
    try:
        if not parent.exists():
            if not create:
                raise DispatchError("generated output root or directory is missing")
            parent.mkdir(mode=0o755)
        resolved_parent = parent.resolve(strict=True)
    except DispatchError:
        raise
    except (OSError, RuntimeError) as exc:
        raise DispatchError("generated output root or directory is invalid") from exc
    if not resolved_parent.is_dir() or not resolved_parent.is_relative_to(root):
        raise DispatchError("generated output path escapes through a symlink")
    target = resolved_parent / relative.name
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise DispatchError("generated output must be a regular non-symlink file")
    return target


def _read_existing(target: Path) -> str | None:
    if not target.exists():
        return None
    try:
        if target.stat().st_size > MAX_OUTPUT_BYTES:
            raise DispatchError("existing generated output exceeds the size bound")
        content = target.read_bytes()
        if len(content) > MAX_OUTPUT_BYTES:
            raise DispatchError("existing generated output exceeds the size bound")
        return content.decode("utf-8")
    except DispatchError:
        raise
    except UnicodeError as exc:
        raise DispatchError("cannot read generated output: UnicodeError") from exc
    except OSError as exc:
        raise DispatchError(f"cannot read generated output: {type(exc).__name__}") from exc


def write_generated_files(
    output_root: Path,
    files: Sequence[GeneratedFile],
    *,
    check: bool = False,
) -> tuple[Path, ...]:
    """Atomically write only fixed publication-tree paths, or check them."""

    changed: list[Path] = []
    seen: set[Path] = set()
    for generated in files:
        relative = generated.relative_path
        _validate_output_path(relative)
        if relative in seen:
            raise DispatchError("generated output path duplicates the publication tree")
        if len(generated.content.encode("utf-8")) > MAX_OUTPUT_BYTES:
            raise DispatchError("generated output exceeds the size bound")
        seen.add(relative)
    if not files:
        return ()

    root = _output_root(output_root, create=not check)
    for generated in files:
        relative = generated.relative_path
        target = _output_target(root, relative, create=not check)
        existing = _read_existing(target)
        if existing == generated.content:
            continue
        if check:
            raise DispatchError(f"generated output is missing or stale: {relative.as_posix()}")
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=target.parent,
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(fd, 0o644)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                fd = -1
                handle.write(generated.content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        finally:
            if fd >= 0:
                os.close(fd)
            temporary.unlink(missing_ok=True)
        changed.append(relative)
    return tuple(changed)
