"""Small durable Relay workflow for evidence-backed factory proposals.

Candidate body fields are nominations, not facts.  This module only records a
candidate after a caller-provided verifier returns bounded authoritative facts
and an existing-issue checker has run.  Canonical nomination provenance comes
from :func:`completion_notes.parse_completion_envelope`.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import tempfile
import threading
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any

from safeyolo.coord import completion_notes
from safeyolo.coord.identity import coord_data_dir

LEDGER_VERSION = 1
MAX_LEDGER_BYTES = 2 * 1024 * 1024
MAX_PROPOSALS = 256
MAX_EVIDENCE = 64
MAX_FACTS = 16
MAX_KEY_BYTES = 128
MAX_REF_BYTES = 512
MAX_FACT_BYTES = 512
MAX_TEXT_BYTES = 2 * 1024

_FINGERPRINT_RE = re.compile(r"^factory-[0-9a-f]{64}$")
_REVISION_RE = re.compile(r"^rev-[0-9a-f]{64}$")
_MSG_ID_RE = re.compile(r"^msg-[0-9a-f]{32}$")
_TASK_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,127}$")
_PATH_LOCKS: dict[str, threading.RLock] = {}
_PATH_LOCKS_GUARD = threading.Lock()


class ProposalStatus(
    StrEnum
):  # DOC: docs/factory-proposals.md, cli/src/safeyolo/agent_context/skills/safeyolo/references/factory-proposals.md
    OBSERVED = "observed"
    PROPOSAL_READY = "proposal_ready"
    PRESENTED = "presented"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    DEFERRED = "deferred"
    COVERED = "covered"


class OperatorOutcome(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    DEFERRED = "deferred"
    COVERED = "covered"


class ProposalLedgerError(RuntimeError):
    """Base error for the local proposal ledger."""


class ProposalLedgerCorruptionError(ProposalLedgerError):
    """The existing ledger is malformed and was left untouched."""


class ProposalLedgerLimitError(ProposalLedgerError):
    """A bounded ledger or proposal limit would be exceeded."""


class ProposalTransitionError(ProposalLedgerError):
    """A requested status or presentation transition is invalid."""


@dataclass(frozen=True, order=True)
class VerifiedEvidence:
    kind: completion_notes.EvidenceKind
    ref: str
    task_key: str
    nomination: bool = False

    def to_wire(self) -> dict[str, str]:
        return {
            "kind": self.kind.value,
            "nomination": self.nomination,
            "ref": self.ref,
            "task_key": self.task_key,
        }


@dataclass(frozen=True)
class VerifiedFactoryObservation:
    """Authoritative facts returned by Relay's external evidence verifier."""

    correlation_key: str
    task_key: str
    facts: tuple[str, ...]
    inference: str
    recommendation: str
    recommendation_key: str
    evidence: tuple[VerifiedEvidence, ...]
    impact: str | None = None
    confidence: str | None = None
    material: bool = False


@dataclass(frozen=True)
class ExistingIssueCoverage:
    ref: str


@dataclass(frozen=True)
class ProposalRecord:
    fingerprint: str
    correlation_key: str
    facts: tuple[str, ...]
    inference: str
    recommendation: str
    recommendation_key: str
    impact: str | None
    confidence: str | None
    covered_by: str | None
    evidence: tuple[VerifiedEvidence, ...]
    first_seen: int
    last_seen: int
    status: ProposalStatus
    last_presented_revision: str | None
    proposal_source_sent_at: int
    proposal_source_msg_id: str

    @property
    def revision(self) -> str:
        proposal = {
            "correlation_key": self.correlation_key,
            "facts": list(self.facts),
            "recommendation_key": self.recommendation_key,
        }
        payload = {
            "nomination_tasks": sorted({item.task_key for item in self.evidence if item.nomination}),
            "proposal": proposal,
            "verified_evidence": [item.to_wire() for item in self.evidence if not item.nomination],
        }
        encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
        return "rev-" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class RenderedProposal:
    fingerprint: str
    revision: str
    body: str


EvidenceVerifier = Callable[[completion_notes.ParsedCandidate], VerifiedFactoryObservation | None]
IssueCoverageChecker = Callable[[VerifiedFactoryObservation], ExistingIssueCoverage | None]


def default_ledger_path() -> (
    Path
):  # DOC: docs/factory-proposals.md, cli/src/safeyolo/agent_context/skills/safeyolo/references/factory-proposals.md
    return coord_data_dir() / "factory-proposals.json"


def _path_lock(path: Path) -> threading.RLock:
    key = str(path.resolve(strict=False))
    with _PATH_LOCKS_GUARD:
        return _PATH_LOCKS.setdefault(key, threading.RLock())


def _bounded_text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError(f"{field} must be valid UTF-8") from exc
    if len(encoded) > maximum:
        raise ValueError(f"{field} exceeds {maximum} UTF-8 bytes")
    if any(ord(char) < 0x20 for char in value):
        raise ValueError(f"{field} contains controls")
    return value.strip()


def _stable_key(value: Any, field: str) -> str:
    text = _bounded_text(value, field, MAX_KEY_BYTES)
    normalized = unicodedata.normalize("NFKC", text).casefold()
    normalized = re.sub(r"[^a-z0-9]+", "-", normalized).strip("-")
    if not normalized or len(normalized.encode("ascii")) > MAX_KEY_BYTES:
        raise ValueError(f"{field} does not produce a bounded stable key")
    return normalized


def _correlation_key(value: Any) -> str:
    return _stable_key(value, "correlation_key")


def proposal_fingerprint(correlation_key: str) -> str:
    normalized = _correlation_key(correlation_key)
    digest = hashlib.sha256(b"safeyolo-factory-proposal-v1\0" + normalized.encode("ascii")).hexdigest()
    return "factory-" + digest


def _task_key(value: Any, field: str = "task_key") -> str:
    text = _bounded_text(value, field, MAX_KEY_BYTES)
    if not _TASK_KEY_RE.fullmatch(text):
        raise ValueError(f"{field} has invalid characters")
    return text


def _validate_evidence(
    values: Sequence[VerifiedEvidence],
) -> tuple[VerifiedEvidence, ...]:
    if isinstance(values, (str, bytes)):
        raise ValueError("evidence must be a sequence of VerifiedEvidence")
    normalized: set[VerifiedEvidence] = set()
    for index, item in enumerate(values):
        if not isinstance(item, VerifiedEvidence):
            raise ValueError(f"evidence[{index}] must be VerifiedEvidence")
        try:
            kind = completion_notes.EvidenceKind(item.kind)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"evidence[{index}].kind is invalid") from exc
        if not isinstance(item.nomination, bool):
            raise ValueError(f"evidence[{index}].nomination must be boolean")
        normalized.add(
            VerifiedEvidence(
                kind=kind,
                nomination=item.nomination,
                ref=_bounded_text(item.ref, f"evidence[{index}].ref", MAX_REF_BYTES),
                task_key=_task_key(item.task_key, f"evidence[{index}].task_key"),
            )
        )
        if len(normalized) > MAX_EVIDENCE:
            raise ValueError(f"evidence must contain at most {MAX_EVIDENCE} unique entries")
    return tuple(sorted(normalized))


def _validate_observation(
    observation: VerifiedFactoryObservation,
) -> VerifiedFactoryObservation:
    if not isinstance(observation, VerifiedFactoryObservation):
        raise ValueError("verifier must return VerifiedFactoryObservation or None")
    if not observation.facts or len(observation.facts) > MAX_FACTS:
        raise ValueError(f"facts must contain 1..{MAX_FACTS} entries")
    facts = tuple(
        sorted(
            {_bounded_text(value, f"facts[{index}]", MAX_FACT_BYTES) for index, value in enumerate(observation.facts)}
        )
    )
    return VerifiedFactoryObservation(
        correlation_key=_correlation_key(observation.correlation_key),
        task_key=_task_key(observation.task_key),
        facts=facts,
        inference=_bounded_text(observation.inference, "inference", MAX_TEXT_BYTES),
        recommendation=_bounded_text(observation.recommendation, "recommendation", MAX_TEXT_BYTES),
        recommendation_key=_stable_key(observation.recommendation_key, "recommendation_key"),
        evidence=_validate_evidence(observation.evidence),
        impact=(
            _bounded_text(observation.impact, "impact", MAX_TEXT_BYTES) if observation.impact is not None else None
        ),
        confidence=(
            _bounded_text(observation.confidence, "confidence", MAX_FACT_BYTES)
            if observation.confidence is not None
            else None
        ),
        material=observation.material is True,
    )


def _canonical_source_evidence(
    candidate: completion_notes.ParsedCandidate,
    task_key: str,
) -> VerifiedEvidence:
    provenance = candidate.provenance
    agent_id = provenance.sender_agent_id or "none"
    agent_name = provenance.sender_agent_name or "none"
    ref = (
        f"msg_id={provenance.msg_id};sequence={provenance.coord_sequence};"
        f"sender_kind={provenance.sender_kind};sender_agent_id={agent_id};"
        f"sender_agent_name={agent_name};origin={provenance.origin_instance_id}"
    )
    return VerifiedEvidence(
        kind=completion_notes.EvidenceKind.COORD,
        nomination=True,
        ref=_bounded_text(ref, "canonical coord evidence", MAX_REF_BYTES),
        task_key=task_key,
    )


def _record_to_wire(record: ProposalRecord) -> dict[str, Any]:
    return {
        "evidence": [item.to_wire() for item in record.evidence],
        "fingerprint": record.fingerprint,
        "first_seen": record.first_seen,
        "last_presented_revision": record.last_presented_revision,
        "last_seen": record.last_seen,
        "proposal": {
            "confidence": record.confidence,
            "correlation_key": record.correlation_key,
            "covered_by": record.covered_by,
            "facts": list(record.facts),
            "impact": record.impact,
            "inference": record.inference,
            "recommendation": record.recommendation,
            "recommendation_key": record.recommendation_key,
            "source_msg_id": record.proposal_source_msg_id,
            "source_sent_at": record.proposal_source_sent_at,
        },
        "status": record.status.value,
    }


def _wire_to_record(value: Any, expected_fingerprint: str) -> ProposalRecord:
    if not isinstance(value, dict) or set(value) != {
        "evidence",
        "fingerprint",
        "first_seen",
        "last_presented_revision",
        "last_seen",
        "proposal",
        "status",
    }:
        raise ProposalLedgerCorruptionError("proposal entry has invalid shape")
    proposal = value["proposal"]
    if not isinstance(proposal, dict) or set(proposal) != {
        "confidence",
        "correlation_key",
        "covered_by",
        "facts",
        "impact",
        "inference",
        "recommendation",
        "recommendation_key",
        "source_msg_id",
        "source_sent_at",
    }:
        raise ProposalLedgerCorruptionError("stored proposal has invalid shape")
    try:
        correlation_key = _correlation_key(proposal["correlation_key"])
        fingerprint = proposal_fingerprint(correlation_key)
        if (
            value["fingerprint"] != expected_fingerprint
            or fingerprint != expected_fingerprint
            or not _FINGERPRINT_RE.fullmatch(expected_fingerprint)
        ):
            raise ValueError("fingerprint mismatch")
        facts_value = proposal["facts"]
        if not isinstance(facts_value, list) or not facts_value:
            raise ValueError("facts invalid")
        facts = tuple(_bounded_text(item, "stored fact", MAX_FACT_BYTES) for item in facts_value)
        if facts != tuple(sorted(set(facts))) or len(facts) > MAX_FACTS:
            raise ValueError("facts not canonical")
        evidence_value = value["evidence"]
        if not isinstance(evidence_value, list):
            raise ValueError("evidence invalid")
        evidence = _validate_evidence(
            tuple(
                VerifiedEvidence(
                    kind=completion_notes.EvidenceKind(item["kind"]),
                    nomination=item["nomination"],
                    ref=item["ref"],
                    task_key=item["task_key"],
                )
                for item in evidence_value
                if isinstance(item, dict) and set(item) == {"kind", "nomination", "ref", "task_key"}
            )
        )
        if len(evidence) != len(evidence_value):
            raise ValueError("evidence shape invalid")
        first_seen = value["first_seen"]
        last_seen = value["last_seen"]
        if (
            isinstance(first_seen, bool)
            or not isinstance(first_seen, int)
            or isinstance(last_seen, bool)
            or not isinstance(last_seen, int)
            or first_seen < 0
            or last_seen < first_seen
        ):
            raise ValueError("timestamps invalid")
        source_sent_at = proposal["source_sent_at"]
        source_msg_id = proposal["source_msg_id"]
        if (
            isinstance(source_sent_at, bool)
            or not isinstance(source_sent_at, int)
            or source_sent_at < first_seen
            or source_sent_at > last_seen
            or not isinstance(source_msg_id, str)
            or not _MSG_ID_RE.fullmatch(source_msg_id)
        ):
            raise ValueError("proposal source is invalid")
        last_revision = value["last_presented_revision"]
        if last_revision is not None and (
            not isinstance(last_revision, str) or not _REVISION_RE.fullmatch(last_revision)
        ):
            raise ValueError("revision invalid")
        record = ProposalRecord(
            fingerprint=fingerprint,
            correlation_key=correlation_key,
            facts=facts,
            inference=_bounded_text(proposal["inference"], "stored inference", MAX_TEXT_BYTES),
            recommendation=_bounded_text(
                proposal["recommendation"],
                "stored recommendation",
                MAX_TEXT_BYTES,
            ),
            recommendation_key=_stable_key(proposal["recommendation_key"], "stored recommendation_key"),
            impact=(
                _bounded_text(proposal["impact"], "stored impact", MAX_TEXT_BYTES)
                if proposal["impact"] is not None
                else None
            ),
            confidence=(
                _bounded_text(proposal["confidence"], "stored confidence", MAX_FACT_BYTES)
                if proposal["confidence"] is not None
                else None
            ),
            covered_by=(
                _bounded_text(proposal["covered_by"], "covered_by", MAX_REF_BYTES)
                if proposal["covered_by"] is not None
                else None
            ),
            evidence=evidence,
            first_seen=first_seen,
            last_seen=last_seen,
            status=ProposalStatus(value["status"]),
            last_presented_revision=last_revision,
            proposal_source_sent_at=source_sent_at,
            proposal_source_msg_id=source_msg_id,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProposalLedgerCorruptionError("proposal entry failed validation") from exc
    if record.status is ProposalStatus.COVERED and record.covered_by is None:
        raise ProposalLedgerCorruptionError("covered proposal is missing its coverage marker")
    if (
        record.status
        in {
            ProposalStatus.PRESENTED,
            ProposalStatus.ACCEPTED,
            ProposalStatus.REJECTED,
            ProposalStatus.DEFERRED,
        }
        and record.last_presented_revision is None
    ):
        raise ProposalLedgerCorruptionError("post-presentation status is missing its revision marker")
    if (
        record.status
        in {
            ProposalStatus.PRESENTED,
            ProposalStatus.DEFERRED,
        }
        and record.revision != record.last_presented_revision
    ):
        raise ProposalLedgerCorruptionError("active presentation status does not match its revision marker")
    return record


class FactoryProposalLedger:  # DOC: docs/factory-proposals.md, cli/src/safeyolo/agent_context/skills/safeyolo/references/factory-proposals.md
    """Locked, atomic JSON proposal ledger; not a general observation store."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_ledger_path()
        self.lock_path = self.path.with_name(self.path.name + ".lock")

    @contextmanager
    def _locked(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock = _path_lock(self.path)
        with lock:
            fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            with os.fdopen(fd, "r+") as lock_file:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _read_unlocked(self) -> dict[str, ProposalRecord]:
        if not self.path.exists():
            return {}
        try:
            if self.path.stat().st_size > MAX_LEDGER_BYTES:
                raise ProposalLedgerCorruptionError("proposal ledger exceeds size bound")
            raw = self.path.read_text(encoding="utf-8")

            def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
                result: dict[str, Any] = {}
                for key, value in values:
                    if key in result:
                        raise ProposalLedgerCorruptionError("proposal ledger contains duplicate JSON keys")
                    result[key] = value
                return result

            document = json.loads(raw, object_pairs_hook=pairs)
        except ProposalLedgerCorruptionError:
            raise
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            RecursionError,
            ValueError,
            OverflowError,
        ) as exc:
            raise ProposalLedgerCorruptionError("proposal ledger is unreadable") from exc
        if (
            not isinstance(document, dict)
            or set(document) != {"proposals", "version"}
            or document["version"] != LEDGER_VERSION
            or not isinstance(document["proposals"], dict)
            or len(document["proposals"]) > MAX_PROPOSALS
        ):
            raise ProposalLedgerCorruptionError("proposal ledger root is invalid")
        return {
            fingerprint: _wire_to_record(value, fingerprint) for fingerprint, value in document["proposals"].items()
        }

    def _write_unlocked(self, records: Mapping[str, ProposalRecord]) -> None:
        document = {
            "proposals": {key: _record_to_wire(records[key]) for key in sorted(records)},
            "version": LEDGER_VERSION,
        }
        payload = json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
        if len(payload.encode("ascii")) > MAX_LEDGER_BYTES:
            raise ProposalLedgerLimitError("proposal ledger exceeds size bound")
        fd, temporary = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.name}.", suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise

    def list(self) -> tuple[ProposalRecord, ...]:
        with self._locked():
            records = self._read_unlocked()
            return tuple(records[key] for key in sorted(records))

    def get(self, fingerprint: str) -> ProposalRecord | None:
        with self._locked():
            return self._read_unlocked().get(fingerprint)

    def _observe_checked(
        self,
        observation: VerifiedFactoryObservation,
        candidate: completion_notes.ParsedCandidate,
        coverage: ExistingIssueCoverage | None,
    ) -> ProposalRecord:
        verified = _validate_observation(observation)
        if candidate.candidate_type is not completion_notes.CandidateType.FACTORY:
            raise ValueError("only FACTORY_CANDIDATE observations can enter this ledger")
        covered_by = _bounded_text(coverage.ref, "existing issue ref", MAX_REF_BYTES) if coverage is not None else None
        source = _canonical_source_evidence(candidate, verified.task_key)
        incoming_evidence = _validate_evidence((*verified.evidence, source))
        fingerprint = proposal_fingerprint(verified.correlation_key)
        seen_at = candidate.provenance.sent_at
        with self._locked():
            records = self._read_unlocked()
            current = records.get(fingerprint)
            if current is None:
                if len(records) >= MAX_PROPOSALS:
                    raise ProposalLedgerLimitError(f"proposal ledger supports at most {MAX_PROPOSALS} proposals")
                evidence = incoming_evidence
                task_count = len({item.task_key for item in evidence})
                status = (
                    ProposalStatus.COVERED
                    if covered_by is not None
                    else (
                        ProposalStatus.PROPOSAL_READY
                        if verified.material or task_count >= 2
                        else ProposalStatus.OBSERVED
                    )
                )
                updated = ProposalRecord(
                    fingerprint=fingerprint,
                    correlation_key=verified.correlation_key,
                    facts=verified.facts,
                    inference=verified.inference,
                    recommendation=verified.recommendation,
                    recommendation_key=verified.recommendation_key,
                    impact=verified.impact,
                    confidence=verified.confidence,
                    covered_by=covered_by,
                    evidence=evidence,
                    first_seen=seen_at,
                    last_seen=seen_at,
                    status=status,
                    last_presented_revision=None,
                    proposal_source_sent_at=seen_at,
                    proposal_source_msg_id=candidate.provenance.msg_id,
                )
            else:
                if current.status in {
                    ProposalStatus.ACCEPTED,
                    ProposalStatus.REJECTED,
                    ProposalStatus.COVERED,
                }:
                    # Operator decisions bind the exact decided snapshot. A
                    # later nomination cannot rewrite what was accepted,
                    # rejected, or already covered.
                    return current
                evidence = _validate_evidence((*current.evidence, *incoming_evidence))
                facts = tuple(sorted(set(current.facts) | set(verified.facts)))
                if len(facts) > MAX_FACTS:
                    raise ProposalLedgerLimitError(f"proposal supports at most {MAX_FACTS} facts")
                incoming_source = (seen_at, candidate.provenance.msg_id)
                current_source = (
                    current.proposal_source_sent_at,
                    current.proposal_source_msg_id,
                )
                selected = (
                    {
                        "confidence": verified.confidence,
                        "impact": verified.impact,
                        "inference": verified.inference,
                        "proposal_source_msg_id": candidate.provenance.msg_id,
                        "proposal_source_sent_at": seen_at,
                        "recommendation": verified.recommendation,
                        "recommendation_key": verified.recommendation_key,
                    }
                    if incoming_source > current_source
                    else {}
                )
                updated = replace(
                    current,
                    facts=facts,
                    covered_by=current.covered_by or covered_by,
                    evidence=evidence,
                    first_seen=min(current.first_seen, seen_at),
                    last_seen=max(current.last_seen, seen_at),
                    **selected,
                )
                if (
                    current.status is ProposalStatus.PROPOSAL_READY
                    and updated.revision == current.revision
                    and covered_by is None
                ):
                    # Once pending() can hand this revision to Relay, its exact
                    # rendered snapshot stays fixed. Non-material nominations
                    # may advance last_seen but cannot create a second body for
                    # the same presentation revision.
                    updated = replace(
                        current,
                        last_seen=max(current.last_seen, seen_at),
                    )
                task_count = len({item.task_key for item in evidence})
                if current.status is ProposalStatus.OBSERVED and (verified.material or task_count >= 2):
                    updated = replace(updated, status=ProposalStatus.PROPOSAL_READY)
                elif (
                    current.status
                    in {
                        ProposalStatus.PRESENTED,
                        ProposalStatus.DEFERRED,
                    }
                    and updated.revision != current.last_presented_revision
                ):
                    updated = replace(updated, status=ProposalStatus.PROPOSAL_READY)
                elif current.status in {
                    ProposalStatus.PRESENTED,
                    ProposalStatus.DEFERRED,
                }:
                    # Non-material rendering metadata never rewrites the
                    # presented proposal snapshot or causes re-presentation.
                    updated = replace(
                        updated,
                        confidence=current.confidence,
                        impact=current.impact,
                        inference=current.inference,
                        proposal_source_msg_id=current.proposal_source_msg_id,
                        proposal_source_sent_at=current.proposal_source_sent_at,
                        recommendation=current.recommendation,
                        recommendation_key=current.recommendation_key,
                    )
                if updated.covered_by is not None:
                    updated = replace(updated, status=ProposalStatus.COVERED)
            records[fingerprint] = updated
            self._write_unlocked(records)
            return updated

    def pending(self) -> tuple[RenderedProposal, ...]:
        with self._locked():
            records = self._read_unlocked()
            return tuple(
                render_proposal(record)
                for _, record in sorted(records.items())
                if record.status is ProposalStatus.PROPOSAL_READY and record.revision != record.last_presented_revision
            )

    def mark_presented(
        self,
        rendered: RenderedProposal,
        sent_envelope: Mapping[str, Any],
        *,
        relay_agent_name: str = "relay",
    ) -> ProposalRecord:
        parsed_provenance = completion_notes.parse_completion_envelope(sent_envelope)
        if (
            parsed_provenance.delivery_state is not None
            or sent_envelope.get("sender_kind") != "agent"
            or sent_envelope.get("sender_agent_name") != relay_agent_name
            or sent_envelope.get("body") != rendered.body
        ):
            raise ProposalTransitionError("presentation must be the exact canonical Relay agent envelope")
        with self._locked():
            records = self._read_unlocked()
            current = records.get(rendered.fingerprint)
            if current is None:
                raise ProposalTransitionError("proposal no longer exists")
            current_rendered = render_proposal(current) if current.status is ProposalStatus.PROPOSAL_READY else None
            if (
                current_rendered is None
                or current.revision != rendered.revision
                or current_rendered.body != rendered.body
            ):
                raise ProposalTransitionError("proposal revision is no longer ready")
            updated = ProposalRecord(
                **{
                    **current.__dict__,
                    "status": ProposalStatus.PRESENTED,
                    "last_presented_revision": rendered.revision,
                }
            )
            records[current.fingerprint] = updated
            self._write_unlocked(records)
            return updated

    def reconcile_presentations(
        self,
        retained_envelopes: Sequence[Mapping[str, Any]],
        *,
        relay_agent_name: str = "relay",
    ) -> tuple[ProposalRecord, ...]:
        """Mark exact Relay sends found after a send/ledger crash boundary.

        Relay calls this on retained operator-facing room history before
        sending anything returned by :meth:`pending` after restart.
        """

        pending_by_body = {item.body: item for item in self.pending()}
        reconciled: list[ProposalRecord] = []
        for envelope in retained_envelopes:
            body = envelope.get("body")
            rendered = pending_by_body.get(body) if isinstance(body, str) else None
            if (
                rendered is None
                or envelope.get("sender_kind") != "agent"
                or envelope.get("sender_agent_name") != relay_agent_name
            ):
                continue
            reconciled.append(
                self.mark_presented(
                    rendered,
                    envelope,
                    relay_agent_name=relay_agent_name,
                )
            )
            pending_by_body.pop(body)
        return tuple(reconciled)

    def record_operator_outcome(
        self,
        fingerprint: str,
        outcome: OperatorOutcome,
        operator_envelope: Mapping[str, Any],
    ) -> ProposalRecord:
        if not isinstance(outcome, OperatorOutcome):
            raise ProposalTransitionError("operator outcome is invalid")
        expected_body = f"FACTORY_PROPOSAL_OUTCOME fingerprint={fingerprint} status={outcome.value}"
        completion_notes.parse_completion_envelope(operator_envelope)
        if operator_envelope.get("sender_kind") != "operator" or operator_envelope.get("body") != expected_body:
            raise ProposalTransitionError("outcome must be the exact canonical operator envelope")
        with self._locked():
            records = self._read_unlocked()
            current = records.get(fingerprint)
            if current is None:
                raise ProposalTransitionError("proposal does not exist")
            if current.status not in {
                ProposalStatus.PRESENTED,
                ProposalStatus.DEFERRED,
            }:
                raise ProposalTransitionError(f"cannot apply operator outcome from {current.status.value}")
            updated = ProposalRecord(
                **{
                    **current.__dict__,
                    "covered_by": (
                        current.covered_by or "operator-confirmed"
                        if outcome is OperatorOutcome.COVERED
                        else current.covered_by
                    ),
                    "status": ProposalStatus(outcome.value),
                }
            )
            records[fingerprint] = updated
            self._write_unlocked(records)
            return updated


class FactoryProposalWorkflow:  # DOC: docs/factory-proposals.md, cli/src/safeyolo/agent_context/skills/safeyolo/references/factory-proposals.md
    """Parse, verify, coverage-check, and record factory nominations."""

    def __init__(self, ledger: FactoryProposalLedger) -> None:
        self.ledger = ledger

    def consume_envelope(
        self,
        envelope: Mapping[str, Any],
        *,
        verify: EvidenceVerifier,
        find_existing_issue: IssueCoverageChecker,
    ) -> tuple[ProposalRecord, ...]:
        parsed = completion_notes.parse_completion_envelope(envelope)
        if parsed.trailer_status != "valid":
            return ()
        records: list[ProposalRecord] = []
        for candidate in parsed.candidates:
            if candidate.candidate_type is not completion_notes.CandidateType.FACTORY:
                continue
            observation = verify(candidate)
            if observation is None:
                continue
            verified = _validate_observation(observation)
            # The authoritative issue lookup happens before any durable write.
            coverage = find_existing_issue(verified)
            if coverage is not None and not isinstance(coverage, ExistingIssueCoverage):
                raise ValueError("issue checker must return ExistingIssueCoverage or None")
            records.append(self.ledger._observe_checked(verified, candidate, coverage))
        return tuple(records)


def render_proposal(  # DOC: docs/factory-proposals.md, cli/src/safeyolo/agent_context/skills/safeyolo/references/factory-proposals.md
    record: ProposalRecord,
) -> RenderedProposal:
    if record.status is not ProposalStatus.PROPOSAL_READY:
        raise ProposalTransitionError("only proposal-ready records can be rendered")
    evidence_lines = [f"- [{item.kind.value}] {item.ref} (task {item.task_key})" for item in record.evidence]
    fact_lines = [f"- {fact}" for fact in record.facts]
    lines = [
        "Factory improvement proposal",
        "",
        f"Fingerprint: {record.fingerprint}",
        f"Revision: {record.revision}",
        "",
        "Observed facts (verified):",
        *fact_lines,
        "",
        "Authoritative evidence:",
        *evidence_lines,
        "",
        "Observed cost/risk:",
        record.impact or "Not independently quantified.",
        "",
        "Relay inference:",
        record.inference,
        "",
        "Relay recommendation:",
        record.recommendation,
        "",
        "Confidence / uncertainty:",
        record.confidence or "Not stated.",
        "",
        "Existing issue coverage:",
        record.covered_by or "None found during authoritative verification.",
        "",
        "Operator decision required; no change has been applied.",
    ]
    return RenderedProposal(
        fingerprint=record.fingerprint,
        revision=record.revision,
        body="\n".join(lines),
    )
