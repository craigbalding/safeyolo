"""Trusted attempt records and bounded readers for paired hardware results.

Keep this installation outside candidate execution trees. Candidate reports
are input, never allocation, cleanup or publication authority.
"""

from __future__ import annotations

import collections
import json
import os
import re
import stat
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from ..installed_sections import PYTEST_SUITES, SECTIONS, installed_runtime_summary, pytest_summary
from ..installed_staging import BOOT_FILES, verify_boot_provenance
from ..pytest_observations import MAX_CASES

MAX_REPORT_BYTES = 8 * 1024 * 1024
FAILURE_STAGES = {"selection", "preflight", "allocation", "build", "transfer", "execution", "report", "cleanup",
                  "publication", "cancelled"}


def read_json(path: Path, *, maximum: int | None = None) -> dict:
    """Never follow a report symlink, block on a FIFO or read unbounded output."""
    maximum = MAX_REPORT_BYTES if maximum is None else maximum
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("report must be a bounded regular file")
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("report grew beyond the read bound")
    document = json.loads(data)
    if not isinstance(document, dict):
        raise ValueError("report must contain a JSON mapping")
    return document


def hexadecimal(value, length: int) -> str:
    if not isinstance(value, str) or re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is None:
        raise ValueError("invalid recorded identity")
    return value


def integer(value, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError("invalid recorded count or exit")
    return value


def timestamp(value) -> datetime:
    if not isinstance(value, str):
        raise ValueError("missing recorded timestamp")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("recorded timestamp needs a timezone")
    return parsed.astimezone(UTC)


def interval(data: dict, start: datetime, finish: datetime) -> tuple[datetime, datetime]:
    first, last = timestamp(data["started_at"]), timestamp(data["finished_at"])
    if not start <= first <= last <= finish:
        raise ValueError("stale or inconsistent report interval")
    return first, last


def pytest_result(data: dict, summary: dict, section_interval: tuple[datetime, datetime]) -> dict:
    """Select the maintained pytest schema; retained failures remain failures."""
    if (data["schema_version"] != 1 or type(data["schema_version"]) is not int
            or data["run_id"] != summary["run_id"] or data["source_revision"] != summary["source_revision"]
            or data["suite"] not in PYTEST_SUITES):
        raise ValueError("pytest result has mismatched attribution")
    interval(data, *section_interval)
    for name in ("exit", "collected", "deselected", "collection_errors", "omitted_cases"):
        integer(data[name])
    counts, cases = data["counts"], data["cases"]
    if (not isinstance(counts, dict) or not isinstance(cases, list) or len(cases) > MAX_CASES
            or set(counts) - {"passed", "failed", "skipped", "unexecuted"}):
        raise ValueError("invalid pytest outcome inventory")
    for count in counts.values():
        integer(count)
    if (sum(counts.values()) != data["collected"]
            or len(cases) + data["omitted_cases"] != data["collected"]):
        raise ValueError("partial pytest outcome inventory")
    for case in cases:
        if (not isinstance(case["test"], str) or re.fullmatch(r"[A-Za-z0-9_.:-]{1,300}", case["test"]) is None
                or case["outcome"] not in {"passed", "failed", "skipped", "unexecuted"}
                or case["phase"] not in {None, "setup", "call", "teardown"}):
            raise ValueError("invalid pytest case")
        hexadecimal(case["case_sha256"], 64)
    if not data["omitted_cases"] and dict(collections.Counter(case["outcome"] for case in cases)) != counts:
        raise ValueError("pytest counts contradict retained cases")
    return pytest_summary(data)


def runtime_result(data: dict, summary: dict, section_interval: tuple[datetime, datetime]) -> dict:
    """Check attribution again after transfer, independently of command status."""
    if (data["run_id"] != summary["run_id"] or data["source_revision"] != summary["source_revision"]
            or data["wheel_source_revision"] != summary["source_revision"]
            or data["isolation_platform"] != summary["lane"]
            or data["native_sha256"] != summary["preparation"]["native_sha256"]):
        raise ValueError("runtime differs from selected installed build")
    captured = timestamp(data["captured_at"])
    if not section_interval[0] <= captured <= section_interval[1]:
        raise ValueError("runtime observation is stale")
    host, process = data["host"], data["process"]
    system = "Darwin" if summary["lane"] == "vz" else "Linux"
    if (host["system"] != system or not isinstance(host["machine"], str)
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", host["machine"]) is None
            or (system == "Darwin" and host["machine"] != "arm64")):
        raise ValueError("runtime observation has the wrong execution host")
    pid = integer(process["pid"], minimum=2)
    token = (rf"darwin:{pid}:[0-9]+:[0-9]+" if system == "Darwin"
             else rf"linux:[0-9a-f]{{8}}(?:-[0-9a-f]{{4}}){{3}}-[0-9a-f]{{12}}:{pid}:[0-9]+")
    if not isinstance(process["start_token"], str) or re.fullmatch(token, process["start_token"]) is None:
        raise ValueError("runtime observation has no process start identity")
    hexadecimal(process["instance_id"], 32)
    return installed_runtime_summary(data)


def preparation_result(data: dict, lane: str, revision: str) -> dict:
    result = {"exit": integer(data["exit"])}
    for name in ("native_sha256", "wheel_sha256", "input_index_sha256", "tmux_sha256"):
        if name in data:
            result[name] = hexadecimal(data[name], 64)
    if "tmux_version" in data:
        if not isinstance(data["tmux_version"], str) or re.fullmatch(r"tmux [0-9]+(?:\.[0-9]+)*[a-z]?", data["tmux_version"]) is None:
            raise ValueError("prepared private tmux version is invalid")
        result["tmux_version"] = data["tmux_version"]
    if "source_revision" in data:
        if data["source_revision"] != revision:
            raise ValueError("prepared source differs from selected commit")
        result["source_revision"] = revision
    if "boot_inputs" in data:
        boots = data["boot_inputs"]
        result["boot_inputs"] = verify_boot_provenance(boots, {
            name: hexadecimal(boots[name]["sha256"], 64) for name in BOOT_FILES
        })
    if "vm_helper" in data:
        helper = data["vm_helper"]
        if (helper["git_sha"] != revision or helper["git_dirty"] is not False
                or helper["architecture"] != "arm64" or helper["build_profile"] not in {"production", "development"}):
            raise ValueError("prepared VM helper differs from selected commit")
        result["vm_helper"] = {name: helper[name] for name in ("git_sha", "git_dirty", "architecture", "build_profile")}
    if result["exit"] == 0:
        required = {"native_sha256"}
        if lane == "vz":
            required |= {"wheel_sha256", "source_revision", "input_index_sha256", "boot_inputs", "vm_helper",
                         "tmux_sha256", "tmux_version"}
        if not required <= result.keys():
            raise ValueError("successful preparation lacks installed input identities")
    return result


def section_result(row: dict, summary: dict, bounds: tuple[datetime, datetime]) -> dict:
    if (row["section"] not in SECTIONS[summary["lane"]] or type(row["executed"]) is not bool
            or row["result"] not in {"passed", "assertion_failure", "preparation_failure", "cleanup_failure", "evidence_failure"}
            or row["cleanup"] not in {"stopped", "failed"}):
        raise ValueError("invalid installed section result")
    section_interval = interval(row, *bounds)
    result = {name: row[name] for name in ("section", "executed", "started_at", "finished_at", "result", "cleanup")}
    for name in ("exit", "cleanup_failure_count", "evidence_failure_count"):
        result[name] = integer(row[name])
    if row.get("installed_runtime") is not None:
        result["installed_runtime"] = runtime_result(row["installed_runtime"], summary, section_interval)
    if row["section"] == "isolation":
        result["pytest"] = [pytest_result(data, summary, section_interval) for data in row["pytest"]]
        suites = [data["suite"] for data in result["pytest"]]
        if len(suites) != len(set(suites)):
            raise ValueError("duplicate pytest suite observation")
    return result


def section_passed(row: dict) -> bool:
    if (not row["executed"] or row["exit"] != 0 or row["result"] != "passed" or row["cleanup"] != "stopped"
            or row["cleanup_failure_count"] or row["evidence_failure_count"]):
        return False
    if row["section"] != "continuity" and "installed_runtime" not in row:
        return False
    if row["section"] == "isolation":
        suites = row["pytest"]
        return ({data["suite"] for data in suites} == set(PYTEST_SUITES)
                and all(data["exit"] == 0 and data["collected"] > 0
                        and not any(data[name] for name in ("deselected", "collection_errors", "omitted_cases"))
                        and not any(data["counts"].get(name) for name in ("failed", "unexecuted")) for data in suites))
    return True


def lane_result(path: Path, expected: dict) -> dict:
    """Read only the named summary; reject another attempt, SHA or time window."""
    return verified_lane_summary(read_json(path), expected)


def verified_lane_summary(data: dict, expected: dict) -> dict:
    """Use the same field projection for transferred and retained summaries."""
    if (type(data["schema_version"]) is not int or data["schema_version"] != 1
            or any(data[name] != expected[name] for name in ("source_revision", "run_id", "lane"))):
        raise ValueError("installed summary has mismatched attribution")
    started = timestamp(data["started_at"])
    finished = timestamp(data["finished_at"]) if data["finished_at"] is not None else None
    if not timestamp(expected["started_at"]) <= started <= (finished or datetime.now(UTC)) <= datetime.now(UTC):
        raise ValueError("installed summary is stale or has invalid timestamps")
    required = SECTIONS[data["lane"]]
    requested, unexecuted = data["requested_sections"], data["unexecuted_sections"]
    if (not isinstance(requested, list) or not isinstance(unexecuted, list)
            or len(requested) != len(set(requested)) or set(requested) - set(required)
            or len(unexecuted) != len(set(unexecuted)) or set(unexecuted) - set(requested)):
        raise ValueError("invalid section inventory")
    complete_selection = set(requested) == set(required)
    if type(data["full_section_selection"]) is not bool or data["full_section_selection"] != complete_selection:
        raise ValueError("summary contradicts selected sections")
    result = {name: data[name] for name in ("schema_version", "source_revision", "run_id", "lane", "started_at", "finished_at",
                                          "requested_sections", "unexecuted_sections", "full_section_selection")}
    result["exit"] = integer(data["exit"]) if data["exit"] is not None else None
    result["preparation"] = preparation_result(data["preparation"], data["lane"], data["source_revision"])
    result["sections"] = [section_result(row, result, (started, finished or datetime.now(UTC))) for row in data["sections"]]
    names = [row["section"] for row in result["sections"]]
    if len(names) != len(set(names)) or set(names) - set(requested):
        raise ValueError("duplicate or unrequested installed section")
    executed = {row["section"] for row in result["sections"] if row["executed"]}
    if set(unexecuted) != set(requested) - executed:
        raise ValueError("summary contradicts unexecuted sections")
    result["complete_success"] = (finished is not None and result["exit"] == 0 and result["preparation"]["exit"] == 0
                                  and complete_selection and not unexecuted and set(names) == set(required)
                                  and all(section_passed(row) for row in result["sections"]))
    result["skipped_assertions"] = sum(data["counts"].get("skipped", 0)
                                       for row in result["sections"] for data in row.get("pytest", []))
    return result


class HardwareAttempt:
    """Save an attempt before selection/preflight; keep retries in new trees."""

    def __init__(self, root: Path, controller_revision: str, trigger: str):
        hexadecimal(controller_revision, 40)
        if trigger not in {"overnight", "on-demand"}:
            raise ValueError("unknown hardware trigger")
        run_id = uuid.uuid4().hex
        self.directory = root / run_id
        self.directory.mkdir(parents=True, mode=0o700, exist_ok=False)
        self.data = {"schema_version": 1, "run_id": run_id, "owner": f"issue889-{run_id}",
                     "controller_revision": controller_revision, "trigger": trigger,
                     "source_revision": None, "started_at": datetime.now(UTC).isoformat(), "finished_at": None,
                     "failures": [], "lanes": {}, "publication": {"verified": False, "index": None, "parts": []}}
        self.save()

    @classmethod
    def restore(cls, directory: Path) -> HardwareAttempt:
        """Replay the trusted outbox without rerunning or replacing an attempt."""
        data = read_json(directory / "attempt.json", maximum=2 * MAX_REPORT_BYTES + 1024 * 1024)
        run_id = hexadecimal(data["run_id"], 32)
        hexadecimal(data["controller_revision"], 40)
        if (directory.name != run_id or data["owner"] != f"issue889-{run_id}"
                or type(data["schema_version"]) is not int or data["schema_version"] != 1
                or data["trigger"] not in {"overnight", "on-demand"}):
            raise ValueError("invalid trusted attempt identity")
        if data["source_revision"] is not None:
            hexadecimal(data["source_revision"], 40)
        started = timestamp(data["started_at"])
        if data["finished_at"] is not None and timestamp(data["finished_at"]) < started:
            raise ValueError("invalid trusted attempt interval")
        for failure in data["failures"]:
            if failure["stage"] not in FAILURE_STAGES or failure["lane"] not in {None, "kvm", "vz"}:
                raise ValueError("invalid trusted failure stage")
        for lane, row in data["lanes"].items():
            if (lane not in {"kvm", "vz"} or row["lane"] != lane or row["source_revision"] != data["source_revision"]
                    or row["cleanup"] not in {"unverified", "failed", "verified"} or timestamp(row["started_at"]) < started):
                raise ValueError("invalid trusted lane attribution")
            hexadecimal(row["run_id"], 32)
            if row["result"] is not None:
                row["result"] = verified_lane_summary(row["result"], row)
        publication = data["publication"]
        if type(publication["verified"]) is not bool:
            raise ValueError("invalid trusted publication state")
        receipts = publication["parts"] + ([publication["index"]] if publication["index"] is not None else [])
        for receipt in receipts:
            identifier = integer(receipt["id"], minimum=1)
            hexadecimal(receipt["sha256"], 64)
            if receipt["url"] != f"https://github.com/craigbalding/safeyolo/issues/889#issuecomment-{identifier}":
                raise ValueError("publication receipt points outside the hardware issue")
        restored = cls.__new__(cls)
        restored.directory, restored.data = directory, data
        return restored

    def save(self) -> None:
        temporary = self.directory / "attempt.json.tmp"
        with temporary.open("w") as stream:
            json.dump(self.data, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(self.directory / "attempt.json")
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def select(self, revision: str) -> None:
        hexadecimal(revision, 40)
        if self.data["source_revision"] is not None:
            raise ValueError("an attempt cannot select a second commit")
        self.data["source_revision"] = revision
        self.save()

    def start_lane(self, lane: str) -> dict:
        if (lane not in {"kvm", "vz"} or lane in self.data["lanes"] or self.data["source_revision"] is None
                or self.data["finished_at"] is not None):
            raise ValueError("lane needs a selected commit and a new invocation")
        receipt = {"lane": lane, "source_revision": self.data["source_revision"], "run_id": uuid.uuid4().hex,
                   "started_at": datetime.now(UTC).isoformat(), "result": None, "cleanup": "unverified",
                   "command_exit": None, "trusted_host": None}
        self.data["lanes"][lane] = receipt
        self.save()
        return receipt

    def fail(self, stage: str, *, lane: str | None = None) -> None:
        if stage not in FAILURE_STAGES or lane not in {None, "kvm", "vz"}:
            raise ValueError("unknown hardware failure stage")
        failure = {"stage": stage, "lane": lane}
        if failure not in self.data["failures"]:
            self.data["failures"].append(failure)
        self.save()

    @contextmanager
    def phase(self, stage: str, *, lane: str | None = None):
        """Record failures, including cancellation, without swallowing them."""
        if stage not in FAILURE_STAGES or lane not in {None, "kvm", "vz"}:
            raise ValueError("unknown hardware failure stage")
        completed = False
        try:
            yield
            completed = True
        except KeyboardInterrupt:
            self.fail("cancelled", lane=lane)
            raise
        finally:
            if not completed:
                self.fail(stage, lane=lane)

    def retain_lane(self, lane: str, summary: Path) -> None:
        receipt = self.data["lanes"][lane]
        try:
            receipt["result"] = lane_result(summary, receipt)
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            # The named report is untrusted input. Publish the failure stage,
            # never its raw contents, exception text or private instance path.
            self.fail("report", lane=lane)
            return
        if not receipt["result"]["complete_success"]:
            self.fail("execution", lane=lane)
        self.save()

    def execution_succeeded(self) -> bool:
        return (self.data["finished_at"] is not None and not self.data["failures"]
                and set(self.data["lanes"]) == {"kvm", "vz"}
                and all(row["cleanup"] == "verified" and row["result"] is not None
                        and row["result"]["complete_success"] for row in self.data["lanes"].values()))

    def finish(self) -> None:
        if self.data["finished_at"] is None:
            self.data["finished_at"] = datetime.now(UTC).isoformat()
        self.save()

    def passed(self) -> bool:
        return self.execution_succeeded() and self.data["publication"]["verified"] is True

    def publication_result(self) -> dict:
        """Credentials, adapter paths and private logs never enter this view."""
        lanes = {}
        for lane, receipt in self.data["lanes"].items():
            row = {name: receipt[name] for name in ("lane", "source_revision", "run_id", "started_at", "cleanup")}
            status = receipt.get("command_exit")
            if status is not None and type(status) is not int:
                raise ValueError("invalid observed hardware command exit")
            row["command_exit"] = status
            host = receipt.get("trusted_host")
            row["trusted_host"] = None
            if host is not None:
                allowed = {}
                for name in ("kvm_api", "available_memory_bytes", "memory_bytes", "free_disk_bytes", "cpus"):
                    if name in host:
                        allowed[name] = integer(host[name])
                for name in ("system", "machine", "model"):
                    if name in host:
                        if not isinstance(host[name], str) or re.fullmatch(r"[A-Za-z0-9_,.-]{1,80}", host[name]) is None:
                            raise ValueError("invalid trusted host observation")
                        allowed[name] = host[name]
                row["trusted_host"] = allowed
            row["result"] = (verified_lane_summary(receipt["result"], receipt)
                             if receipt["result"] is not None else None)
            lanes[lane] = row
        return {name: self.data[name] for name in (
            "schema_version", "run_id", "owner", "controller_revision", "trigger", "source_revision", "started_at",
            "finished_at",
        )} | {"execution_succeeded": self.execution_succeeded(), "lanes": lanes,
             "failures": [{name: row[name] for name in ("stage", "lane")} for row in self.data["failures"]]}
