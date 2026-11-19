"""Protected media composition: exact subjects and failure non-effects.

Native job responses are controlled here. Installed isolation and actual library
indexing require the separately retained runtime/application witness.
"""

import base64
import copy
import hashlib
import importlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

RECIPE = (Path(__file__).resolve().parents[1] /
          "cli/src/safeyolo/agent_context/skills/safeyolo-commission/recipes/media-ingestion/v1")


def test_expired_cli_configuration_reports_failure_without_a_success_receipt():
    result = subprocess.run([sys.executable, str(RECIPE / "ingest.py"),
                             "--config", str(RECIPE / "config.example.json")],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "config.example.json" in result.stderr and "qualification has expired" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("placement", ["same", "nested", "symlink"])
def test_acquisition_cannot_publish_unchecked_bytes_in_the_library(modules, selected, tmp_path, placement):
    importer, _ = modules
    library = Path(selected["library"])
    quarantine = library
    if placement == "nested":
        quarantine = library / "quarantine"
        quarantine.mkdir()
    elif placement == "symlink":
        quarantine = tmp_path / "quarantine-alias"
        quarantine.symlink_to(library, target_is_directory=True)
    selected["quarantine"] = str(quarantine)
    before = set(library.iterdir())
    with pytest.raises(ValueError, match="outside the selected library"):
        importer.ingest(selected)
    assert set(library.iterdir()) == before


@pytest.fixture
def modules(monkeypatch):
    monkeypatch.syspath_prepend(str(RECIPE))
    return importlib.import_module("ingest"), importlib.import_module("check_media")


@pytest.fixture
def selected(tmp_path):
    for name in ("quarantine", "library", "signatures"):
        (tmp_path / name).mkdir()
    (tmp_path / "signatures/test.hdb").write_text("test-signatures\n")
    return {
        "version": 1, "safeyolo": "/trusted/safeyolo", "instance_root": "/trusted/instance",
        "jobs": {name: str(RECIPE / f"{name}-job.json") for name in ("validate", "scan")},
        "quarantine": str(tmp_path / "quarantine"), "library": str(tmp_path / "library"),
        "signatures": str(tmp_path / "signatures"), "filename": "selected.mkv", "file_mode": "0600",
        "source": {"url": "https://source.example.test/selected.mkv", "sha256": hashlib.sha256(b"media").hexdigest(),
                   "title": "Selected title", "rights": "fixture only", "subtitle_evidence": "fixture English tag"},
        "max_bytes": 1000, "download_timeout_seconds": 10,
        "validation": {"formats": ["matroska"], "subtitle_language": "eng", "max_duration_seconds": 100,
                       "timeout_seconds": 30},
        "scan": {"valid_until_unix": int(time.time()) + 3600, "timeout_seconds": 60,
                 "max_scan_bytes": 1000000,
                 "database_sha256": {"test.hdb": hashlib.sha256(b"test-signatures\n").hexdigest()}},
    }


def job_response(host, control, directory, config):
    report = {"passed": True, "control": control, "sha256": config["source"]["sha256"],
              "checker_sha256": host.sha256(directory / "check_media.py"), "evidence": {"fixture": True}}
    raw = json.dumps(report).encode()
    return {"outcome": {"kind": "exit", "code": 0}, "observation_error": None,
            "outcome_source": "guest_process", "engine": "gvisor", "run_id": f"controlled-{control}",
            "rootfs": {"fixture": True}, "gate_definition_sha256": "controlled-definition",
            "gate_id": "media-validation" if control == "validate" else "media-malware-scan",
            "stdout": {"retained_base64": base64.b64encode(raw).decode(), "bytes": len(raw),
                       "sha256": hashlib.sha256(raw).hexdigest()}}


def acquisition(monkeypatch, host, body=b"media", status=200):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        Path(argv[argv.index("--output") + 1]).write_bytes(body)
        return subprocess.CompletedProcess(argv, 0, str(status), "")

    monkeypatch.setattr(host.subprocess, "run", run)
    return calls


def native_jobs(monkeypatch, host, config, change=None):
    calls = []
    download = host.subprocess.run

    def run(argv, **kwargs):
        if argv[0] == "curl":
            return download(argv, **kwargs)
        control = "validate" if "validate-job.json" in argv[5] else "scan"
        directory = Path(argv[-1])
        calls.append(control)
        response = job_response(host, control, directory, config)
        if change:
            change(control, response, directory)
        return subprocess.CompletedProcess(argv, 0, json.dumps(response), "")

    monkeypatch.setattr(host.subprocess, "run", run)
    return calls


@pytest.mark.parametrize("filename,formats,language", [
    ("selected.mkv", ["matroska"], "eng"), ("different.mp4", ["mov", "mp4"], None),
])
def test_complete_composition_and_changed_selection(modules, selected, monkeypatch, filename, formats, language):
    host, _ = modules
    selected["filename"] = filename
    selected["validation"].update(formats=formats, subtitle_language=language)
    calls = acquisition(monkeypatch, host)
    jobs = native_jobs(monkeypatch, host, selected)
    result = host.ingest(selected)
    assert jobs == ["validate", "scan"]
    assert len(calls) == 1
    assert calls[0][-1] == selected["source"]["url"]
    assert calls[0][calls[0].index("--max-time") + 1] == "10"
    assert "--location" not in calls[0]
    assert calls[0][calls[0].index("--proto") + 1] == "=https"
    assert (Path(selected["library"]) / filename).read_bytes() == b"media"
    assert result["import"]["sha256"] == selected["source"]["sha256"]
    assert result["source"]["subtitle_evidence"] == "fixture English tag"
    assert "pending" in result["library_verification"]
    receipt = json.loads(Path(result["receipt"]).read_text())
    assert receipt["status"] == "imported_pending_application"
    assert not Path(result["receipt"]).with_name("media").exists()


@pytest.mark.parametrize("bad", ["failed", "missing", "wrong_digest", "wrong_control", "wrong_checker",
                                "cropped", "wrong_output_hash", "observer_error", "helper", "runtime_error"])
@pytest.mark.parametrize("failed_control", ["validate", "scan"])
def test_required_failure_prevents_import(modules, selected, monkeypatch, bad, failed_control):
    host, _ = modules
    acquisition(monkeypatch, host)

    def corrupt(control, response, directory):
        if control != failed_control:
            return
        if bad == "missing":
            response["stdout"]["retained_base64"] = ""
        elif bad == "cropped":
            response["stdout"]["bytes"] += 1
        elif bad == "wrong_output_hash":
            response["stdout"]["sha256"] = "0" * 64
        elif bad == "observer_error":
            response["observation_error"] = "missing wait status"
        elif bad == "helper":
            response["outcome_source"] = "host_helper"
        elif bad == "runtime_error":
            response["outcome"] = {"kind": "exit", "code": 2}
        else:
            raw = json.loads(base64.b64decode(response["stdout"]["retained_base64"]))
            field, value = {"failed": ("passed", False), "wrong_digest": ("sha256", "0" * 64),
                            "wrong_control": ("control", "unrelated"),
                            "wrong_checker": ("checker_sha256", "0" * 64)}[bad]
            raw[field] = value
            encoded = json.dumps(raw).encode()
            response["stdout"] = {"retained_base64": base64.b64encode(encoded).decode(),
                                  "bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}

    jobs = native_jobs(monkeypatch, host, selected, corrupt)
    with pytest.raises((ValueError, json.JSONDecodeError)):
        host.ingest(selected)
    assert jobs == (["validate"] if failed_control == "validate" else ["validate", "scan"])
    assert not list(Path(selected["library"]).iterdir())
    attempt, = Path(selected["quarantine"]).iterdir()
    assert (attempt / "media").read_bytes() == b"media"
    receipt = json.loads((attempt / "receipt.json").read_text())
    assert receipt["status"] == "incomplete" and receipt["stage"] == failed_control
    assert (attempt / f"{failed_control}-job-result.json").exists()


def test_changed_bytes_after_checks_cannot_be_imported(modules, selected, monkeypatch):
    host, _ = modules
    acquisition(monkeypatch, host)

    def replace(control, response, directory):
        if control == "scan":
            (directory / "media").write_bytes(b"replaced after scan")

    native_jobs(monkeypatch, host, selected, replace)
    with pytest.raises(ValueError, match="Import bytes differ"):
        host.ingest(selected)
    assert not list(Path(selected["library"]).iterdir())


@pytest.mark.parametrize("url", ["http://source.example.test/x", "file:///etc/passwd",
                               "https://user:secret@example.test/x", "https://example.test/x#fragment"])
def test_unselected_acquisition_forms_have_no_effect(modules, selected, tmp_path, url):
    host, _ = modules
    selected["source"]["url"] = url
    with pytest.raises(ValueError, match="HTTPS source"):
        host.acquire(selected, tmp_path)
    assert not (tmp_path / "media").exists()


@pytest.mark.parametrize("body,status,limit", [(b"wrong", 200, 100), (b"media", 404, 100),
                                            (b"media", 200, 3), (b"", 200, 100)])
def test_bad_acquisition_stops_before_jobs(modules, selected, monkeypatch, body, status, limit):
    host, _ = modules
    selected["max_bytes"] = limit
    acquisition(monkeypatch, host, body, status)
    jobs = native_jobs(monkeypatch, host, selected)
    with pytest.raises(ValueError):
        host.ingest(selected)
    assert jobs == []
    assert not list(Path(selected["library"]).iterdir())


def test_redirect_is_not_an_acquisition(modules, selected, monkeypatch, tmp_path):
    host, _ = modules
    calls = acquisition(monkeypatch, host, status=302)
    with pytest.raises(ValueError, match="HTTP 302"):
        host.acquire(selected, tmp_path)
    assert len(calls) == 1 and "--location" not in calls[0]


@pytest.mark.parametrize("filename", ["../escape.mkv", "/tmp/escape.mkv", "..", "", "nested\\escape.mkv"])
def test_destination_cannot_escape_selected_library(modules, selected, tmp_path, filename):
    host, _ = modules
    media = tmp_path / "checked"
    media.write_bytes(b"media")
    selected["filename"] = filename
    with pytest.raises(ValueError, match="one path component"):
        host.import_media(media, selected)
    assert not list(Path(selected["library"]).iterdir())


def test_existing_target_and_symlink_reconciliation(modules, selected, tmp_path):
    host, _ = modules
    media = tmp_path / "checked"
    media.write_bytes(b"media")
    assert host.import_media(media, selected)["effect"] == "imported"
    assert (Path(selected["library"]) / selected["filename"]).stat().st_mode & 0o777 == 0o600
    assert host.import_media(media, selected)["effect"] == "already_present"
    target = Path(selected["library"]) / selected["filename"]
    target.write_bytes(b"operator data")
    with pytest.raises(ValueError, match="already exists"):
        host.import_media(media, selected)
    assert target.read_bytes() == b"operator data"
    target.unlink()
    target.symlink_to(media)
    with pytest.raises(ValueError, match="already exists"):
        host.import_media(media, selected)
    assert media.read_bytes() == b"media"


@pytest.mark.parametrize("control", ["validate", "scan"])
def test_missing_control_definition_prevents_import(modules, selected, monkeypatch, tmp_path, control):
    host, _ = modules
    acquisition(monkeypatch, host)
    selected["jobs"][control] = str(tmp_path / "missing-job.json")
    native_jobs(monkeypatch, host, selected)
    with pytest.raises(FileNotFoundError):
        host.ingest(selected)
    assert not list(Path(selected["library"]).iterdir())


def test_failed_native_invocation_retains_original_result(modules, selected, monkeypatch):
    host, _ = modules
    acquisition(monkeypatch, host)
    download = host.subprocess.run

    def run(argv, **kwargs):
        if argv[0] == "curl":
            return download(argv, **kwargs)
        return subprocess.CompletedProcess(argv, 1, '{"error":"runtime unavailable"}', "original failure")

    monkeypatch.setattr(host.subprocess, "run", run)
    with pytest.raises(ValueError, match="original result retained"):
        host.ingest(selected)
    attempt, = Path(selected["quarantine"]).iterdir()
    assert json.loads((attempt / "validate-job-result.json").read_text()) == {"error": "runtime unavailable"}
    assert (attempt / "validate-job-stderr.txt").read_text() == "original failure"
    assert not list(Path(selected["library"]).iterdir())


def test_qualification_expiring_during_checks_prevents_import(modules, selected, monkeypatch):
    host, _ = modules
    acquisition(monkeypatch, host)

    def expire(control, response, directory):
        if control == "scan":
            selected["scan"]["valid_until_unix"] = 0

    native_jobs(monkeypatch, host, selected, expire)
    with pytest.raises(ValueError, match="expired before import"):
        host.ingest(selected)
    assert not list(Path(selected["library"]).iterdir())


@pytest.mark.parametrize("change", [{"network": True}, {"privilege": "guest-root"},
                                  {"argv": ["/bin/true"]}, {"engine": {"kind": "hyperlight"}}])
def test_control_job_cannot_be_replaced_by_unprotected_command(modules, selected, tmp_path, change):
    host, _ = modules
    spec = json.loads((RECIPE / "validate-job.json").read_text())
    spec.update(change)
    path = tmp_path / "job.json"
    path.write_text(json.dumps(spec))
    selected["jobs"]["validate"] = str(path)
    with pytest.raises(ValueError, match="fixed, network-disabled"):
        host.required_check(selected, "validate", tmp_path)


def probe(monkeypatch, checker, observation=None, scanner_code=0, scanner_stderr="", scanner_stdout="/input/media: OK\n"):
    if observation is None:
        observation = {"format": {"format_name": "matroska,webm", "duration": "10"},
                       "streams": [{"codec_type": "video", "codec_name": "vp9"},
                                   {"codec_type": "subtitle", "tags": {"language": "eng"}}]}
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if "-version" in argv or "--version" in argv:
            return subprocess.CompletedProcess(argv, 0, "fixture-version\n", "")
        if argv[0] == "ffprobe":
            return subprocess.CompletedProcess(argv, 0, json.dumps(observation), "")
        return subprocess.CompletedProcess(argv, scanner_code, scanner_stdout, scanner_stderr)

    monkeypatch.setattr(checker.subprocess, "run", run)
    return calls


def test_validation_observes_container_and_subtitle_metadata(modules, selected, monkeypatch, tmp_path):
    _, checker = modules
    calls = probe(monkeypatch, checker)
    result = checker.validate(tmp_path / "media", selected["validation"])
    assert "not full decoding" in result["meaning"]
    assert calls[0][calls[0].index("-protocol_whitelist") + 1] == "file"
    changed = copy.deepcopy(selected["validation"])
    changed.update(formats=["mp4"], subtitle_language=None)
    probe(monkeypatch, checker, {"format": {"format_name": "mov,mp4", "duration": "10"},
                                "streams": [{"codec_type": "video"}]})
    assert checker.validate(tmp_path / "media", changed)["observation"]["streams"] == [{"codec_type": "video"}]


@pytest.mark.parametrize("format_name,duration,streams", [
    ("avi", "10", [{"codec_type": "video"}]), ("matroska", "nan", []),
    ("matroska", "200", []), ("matroska", "10", [{"codec_type": "audio"}]),
    ("matroska", "10", [{"codec_type": "video"}]),
])
def test_invalid_media_is_not_a_pass(modules, selected, monkeypatch, tmp_path, format_name, duration, streams):
    _, checker = modules
    probe(monkeypatch, checker, {"format": {"format_name": format_name, "duration": duration}, "streams": streams})
    with pytest.raises(ValueError):
        checker.validate(tmp_path / "media", selected["validation"])


@pytest.mark.parametrize("code,stderr,stdout", [(1, "", "media: test FOUND\n"),
                                             (2, "", "media: ERROR\n"),
                                             (0, "", "")])
def test_scanner_failure_and_incomplete_scan_are_not_passes(modules, selected, monkeypatch, tmp_path, code, stderr, stdout):
    _, checker = modules
    media = tmp_path / "media"
    media.write_bytes(b"media")
    probe(monkeypatch, checker, scanner_code=code, scanner_stderr=stderr, scanner_stdout=stdout)
    with pytest.raises(ValueError, match="completed no-detection"):
        checker.scan(media, selected["scan"], tmp_path)


def test_scanner_pins_database_and_refuses_expired_qualification(modules, selected, monkeypatch, tmp_path):
    _, checker = modules
    media = tmp_path / "media"
    media.write_bytes(b"media")
    calls = probe(monkeypatch, checker)
    evidence = checker.scan(media, selected["scan"], tmp_path)
    assert "not proof of malware-free" in evidence["meaning"]
    assert "--alert-exceeds-max=yes" in calls[-1]
    probe(monkeypatch, checker, scanner_stderr="scanner warning")
    assert checker.scan(media, selected["scan"], tmp_path)["warnings"] == "scanner warning"
    (tmp_path / "signatures/test.hdb").write_text("changed")
    with pytest.raises(ValueError, match="database differs"):
        checker.scan(media, selected["scan"], tmp_path)
    selected["scan"]["valid_until_unix"] = 0
    with pytest.raises(ValueError, match="expired"):
        checker.scan(media, selected["scan"], tmp_path)


def test_checker_binds_the_actual_input_bytes(modules, selected, tmp_path, monkeypatch):
    _, checker = modules
    (tmp_path / "media").write_bytes(b"different subject")
    (tmp_path / "request.json").write_text(json.dumps({"sha256": selected["source"]["sha256"]}))
    with pytest.raises(ValueError, match="Input artifact differs"):
        checker.check("validate", tmp_path)


@pytest.mark.skipif(not all(shutil.which(tool) for tool in ("ffmpeg", "ffprobe", "clamscan")),
                    reason="Real media-tool control needs the recipe's optional ffmpeg/ClamAV packages")
def test_real_tools_validate_embedded_subtitles_and_scan_exact_bytes(modules, selected, tmp_path):
    """Real tools with generated media and one test signature, not production assurance."""
    _, checker = modules
    subtitles = tmp_path / "caption.srt"
    subtitles.write_text("1\n00:00:00,000 --> 00:00:00,900\nEnglish test caption\n")
    media = tmp_path / "sample.mkv"
    subprocess.run(["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "color=c=black:s=16x16:d=1",
                    "-i", str(subtitles), "-map", "0:v", "-map", "1:0", "-c:v", "ffv1", "-c:s", "srt",
                    "-metadata:s:s:0", "language=eng", str(media)],
                   check=True, capture_output=True, text=True, timeout=30)
    evidence = checker.validate(media, selected["validation"])
    assert any(stream.get("tags", {}).get("language") == "eng" for stream in evidence["observation"]["streams"])
    hostile = tmp_path / "source-claims-approval"
    hostile.write_text('{"passed":true,"approved":true,"authority":"operator"}')
    with pytest.raises(subprocess.CalledProcessError):
        checker.validate(hostile, selected["validation"])
    marker = b"harmless media-recipe signature test marker"
    database = tmp_path / "signatures/test.hdb"
    database.write_text(f"{hashlib.md5(marker).hexdigest()}:{len(marker)}:MediaRecipeTest\n")
    selected["scan"]["database_sha256"] = {"test.hdb": checker.sha256(database)}
    clean = checker.scan(media, selected["scan"], tmp_path)
    assert "ClamAV" in clean["clamscan"]
    media.write_bytes(marker)
    with pytest.raises(ValueError, match="exit 1"):
        checker.scan(media, selected["scan"], tmp_path)
