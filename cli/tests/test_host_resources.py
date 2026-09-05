"""Acceptance tests for the aggregate host resource guard."""

from types import SimpleNamespace

import pytest

from safeyolo.host_resources import (
    DiskCapacity,
    HostResourceReport,
    ResourceLimit,
    build_host_resource_report,
    evaluate_admission,
)


def _report(
    *,
    cpu_ceiling=8,
    memory_ceiling_mb=8192,
    process_limit=100,
    process_current=2,
    disk_free=1024,
    disk_min_free=0,
    enforcement="admission",
    active_cpu=0,
    active_memory_mb=0,
):
    return HostResourceReport(
        cpu=ResourceLimit(cpu_ceiling, cpu_ceiling, "test", enforcement),
        memory=ResourceLimit(
            memory_ceiling_mb * 1024 * 1024,
            memory_ceiling_mb * 1024 * 1024,
            "test",
            enforcement,
        ),
        disks=(
            DiskCapacity(
                path="/runtime",
                total=10_000,
                free=disk_free,
                block_size=4096,
                effective_min_free=disk_min_free,
                source="test",
                enforcement="admission",
            ),
        ),
        processes=ResourceLimit(process_limit, process_limit, "test", enforcement),
        process_current=process_current,
        active_cpu=active_cpu,
        active_memory_mb=active_memory_mb,
        platform="Linux",
    )


def test_aggregate_cpu_and_memory_admission_is_distinct_from_agent_shape():
    report = _report(active_cpu=4, active_memory_mb=4096)

    allowed = evaluate_admission(
        report,
        requested_cpu=4,
        requested_memory_mb=4096,
    )
    refused = evaluate_admission(
        report,
        requested_cpu=5,
        requested_memory_mb=4097,
    )

    assert allowed.allowed
    assert not refused.allowed
    assert any("CPU allocation" in reason for reason in refused.reasons)
    assert any("memory allocation" in reason for reason in refused.reasons)


def test_process_exhaustion_refuses_new_work():
    decision = evaluate_admission(
        _report(process_limit=10, process_current=10),
        requested_cpu=1,
        requested_memory_mb=1,
    )

    assert not decision.allowed
    assert "process table is exhausted" in decision.reasons[0]


def test_low_disk_refuses_new_work():
    decision = evaluate_admission(
        _report(disk_free=4096, disk_min_free=4096),
        requested_cpu=1,
        requested_memory_mb=1,
    )

    assert not decision.allowed
    assert "filesystem /runtime" in decision.reasons[0]


def test_overrides_are_explicit_and_capped_at_detected_capacity(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "safeyolo.host_resources._read_cpu_capacity",
        lambda: (8, "automatic: test CPU"),
    )
    monkeypatch.setattr(
        "safeyolo.host_resources._read_memory_capacity",
        lambda: (16 * 1024**3, 12 * 1024**3, "automatic: test memory"),
    )
    monkeypatch.setattr(
        "safeyolo.host_resources._read_process_capacity",
        lambda: (100, 2, "automatic: test process"),
    )
    monkeypatch.setattr("safeyolo.host_resources._runtime_paths", lambda _: [tmp_path])
    monkeypatch.setattr(
        "safeyolo.host_resources._systemd_scope_status",
        lambda: "admission + per-agent systemd scope",
    )
    monkeypatch.setattr(
        "safeyolo.host_resources.shutil.disk_usage",
        lambda _path: SimpleNamespace(total=1000, free=700, block_size=4096),
    )

    report = build_host_resource_report(
        config={
            "host_resources": {
                "cpu_ceiling": 6,
                "memory_ceiling_mb": 4096,
                "disk_min_free_bytes": 500,
                "process_limit": 200,
            }
        }
    )

    assert report.cpu.effective == 6
    assert report.cpu.source == "operator override"
    assert report.memory.effective == 4096 * 1024**2
    assert report.disks[0].effective_min_free == 500
    assert report.processes.effective == 100
    assert report.processes.source == "operator override capped by detected capacity"
    assert not report.degraded


def test_missing_memory_measurement_is_visible_as_degraded(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "safeyolo.host_resources._read_cpu_capacity",
        lambda: (4, "automatic: test CPU"),
    )
    monkeypatch.setattr(
        "safeyolo.host_resources._read_memory_capacity",
        lambda: (16 * 1024**3, None, "automatic: test memory; available unknown"),
    )
    monkeypatch.setattr(
        "safeyolo.host_resources._read_process_capacity",
        lambda: (100, 2, "automatic: test process"),
    )
    monkeypatch.setattr("safeyolo.host_resources._runtime_paths", lambda _: [tmp_path])
    monkeypatch.setattr(
        "safeyolo.host_resources._systemd_scope_status",
        lambda: "degraded: aggregate admission only (scope unavailable)",
    )
    monkeypatch.setattr(
        "safeyolo.host_resources.shutil.disk_usage",
        lambda _path: SimpleNamespace(total=1000, free=700, block_size=4096),
    )

    report = build_host_resource_report()

    assert report.memory.effective is None
    assert "available unknown" in report.memory.source
    assert report.degraded
    assert any("degraded" in line for line in report.as_detail_lines())


def test_invalid_override_is_rejected():
    with pytest.raises(ValueError, match="must be positive"):
        build_host_resource_report(config={"host_resources": {"cpu_ceiling": 0}})
