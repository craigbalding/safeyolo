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

_UNSET = object()


def _report(
    *,
    cpu_ceiling=9,
    memory_ceiling_mb=8192,
    process_limit=100,
    process_current=2,
    disk_free=1024,
    disk_min_free=0,
    enforcement="admission",
    cpu_source="test",
    active_cpu=0,
    active_memory_mb=0,
    memory_available=_UNSET,
    memory_source="test",
):
    return HostResourceReport(
        cpu=ResourceLimit(cpu_ceiling, cpu_ceiling, cpu_source, enforcement),
        memory=ResourceLimit(
            memory_ceiling_mb * 1024 * 1024,
            memory_ceiling_mb * 1024 * 1024,
            memory_source,
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
        memory_available=(
            memory_ceiling_mb * 1024 * 1024
            if memory_available is _UNSET
            else memory_available
        ),
    )


def test_aggregate_cpu_and_memory_admission_is_distinct_from_agent_shape():
    report = _report(
        active_cpu=4,
        active_memory_mb=4096,
        memory_available=4096 * 1024 * 1024,
    )

    allowed = evaluate_admission(
        report,
        requested_cpu=4,
        requested_memory_mb=4095,
    )
    refused = evaluate_admission(
        report,
        requested_cpu=5,
        requested_memory_mb=4096,
    )

    assert allowed.allowed
    assert not refused.allowed
    assert any("CPU allocation" in reason for reason in refused.reasons)
    assert any("memory request" in reason for reason in refused.reasons)


def test_explicit_cpu_ceiling_can_admit_the_default_small_host_shape():
    decision = evaluate_admission(
        _report(cpu_ceiling=4, cpu_source="operator override"),
        requested_cpu=4,
        requested_memory_mb=1,
    )

    assert decision.allowed


def test_explicit_memory_ceiling_adds_aggregate_cap():
    report = _report(
        active_memory_mb=4096,
        memory_ceiling_mb=8192,
        memory_available=8192 * 1024 * 1024,
        memory_source="operator override",
    )

    decision = evaluate_admission(
        report,
        requested_cpu=1,
        requested_memory_mb=4097,
    )

    assert not decision.allowed
    assert "memory allocation 8193 MiB reaches ceiling" in decision.reasons[0]


def test_explicit_memory_ceiling_still_checks_live_pressure():
    report = _report(
        memory_ceiling_mb=16_384,
        memory_available=1024 * 1024,
        memory_source="operator override",
    )

    decision = evaluate_admission(report, requested_cpu=1, requested_memory_mb=2)

    assert not decision.allowed
    assert "memory request 2 MiB reaches currently available memory" in decision.reasons[0]


def test_missing_measurements_close_admission():
    report = _report(memory_available=None)

    decision = evaluate_admission(report, requested_cpu=1, requested_memory_mb=1)

    assert not decision.allowed
    assert any("available host memory is unavailable" in reason for reason in decision.reasons)


def test_process_exhaustion_refuses_new_work():
    decision = evaluate_admission(
        _report(process_limit=10, process_current=8),
        requested_cpu=1,
        requested_memory_mb=1,
    )

    assert not decision.allowed
    assert "process table has no launch headroom" in decision.reasons[0]


def test_low_disk_refuses_new_work():
    decision = evaluate_admission(
        _report(disk_free=4096, disk_min_free=4096),
        requested_cpu=1,
        requested_memory_mb=1,
    )

    assert not decision.allowed
    assert "filesystem /runtime" in decision.reasons[0]


def test_automatic_boundaries_leave_host_derived_headroom(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "safeyolo.host_resources._read_cpu_capacity",
        lambda: (8, "automatic: test CPU"),
    )
    monkeypatch.setattr(
        "safeyolo.host_resources._read_memory_capacity",
        lambda: (16 * 1024**3, 4096 * 1024**2, "automatic: test memory"),
    )
    monkeypatch.setattr(
        "safeyolo.host_resources._read_process_capacity",
        lambda: (100, 2, "automatic: test process"),
    )
    monkeypatch.setattr("safeyolo.host_resources._runtime_paths", lambda _: [tmp_path])
    monkeypatch.setattr(
        "safeyolo.host_resources.shutil.disk_usage",
        lambda _path: SimpleNamespace(total=10000, free=4096, block_size=4096),
    )
    monkeypatch.setattr(
        "safeyolo.host_resources._minimum_start_disk_headroom",
        lambda: 8192,
    )
    monkeypatch.setattr(
        "safeyolo.host_resources._systemd_scope_status",
        lambda: "admission + per-agent systemd scope",
    )

    report = build_host_resource_report()

    assert report.cpu.effective == 8
    assert report.memory.effective == 12 * 1024**3
    assert report.disks[0].effective_min_free == 12_288
    decision = evaluate_admission(report, requested_cpu=8, requested_memory_mb=1)
    assert not decision.allowed
    assert any(f"filesystem {tmp_path}" in reason for reason in decision.reasons)


def test_cgroup_process_boundaries_include_a_constrained_parent(monkeypatch, tmp_path):
    import safeyolo.host_resources as host_resources

    parent = tmp_path / "parent"
    leaf = parent / "leaf"
    leaf.mkdir(parents=True)
    (parent / "pids.max").write_text("128\n")
    (parent / "pids.current").write_text("120\n")
    (leaf / "pids.max").write_text("max\n")
    (leaf / "pids.current").write_text("2\n")
    monkeypatch.setattr(
        host_resources,
        "_cgroup_v2_paths",
        lambda: [parent, leaf],
    )

    boundaries = host_resources._cgroup_process_boundaries()

    assert (128, 120, "automatic: " + str(parent) + "/pids.max") in boundaries
    assert (None, 2, "automatic: " + str(leaf) + "/pids.max") in boundaries


def test_cgroup_process_boundary_wins_when_it_has_less_headroom(monkeypatch):
    import safeyolo.host_resources as host_resources

    monkeypatch.setattr(host_resources, "_process_count", lambda: 100)
    monkeypatch.setattr(
        host_resources.Path,
        "read_text",
        lambda path: "65536\n" if str(path) == "/proc/sys/kernel/pid_max" else "",
    )
    monkeypatch.setattr(
        host_resources,
        "_cgroup_process_boundaries",
        lambda: [
            (None, 2, "automatic: leaf cgroup pids.max= max"),
            (128, 120, "automatic: parent cgroup pids.max"),
        ],
    )

    capacity, current, source = host_resources._read_process_capacity()

    assert (capacity, current) == (128, 120)
    assert source == "automatic: parent cgroup pids.max"


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

    assert report.memory.effective == 12 * 1024**3
    assert "available unknown" in report.memory.source
    assert report.degraded
    assert any("degraded" in line for line in report.as_detail_lines())


def test_disk_measurement_failure_closes_admission():
    decision = evaluate_admission(
        _report(disk_free=None),
        requested_cpu=1,
        requested_memory_mb=1,
    )

    assert not decision.allowed
    assert "free space is unavailable" in decision.reasons[0]


def test_darwin_memory_read_keeps_total_when_available_probe_fails(monkeypatch):
    import subprocess

    import safeyolo.host_resources as host_resources

    def run(command, **_kwargs):
        if command[0] == "sysctl":
            return subprocess.CompletedProcess(command, 0, "17179869184\n", "")
        return subprocess.CompletedProcess(command, 1, "", "vm_stat unavailable")

    monkeypatch.setattr(host_resources.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(host_resources.subprocess, "run", run)

    total, available, source = host_resources._read_memory_capacity()

    assert total == 16 * 1024**3
    assert available is None
    assert "available unknown" in source


def test_running_allocation_uses_runtime_record_not_mutable_policy(
    monkeypatch, tmp_path
):
    import safeyolo.host_resources as host_resources
    from safeyolo import agents_store, platform

    monkeypatch.setattr(
        agents_store,
        "load_all_agents",
        lambda: {"worker": {"memory_mb": 999}},
    )
    monkeypatch.setattr(platform, "get_platform", lambda: type(
        "Platform", (), {"is_sandbox_running": lambda _self, _name: True}
    )())
    monkeypatch.setattr(host_resources, "get_agents_dir", lambda: tmp_path)
    host_resources.record_running_agent_allocation(
        "worker", cpus=2, memory_mb=4096
    )

    assert host_resources.running_agent_allocations() == (2, 4096)


def test_invalid_override_is_rejected():
    with pytest.raises(ValueError, match="must be positive"):
        build_host_resource_report(config={"host_resources": {"cpu_ceiling": 0}})
