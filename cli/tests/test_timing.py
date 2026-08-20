"""Lifecycle profiling contracts."""

from mitmproxy import addonmanager

from safeyolo import timing


def test_addon_dispatcher_is_restored_after_startup_profile(tmp_path, monkeypatch):
    profile_path = tmp_path / "profile.jsonl"
    profile_path.touch()
    original = addonmanager.AddonManager.invoke_addon
    monkeypatch.setattr(timing, "_path", profile_path)
    monkeypatch.setattr(timing, "_emitted", False)
    monkeypatch.setattr(timing, "_addon_profiler_installed", False)
    monkeypatch.setattr(timing, "_original_addon_invoke", None)

    for _ in range(2):
        try:
            timing.install_mitmproxy_addon_profiling()
            assert addonmanager.AddonManager.invoke_addon is not original
        finally:
            timing.uninstall_mitmproxy_addon_profiling()

        assert addonmanager.AddonManager.invoke_addon is original


def test_finished_parent_profile_is_not_propagated_to_later_children(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(timing, "_path", tmp_path / "finished.jsonl")
    monkeypatch.setattr(timing, "_emitted", True)
    assert timing.child_environment("traffic-master") == {}
