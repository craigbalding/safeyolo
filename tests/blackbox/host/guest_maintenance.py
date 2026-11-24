#!/usr/bin/env python3
"""Finite #1611 maintenance probe for an owned, prepared Linux/gVisor guest.

Adapted from the retained installed assessment driver. The platform owner
installs the matching host/guest pair, supplies a healthy retained-state base,
and selects each boot externally. This driver performs no host lifecycle,
image acquisition or approval decision. It changes its fixture package,
configuration and the prepared q1611 signal rule. Preserve a failed result;
inspect the original operation before selecting another effect.

Run prepare once in an idle disposable guest, then patch. After externally
selected recreation use restored; on a satisfactory later base use fixed.
Use recover on a separate prepared guest to fail health deliberately.
Service restart, startup gating and physical VZ witnesses remain separate.

prepare_guest_maintenance_inputs.sh makes a separate corrected Linux tree.
Pass the prepared directory to install_native.sh --platform-assets DIRECTORY
in a fresh owned instance for the normal-default case; leave agent/rootfs absent.
An explicit agent/rootfs override is the separate custom case. Bind the printed
hook SHA-256 as --hook-sha256. A copied custom-built input is not a released image.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import time
import tomllib
from pathlib import Path

PACKAGE = "sy-maintenance-fixture"
PROBE = "/home/agent/.q1611-maintenance"
CONFIG = "/usr/local/etc/safeyolo-maintenance-probe.conf"
PAYLOAD = "/usr/share/safeyolo-maintenance-fixture/version"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--hook-sha256", required=True)
    parser.add_argument("--root-kind", required=True, choices=["stock", "custom"])
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--base-id", required=True, help="actual retained-state base, not the OCI index")
    parser.add_argument("--overlay", required=True, choices=["file", "memory"])
    parser.add_argument("--phase", required=True,
                        choices=["inspect", "prepare", "patch", "restored", "fixed", "recover"])
    parser.add_argument("--authority", choices=["standing", "approval"], default="standing")
    parser.add_argument("--prior-result", type=Path, help="passed previous phase for a new boot")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    agent = root / "agents" / args.agent
    cli = root / "bin/safeyolo"
    report = {"phase": args.phase, "root": str(root), "agent": args.agent,
              "agent_id": args.agent_id, "run_id": args.run_id, "commit": args.commit,
              "hook_sha256": args.hook_sha256,
              "root_kind": args.root_kind, "rootfs": str(args.rootfs), "overlay": args.overlay,
              "base_id": args.base_id, "started_at": time.time(), "outcome": "in_progress"}
    # Reserve the result before effects. A killed caller leaves its original
    # input binding instead of making another invocation look new.
    with args.output.open("x") as stream:
        json.dump(report, stream)
    args.output.chmod(0o600)

    def command(*words: str) -> str:
        result = subprocess.run([str(cli), "--root", str(root), *words],
                                capture_output=True, text=True, timeout=150)
        if result.returncode:
            raise RuntimeError(f"{words[:2]} failed: {result.stderr[-1500:]}")
        return result.stdout

    def value(*words: str):
        return json.loads(command(*words))

    def binding() -> None:
        runtime = json.loads((agent / "runtime.json").read_text())
        context = json.loads((agent / "config-share/host-launch-context.json").read_text())
        assert runtime["agent_id"] == context["agent_id"] == args.agent_id
        assert runtime["run_id"] == context["generation"] == args.run_id
        assert runtime["state"] in {"running", "starting"}
        observed = value("agent", "status", args.agent)
        assert observed["agent_id"] == args.agent_id and observed["run_id"] == args.run_id
        assert observed["exec"] is True
        spec = json.loads((agent / "config.json").read_text())
        assert Path(spec["root"]["path"]).resolve(strict=True) == args.rootfs.resolve(strict=True)
        custom = agent / "rootfs"
        assert custom.is_dir() == (args.root_kind == "custom")
        if args.root_kind == "custom":
            assert custom.resolve(strict=True) == args.rootfs.resolve(strict=True)
        policy = tomllib.loads((root / "policy.toml").read_text())
        assert policy["agents"][args.agent].get("rootfs_overlay", "file") == args.overlay

    def shell(script: str) -> str:
        binding()
        return command("agent", "shell", args.agent, "-c", "set -eu; " + script)

    def guest_root(script: str) -> str:
        return shell("exec sudo -n /bin/sh -eu -c " + shlex.quote("umask 022; export LC_ALL=C; " + script))

    def retained():
        status = json.loads(guest_root("safeyolo-guest-state status"))
        report["retained_state"] = status
        assert status["actual_base_id"] == args.base_id and status["baseline_known"] is True
        assert status["last_completed_capture"] is not None and not status.get("capture_error")
        assert status["configuration_commit"], "bind a completed configuration capture"
        return status

    def applied() -> int:
        return int(shell(f"wc -l < {PROBE}/applied").strip())

    try:
        for name in ["safeyolo", "safeyolo-proxy", "safeyolo-coord"]:
            identity = subprocess.check_output([str(root / "bin" / name), "--version"], text=True)
            assert f"commit={args.commit} profile=debug" in identity
        binding()
        identity = shell("/safeyolo/safeyolo-guest --version")
        assert f"commit={args.commit} profile=debug" in identity
        report["observed_hook_sha256"] = guest_root(
            "sha256sum /usr/local/lib/safeyolo/guest-state-hook").split()[0]
        assert report["observed_hook_sha256"] == args.hook_sha256
        retained()
        prior = None
        if args.phase in {"restored", "fixed"}:
            assert args.prior_result, "bind the prior completed phase"
            prior = json.loads(args.prior_result.read_text())
            assert prior["outcome"] == "passed" and prior["agent_id"] == args.agent_id
            assert prior["root"] == str(root) and prior["run_id"] != args.run_id
            assert (prior["base_id"] == args.base_id) == (args.phase == "restored")
            report["advisory"] = prior["advisory"]
        if args.phase == "prepare":
            config = tomllib.loads((root / "signals.toml").read_text())
            assert all(rule["response"]["kind"] != "maintenance" for rule in config["rules"].values())
            installed = guest_root(f"dpkg-query -W -f='${{db:Status-Status}}' {PACKAGE} 2>/dev/null || true")
            assert installed.strip() != "installed"
            shell(f"test ! -e {PROBE}; mkdir -m 0700 {PROBE}; : > {PROBE}/applied; "
                  f"printf 'required local setting\\n' > {PROBE}/custom.conf; "
                  f"printf %s {shlex.quote(args.agent_id)} > {PROBE}/work; "
                  f"test ! -e /workspace/.q1611-maintenance; cp {PROBE}/work /workspace/.q1611-maintenance")
            guest_root(f"""
test ! -e {CONFIG}
for version in 1.0 2.0; do
    package={PROBE}/package-$version
    mkdir -p "$package/DEBIAN" "$package/usr/share/safeyolo-maintenance-fixture"
    printf 'Package: {PACKAGE}\\nVersion: %s\\nArchitecture: all\\nMaintainer: Probe <probe@invalid>\\nDescription: disposable maintenance witness\\n' "$version" > "$package/DEBIAN/control"
    printf %s "$version" > "$package{PAYLOAD}"
    (cd "$package"; md5sum usr/share/safeyolo-maintenance-fixture/version > DEBIAN/md5sums)
    dpkg-deb --root-owner-group --build "$package" {PROBE}/$version.deb >/dev/null
done
dpkg --install {PROBE}/1.0.deb >/dev/null
install -m 0640 {PROBE}/custom.conf {CONFIG}
safeyolo-guest-state capture
""")
            retained()
        elif args.phase != "inspect":
            assert shell(f"cat {PROBE}/work").strip() == args.agent_id
            assert shell("cat /workspace/.q1611-maintenance").strip() == args.agent_id
            before = applied()
            current = guest_root(f"dpkg-query -W -f='${{Version}}' {PACKAGE}").strip()
            if args.phase in {"patch", "restored", "recover"}:
                assert current == "1.0", "select the actual vulnerable fixture base before this phase"
            else:
                guest_root(f"dpkg --compare-versions {shlex.quote(current)} ge 2.0")
            config = tomllib.loads((root / "signals.toml").read_text())
            assert set(config["sources"]) == {"advisories"} and set(config["rules"]) == {"packages"}
            source = config["sources"]["advisories"]
            assert source["source_id"] == source["bucket"] == "q1611"
            broker = value("coord", "status")["process"]["client_port"]
            assert source["endpoint"] == {"mode": "loopback", "url": f"nats://127.0.0.1:{broker}"}
            assert Path(source["credential_file"]).resolve() == (root / "data/coord/nats/creds").resolve()
            checkpoint = f'cp {PROBE}/1.0.deb "$SAFEYOLO_MAINTENANCE_DIRECTORY/before.deb"; cp -a {CONFIG} "$SAFEYOLO_MAINTENANCE_DIRECTORY/config"'
            patch = (f'dpkg --install {PROBE}/2.0.deb; install -m 0640 {PROBE}/custom.conf {CONFIG}; '
                     f'printf "applied\\n" >> {PROBE}/applied')
            health = f'test "$(cat {PAYLOAD})" = ' + ("1.0" if args.phase == "recover" else "2.0")
            if args.phase == "fixed":
                health = f'dpkg --compare-versions "$(cat {PAYLOAD})" ge 2.0'
            recover = f'dpkg --install "$SAFEYOLO_MAINTENANCE_DIRECTORY/before.deb"; cp -a "$SAFEYOLO_MAINTENANCE_DIRECTORY/config" {CONFIG}'
            # Reuse the assessment driver's private source/explicit-rule format.
            # Broker credentials stay referenced, never copied into the report.
            text = f"""[sources.advisories]
endpoint={{mode='loopback',url='nats://127.0.0.1:{broker}'}}
username='safeyolo'
credential_file={json.dumps(str(root / 'data/coord/nats/creds'))}
bucket='q1611'
keys='advisories.q1611-maintenance'
source_id='q1611'
max_bytes=16384
max_signals=10
max_age_seconds=3600
retry_seconds=1
[rules.packages]
source='advisories'
agents={json.dumps([args.agent])}
distribution='debian:trixie'
min_severity=7
authority='{args.authority}'
on_stale='retain'
on_inactive='release'
inventory_max_age_seconds=30
[rules.packages.guest_inventory]
timeout_seconds=15
max_output_bytes=1048576
[rules.packages.response]
kind='maintenance'
checkpoint_command={json.dumps(checkpoint)}
patch_command={json.dumps(patch)}
health_command={json.dumps(health)}
recover_command={json.dumps(recover)}
timeout_seconds=120
max_output_bytes=1048576
"""
            inputs = root / "q1611-inputs"
            path = inputs / f"maintenance-{args.phase}.toml"
            with path.open("x") as stream:
                stream.write(text)
            path.chmod(0o600)
            command("signals", "configure", str(path))
            if args.phase in {"patch", "recover"}:
                now = int(time.time())
                advisory = {"source_id": "q1611", "id": "advisories.q1611-maintenance", "revision": 1,
                            "observed_at": now, "expires_at": now + 3600, "withdrawn": False,
                            "evidence_refs": ["fixture:disposable-maintenance-package"],
                            "evidence": {"kind": "advisory", "distribution": "debian:trixie", "severity": 9,
                                         "subject": {"kind": "package", "name": PACKAGE,
                                                     "distribution": "debian:trixie", "fixed_version": "2.0"}}}
                report["advisory"] = advisory
                path = inputs / "maintenance-advisory.json"
                with path.open("x") as stream:
                    json.dump(advisory, stream)
                command("signals", "publish", "advisories", advisory["id"], str(path))
            report["assessment_request"] = value("signals", "assess", "packages")
            request_id = report["assessment_request"]["request"]["request_id"]
            expected = "recovered" if args.phase == "recover" else "verified"
            deadline = time.monotonic() + 140
            while True:
                status = value("signals", "status")
                report["signals"] = status
                selected = next((row for row in status["responses"]
                                 if row["rule"] == "packages" and row["agent"] == args.agent), None)
                result = selected.get("response") if selected else None
                inventory = (selected.get("selection") or {}).get("inventory") if selected else None
                if not inventory or inventory.get("request_id") != request_id:
                    assert time.monotonic() < deadline, selected
                    time.sleep(0.25)
                    continue
                if result and result["status"] == "pending_approval":
                    report["outcome"] = "pending_approval"
                    report["approval"] = value("approvals", "show", result["approval_id"], "--json")
                    return
                if result and result["status"] == expected:
                    assert selected["selection"]["run"]["run_id"] == args.run_id
                    assert any(row["evidence"] == report["advisory"]
                               for row in status["sources"]["advisories"]["accepted"])
                    report["maintenance"] = result
                    break
                assert time.monotonic() < deadline, result
                time.sleep(0.25)
            after = applied()
            assert after == before + (args.phase != "fixed")
            if args.phase == "fixed":
                assert guest_root(f"dpkg-query -W -f='${{Version}}' {PACKAGE}").strip() == current
            expected_version = "1.0" if args.phase == "recover" else current if args.phase == "fixed" else "2.0"
            assert guest_root(f"cat {PAYLOAD}").strip() == expected_version
            assert guest_root(f"dpkg --verify {PACKAGE}").strip() == ""
            guest_root(f"cmp {CONFIG} {PROBE}/custom.conf; test $(stat -c %a {CONFIG}) = 640")
            assert shell(f"cat {PROBE}/work").strip() == args.agent_id
            assert shell("cat /workspace/.q1611-maintenance").strip() == args.agent_id
            state = retained()
            assert state["requirements"][PACKAGE]["version"] == "2.0"
            assert state["requirements"][PACKAGE]["operator"] == "ge"
        report["outcome"] = "passed"
    except Exception as error:
        # Keep the failed phase's diagnosis while preserving its nonzero exit.
        # Cancellation remains incomplete and propagates through finally.
        report["outcome"] = "failed"
        report["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        # Exceptions and cancellation propagate. The original result remains
        # incomplete, with its last observations, instead of claiming success.
        report["ended_at"] = time.time()
        args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
