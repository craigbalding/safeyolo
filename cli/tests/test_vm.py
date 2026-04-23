"""Tests for safeyolo.vm -- microVM lifecycle management."""

import json
import os
import signal
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from safeyolo.vm import (
    VMError,
    _update_agent_map,
    check_guest_images,
    create_agent_rootfs,
    find_vm_helper,
    get_agent_config_share_dir,
    get_agent_pid_path,
    get_agent_rootfs_path,
    get_base_rootfs_path,
    get_initrd_path,
    get_kernel_path,
    guest_image_status,
    is_vm_running,
    prepare_config_share,
    start_vm,
    stop_vm,
)

# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


class TestPathHelpers:
    """Path derivation from config dir and agent name."""

    def test_kernel_path(self, tmp_config_dir):
        assert get_kernel_path() == tmp_config_dir / "share" / "Image"

    def test_initrd_path(self, tmp_config_dir):
        assert get_initrd_path() == tmp_config_dir / "share" / "initramfs.cpio.gz"

    def test_base_rootfs_path(self, tmp_config_dir):
        assert get_base_rootfs_path() == tmp_config_dir / "share" / "rootfs-base.ext4"

    def test_agent_rootfs_path_returns_shared_base(self, tmp_config_dir):
        # After exp/erofs-vz-phase-a, there is no per-agent rootfs clone.
        # The shared ext4 base is read-only-booted by every macOS VZ agent;
        # per-agent writes land in the overlay (/dev/vdb) and /home/agent.
        # get_agent_rootfs_path therefore aliases the shared base so
        # callers that expect a Path to boot from get the right file.
        assert get_agent_rootfs_path("myagent") == tmp_config_dir / "share" / "rootfs-base.ext4"
        assert get_agent_rootfs_path("other") == tmp_config_dir / "share" / "rootfs-base.ext4"

    def test_agent_pid_path(self, tmp_config_dir):
        assert get_agent_pid_path("myagent") == tmp_config_dir / "agents" / "myagent" / "vm.pid"

    def test_agent_config_share_dir(self, tmp_config_dir):
        assert get_agent_config_share_dir("myagent") == tmp_config_dir / "agents" / "myagent" / "config-share"


# ---------------------------------------------------------------------------
# find_vm_helper
# ---------------------------------------------------------------------------


class TestFindVmHelper:
    """Binary lookup in three locations with priority order."""

    def test_finds_in_config_bin(self, tmp_config_dir):
        """~/.safeyolo/bin/safeyolo-vm is found first."""
        bin_dir = tmp_config_dir / "bin"
        bin_dir.mkdir(exist_ok=True)
        helper = bin_dir / "safeyolo-vm"
        helper.write_text("#!/bin/sh\n")
        helper.chmod(0o755)

        result = find_vm_helper()
        assert result == helper

    def test_config_bin_must_be_executable(self, tmp_config_dir, monkeypatch):
        """A non-executable file in config/bin is skipped."""
        bin_dir = tmp_config_dir / "bin"
        bin_dir.mkdir(exist_ok=True)
        helper = bin_dir / "safeyolo-vm"
        helper.write_text("not executable")
        helper.chmod(0o644)

        # Block both PATH lookup and repo layout fallback
        monkeypatch.setattr("shutil.which", lambda name: None)
        _real_access = os.access
        def _deny_repo_access(path, mode):
            if "vm/.build/release" in str(path):
                return False
            return _real_access(path, mode)
        monkeypatch.setattr("os.access", _deny_repo_access)

        with pytest.raises(VMError, match="Cannot find safeyolo-vm"):
            find_vm_helper()

    def test_falls_back_to_path(self, tmp_config_dir, monkeypatch):
        """Falls back to shutil.which when config/bin has nothing."""
        monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/safeyolo-vm")

        result = find_vm_helper()
        assert result == Path("/usr/local/bin/safeyolo-vm")

    def test_falls_back_to_repo_layout(self, tmp_config_dir, monkeypatch):
        """Falls back to repo dev build directory when config/bin and PATH miss."""
        # Block PATH lookup -- config/bin doesn't have it (tmp_config_dir is clean)
        monkeypatch.setattr("shutil.which", lambda name: None)

        # The real repo has vm/.build/release/safeyolo-vm -- verify the
        # fallback finds it. This test is environment-dependent by design:
        # it validates the dev-layout heuristic in the actual repo.
        import safeyolo.vm as vm_mod
        repo_bin = Path(vm_mod.__file__).resolve().parents[3] / "vm" / ".build" / "release" / "safeyolo-vm"
        if not (repo_bin.exists() and os.access(repo_bin, os.X_OK)):
            pytest.skip("repo dev binary not present -- cannot test repo layout fallback")

        result = find_vm_helper()
        assert result == repo_bin

    def _block_all_fallbacks(self, monkeypatch):
        """Helper: block both PATH and repo layout so nothing is found."""
        monkeypatch.setattr("shutil.which", lambda name: None)
        _real_access = os.access
        def _deny_repo(path, mode):
            if "vm/.build/release" in str(path):
                return False
            return _real_access(path, mode)
        monkeypatch.setattr("os.access", _deny_repo)

    def test_raises_vmerror_when_not_found(self, tmp_config_dir, monkeypatch):
        """Raises VMError with install instructions when binary not found anywhere."""
        self._block_all_fallbacks(monkeypatch)

        with pytest.raises(VMError, match="Cannot find safeyolo-vm"):
            find_vm_helper()

    def test_error_message_includes_install_instructions(self, tmp_config_dir, monkeypatch):
        """Error message tells the user how to install."""
        self._block_all_fallbacks(monkeypatch)

        with pytest.raises(VMError, match="cd vm && make install"):
            find_vm_helper()


# ---------------------------------------------------------------------------
# create_agent_rootfs
# ---------------------------------------------------------------------------


class TestCreateAgentRootfs:
    """Per-agent dir setup (no rootfs clone).

    Phase A dropped the per-agent rootfs copy: every agent boots from
    the shared read-only ext4 base, with writes captured in the overlay
    upper (/dev/vdb persistent, or tmpfs ephemeral) and /home/agent.
    create_agent_rootfs now only (a) verifies the base exists and (b)
    ensures the per-agent directory exists (for overlay.img, config
    share, status, ssh keys). It does not copy any bytes.
    """

    def test_raises_when_base_rootfs_missing(self, tmp_config_dir):
        """Raises VMError if base rootfs doesn't exist."""
        with pytest.raises(VMError, match="Base rootfs not found"):
            create_agent_rootfs("myagent")

    def test_error_includes_build_instructions(self, tmp_config_dir):
        """Error tells user how to build guest images."""
        with pytest.raises(VMError, match="build-all.sh"):
            create_agent_rootfs("myagent")

    def test_creates_agent_dir(self, tmp_config_dir):
        """Creates the agents/{name}/ directory so later code (overlay,
        config-share, status) can write into it."""
        share_dir = tmp_config_dir / "share"
        share_dir.mkdir(exist_ok=True)
        (share_dir / "rootfs-base.ext4").write_bytes(b"rootfs-data")

        create_agent_rootfs("newagent")
        assert (tmp_config_dir / "agents" / "newagent").is_dir()

    def test_returns_shared_base_path(self, tmp_config_dir):
        """Return value is the shared base, not a per-agent file."""
        share_dir = tmp_config_dir / "share"
        share_dir.mkdir(exist_ok=True)
        base = share_dir / "rootfs-base.ext4"
        base.write_bytes(b"rootfs-data")

        result = create_agent_rootfs("agent1")
        assert result == base

    def test_does_not_copy_base_to_agent_dir(self, tmp_config_dir):
        """No per-agent rootfs.ext4 file is created. The agent dir exists
        but must not contain a rootfs clone."""
        share_dir = tmp_config_dir / "share"
        share_dir.mkdir(exist_ok=True)
        (share_dir / "rootfs-base.ext4").write_bytes(b"rootfs-data")

        create_agent_rootfs("agent1")
        assert not (tmp_config_dir / "agents" / "agent1" / "rootfs.ext4").exists()

    def test_idempotent_when_agent_dir_already_exists(self, tmp_config_dir):
        """Calling twice does not raise -- the per-agent dir mkdir is
        idempotent (parents=True, exist_ok=True)."""
        share_dir = tmp_config_dir / "share"
        share_dir.mkdir(exist_ok=True)
        (share_dir / "rootfs-base.ext4").write_bytes(b"rootfs-data")

        agent_dir = tmp_config_dir / "agents" / "myagent"
        agent_dir.mkdir(parents=True)
        (agent_dir / "overlay.img").write_bytes(b"preexisting overlay")

        result = create_agent_rootfs("myagent")
        assert result == share_dir / "rootfs-base.ext4"
        # Unrelated per-agent files must not be disturbed.
        assert (agent_dir / "overlay.img").read_bytes() == b"preexisting overlay"


# ---------------------------------------------------------------------------
# prepare_config_share
# ---------------------------------------------------------------------------


class TestPrepareConfigShare:
    """Config share directory contents for guest init."""

    @pytest.fixture(autouse=True)
    def setup_config_share_deps(self, tmp_config_dir, monkeypatch):
        """Set up dependencies for prepare_config_share tests."""
        self.config_dir = tmp_config_dir

        # Create the guest-init*.sh source files where the code expects
        # them (same directory as vm.py). Three files: the orchestrator
        # and its static/per-run phase scripts.
        import safeyolo.vm as vm_mod

        self._created_guest_init_srcs: list[Path] = []
        for src_name in ("guest-init.sh", "guest-init-static.sh", "guest-init-per-run.sh"):
            src = Path(vm_mod.__file__).parent / src_name
            if not src.exists():
                src.write_text(f"#!/bin/bash\necho {src_name}\n")
                self._created_guest_init_srcs.append(src)

        # Mock _ensure_ssh_key to avoid subprocess calls
        monkeypatch.setattr("safeyolo.vm._ensure_ssh_key", lambda: None)

        # Create SSH public key
        data_dir = tmp_config_dir / "data"
        data_dir.mkdir(exist_ok=True)
        ssh_key = data_dir / "vm_ssh_key"
        ssh_key.write_text("fake-private-key")
        ssh_key.with_suffix(".pub").write_text("ssh-ed25519 AAAA... agent@safeyolo")

        yield

        for src in self._created_guest_init_srcs:
            src.unlink(missing_ok=True)

    def test_returns_config_share_dir(self, tmp_config_dir):
        result = prepare_config_share("agent1", "/workspace")
        assert result == tmp_config_dir / "agents" / "agent1" / "config-share"

    def test_creates_config_share_directory(self, tmp_config_dir):
        result = prepare_config_share("agent1", "/workspace")
        assert result.is_dir()

    def test_guest_init_is_executable(self, tmp_config_dir):
        share = prepare_config_share("agent1", "/workspace")
        guest_init = share / "guest-init"
        assert guest_init.exists()
        assert os.access(guest_init, os.X_OK)

    def test_guest_init_static_and_per_run_are_executable(self, tmp_config_dir):
        """The orchestrator execs two phase scripts -- both must be present
        and executable on the config share or the guest hangs."""
        share = prepare_config_share("agent1", "/workspace")
        for name in ("guest-init-static", "guest-init-per-run"):
            path = share / name
            assert path.exists(), f"{name} missing from config share"
            assert os.access(path, os.X_OK), f"{name} not executable"

    def test_per_run_go_sentinel_pre_written(self, tmp_config_dir):
        """Pre-write /safeyolo/per-run-go so the orchestrator falls straight
        through in passthrough mode. PR 3/4 will remove this and write it
        at the snapshot-completion point instead."""
        share = prepare_config_share("agent1", "/workspace")
        assert (share / "per-run-go").exists()

    def test_per_run_go_not_pre_written_when_opted_out(self, tmp_config_dir):
        """Capture mode needs the gate closed at prepare time so the guest
        pauses at the static/per-run boundary for the snapshot signal."""
        share = prepare_config_share("agent1", "/workspace", pre_write_per_run_go=False)
        assert not (share / "per-run-go").exists()

    def test_stale_per_run_go_cleared_when_opted_out(self, tmp_config_dir):
        """A stale per-run-go from an earlier passthrough run would let
        the guest skip the snapshot point. prepare_config_share must
        clear it when pre_write_per_run_go=False."""
        share_dir = tmp_config_dir / "agents" / "agent1" / "config-share"
        share_dir.mkdir(parents=True, exist_ok=True)
        (share_dir / "per-run-go").write_text("stale")
        prepare_config_share("agent1", "/workspace", pre_write_per_run_go=False)
        assert not (share_dir / "per-run-go").exists()

    def test_stale_static_init_done_is_cleared(self, tmp_config_dir):
        """A static-init-done left over from a prior run must not persist
        into the next run -- the orchestrator writes it fresh on the
        (writable) status share."""
        status_dir = tmp_config_dir / "agents" / "agent1" / "status"
        status_dir.mkdir(parents=True, exist_ok=True)
        (status_dir / "static-init-done").write_text("stale")
        prepare_config_share("agent1", "/workspace")
        assert not (status_dir / "static-init-done").exists()

    def test_stale_per_run_started_is_cleared(self, tmp_config_dir):
        """A per-run-started left over from a prior run would make a
        failed restore look successful -- the CLI polls for this file
        specifically as the definitive readiness signal. Lives on the
        status share."""
        status_dir = tmp_config_dir / "agents" / "agent1" / "status"
        status_dir.mkdir(parents=True, exist_ok=True)
        (status_dir / "per-run-started").write_text("stale")
        prepare_config_share("agent1", "/workspace")
        assert not (status_dir / "per-run-started").exists()

    def test_proxy_env_uses_gateway_ip_and_port(self, tmp_config_dir):
        """proxy.env uses whatever (gateway_ip, proxy_port) the caller
        passes. Both platforms pass (127.0.0.1, 8080) -- the guest-proxy-forwarder
        listens on that address inside the sandbox and the host bridge
        decouples it from mitmproxy's actual port. prepare_config_share
        is platform-agnostic -- it just renders."""
        share = prepare_config_share(
            "agent1", "/workspace",
            gateway_ip="10.0.0.1", proxy_port=9999,
        )
        proxy_env = (share / "proxy.env").read_text()
        assert 'HTTP_PROXY="http://10.0.0.1:9999"' in proxy_env
        assert 'HTTPS_PROXY="http://10.0.0.1:9999"' in proxy_env
        assert 'http_proxy="http://10.0.0.1:9999"' in proxy_env
        assert 'https_proxy="http://10.0.0.1:9999"' in proxy_env

    def test_proxy_env_default_values(self, tmp_config_dir):
        share = prepare_config_share("agent1", "/workspace")
        proxy_env = (share / "proxy.env").read_text()
        # Default gateway_ip=127.0.0.1, proxy_port=8080
        assert 'HTTP_PROXY="http://127.0.0.1:8080"' in proxy_env

    def test_proxy_env_includes_no_proxy(self, tmp_config_dir):
        share = prepare_config_share("agent1", "/workspace")
        proxy_env = (share / "proxy.env").read_text()
        assert 'NO_PROXY="localhost,127.0.0.1"' in proxy_env
        assert 'no_proxy="localhost,127.0.0.1"' in proxy_env

    def test_proxy_env_includes_ssl_cert_paths(self, tmp_config_dir):
        share = prepare_config_share("agent1", "/workspace")
        proxy_env = (share / "proxy.env").read_text()
        assert 'SSL_CERT_FILE="/usr/local/share/ca-certificates/safeyolo.crt"' in proxy_env
        assert 'REQUESTS_CA_BUNDLE="/usr/local/share/ca-certificates/safeyolo.crt"' in proxy_env
        assert 'NODE_EXTRA_CA_CERTS="/usr/local/share/ca-certificates/safeyolo.crt"' in proxy_env

    def test_proxy_env_sets_home(self, tmp_config_dir):
        share = prepare_config_share("agent1", "/workspace")
        proxy_env = (share / "proxy.env").read_text()
        assert 'HOME=/home/agent' in proxy_env

    def test_network_env_uses_guest_and_gateway_ips(self, tmp_config_dir):
        share = prepare_config_share(
            "agent1", "/workspace",
            gateway_ip="192.168.66.1", guest_ip="192.168.66.2",
        )
        network_env = (share / "network.env").read_text()
        assert network_env == (
            "GUEST_IP=192.168.66.2\n"
            "GATEWAY_IP=192.168.66.1\n"
            "NETMASK=255.255.255.0\n"
        )

    def test_network_env_default_values(self, tmp_config_dir):
        share = prepare_config_share("agent1", "/workspace")
        network_env = (share / "network.env").read_text()
        assert network_env == (
            "GUEST_IP=127.0.0.1\n"
            "GATEWAY_IP=127.0.0.1\n"
            "NETMASK=255.255.255.0\n"
        )

    def test_agent_name_file_written_for_guest_hostname(self, tmp_config_dir):
        """Guest reads /safeyolo/agent-name and calls `hostname <name>` in
        static phase so the VM identifies itself as its agent name."""
        share = prepare_config_share("claude-snaptest", "/workspace")
        assert (share / "agent-name").read_text() == "claude-snaptest"

    def test_agent_name_file_matches_name_argument(self, tmp_config_dir):
        share = prepare_config_share("myagent", "/workspace")
        assert (share / "agent-name").read_text() == "myagent"

    def test_agent_env_carries_agent_args_and_extra_env(self, tmp_config_dir):
        share = prepare_config_share(
            "agent1", "/workspace",
            agent_args="--model opus",
            extra_env={"FOO": "bar", "BAZ": "qux"},
        )
        agent_env = (share / "agent.env").read_text()
        assert 'SAFEYOLO_AGENT_ARGS="--model opus"' in agent_env
        assert 'FOO="bar"' in agent_env
        assert 'BAZ="qux"' in agent_env

    def test_agent_env_empty_when_no_parameters(self, tmp_config_dir):
        share = prepare_config_share("agent1", "/workspace")
        agent_env = (share / "agent.env").read_text()
        # Should just be a trailing newline with no export lines
        assert agent_env == "\n"

    def test_agent_env_omits_agent_args_when_empty(self, tmp_config_dir):
        share = prepare_config_share(
            "agent1", "/workspace",
            extra_env={"FOO": "bar"},
        )
        agent_env = (share / "agent.env").read_text()
        assert 'FOO="bar"' in agent_env
        assert "SAFEYOLO_AGENT_ARGS" not in agent_env

    def test_ca_cert_copied_if_exists(self, tmp_config_dir):
        certs_dir = tmp_config_dir / "certs"
        certs_dir.mkdir(exist_ok=True)
        (certs_dir / "mitmproxy-ca-cert.pem").write_text("CA-CERT-DATA")

        share = prepare_config_share("agent1", "/workspace")
        assert (share / "mitmproxy-ca-cert.pem").read_text() == "CA-CERT-DATA"

    def test_ca_cert_not_copied_if_missing(self, tmp_config_dir):
        share = prepare_config_share("agent1", "/workspace")
        assert not (share / "mitmproxy-ca-cert.pem").exists()

    def test_ssh_authorized_keys_copied(self, tmp_config_dir):
        share = prepare_config_share("agent1", "/workspace")
        assert (share / "authorized_keys").read_text() == "ssh-ed25519 AAAA... agent@safeyolo"

    def test_agent_token_copied_if_exists(self, tmp_config_dir):
        (tmp_config_dir / "data" / "agent_token").write_text("tok-abc-123")

        share = prepare_config_share("agent1", "/workspace")
        assert (share / "agent_token").read_text() == "tok-abc-123"

    def test_agent_token_not_copied_if_missing(self, tmp_config_dir):
        # Ensure no agent_token file exists
        token_path = tmp_config_dir / "data" / "agent_token"
        token_path.unlink(missing_ok=True)

        share = prepare_config_share("agent1", "/workspace")
        assert not (share / "agent_token").exists()

    def test_vsock_term_copied_if_exists(self, tmp_config_dir):
        bin_dir = tmp_config_dir / "bin"
        bin_dir.mkdir(exist_ok=True)
        (bin_dir / "vsock-term").write_bytes(b"\x7fELF-fake")

        share = prepare_config_share("agent1", "/workspace")
        vsock = share / "vsock-term"
        assert vsock.exists()
        assert os.access(vsock, os.X_OK)

    def test_vsock_term_not_copied_if_missing(self, tmp_config_dir):
        share = prepare_config_share("agent1", "/workspace")
        assert not (share / "vsock-term").exists()

    def test_host_mounts_manifest_under_home(self, tmp_config_dir, monkeypatch):
        """Paths under $HOME are mapped to /home/agent/..."""
        home = Path.home()
        share = prepare_config_share(
            "agent1", "/workspace",
            host_mounts=[(str(home / ".claude"), "dotclaude", True)],
        )
        manifest = (share / "host-mounts").read_text()
        assert manifest == "dotclaude:/home/agent/.claude\n"

    def test_host_mounts_manifest_outside_home(self, tmp_config_dir):
        """Paths outside $HOME are mapped to /mnt/{tag}."""
        share = prepare_config_share(
            "agent1", "/workspace",
            host_mounts=[("/opt/data", "optdata", False)],
        )
        manifest = (share / "host-mounts").read_text()
        assert manifest == "optdata:/mnt/optdata\n"

    def test_host_mounts_multiple_entries(self, tmp_config_dir):
        home = Path.home()
        share = prepare_config_share(
            "agent1", "/workspace",
            host_mounts=[
                (str(home / ".config"), "dotconfig", True),
                ("/opt/tools", "tools", False),
            ],
        )
        manifest = (share / "host-mounts").read_text()
        lines = manifest.strip().split("\n")
        assert len(lines) == 2
        assert lines[0] == "dotconfig:/home/agent/.config"
        assert lines[1] == "tools:/mnt/tools"

    def test_host_mounts_not_written_when_none(self, tmp_config_dir):
        share = prepare_config_share("agent1", "/workspace")
        assert not (share / "host-mounts").exists()



# ---------------------------------------------------------------------------
# start_vm
# ---------------------------------------------------------------------------


class TestStartVm:
    """VM process startup and PID file management."""

    @pytest.fixture(autouse=True)
    def setup_vm_deps(self, tmp_config_dir, monkeypatch):
        """Create required files for start_vm.

        Phase A: rootfs is the shared ext4 base under share/, not a
        per-agent file. Overlay.img is per-agent under agents/<name>/.
        """
        self.config_dir = tmp_config_dir

        # Shared kernel / initrd / ext4 base. get_agent_rootfs_path now
        # returns the shared base directly.
        share_dir = tmp_config_dir / "share"
        share_dir.mkdir(exist_ok=True)
        (share_dir / "Image").write_bytes(b"kernel")
        (share_dir / "initramfs.cpio.gz").write_bytes(b"initrd")
        (share_dir / "rootfs-base.ext4").write_bytes(b"shared-rootfs-base")

        # Per-agent dir holds the overlay.img (created lazily by
        # ensure_agent_overlay) and the config-share.
        agent_dir = tmp_config_dir / "agents" / "agent1"
        agent_dir.mkdir(parents=True)
        (agent_dir / "config-share").mkdir()

        # Create vm helper
        bin_dir = tmp_config_dir / "bin"
        bin_dir.mkdir(exist_ok=True)
        helper = bin_dir / "safeyolo-vm"
        helper.write_text("#!/bin/sh\n")
        helper.chmod(0o755)

    def test_raises_when_base_rootfs_missing(self, tmp_config_dir, monkeypatch):
        # get_agent_rootfs_path aliases the shared base; removing the
        # base reproduces the "guest images not built" situation.
        (tmp_config_dir / "share" / "rootfs-base.ext4").unlink()

        with pytest.raises(VMError, match="Agent rootfs not found"):
            start_vm("agent1", "/workspace")

    def test_raises_when_kernel_missing(self, tmp_config_dir):
        (tmp_config_dir / "share" / "Image").unlink()

        with pytest.raises(VMError, match="kernel not found"):
            start_vm("agent1", "/workspace")

    def test_raises_when_initrd_missing(self, tmp_config_dir):
        (tmp_config_dir / "share" / "initramfs.cpio.gz").unlink()

        with pytest.raises(VMError, match="initramfs not found"):
            start_vm("agent1", "/workspace")

    def test_writes_pid_file(self, tmp_config_dir, monkeypatch):
        mock_proc = MagicMock()
        mock_proc.pid = 12345
        monkeypatch.setattr(
            "subprocess.Popen",
            lambda cmd, **kw: mock_proc,
        )

        start_vm("agent1", "/workspace")

        pid_path = tmp_config_dir / "agents" / "agent1" / "vm.pid"
        assert pid_path.read_text() == "12345"

    def test_returns_popen_handle(self, tmp_config_dir, monkeypatch):
        mock_proc = MagicMock()
        mock_proc.pid = 99
        monkeypatch.setattr("subprocess.Popen", lambda cmd, **kw: mock_proc)

        result = start_vm("agent1", "/workspace")
        assert result is mock_proc

    def test_command_includes_kernel_initrd_rootfs(self, tmp_config_dir, monkeypatch):
        captured_cmd = []

        def mock_popen(cmd, **kw):
            captured_cmd.extend(cmd)
            proc = MagicMock()
            proc.pid = 1
            return proc

        monkeypatch.setattr("subprocess.Popen", mock_popen)

        start_vm("agent1", "/workspace")

        assert "--kernel" in captured_cmd
        assert "--initrd" in captured_cmd
        assert "--rootfs" in captured_cmd

    def test_command_includes_cpus_and_memory(self, tmp_config_dir, monkeypatch):
        captured_cmd = []

        def mock_popen(cmd, **kw):
            captured_cmd.extend(cmd)
            proc = MagicMock()
            proc.pid = 1
            return proc

        monkeypatch.setattr("subprocess.Popen", mock_popen)

        start_vm("agent1", "/workspace", cpus=8, memory_mb=8192)

        cpu_idx = captured_cmd.index("--cpus")
        assert captured_cmd[cpu_idx + 1] == "8"
        mem_idx = captured_cmd.index("--memory")
        assert captured_cmd[mem_idx + 1] == "8192"

    def test_command_includes_workspace_and_config_shares(self, tmp_config_dir, monkeypatch):
        captured_cmd = []

        def mock_popen(cmd, **kw):
            captured_cmd.extend(cmd)
            proc = MagicMock()
            proc.pid = 1
            return proc

        monkeypatch.setattr("subprocess.Popen", mock_popen)

        start_vm("agent1", "/my/workspace")

        # Find the --share arguments
        share_args = []
        for i, arg in enumerate(captured_cmd):
            if arg == "--share":
                share_args.append(captured_cmd[i + 1])

        assert any(a.startswith("/my/workspace:workspace:rw") for a in share_args)
        assert any(":config:ro" in a for a in share_args)

    def test_proxy_socket_flag_threaded_through(self, tmp_config_dir, monkeypatch):
        captured_cmd = []

        def mock_popen(cmd, **kw):
            captured_cmd.extend(cmd)
            proc = MagicMock()
            proc.pid = 1
            return proc

        monkeypatch.setattr("subprocess.Popen", mock_popen)

        start_vm("agent1", "/workspace", proxy_socket_path="/tmp/agent1.sock")

        idx = captured_cmd.index("--proxy-socket")
        assert captured_cmd[idx + 1] == "/tmp/agent1.sock"

    def test_shell_socket_flag_threaded_through(self, tmp_config_dir, monkeypatch):
        captured_cmd = []

        def mock_popen(cmd, **kw):
            captured_cmd.extend(cmd)
            proc = MagicMock()
            proc.pid = 1
            return proc

        monkeypatch.setattr("subprocess.Popen", mock_popen)

        start_vm("agent1", "/workspace", shell_socket_path="/tmp/shell.sock")

        idx = captured_cmd.index("--shell-socket")
        assert captured_cmd[idx + 1] == "/tmp/shell.sock"

    def test_extra_shares_added_with_correct_mode(self, tmp_config_dir, monkeypatch):
        captured_cmd = []

        def mock_popen(cmd, **kw):
            captured_cmd.extend(cmd)
            proc = MagicMock()
            proc.pid = 1
            return proc

        monkeypatch.setattr("subprocess.Popen", mock_popen)

        start_vm(
            "agent1", "/workspace",
            extra_shares=[
                ("/data", "data", False),
                ("/secrets", "secrets", True),
            ],
        )

        share_args = []
        for i, arg in enumerate(captured_cmd):
            if arg == "--share":
                share_args.append(captured_cmd[i + 1])

        assert "/data:data:rw" in share_args
        assert "/secrets:secrets:ro" in share_args

    def test_background_mode_redirects_to_serial_log(self, tmp_config_dir, monkeypatch):
        captured_kwargs = {}

        def mock_popen(cmd, **kw):
            captured_kwargs.update(kw)
            proc = MagicMock()
            proc.pid = 1
            return proc

        monkeypatch.setattr("subprocess.Popen", mock_popen)

        start_vm("agent1", "/workspace", background=True)

        assert captured_kwargs.get("stdin") == subprocess.DEVNULL
        # stdout and stderr should be file handles (not None/PIPE)
        assert captured_kwargs.get("stdout") is not None
        assert captured_kwargs.get("stderr") is not None

    def test_foreground_mode_no_redirection(self, tmp_config_dir, monkeypatch):
        captured_kwargs = {}

        def mock_popen(cmd, **kw):
            captured_kwargs.update(kw)
            proc = MagicMock()
            proc.pid = 1
            return proc

        monkeypatch.setattr("subprocess.Popen", mock_popen)

        start_vm("agent1", "/workspace", background=False)

        assert "stdin" not in captured_kwargs
        assert "stdout" not in captured_kwargs

    def test_snapshot_capture_path_adds_flag(self, tmp_config_dir, monkeypatch):
        """When snapshot_capture_path is set, --snapshot-on-signal should
        be threaded to the helper."""
        captured_cmd = []

        def mock_popen(cmd, **kw):
            captured_cmd.extend(cmd)
            proc = MagicMock()
            proc.pid = 1
            return proc

        monkeypatch.setattr("subprocess.Popen", mock_popen)
        snap_path = tmp_config_dir / "agents" / "agent1" / "snapshot.bin"
        start_vm("agent1", "/workspace", snapshot_capture_path=snap_path)

        assert "--snapshot-on-signal" in captured_cmd
        idx = captured_cmd.index("--snapshot-on-signal")
        assert captured_cmd[idx + 1] == str(snap_path)

    def test_restore_clones_overlay_to_per_run_working_copy(self, tmp_config_dir, monkeypatch):
        """Restore must not attach the pristine overlay clone directly: the
        live restored VM writes to its /dev/vdb overlay, and VZ requires
        every attached disk to match its save-time state byte-for-byte.
        start_vm clones snapshot.bin.overlay to snapshot.bin.overlay.run
        and attaches that as --overlay. The pristine clone stays untouched
        for the next restore.

        The rootfs (shared read-only ext4 base) does NOT change between
        save and restore, so --rootfs keeps pointing at the shared base
        with no pairing."""
        captured_cmd = []

        def mock_popen(cmd, **kw):
            captured_cmd.extend(cmd)
            proc = MagicMock()
            proc.pid = 1
            return proc

        cp_calls: list[list[str]] = []

        def mock_cp_run(cmd, **kw):
            # Simulate successful `cp -c` by copying the file content.
            cp_calls.append(list(cmd))
            if cmd[0] == "cp" and "-c" in cmd:
                src, dst = cmd[-2], cmd[-1]
                Path(dst).write_bytes(Path(src).read_bytes())
                return MagicMock(returncode=0, stdout=b"", stderr=b"")
            return MagicMock(returncode=0)

        monkeypatch.setattr("subprocess.Popen", mock_popen)
        monkeypatch.setattr("subprocess.run", mock_cp_run)
        snap_path = tmp_config_dir / "agents" / "agent1" / "snapshot.bin"
        pristine = tmp_config_dir / "agents" / "agent1" / "snapshot.bin.overlay"
        pristine.write_bytes(b"pristine-overlay")

        start_vm("agent1", "/workspace", restore_from_path=snap_path)

        # --overlay must point at the per-run working copy, NOT the pristine.
        overlay_idx = captured_cmd.index("--overlay")
        working_copy = tmp_config_dir / "agents" / "agent1" / "snapshot.bin.overlay.run"
        assert captured_cmd[overlay_idx + 1] == str(working_copy)
        # --rootfs still points at the shared base -- unchanged between save/restore.
        rootfs_idx = captured_cmd.index("--rootfs")
        assert captured_cmd[rootfs_idx + 1] == str(
            tmp_config_dir / "share" / "rootfs-base.ext4"
        )
        # Working copy must exist and match pristine at invocation time.
        assert working_copy.exists()
        assert working_copy.read_bytes() == b"pristine-overlay"
        # Pristine clone must not have been touched (still the same bytes).
        assert pristine.read_bytes() == b"pristine-overlay"
        # cp -c must have been attempted (APFS clonefile fast path).
        assert any("cp" in c and "-c" in c for c in cp_calls)

    def test_restore_working_copy_overwrites_stale_one(self, tmp_config_dir, monkeypatch):
        """A .overlay.run file left behind by a previous restore session
        must be replaced, not appended to -- otherwise subsequent restores
        attach an overlay that drifted from save-time state."""
        def mock_popen(cmd, **kw):
            return MagicMock(pid=1)

        def mock_cp_run(cmd, **kw):
            if cmd[0] == "cp" and "-c" in cmd:
                src, dst = cmd[-2], cmd[-1]
                Path(dst).write_bytes(Path(src).read_bytes())
                return MagicMock(returncode=0)
            return MagicMock(returncode=0)

        monkeypatch.setattr("subprocess.Popen", mock_popen)
        monkeypatch.setattr("subprocess.run", mock_cp_run)
        snap_path = tmp_config_dir / "agents" / "agent1" / "snapshot.bin"
        pristine = tmp_config_dir / "agents" / "agent1" / "snapshot.bin.overlay"
        pristine.write_bytes(b"pristine")
        stale_run = tmp_config_dir / "agents" / "agent1" / "snapshot.bin.overlay.run"
        stale_run.write_bytes(b"STALE-FROM-PRIOR-RESTORE")

        start_vm("agent1", "/workspace", restore_from_path=snap_path)

        assert stale_run.exists()
        assert stale_run.read_bytes() == b"pristine"

    def test_restore_without_overlay_clone_raises(self, tmp_config_dir, monkeypatch):
        """If the paired overlay clone is missing, restore can't possibly
        succeed -- refuse early rather than hand VZ a mismatched overlay."""
        monkeypatch.setattr("subprocess.Popen", lambda *a, **kw: MagicMock(pid=1))
        snap_path = tmp_config_dir / "agents" / "agent1" / "snapshot.bin"
        # No overlay clone file.

        with pytest.raises(VMError, match="overlay clone missing"):
            start_vm("agent1", "/workspace", restore_from_path=snap_path)

    def test_ephemeral_restore_skips_overlay_pairing(self, tmp_config_dir, monkeypatch):
        """Ephemeral agents have no overlay disk attached at save time,
        so no .overlay clone is produced and none is required on restore.
        start_vm must not fail with "overlay clone missing" in this mode,
        and must not emit --overlay."""
        captured_cmd = []

        def mock_popen(cmd, **kw):
            captured_cmd.extend(cmd)
            return MagicMock(pid=1)

        monkeypatch.setattr("subprocess.Popen", mock_popen)
        snap_path = tmp_config_dir / "agents" / "agent1" / "snapshot.bin"
        # Intentionally no .overlay file.

        start_vm(
            "agent1", "/workspace",
            restore_from_path=snap_path, ephemeral=True,
        )
        assert "--overlay" not in captured_cmd

    def test_snapshot_and_restore_mutually_exclusive(self, tmp_config_dir, monkeypatch):
        """The helper's own arg parser would reject both flags together,
        but we should fail in Python so the error message is clearer."""
        monkeypatch.setattr("subprocess.Popen", lambda *a, **kw: MagicMock(pid=1))
        snap_path = tmp_config_dir / "agents" / "agent1" / "snapshot.bin"
        with pytest.raises(VMError, match="mutually exclusive"):
            start_vm(
                "agent1", "/workspace",
                snapshot_capture_path=snap_path,
                restore_from_path=snap_path,
            )


# ---------------------------------------------------------------------------
# stop_vm
# ---------------------------------------------------------------------------


class TestStopVm:
    """VM process shutdown and cleanup."""

    def test_no_pid_file_still_cleans_up(self, tmp_config_dir, monkeypatch):
        """When no PID file exists, still clears the agent map entry."""
        agents_dir = tmp_config_dir / "agents"
        agents_dir.mkdir(exist_ok=True)
        (agents_dir / "agent1").mkdir(exist_ok=True)

        map_calls = []
        monkeypatch.setattr(
            "safeyolo.vm._update_agent_map",
            lambda name, **kw: map_calls.append((name, kw)),
        )

        stop_vm("agent1")
        assert map_calls == [("agent1", {"remove": True})]

    def test_sends_sigterm(self, tmp_config_dir, monkeypatch):
        """Sends SIGTERM to the VM process."""
        agent_dir = tmp_config_dir / "agents" / "agent1"
        agent_dir.mkdir(parents=True)
        (agent_dir / "vm.pid").write_text("12345")

        killed_signals = []

        def mock_kill(pid, sig):
            killed_signals.append((pid, sig))
            if sig == signal.SIGTERM:
                return  # Success
            # For os.kill(pid, 0) -- pretend process is dead after SIGTERM
            raise ProcessLookupError()

        monkeypatch.setattr("os.kill", mock_kill)
        monkeypatch.setattr("safeyolo.vm._update_agent_map", lambda name, **kw: None)

        stop_vm("agent1")

        assert (12345, signal.SIGTERM) in killed_signals

    def test_cleans_up_pid_file_after_stop(self, tmp_config_dir, monkeypatch):
        agent_dir = tmp_config_dir / "agents" / "agent1"
        agent_dir.mkdir(parents=True)
        pid_path = agent_dir / "vm.pid"
        pid_path.write_text("12345")

        def mock_kill(pid, sig):
            if sig == 0:
                raise ProcessLookupError()

        monkeypatch.setattr("os.kill", mock_kill)
        monkeypatch.setattr("safeyolo.vm._update_agent_map", lambda name, **kw: None)

        stop_vm("agent1")
        assert not pid_path.exists()

    def test_handles_already_dead_process(self, tmp_config_dir, monkeypatch):
        """ProcessLookupError on SIGTERM is handled gracefully."""
        agent_dir = tmp_config_dir / "agents" / "agent1"
        agent_dir.mkdir(parents=True)
        pid_path = agent_dir / "vm.pid"
        pid_path.write_text("99999")

        def mock_kill(pid, sig):
            raise ProcessLookupError()

        monkeypatch.setattr("os.kill", mock_kill)
        monkeypatch.setattr("safeyolo.vm._update_agent_map", lambda name, **kw: None)

        stop_vm("agent1")  # Should not raise
        assert not pid_path.exists()

    def test_sends_sigkill_after_timeout(self, tmp_config_dir, monkeypatch):
        """Sends SIGKILL when process doesn't die after SIGTERM."""
        agent_dir = tmp_config_dir / "agents" / "agent1"
        agent_dir.mkdir(parents=True)
        (agent_dir / "vm.pid").write_text("12345")

        kill_count = 0
        signals_sent = []

        def mock_kill(pid, sig):
            nonlocal kill_count
            signals_sent.append(sig)
            kill_count += 1
            # Process stays alive for all signal-0 checks, then dies on SIGKILL
            if sig == signal.SIGKILL:
                return
            if sig == 0:
                return  # Process is always alive
            # SIGTERM succeeds but process doesn't die

        monkeypatch.setattr("os.kill", mock_kill)
        monkeypatch.setattr("time.sleep", lambda x: None)  # Skip waits
        monkeypatch.setattr("safeyolo.vm._update_agent_map", lambda name, **kw: None)

        stop_vm("agent1")

        assert signal.SIGTERM in signals_sent
        assert signal.SIGKILL in signals_sent

    def test_removes_from_agent_map(self, tmp_config_dir, monkeypatch):
        agent_dir = tmp_config_dir / "agents" / "agent1"
        agent_dir.mkdir(parents=True)
        (agent_dir / "vm.pid").write_text("12345")

        map_calls = []

        def mock_kill(pid, sig):
            if sig == 0:
                raise ProcessLookupError()

        monkeypatch.setattr("os.kill", mock_kill)
        monkeypatch.setattr(
            "safeyolo.vm._update_agent_map",
            lambda name, **kw: map_calls.append((name, kw)),
        )

        stop_vm("agent1")
        assert map_calls == [("agent1", {"remove": True})]


# ---------------------------------------------------------------------------
# is_vm_running
# ---------------------------------------------------------------------------


class TestIsVmRunning:
    """PID file check and process liveness probe."""

    def test_returns_false_when_no_pid_file(self, tmp_config_dir):
        assert is_vm_running("nonexistent") is False

    def test_returns_true_when_process_alive(self, tmp_config_dir, monkeypatch):
        agent_dir = tmp_config_dir / "agents" / "agent1"
        agent_dir.mkdir(parents=True)
        (agent_dir / "vm.pid").write_text("12345")

        monkeypatch.setattr("os.kill", lambda pid, sig: None)  # Process is alive

        assert is_vm_running("agent1") is True

    def test_returns_false_and_cleans_stale_pid(self, tmp_config_dir, monkeypatch):
        """Stale PID file (dead process) is cleaned up and returns False."""
        agent_dir = tmp_config_dir / "agents" / "agent1"
        agent_dir.mkdir(parents=True)
        pid_path = agent_dir / "vm.pid"
        pid_path.write_text("99999")

        def mock_kill(pid, sig):
            raise ProcessLookupError()

        monkeypatch.setattr("os.kill", mock_kill)

        assert is_vm_running("agent1") is False
        assert not pid_path.exists()


# ---------------------------------------------------------------------------
# _update_agent_map
# ---------------------------------------------------------------------------


class TestUpdateAgentMap:
    """Agent map JSON for service discovery."""

    def test_adds_agent_with_ip(self, tmp_config_dir, monkeypatch):
        monkeypatch.setattr(
            "time.strftime",
            lambda fmt, t: "2026-04-06T12:00:00Z",
        )

        _update_agent_map("agent1", ip="192.168.65.2")

        map_path = tmp_config_dir / "data" / "agent_map.json"
        data = json.loads(map_path.read_text())
        assert data == {
            "agent1": {
                "ip": "192.168.65.2",
                "started": "2026-04-06T12:00:00Z",
            }
        }

    def test_removes_agent(self, tmp_config_dir):
        map_path = tmp_config_dir / "data" / "agent_map.json"
        map_path.write_text(json.dumps({
            "agent1": {"ip": "1.2.3.4", "started": "2026-01-01T00:00:00Z"},
            "agent2": {"ip": "5.6.7.8", "started": "2026-01-01T00:00:00Z"},
        }))

        _update_agent_map("agent1", remove=True)

        data = json.loads(map_path.read_text())
        assert "agent1" not in data
        assert "agent2" in data

    def test_remove_nonexistent_agent_is_noop(self, tmp_config_dir):
        map_path = tmp_config_dir / "data" / "agent_map.json"
        map_path.write_text(json.dumps({"other": {"ip": "1.2.3.4", "started": "t"}}))

        _update_agent_map("ghost", remove=True)

        data = json.loads(map_path.read_text())
        assert data == {"other": {"ip": "1.2.3.4", "started": "t"}}

    def test_creates_map_file_if_missing(self, tmp_config_dir, monkeypatch):
        monkeypatch.setattr(
            "time.strftime",
            lambda fmt, t: "2026-04-06T00:00:00Z",
        )

        _update_agent_map("agent1", ip="10.0.0.1")

        map_path = tmp_config_dir / "data" / "agent_map.json"
        assert map_path.exists()
        data = json.loads(map_path.read_text())
        assert data["agent1"]["ip"] == "10.0.0.1"

    def test_handles_corrupt_json(self, tmp_config_dir, monkeypatch):
        """Corrupt agent_map.json is treated as empty."""
        map_path = tmp_config_dir / "data" / "agent_map.json"
        map_path.write_text("{broken json!!!")

        monkeypatch.setattr(
            "time.strftime",
            lambda fmt, t: "2026-04-06T00:00:00Z",
        )

        _update_agent_map("agent1", ip="10.0.0.1")

        data = json.loads(map_path.read_text())
        assert data["agent1"]["ip"] == "10.0.0.1"

    def test_preserves_other_agents(self, tmp_config_dir, monkeypatch):
        map_path = tmp_config_dir / "data" / "agent_map.json"
        map_path.write_text(json.dumps({
            "existing": {"ip": "1.1.1.1", "started": "2026-01-01T00:00:00Z"},
        }))

        monkeypatch.setattr(
            "time.strftime",
            lambda fmt, t: "2026-04-06T00:00:00Z",
        )

        _update_agent_map("new-agent", ip="2.2.2.2")

        data = json.loads(map_path.read_text())
        assert data["existing"]["ip"] == "1.1.1.1"
        assert data["new-agent"]["ip"] == "2.2.2.2"

    def test_json_has_trailing_newline(self, tmp_config_dir, monkeypatch):
        """Output is pretty-printed with trailing newline."""
        monkeypatch.setattr(
            "time.strftime",
            lambda fmt, t: "2026-04-06T00:00:00Z",
        )

        _update_agent_map("agent1", ip="10.0.0.1")

        map_path = tmp_config_dir / "data" / "agent_map.json"
        content = map_path.read_text()
        assert content.endswith("\n")
        # Verify pretty-printed (indented)
        assert "\n  " in content

    def test_no_ip_and_no_remove_is_noop(self, tmp_config_dir):
        """Calling with neither ip nor remove writes back unchanged map."""
        map_path = tmp_config_dir / "data" / "agent_map.json"
        map_path.write_text(json.dumps({"x": {"ip": "1.1.1.1", "started": "t"}}))

        _update_agent_map("y")  # No ip, no remove

        data = json.loads(map_path.read_text())
        assert "y" not in data
        assert data["x"]["ip"] == "1.1.1.1"


# ---------------------------------------------------------------------------
# check_guest_images / guest_image_status
# ---------------------------------------------------------------------------


class TestGuestImageChecks:
    """Guest image artifact existence checks.

    check_guest_images() is platform-aware:
      - macOS (Virtualization.framework): kernel + initramfs + ext4 rootfs.
      - Linux (gVisor): unpacked rootfs tree (OCI root.path). gVisor ships
        its own kernel, and the tree is consumed directly -- no image
        file is produced.

    A "valid" Linux tree is a directory that at least contains /etc --
    a bare directory with nothing inside would indicate a half-unpacked
    or rm-rf'd rootfs.
    """

    def test_check_guest_images_all_present_darwin(self, tmp_config_dir):
        share = tmp_config_dir / "share"
        share.mkdir(exist_ok=True)
        (share / "Image").write_bytes(b"k")
        (share / "initramfs.cpio.gz").write_bytes(b"i")
        (share / "rootfs-base.ext4").write_bytes(b"r")

        with patch("safeyolo.vm.platform.system", return_value="Darwin"):
            assert check_guest_images() is True

    def test_check_guest_images_missing_kernel_darwin(self, tmp_config_dir):
        share = tmp_config_dir / "share"
        share.mkdir(exist_ok=True)
        (share / "initramfs.cpio.gz").write_bytes(b"i")
        (share / "rootfs-base.ext4").write_bytes(b"r")

        with patch("safeyolo.vm.platform.system", return_value="Darwin"):
            assert check_guest_images() is False

    def test_check_guest_images_missing_initrd_darwin(self, tmp_config_dir):
        share = tmp_config_dir / "share"
        share.mkdir(exist_ok=True)
        (share / "Image").write_bytes(b"k")
        (share / "rootfs-base.ext4").write_bytes(b"r")

        with patch("safeyolo.vm.platform.system", return_value="Darwin"):
            assert check_guest_images() is False

    def test_check_guest_images_missing_rootfs_on_darwin(self, tmp_config_dir):
        """ext4 rootfs is required on Darwin."""
        share = tmp_config_dir / "share"
        share.mkdir(exist_ok=True)
        (share / "Image").write_bytes(b"k")
        (share / "initramfs.cpio.gz").write_bytes(b"i")

        with patch("safeyolo.vm.platform.system", return_value="Darwin"):
            assert check_guest_images() is False

    def test_check_guest_images_none_present(self, tmp_config_dir):
        assert check_guest_images() is False

    def test_check_guest_images_linux_needs_rootfs_tree(self, tmp_config_dir):
        """On Linux, the unpacked rootfs tree (directory with /etc) is
        what gVisor consumes as OCI root.path."""
        tree = tmp_config_dir / "share" / "rootfs-tree"
        (tree / "etc").mkdir(parents=True)

        with patch("safeyolo.vm.platform.system", return_value="Linux"):
            assert check_guest_images() is True

    def test_check_guest_images_linux_ignores_missing_kernel(self, tmp_config_dir):
        """On Linux, missing kernel/initramfs/ext4 is fine as long as the
        rootfs tree is present. gVisor ships its own kernel and doesn't
        use the ext4 image at all."""
        tree = tmp_config_dir / "share" / "rootfs-tree"
        (tree / "etc").mkdir(parents=True)
        # No Image, no initramfs.cpio.gz, no ext4

        with patch("safeyolo.vm.platform.system", return_value="Linux"):
            assert check_guest_images() is True

    def test_check_guest_images_linux_rejects_ext4_only(self, tmp_config_dir):
        """On Linux, having only the ext4 rootfs must NOT pass — gVisor
        needs the unpacked tree."""
        share = tmp_config_dir / "share"
        share.mkdir(exist_ok=True)
        (share / "rootfs-base.ext4").write_bytes(b"r")

        with patch("safeyolo.vm.platform.system", return_value="Linux"):
            assert check_guest_images() is False

    def test_check_guest_images_linux_rejects_empty_tree(self, tmp_config_dir):
        """An empty directory at share/rootfs-tree/ must NOT pass —
        it catches the "someone rm-rf'd the contents" footgun that a
        plain is_dir() would miss."""
        (tmp_config_dir / "share" / "rootfs-tree").mkdir(parents=True)

        with patch("safeyolo.vm.platform.system", return_value="Linux"):
            assert check_guest_images() is False

    def test_guest_image_status_all_present(self, tmp_config_dir):
        share = tmp_config_dir / "share"
        share.mkdir(exist_ok=True)
        (share / "Image").write_bytes(b"k")
        (share / "initramfs.cpio.gz").write_bytes(b"i")
        (share / "rootfs-base.ext4").write_bytes(b"r")
        (share / "rootfs-tree" / "etc").mkdir(parents=True)

        assert guest_image_status() == {
            "kernel": True,
            "initramfs": True,
            "rootfs-ext4": True,
            "rootfs-tree": True,
        }

    def test_guest_image_status_partial(self, tmp_config_dir):
        share = tmp_config_dir / "share"
        share.mkdir(exist_ok=True)
        (share / "Image").write_bytes(b"k")

        assert guest_image_status() == {
            "kernel": True,
            "initramfs": False,
            "rootfs-ext4": False,
            "rootfs-tree": False,
        }

    def test_guest_image_status_none_present(self, tmp_config_dir):
        assert guest_image_status() == {
            "kernel": False,
            "initramfs": False,
            "rootfs-ext4": False,
            "rootfs-tree": False,
        }

    def test_guest_image_status_tree_without_etc_reports_false(self, tmp_config_dir):
        """An empty rootfs-tree directory reports False, consistent with
        check_guest_images rejecting it. A bare share/rootfs-tree/ with
        no /etc is half-unpacked, not restorable."""
        (tmp_config_dir / "share" / "rootfs-tree").mkdir(parents=True)
        status = guest_image_status()
        assert status["rootfs-tree"] is False


# ---------------------------------------------------------------------------
# build_custom_rootfs (--rootfs-script orchestrator)
# ---------------------------------------------------------------------------


class TestBuildCustomRootfs:
    """Contract verification for the custom-rootfs builder.

    On Linux the script runs natively and produces an unpacked directory
    tree at agents/<name>/rootfs/ (consumed by gVisor as OCI root.path).
    On macOS it runs inside Lima and produces an ext4 image at
    agents/<name>/rootfs.ext4 (consumed by Virtualization.framework).
    Both paths pass SAFEYOLO_ROOTFS_OUT_CACHE_PATHS to let the script
    declare bind-mount target paths for persistent per-agent caches.
    """

    def _write_script(self, tmp_path: Path, body: str) -> Path:
        script = tmp_path / "builder.sh"
        script.write_text(body)
        script.chmod(0o755)
        return script

    def test_linux_writes_tree_and_validates_output(
        self, tmp_config_dir, tmp_path, monkeypatch
    ):
        """On Linux, script writes an unpacked tree at
        $SAFEYOLO_ROOTFS_OUT_TREE; builder validates the tree exists
        with at least /etc."""
        from safeyolo.vm import build_custom_rootfs

        script = self._write_script(
            tmp_path,
            '#!/bin/sh\n'
            'set -e\n'
            ': "${SAFEYOLO_AGENT_NAME:?}"\n'
            ': "${SAFEYOLO_ROOTFS_OUT_TREE:?}"\n'
            ': "${SAFEYOLO_ROOTFS_OUT_CACHE_PATHS:?}"\n'
            ': "${SAFEYOLO_ROOTFS_WORK_DIR:?}"\n'
            ': "${SAFEYOLO_GUEST_SRC_DIR:?}"\n'
            ': "${SAFEYOLO_TARGET_ARCH:?}"\n'
            '[ -d "$SAFEYOLO_ROOTFS_WORK_DIR" ]\n'
            'mkdir -p "$SAFEYOLO_ROOTFS_OUT_TREE/etc"\n'
            'echo -n stub > "$SAFEYOLO_ROOTFS_OUT_TREE/etc/hostname"\n',
        )

        with patch("safeyolo.vm.platform.system", return_value="Linux"):
            out = build_custom_rootfs("myagent", script)

        assert out == tmp_config_dir / "agents" / "myagent" / "rootfs"
        assert out.is_dir()
        assert (out / "etc" / "hostname").read_bytes() == b"stub"

    def test_linux_tree_without_etc_raises(
        self, tmp_config_dir, tmp_path
    ):
        """Script that creates the output dir but fails to populate /etc
        fails validation -- a tree without /etc is not a valid rootfs."""
        from safeyolo.vm import build_custom_rootfs

        script = self._write_script(
            tmp_path,
            '#!/bin/sh\nmkdir -p "$SAFEYOLO_ROOTFS_OUT_TREE"\n',
        )
        with patch("safeyolo.vm.platform.system", return_value="Linux"), \
             pytest.raises(VMError, match="not a valid rootfs tree"):
            build_custom_rootfs("agent0", script)

    def test_linux_missing_output_raises(
        self, tmp_config_dir, tmp_path
    ):
        """Script that exits 0 but never writes the output fails validation."""
        from safeyolo.vm import build_custom_rootfs

        script = self._write_script(tmp_path, '#!/bin/sh\nexit 0\n')
        with patch("safeyolo.vm.platform.system", return_value="Linux"), \
             pytest.raises(VMError, match="did not produce"):
            build_custom_rootfs("agent0", script)

    def test_linux_script_failure_propagates(
        self, tmp_config_dir, tmp_path
    ):
        """Non-zero script exit surfaces as a VMError."""
        from safeyolo.vm import build_custom_rootfs

        script = self._write_script(tmp_path, '#!/bin/sh\nexit 7\n')
        with patch("safeyolo.vm.platform.system", return_value="Linux"), \
             pytest.raises(VMError, match="exited with code 7"):
            build_custom_rootfs("agent0", script)

    def test_linux_work_dir_cleaned_up_on_success(
        self, tmp_config_dir, tmp_path
    ):
        """The scratch work dir is removed even on the happy path."""
        from safeyolo.vm import build_custom_rootfs

        leaked = {}
        script = self._write_script(
            tmp_path,
            '#!/bin/sh\n'
            'echo "$SAFEYOLO_ROOTFS_WORK_DIR" > /tmp/_safeyolo_test_workdir\n'
            'mkdir -p "$SAFEYOLO_ROOTFS_OUT_TREE/etc"\n',
        )
        try:
            with patch("safeyolo.vm.platform.system", return_value="Linux"):
                build_custom_rootfs("agent0", script)
            leaked["workdir"] = Path("/tmp/_safeyolo_test_workdir").read_text().strip()
        finally:
            Path("/tmp/_safeyolo_test_workdir").unlink(missing_ok=True)

        assert not Path(leaked["workdir"]).exists(), (
            f"Scratch dir leaked: {leaked['workdir']}"
        )

    def test_linux_work_dir_cleaned_up_on_failure(
        self, tmp_config_dir, tmp_path
    ):
        """The scratch work dir is removed even when the script fails."""
        from safeyolo.vm import build_custom_rootfs

        script = self._write_script(
            tmp_path,
            '#!/bin/sh\n'
            'echo "$SAFEYOLO_ROOTFS_WORK_DIR" > /tmp/_safeyolo_test_workdir\n'
            'exit 1\n',
        )
        try:
            with patch("safeyolo.vm.platform.system", return_value="Linux"), \
                 pytest.raises(VMError):
                build_custom_rootfs("agent0", script)
            workdir = Path("/tmp/_safeyolo_test_workdir").read_text().strip()
        finally:
            Path("/tmp/_safeyolo_test_workdir").unlink(missing_ok=True)

        assert not Path(workdir).exists(), f"Scratch dir leaked: {workdir}"

    def test_linux_stale_output_is_cleared(
        self, tmp_config_dir, tmp_path
    ):
        """A previous rebuild's tree is removed before the script runs,
        so the script sees a clean slot and never picks up junk from a
        prior failed build."""
        from safeyolo.vm import build_custom_rootfs

        stale = tmp_config_dir / "agents" / "agent0" / "rootfs"
        (stale / "etc").mkdir(parents=True)
        (stale / "stale-marker").write_bytes(b"from prior build")

        script = self._write_script(
            tmp_path,
            '#!/bin/sh\n'
            'set -e\n'
            # The builder must have cleared the tree before calling us.
            '[ ! -e "$SAFEYOLO_ROOTFS_OUT_TREE" ] || exit 5\n'
            'mkdir -p "$SAFEYOLO_ROOTFS_OUT_TREE/etc"\n'
            'echo -n fresh > "$SAFEYOLO_ROOTFS_OUT_TREE/etc/hostname"\n',
        )
        with patch("safeyolo.vm.platform.system", return_value="Linux"):
            out = build_custom_rootfs("agent0", script)

        assert (out / "etc" / "hostname").read_bytes() == b"fresh"
        assert not (out / "stale-marker").exists()

    def test_macos_requires_limactl(
        self, tmp_config_dir, tmp_path
    ):
        """Darwin path fails fast with a brew-install hint when Lima is
        missing."""
        from safeyolo.vm import build_custom_rootfs

        script = self._write_script(tmp_path, '#!/bin/sh\nexit 0\n')
        with patch("safeyolo.vm.platform.system", return_value="Darwin"), \
             patch("safeyolo.vm.shutil.which", return_value=None), \
             pytest.raises(VMError, match="brew install lima"):
            build_custom_rootfs("agent0", script)
