"""Tests for safeyolo.firewall — macOS pf firewall and feth interface management."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call

import pytest

from safeyolo.firewall import (
    ALLOWED_ANCHORS,
    ANCHOR_FILE,
    ANCHOR_NAME,
    DEFAULT_ANCHOR,
    PF_CONF,
    SUBNET_BASE,
    _detect_outbound_interface,
    _pf_conf_declares_anchor,
    _require_pf_conf_hook,
    _resolve_anchor_name,
    _sudo_run,
    _sudo_write_file,
    allocate_subnet,
    generate_rules,
    is_loaded,
    load_rules,
    setup_feth,
    teardown_feth,
    unload_rules,
)


# ---------------------------------------------------------------------------
# allocate_subnet
# ---------------------------------------------------------------------------


class TestAllocateSubnet:
    def test_index_zero_returns_base_subnet(self):
        alloc = allocate_subnet(0)
        assert alloc["host_ip"] == "192.168.65.1"
        assert alloc["guest_ip"] == "192.168.65.2"
        assert alloc["subnet"] == "192.168.65.0/24"
        assert alloc["feth_vm"] == "feth0"
        assert alloc["feth_host"] == "feth1"
        assert alloc["third_octet"] == 65

    def test_index_one_returns_next_subnet(self):
        alloc = allocate_subnet(1)
        assert alloc["host_ip"] == "192.168.66.1"
        assert alloc["guest_ip"] == "192.168.66.2"
        assert alloc["subnet"] == "192.168.66.0/24"
        assert alloc["feth_vm"] == "feth2"
        assert alloc["feth_host"] == "feth3"
        assert alloc["third_octet"] == 66

    def test_index_ten_returns_correct_subnet(self):
        alloc = allocate_subnet(10)
        assert alloc["host_ip"] == "192.168.75.1"
        assert alloc["guest_ip"] == "192.168.75.2"
        assert alloc["subnet"] == "192.168.75.0/24"
        assert alloc["feth_vm"] == "feth20"
        assert alloc["feth_host"] == "feth21"
        assert alloc["third_octet"] == 75

    def test_all_dict_keys_present(self):
        alloc = allocate_subnet(0)
        assert set(alloc.keys()) == {
            "host_ip",
            "guest_ip",
            "subnet",
            "feth_vm",
            "feth_host",
            "third_octet",
        }

    def test_feth_vm_is_even_feth_host_is_next_odd(self):
        for idx in (0, 1, 5, 10):
            alloc = allocate_subnet(idx)
            vm_num = int(alloc["feth_vm"].removeprefix("feth"))
            host_num = int(alloc["feth_host"].removeprefix("feth"))
            assert vm_num % 2 == 0, f"feth_vm should be even for index {idx}"
            assert host_num == vm_num + 1, f"feth_host should be vm+1 for index {idx}"


# ---------------------------------------------------------------------------
# setup_feth
# ---------------------------------------------------------------------------


class TestSetupFeth:
    @pytest.fixture()
    def mock_sudo_run(self, monkeypatch):
        """Mock _sudo_run to capture all calls without touching the OS."""
        mock = MagicMock(
            return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        )
        monkeypatch.setattr("safeyolo.firewall._sudo_run", mock)
        return mock

    def test_destroys_stale_interfaces_first(self, mock_sudo_run):
        setup_feth(0)
        # First two calls should be destroy with check=False
        first_call = mock_sudo_run.call_args_list[0]
        second_call = mock_sudo_run.call_args_list[1]
        assert first_call == call(["ifconfig", "feth0", "destroy"], check=False, capture=True)
        assert second_call == call(["ifconfig", "feth1", "destroy"], check=False, capture=True)

    def test_creates_feth_pair_and_configures(self, mock_sudo_run):
        setup_feth(0)
        calls = mock_sudo_run.call_args_list
        # After 2 destroys: create vm, create host, peer, configure host, bring up vm
        assert calls[2] == call(["ifconfig", "feth0", "create"])
        assert calls[3] == call(["ifconfig", "feth1", "create"])
        assert calls[4] == call(["ifconfig", "feth0", "peer", "feth1"])
        assert calls[5] == call(
            ["ifconfig", "feth1", "192.168.65.1", "netmask", "255.255.255.0", "up"]
        )
        assert calls[6] == call(["ifconfig", "feth0", "up"])

    def test_enables_ip_forwarding(self, mock_sudo_run):
        setup_feth(0)
        last_call = mock_sudo_run.call_args_list[-1]
        assert last_call == call(
            ["sysctl", "-w", "net.inet.ip.forwarding=1"], capture=True
        )

    def test_returns_allocation_dict(self, mock_sudo_run):
        result = setup_feth(0)
        expected = allocate_subnet(0)
        assert result == expected

    def test_total_subprocess_call_count(self, mock_sudo_run):
        setup_feth(0)
        # 2 destroy + 3 create/peer + 2 config + 1 sysctl = 8
        assert mock_sudo_run.call_count == 8

    def test_propagates_create_failure(self, monkeypatch):
        call_count = 0

        def side_effect(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            # First two calls are destroy (check=False), let them pass
            if call_count <= 2:
                return subprocess.CompletedProcess(args=cmd, returncode=0)
            # Third call is "ifconfig feth0 create" -- make it fail
            raise subprocess.CalledProcessError(1, cmd)

        monkeypatch.setattr("safeyolo.firewall._sudo_run", side_effect)
        with pytest.raises(subprocess.CalledProcessError):
            setup_feth(0)

    def test_stale_destroy_failure_does_not_propagate(self, monkeypatch):
        calls = []

        def side_effect(cmd, **kwargs):
            calls.append((cmd, kwargs))
            if "destroy" in cmd:
                # Simulate failure, but check=False so we just return
                return subprocess.CompletedProcess(args=cmd, returncode=1, stderr="no such interface")
            return subprocess.CompletedProcess(args=cmd, returncode=0)

        monkeypatch.setattr("safeyolo.firewall._sudo_run", side_effect)
        # Should not raise despite destroy returning non-zero
        result = setup_feth(0)
        assert result["feth_vm"] == "feth0"

    def test_uses_correct_interfaces_for_nonzero_index(self, mock_sudo_run):
        setup_feth(3)
        calls = mock_sudo_run.call_args_list
        # Destroy calls use feth6/feth7
        assert calls[0] == call(["ifconfig", "feth6", "destroy"], check=False, capture=True)
        assert calls[1] == call(["ifconfig", "feth7", "destroy"], check=False, capture=True)
        # Create calls
        assert calls[2] == call(["ifconfig", "feth6", "create"])
        assert calls[3] == call(["ifconfig", "feth7", "create"])
        # Host IP is 192.168.68.1 (65+3)
        assert calls[5] == call(
            ["ifconfig", "feth7", "192.168.68.1", "netmask", "255.255.255.0", "up"]
        )


# ---------------------------------------------------------------------------
# teardown_feth
# ---------------------------------------------------------------------------


class TestTeardownFeth:
    def test_destroys_vm_interface_only(self, monkeypatch):
        mock = MagicMock(
            return_value=subprocess.CompletedProcess(args=[], returncode=0)
        )
        monkeypatch.setattr("safeyolo.firewall._sudo_run", mock)
        teardown_feth(0)
        # Only one call: destroy feth_vm (peer is auto-destroyed)
        assert mock.call_count == 1
        assert mock.call_args == call(["ifconfig", "feth0", "destroy"], check=False)

    def test_destroys_correct_interface_for_index(self, monkeypatch):
        mock = MagicMock(
            return_value=subprocess.CompletedProcess(args=[], returncode=0)
        )
        monkeypatch.setattr("safeyolo.firewall._sudo_run", mock)
        teardown_feth(5)
        assert mock.call_args == call(["ifconfig", "feth10", "destroy"], check=False)

    def test_tolerates_missing_interface(self, monkeypatch):
        mock = MagicMock(
            return_value=subprocess.CompletedProcess(args=[], returncode=1, stderr="no such interface")
        )
        monkeypatch.setattr("safeyolo.firewall._sudo_run", mock)
        # check=False means no CalledProcessError
        teardown_feth(0)  # should not raise


# ---------------------------------------------------------------------------
# generate_rules
# ---------------------------------------------------------------------------


class TestGenerateRules:
    @pytest.fixture(autouse=True)
    def _mock_detect_outbound(self, monkeypatch):
        monkeypatch.setattr(
            "safeyolo.firewall._detect_outbound_interface", lambda: "en0"
        )

    def test_no_subnets_returns_comment_only(self):
        result = generate_rules(active_subnets=None)
        assert "no active VMs" in result
        assert ANCHOR_NAME in result
        assert "nat" not in result
        assert "block" not in result

    def test_empty_list_returns_comment_only(self):
        result = generate_rules(active_subnets=[])
        assert "no active VMs" in result

    def test_single_subnet_produces_nat_rule(self):
        result = generate_rules(active_subnets=["192.168.65.0/24"])
        assert "nat on en0 from 192.168.65.0/24 to any -> (en0)" in result

    def test_single_subnet_produces_pass_rule_for_proxy(self):
        result = generate_rules(proxy_port=8080, active_subnets=["192.168.65.0/24"])
        assert (
            "pass in quick on feth proto tcp from 192.168.65.0/24 to 192.168.65.1 port 8080"
            in result
        )

    def test_single_subnet_produces_block_rule_for_admin(self):
        result = generate_rules(admin_port=9090, active_subnets=["192.168.65.0/24"])
        assert (
            "block in quick on feth proto tcp from 192.168.65.0/24 to any port 9090"
            in result
        )

    def test_single_subnet_produces_catch_all_block(self):
        result = generate_rules(active_subnets=["192.168.65.0/24"])
        assert "block in on feth from 192.168.65.0/24 to any" in result

    def test_custom_proxy_port_in_pass_rule(self):
        result = generate_rules(proxy_port=3128, active_subnets=["192.168.65.0/24"])
        assert "port 3128" in result
        assert "port 8080" not in result

    def test_custom_admin_port_in_block_rule(self):
        result = generate_rules(admin_port=7070, active_subnets=["192.168.65.0/24"])
        assert "port 7070" in result
        # 9090 should not appear (not even in default pass rules)
        lines_with_9090 = [l for l in result.splitlines() if "port 9090" in l]
        assert lines_with_9090 == []

    def test_multiple_subnets_produce_per_subnet_rules(self):
        subnets = ["192.168.65.0/24", "192.168.66.0/24"]
        result = generate_rules(active_subnets=subnets)
        # Two NAT rules
        assert result.count("nat on en0") == 2
        # Two pass rules (one per subnet)
        assert "from 192.168.65.0/24 to 192.168.65.1 port 8080" in result
        assert "from 192.168.66.0/24 to 192.168.66.1 port 8080" in result
        # Two admin blocks
        assert result.count("block in quick on feth proto tcp") == 2
        # Two catch-all blocks
        assert result.count("block in on feth") == 2

    def test_rules_use_detected_outbound_interface(self, monkeypatch):
        monkeypatch.setattr(
            "safeyolo.firewall._detect_outbound_interface", lambda: "utun3"
        )
        result = generate_rules(active_subnets=["192.168.65.0/24"])
        assert "nat on utun3" in result
        assert "-> (utun3)" in result

    def test_rule_ordering_per_subnet(self):
        """pass -> admin block -> catch-all block, per subnet."""
        result = generate_rules(active_subnets=["192.168.65.0/24"])
        lines = [l for l in result.splitlines() if l.strip() and not l.startswith("#")]
        # Find the filter rules (after the NAT rule)
        filter_lines = [l for l in lines if not l.startswith("nat")]
        assert len(filter_lines) == 3
        assert "pass in quick" in filter_lines[0]
        assert "block in quick" in filter_lines[1]
        assert "block in on feth" in filter_lines[2]

    def test_host_ip_derived_from_subnet(self):
        result = generate_rules(active_subnets=["192.168.75.0/24"])
        # host_ip should be 192.168.75.1
        assert "to 192.168.75.1 port 8080" in result

    def test_anchor_name_in_header(self):
        result = generate_rules(active_subnets=["192.168.65.0/24"])
        assert ANCHOR_NAME in result


# ---------------------------------------------------------------------------
# load_rules
# ---------------------------------------------------------------------------


class TestLoadRules:
    @pytest.fixture()
    def mock_helpers(self, monkeypatch):
        """Mock helpers that load_rules depends on.

        The runtime load_rules path no longer mutates /etc/pf.conf; it only
        verifies the hook is present, writes the anchor file, and loads it
        via pfctl. We mock:
          - _require_pf_conf_hook (assumed present by default)
          - generate_rules
          - _sudo_write_file
          - _sudo_run (for pfctl calls)
        """
        mock_require = MagicMock()
        mock_generate = MagicMock(return_value="# test rules\n")
        mock_write = MagicMock()
        mock_sudo = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=[], returncode=0, stdout="Status: Enabled", stderr=""
            )
        )
        monkeypatch.setattr("safeyolo.firewall._require_pf_conf_hook", mock_require)
        monkeypatch.setattr("safeyolo.firewall.generate_rules", mock_generate)
        monkeypatch.setattr("safeyolo.firewall._sudo_write_file", mock_write)
        monkeypatch.setattr("safeyolo.firewall._sudo_run", mock_sudo)
        return {
            "require": mock_require,
            "generate": mock_generate,
            "write": mock_write,
            "sudo_run": mock_sudo,
        }

    def test_requires_pf_conf_hook_present(self, mock_helpers):
        load_rules()
        mock_helpers["require"].assert_called_once()

    def test_writes_rules_to_anchor_file(self, mock_helpers):
        load_rules(proxy_port=8080, admin_port=9090, active_subnets=["192.168.65.0/24"])
        mock_helpers["write"].assert_called_once_with(ANCHOR_FILE, "# test rules\n")

    def test_loads_anchor_via_pfctl(self, mock_helpers):
        load_rules()
        # pfctl -a com.safeyolo -f /etc/pf.anchors/com.safeyolo
        pfctl_call = mock_helpers["sudo_run"].call_args_list[0]
        assert pfctl_call[0][0] == ["pfctl", "-a", ANCHOR_NAME, "-f", str(ANCHOR_FILE)]

    def test_checks_pf_status(self, mock_helpers):
        load_rules()
        # Second sudo_run call checks pf info
        info_call = mock_helpers["sudo_run"].call_args_list[1]
        assert info_call[0][0] == ["pfctl", "-s", "info"]

    def test_enables_pf_when_disabled(self, mock_helpers):
        mock_helpers["sudo_run"].return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Status: Disabled", stderr=""
        )
        load_rules()
        # Should have 3 calls: load, info, enable
        assert mock_helpers["sudo_run"].call_count == 3
        enable_call = mock_helpers["sudo_run"].call_args_list[2]
        assert enable_call[0][0] == ["pfctl", "-e"]

    def test_skips_enable_when_already_enabled(self, mock_helpers):
        # Default mock returns "Status: Enabled"
        load_rules()
        # Only 2 calls: load and info (no enable)
        assert mock_helpers["sudo_run"].call_count == 2

    def test_passes_ports_to_generate(self, mock_helpers):
        load_rules(proxy_port=3128, admin_port=7070, active_subnets=["192.168.65.0/24"])
        mock_helpers["generate"].assert_called_once_with(
            proxy_port=3128, admin_port=7070, active_subnets=["192.168.65.0/24"]
        )

    def test_no_pf_conf_read_or_append(self, monkeypatch):
        """Runtime load_rules must not read or mutate /etc/pf.conf.

        We fail read_text/sudo cat/sudo tee -a if anything tries to touch it.
        """
        monkeypatch.setattr("safeyolo.firewall._require_pf_conf_hook", lambda: None)
        monkeypatch.setattr("safeyolo.firewall.generate_rules", lambda **kw: "# test\n")
        monkeypatch.setattr("safeyolo.firewall._sudo_write_file", lambda *a, **kw: None)

        pfctl_calls = []

        def fake_sudo_run(cmd, capture=False, check=True):
            pfctl_calls.append(cmd)
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="Status: Enabled", stderr="")

        monkeypatch.setattr("safeyolo.firewall._sudo_run", fake_sudo_run)

        # subprocess.run must never be called with tee -a on pf.conf or cat pf.conf.
        original_run = subprocess.run

        def guarded_run(cmd, *args, **kwargs):
            if isinstance(cmd, list):
                joined = " ".join(str(c) for c in cmd)
                assert "tee -a" not in joined, f"load_rules must not append to pf.conf: {cmd}"
                assert "/etc/pf.conf" not in joined, f"load_rules must not touch pf.conf: {cmd}"
            return original_run(cmd, *args, **kwargs)

        monkeypatch.setattr("subprocess.run", guarded_run)

        load_rules(active_subnets=["192.168.65.0/24"])

        # None of the recorded pfctl calls should touch pf.conf either.
        for cmd in pfctl_calls:
            assert "/etc/pf.conf" not in " ".join(str(c) for c in cmd)

    def test_fails_loudly_when_hook_missing(self, monkeypatch):
        """If the pf.conf hook is missing, load_rules must not attempt to add it."""
        def missing_hook():
            raise RuntimeError("anchor hook for 'com.safeyolo' is not installed")

        monkeypatch.setattr("safeyolo.firewall._require_pf_conf_hook", missing_hook)

        # _sudo_write_file and _sudo_run must never be called
        def explode(*a, **kw):
            pytest.fail("runtime must not attempt privileged writes when hook is missing")

        monkeypatch.setattr("safeyolo.firewall._sudo_write_file", explode)
        monkeypatch.setattr("safeyolo.firewall._sudo_run", explode)

        with pytest.raises(RuntimeError, match="not installed"):
            load_rules(active_subnets=["192.168.65.0/24"])


# ---------------------------------------------------------------------------
# unload_rules
# ---------------------------------------------------------------------------


class TestUnloadRules:
    def test_flushes_anchor(self, monkeypatch):
        mock = MagicMock(
            return_value=subprocess.CompletedProcess(args=[], returncode=0)
        )
        monkeypatch.setattr("safeyolo.firewall._sudo_run", mock)
        unload_rules()
        mock.assert_called_once_with(
            ["pfctl", "-a", ANCHOR_NAME, "-F", "all"], check=False
        )


# ---------------------------------------------------------------------------
# is_loaded
# ---------------------------------------------------------------------------


class TestIsLoaded:
    def test_returns_true_when_rules_present(self, monkeypatch):
        mock = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="pass in quick on feth proto tcp from 192.168.65.0/24 to 192.168.65.1 port 8080\n",
                stderr="",
            )
        )
        monkeypatch.setattr("safeyolo.firewall._sudo_run", mock)
        assert is_loaded() is True

    def test_returns_false_when_no_rules(self, monkeypatch):
        mock = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
        )
        monkeypatch.setattr("safeyolo.firewall._sudo_run", mock)
        assert is_loaded() is False

    def test_returns_false_when_stdout_is_whitespace(self, monkeypatch):
        mock = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=[], returncode=0, stdout="   \n  \n", stderr=""
            )
        )
        monkeypatch.setattr("safeyolo.firewall._sudo_run", mock)
        assert is_loaded() is False

    def test_returns_false_when_stdout_is_none(self, monkeypatch):
        mock = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=[], returncode=0, stdout=None, stderr=""
            )
        )
        monkeypatch.setattr("safeyolo.firewall._sudo_run", mock)
        assert is_loaded() is False

    def test_calls_pfctl_with_correct_args(self, monkeypatch):
        mock = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
        )
        monkeypatch.setattr("safeyolo.firewall._sudo_run", mock)
        is_loaded()
        mock.assert_called_once_with(
            ["pfctl", "-a", ANCHOR_NAME, "-s", "rules"],
            capture=True,
            check=False,
        )


# ---------------------------------------------------------------------------
# _detect_outbound_interface
# ---------------------------------------------------------------------------


class TestDetectOutboundInterface:
    def test_parses_interface_from_route_output(self, monkeypatch):
        route_output = (
            "   route to: default\n"
            "destination: default\n"
            "       mask: default\n"
            "    gateway: 192.168.1.1\n"
            "  interface: en0\n"
            "      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n"
        )
        mock = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=[], returncode=0, stdout=route_output, stderr=""
            )
        )
        monkeypatch.setattr("subprocess.run", mock)
        assert _detect_outbound_interface() == "en0"

    def test_parses_non_en0_interface(self, monkeypatch):
        route_output = "  interface: utun3\n"
        mock = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=[], returncode=0, stdout=route_output, stderr=""
            )
        )
        monkeypatch.setattr("subprocess.run", mock)
        assert _detect_outbound_interface() == "utun3"

    def test_falls_back_to_en0_on_subprocess_error(self, monkeypatch):
        mock = MagicMock(side_effect=subprocess.SubprocessError("command not found"))
        monkeypatch.setattr("subprocess.run", mock)
        assert _detect_outbound_interface() == "en0"

    def test_falls_back_to_en0_on_os_error(self, monkeypatch):
        mock = MagicMock(side_effect=OSError("no such file"))
        monkeypatch.setattr("subprocess.run", mock)
        assert _detect_outbound_interface() == "en0"

    def test_falls_back_to_en0_when_no_interface_line(self, monkeypatch):
        route_output = "destination: default\ngateway: 192.168.1.1\n"
        mock = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=[], returncode=0, stdout=route_output, stderr=""
            )
        )
        monkeypatch.setattr("subprocess.run", mock)
        assert _detect_outbound_interface() == "en0"

    def test_calls_route_with_correct_args(self, monkeypatch):
        mock = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=[], returncode=0, stdout="  interface: en0\n", stderr=""
            )
        )
        monkeypatch.setattr("subprocess.run", mock)
        _detect_outbound_interface()
        mock.assert_called_once_with(
            ["route", "-n", "get", "default"],
            capture_output=True,
            text=True,
            timeout=5,
        )


# ---------------------------------------------------------------------------
# _pf_conf_declares_anchor / _require_pf_conf_hook
# ---------------------------------------------------------------------------


class TestPfConfDeclaresAnchor:
    def test_true_when_both_hook_lines_present(self, monkeypatch):
        content = (
            f'anchor "{ANCHOR_NAME}"\n'
            f'load anchor "{ANCHOR_NAME}" from "{ANCHOR_FILE}"\n'
        )
        monkeypatch.setattr(Path, "read_text", lambda self: content if str(self) == str(PF_CONF) else "")
        assert _pf_conf_declares_anchor() is True

    def test_false_when_missing(self, monkeypatch):
        monkeypatch.setattr(Path, "read_text", lambda self: "# empty pf.conf\n")
        assert _pf_conf_declares_anchor() is False

    def test_false_when_only_anchor_declared(self, monkeypatch):
        # Declared but no load line — incomplete.
        content = f'anchor "{ANCHOR_NAME}"\n'
        monkeypatch.setattr(Path, "read_text", lambda self: content)
        assert _pf_conf_declares_anchor() is False

    def test_false_when_only_load_declared(self, monkeypatch):
        content = f'load anchor "{ANCHOR_NAME}" from "{ANCHOR_FILE}"\n'
        monkeypatch.setattr(Path, "read_text", lambda self: content)
        assert _pf_conf_declares_anchor() is False

    def test_false_when_pf_conf_missing(self, monkeypatch):
        def raise_fnf(self):
            raise FileNotFoundError
        monkeypatch.setattr(Path, "read_text", raise_fnf)
        assert _pf_conf_declares_anchor() is False


class TestRequirePfConfHook:
    def test_passes_silently_when_present(self, monkeypatch):
        monkeypatch.setattr("safeyolo.firewall._pf_conf_declares_anchor", lambda: True)
        _require_pf_conf_hook()  # must not raise

    def test_raises_runtime_error_when_missing(self, monkeypatch):
        monkeypatch.setattr("safeyolo.firewall._pf_conf_declares_anchor", lambda: False)
        with pytest.raises(RuntimeError) as exc:
            _require_pf_conf_hook()
        msg = str(exc.value)
        assert "not installed" in msg
        assert "safeyolo setup pf" in msg
        assert str(PF_CONF) in msg


# ---------------------------------------------------------------------------
# _sudo_write_file
# ---------------------------------------------------------------------------


class TestSudoWriteFile:
    def test_writes_content_via_tee(self, monkeypatch, tmp_path):
        target = tmp_path / "subdir" / "test.conf"

        calls = []

        def mock_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        monkeypatch.setattr("subprocess.run", mock_run)

        _sudo_write_file(target, "rule content here")

        assert len(calls) == 1
        cmd, kwargs = calls[0]
        assert cmd == ["sudo", "tee", str(target)]
        assert kwargs["input"] == "rule content here"
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True

    def test_creates_parent_directory(self, monkeypatch, tmp_path):
        target = tmp_path / "deep" / "nested" / "dir" / "file.conf"

        monkeypatch.setattr(
            "subprocess.run",
            lambda cmd, **kw: subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr=""),
        )

        _sudo_write_file(target, "content")

        # Parent directory should have been created
        assert target.parent.exists()

    def test_raises_runtime_error_on_tee_failure(self, monkeypatch, tmp_path):
        target = tmp_path / "fail.conf"

        def mock_run(cmd, **kwargs):
            return subprocess.CompletedProcess(
                args=cmd, returncode=1, stdout="", stderr="permission denied"
            )

        monkeypatch.setattr("subprocess.run", mock_run)

        with pytest.raises(RuntimeError, match="Failed to write"):
            _sudo_write_file(target, "content")


# ---------------------------------------------------------------------------
# _sudo_run
# ---------------------------------------------------------------------------


class TestSudoRun:
    def test_prepends_sudo_to_command(self, monkeypatch):
        calls = []

        def mock_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        monkeypatch.setattr("subprocess.run", mock_run)

        _sudo_run(["pfctl", "-e"])

        assert calls[0][0] == ["sudo", "pfctl", "-e"]

    def test_passes_capture_flag(self, monkeypatch):
        calls = []

        def mock_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        monkeypatch.setattr("subprocess.run", mock_run)

        _sudo_run(["pfctl", "-s", "info"], capture=True)

        assert calls[0][1]["capture_output"] is True

    def test_check_true_raises_on_failure(self, monkeypatch):
        def mock_run(cmd, **kwargs):
            if kwargs.get("check"):
                raise subprocess.CalledProcessError(1, cmd)
            return subprocess.CompletedProcess(args=cmd, returncode=1)

        monkeypatch.setattr("subprocess.run", mock_run)

        with pytest.raises(subprocess.CalledProcessError):
            _sudo_run(["ifconfig", "feth0", "create"], check=True)

    def test_check_false_does_not_raise(self, monkeypatch):
        def mock_run(cmd, **kwargs):
            return subprocess.CompletedProcess(args=cmd, returncode=1)

        monkeypatch.setattr("subprocess.run", mock_run)

        result = _sudo_run(["ifconfig", "feth0", "destroy"], check=False)
        assert result.returncode == 1


# ---------------------------------------------------------------------------
# _resolve_anchor_name / constants
# ---------------------------------------------------------------------------


class TestResolveAnchorName:
    def test_default_is_com_safeyolo(self, monkeypatch):
        monkeypatch.delenv("SAFEYOLO_PF_ANCHOR", raising=False)
        assert _resolve_anchor_name() == "com.safeyolo"

    def test_accepts_blackbox_test_anchor(self, monkeypatch):
        monkeypatch.setenv("SAFEYOLO_PF_ANCHOR", "com.safeyolo-test")
        assert _resolve_anchor_name() == "com.safeyolo-test"

    def test_rejects_arbitrary_value(self, monkeypatch):
        monkeypatch.setenv("SAFEYOLO_PF_ANCHOR", "com.attacker")
        with pytest.raises(RuntimeError, match="not permitted"):
            _resolve_anchor_name()

    def test_rejects_wildcard_style_value(self, monkeypatch):
        monkeypatch.setenv("SAFEYOLO_PF_ANCHOR", "com.safeyolo*")
        with pytest.raises(RuntimeError, match="not permitted"):
            _resolve_anchor_name()


class TestConstants:
    def test_default_anchor(self):
        assert DEFAULT_ANCHOR == "com.safeyolo"

    def test_allowed_anchors_is_exactly_two(self):
        assert ALLOWED_ANCHORS == ("com.safeyolo", "com.safeyolo-test")

    def test_anchor_name_is_in_allowlist(self):
        assert ANCHOR_NAME in ALLOWED_ANCHORS

    def test_anchor_file_path(self):
        assert ANCHOR_FILE == Path("/etc/pf.anchors") / ANCHOR_NAME

    def test_pf_conf_path(self):
        assert PF_CONF == Path("/etc/pf.conf")

    def test_subnet_base(self):
        assert SUBNET_BASE == 65
