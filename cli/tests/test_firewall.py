"""Tests for safeyolo.firewall — macOS pf firewall and feth interface management."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from safeyolo.firewall import (
    ANCHOR_FILE,
    ANCHOR_NAME,
    SUBNET_BASE,
    _detect_outbound_interface,
    _ensure_anchor_in_pf_conf,
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
        """Mock all helpers that load_rules depends on."""
        mock_generate = MagicMock(return_value="# test rules\n")
        mock_write = MagicMock()
        mock_ensure = MagicMock()
        mock_sudo = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=[], returncode=0, stdout="Status: Enabled", stderr=""
            )
        )
        monkeypatch.setattr("safeyolo.firewall.generate_rules", mock_generate)
        monkeypatch.setattr("safeyolo.firewall._sudo_write_file", mock_write)
        monkeypatch.setattr("safeyolo.firewall._ensure_anchor_in_pf_conf", mock_ensure)
        monkeypatch.setattr("safeyolo.firewall._sudo_run", mock_sudo)
        return {
            "generate": mock_generate,
            "write": mock_write,
            "ensure": mock_ensure,
            "sudo_run": mock_sudo,
        }

    def test_writes_rules_to_anchor_file(self, mock_helpers):
        load_rules(proxy_port=8080, admin_port=9090, active_subnets=["192.168.65.0/24"])
        mock_helpers["write"].assert_called_once_with(ANCHOR_FILE, "# test rules\n")

    def test_ensures_anchor_in_pf_conf(self, mock_helpers):
        load_rules()
        mock_helpers["ensure"].assert_called_once()

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
# _ensure_anchor_in_pf_conf
# ---------------------------------------------------------------------------


class TestEnsureAnchorInPfConf:
    def test_adds_nat_anchor_and_filter_anchor_when_both_missing(self, monkeypatch):
        """When pf.conf has neither anchor, both are appended."""
        existing_content = "# Default pf rules\nscrub-anchor \"com.apple/*\"\n"

        # Make Path("/etc/pf.conf").read_text() return our content
        original_read_text = Path.read_text

        def mock_read_text(self):
            if str(self) == "/etc/pf.conf":
                return existing_content
            return original_read_text(self)

        monkeypatch.setattr(Path, "read_text", mock_read_text)

        tee_calls = []

        def mock_run(cmd, **kwargs):
            tee_calls.append((cmd, kwargs))
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        monkeypatch.setattr("subprocess.run", mock_run)

        _ensure_anchor_in_pf_conf()

        # Should call sudo tee -a /etc/pf.conf
        assert len(tee_calls) == 1
        cmd, kwargs = tee_calls[0]
        assert cmd == ["sudo", "tee", "-a", "/etc/pf.conf"]
        appended = kwargs["input"]
        assert f'nat-anchor "{ANCHOR_NAME}"' in appended
        assert f'anchor "{ANCHOR_NAME}"' in appended
        assert f'load anchor "{ANCHOR_NAME}" from "{ANCHOR_FILE}"' in appended

    def test_skips_when_anchors_already_present(self, monkeypatch):
        existing_content = (
            f'nat-anchor "{ANCHOR_NAME}"\n'
            f'anchor "{ANCHOR_NAME}"\n'
            f'load anchor "{ANCHOR_NAME}" from "{ANCHOR_FILE}"\n'
        )

        def mock_read_text(self):
            if str(self) == "/etc/pf.conf":
                return existing_content
            raise FileNotFoundError

        monkeypatch.setattr(Path, "read_text", mock_read_text)

        tee_calls = []

        def mock_run(cmd, **kwargs):
            tee_calls.append(cmd)
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        monkeypatch.setattr("subprocess.run", mock_run)

        _ensure_anchor_in_pf_conf()

        # No tee call because nothing needs adding
        assert len(tee_calls) == 0

    def test_falls_back_to_sudo_cat_on_permission_error(self, monkeypatch):
        def mock_read_text(self):
            if str(self) == "/etc/pf.conf":
                raise PermissionError("Operation not permitted")
            raise FileNotFoundError

        monkeypatch.setattr(Path, "read_text", mock_read_text)

        sudo_calls = []

        def mock_sudo_run(cmd, **kwargs):
            sudo_calls.append(cmd)
            if cmd == ["cat", "/etc/pf.conf"]:
                # Return content that already has both anchors
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0,
                    stdout=f'nat-anchor "{ANCHOR_NAME}"\nanchor "{ANCHOR_NAME}"\n',
                    stderr="",
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        monkeypatch.setattr("safeyolo.firewall._sudo_run", mock_sudo_run)

        tee_calls = []
        monkeypatch.setattr(
            "subprocess.run",
            lambda cmd, **kw: (tee_calls.append(cmd), subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr=""))[1],
        )

        _ensure_anchor_in_pf_conf()

        # Should have called sudo cat
        assert ["cat", "/etc/pf.conf"] in sudo_calls

    def test_adds_only_nat_anchor_when_filter_already_present(self, monkeypatch):
        """When filter anchor exists but nat-anchor is missing, only nat-anchor is added."""
        existing_content = f'anchor "{ANCHOR_NAME}"\nload anchor "{ANCHOR_NAME}" from "{ANCHOR_FILE}"\n'

        def mock_read_text(self):
            if str(self) == "/etc/pf.conf":
                return existing_content
            raise FileNotFoundError

        monkeypatch.setattr(Path, "read_text", mock_read_text)

        tee_calls = []

        def mock_run(cmd, **kwargs):
            tee_calls.append((cmd, kwargs))
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        monkeypatch.setattr("subprocess.run", mock_run)

        _ensure_anchor_in_pf_conf()

        assert len(tee_calls) == 1
        appended = tee_calls[0][1]["input"]
        assert f'nat-anchor "{ANCHOR_NAME}"' in appended
        # Should NOT re-add the filter anchor
        assert f'\nanchor "{ANCHOR_NAME}"' not in appended


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
# Constants
# ---------------------------------------------------------------------------


class TestConstants:
    def test_anchor_name(self):
        assert ANCHOR_NAME == "com.safeyolo"

    def test_anchor_file_path(self):
        assert ANCHOR_FILE == Path("/etc/pf.anchors/com.safeyolo")

    def test_subnet_base(self):
        assert SUBNET_BASE == 65
