"""Owned delivery observers and guest probes for BB-01, BB-02 and BB-03.

Run the host entrypoint only around a disposable installed guest phase. Receiver
observations stay on the host. Guest connection errors are diagnostic data, not
the non-delivery oracle. The receivers deliberately return no useful protocol
reply, so delivery followed by HTTP failure or DNS timeout still fails.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import ipaddress
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import uuid
from contextlib import ExitStack
from pathlib import Path

if __package__:
    from .host_listener import DeliveryReceiver, digest, send_payload
else:
    from host_listener import DeliveryReceiver, digest, send_payload

MANIFEST = Path("/safeyolo/containment.json")
REFUSAL_ERRORS = (errno.ENOSYS, errno.EPERM, errno.EACCES)


def secret_candidates(data: bytes) -> list[bytes]:
    """Select synthetic vault values and complete private-key PEM payloads."""
    data = data.replace(b"\\n", b"\n").replace(b"\\r", b"\r")
    values = re.findall(rb"p3-native-[0-9a-f]{40}", data)
    for key in re.findall(rb"-----BEGIN (?:RSA |EC |)PRIVATE KEY-----(.*?)-----END (?:RSA |EC |)PRIVATE KEY-----", data, re.DOTALL):
        values.append(b"".join(key.split()))
    return values


def secret_commitments(ca_file: Path, vault_value: str) -> list[str]:
    """Publish only fingerprints; neither CA key nor vault value enters a guest."""
    ca = secret_candidates(ca_file.read_bytes())
    assert len(ca) == 1, "selected CA file must contain one actual signing key"
    vault = secret_candidates(vault_value.encode())
    assert len(vault) == 1, "synthetic native vault canary is missing"
    return [digest(value) for value in ca + vault]


def assert_no_secret(data: bytes, commitments: list[str], source: str) -> None:
    exposed = {digest(value) for value in secret_candidates(data)}.intersection(commitments)
    assert not exposed, f"host secret exposed in {source}: fingerprints={sorted(exposed)}"
def manifest() -> dict:
    assert MANIFEST.is_file(), "host containment observer was not prepared"
    return json.loads(MANIFEST.read_text())


def interface_addresses(interfaces: list[dict]) -> set[str]:
    return {row["local"] for interface in interfaces for row in interface.get("addr_info", [])}


def receiver_addresses(interfaces: list[dict], ipv4: str | None, ipv6: str | None) -> list[str]:
    """Select assigned host addresses outside the guest's private loopback."""
    assigned = interface_addresses(interfaces)
    selected = []
    for family, explicit in ((4, ipv4), (6, ipv6)):
        candidates = [address for address in sorted(assigned)
                      if ipaddress.ip_address(address).version == family
                      and not ipaddress.ip_address(address).is_loopback
                      and not ipaddress.ip_address(address).is_link_local]
        if explicit:
            address = ipaddress.ip_address(explicit)
            assert address.version == family and not address.is_loopback and explicit in assigned, (
                f"receiver IPv{family} must be an assigned non-loopback host address: {explicit}")
            candidates = [explicit]
        selected += candidates[:1]
    return selected


def guest_destination(target: dict) -> dict:
    """Retain the actual guest interfaces and route to this external target."""
    interfaces = json.loads(subprocess.check_output(["ip", "-json", "address", "show"]))
    assert target["address"] not in interface_addresses(interfaces), (
        "receiver address is local to the guest; this is not an external delivery probe")
    route = subprocess.run(["ip", "-6" if ":" in target["address"] else "-4", "-json",
                            "route", "get", target["address"]], capture_output=True, text=True, check=False)
    assert route.returncode == 0 or (route.returncode == 2 and "unreachable" in route.stderr.lower()), (
        "guest route inspection failed: " + route.stderr)
    return {"interfaces": interfaces, "route_exit": route.returncode,
            "route": json.loads(route.stdout) if route.returncode == 0 else [],
            "route_error": route.stderr.strip()}


def attempt_network(transport: str, family: int = 4, *, dns: bool = False,
                    tls: bool = False, resolver: bool = False, metadata: bool = False) -> list[dict]:
    """Attempt marked sends; the host, not an exception, judges non-delivery."""
    selected = manifest()
    if not selected["network_supported"]:
        import pytest
        pytest.skip("Owned TCP/UDP/DNS delivery receivers are currently maintained on Linux hosts")
    if resolver:
        return attempt_resolver(selected["resolver"])
    targets = [row for row in selected["receivers"]
               if row["transport"] == transport and row["family"] == family
               and row.get("metadata", False) == metadata]
    assert targets, ("no owned metadata-address route selected; metadata coverage is incomplete" if metadata
                     else f"no live owned {transport}/IPv{family} receiver; coverage is incomplete")
    observations = []
    for target in targets:
        marker = ("guest-" + uuid.uuid4().hex).encode()
        payload = marker
        if dns:
            # A valid DNS question containing this attempt's unique label.
            payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + bytes([len(marker)]) + marker + b"\x04test\x00\x00\x01\x00\x01"
            if transport == "tcp":
                payload = len(payload).to_bytes(2, "big") + payload
        observation = {**target, "uid": os.geteuid(), "sha256": digest(payload),
                       "guest_network": guest_destination(target)}
        try:
            if tls:
                context = ssl.create_default_context()
                with socket.create_connection((target["address"], target["port"]), timeout=2) as connection:
                    with context.wrap_socket(connection, server_hostname="owned-receiver.test"):
                        raise AssertionError("plain owned receiver unexpectedly spoke TLS")
            else:
                send_payload(target, payload)
            observation["send_returned"] = True
        except OSError as error:
            assert error.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ECONNREFUSED,
                                   errno.EACCES, errno.EPERM, errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL,
                                   errno.ETIMEDOUT, errno.ECONNRESET, errno.EPIPE, None) or isinstance(error, ssl.SSLError), f"unrelated send error: {error}"
            observation["errno"] = error.errno
        observations.append(observation)
    print("CONTAINMENT_ATTEMPTS=" + json.dumps(observations), flush=True)
    return observations


def attempt_resolver(endpoint: dict) -> list[dict]:
    """Temporarily select the owned resolver in this disposable guest only."""
    assert endpoint is not None, "no owned IPv4 resolver selected; DNS coverage is incomplete"
    # Perform the lookup as the calling user; use guest sudo only to select
    # and restore resolv.conf. A failed setup or restore must fail the phase.
    path = Path("/etc/resolv.conf")
    route = guest_destination(endpoint)
    original = path.read_bytes()
    setter = ["sudo", "-n", "python3", "-c",
              "import sys; from pathlib import Path; Path('/etc/resolv.conf').write_bytes(sys.stdin.buffer.read())"]
    configured = f"nameserver {endpoint['address']}\noptions attempts:1 timeout:1\n".encode()
    query = "guest-" + uuid.uuid4().hex + ".test"
    try:
        subprocess.run(setter, input=configured, check=True, timeout=10, capture_output=True)
        try:
            socket.getaddrinfo(query, 80, socket.AF_INET, socket.SOCK_STREAM)
            outcome = "answered"
        except socket.gaierror:
            outcome = "no_answer"
    finally:
        subprocess.run(setter, input=original, check=True, timeout=10, capture_output=True)
    result = {"uid": os.geteuid(), "query_sha256": digest(query.encode()), "resolver_outcome": outcome,
              "endpoint": endpoint, "guest_network": route}
    print("CONTAINMENT_RESOLVER=" + json.dumps(result), flush=True)
    return [result]


def assert_host_canaries_absent() -> None:
    """Reject the identifiable host file and process, including PID collisions."""
    canaries = manifest()["host_canaries"]
    inspected = []
    for row in canaries:
        try:
            data = Path(row["path"]).read_bytes()
        except OSError as error:
            assert error.errno in (errno.ENOENT, errno.EACCES, errno.EPERM, errno.ESRCH), error
            inspected.append({"path": row["path"], "errno": error.errno})
            continue
        # /proc can contain an unrelated guest process at the same numeric PID.
        candidates = data.replace(b"\x00", b" ").split()
        assert all(digest(value) != row["sha256"] for value in candidates), (
            "host canary exposed: " + row["path"])
        inspected.append({"path": row["path"], "unrelated_content": True})
    print("HOST_CANARY_REFUSAL=" + json.dumps({"uid": os.geteuid(), "observations": inspected}), flush=True)


def syscall_number(name: str) -> int:
    numbers = {"x86_64": {"bpf": 321, "getpid": 39}, "aarch64": {"bpf": 280, "getpid": 172}}
    assert platform.machine() in numbers, "unsupported syscall architecture"
    return numbers[platform.machine()][name]


def assert_refused(result: int, error: int, operation: str) -> None:
    """Any nonnegative result, including a nonzero FD, is success."""
    assert result == -1 and error in REFUSAL_ERRORS, (
        f"{operation}: result={result} errno={error}; invalid input is not containment proof")


def check_bpf_refusal(*, guest_kernel: bool = False) -> None:
    """Make a valid one-entry BPF hash-map request on the actual architecture."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    assert libc.syscall(syscall_number("getpid")) == os.getpid(), "getpid control failed"
    # union bpf_attr for BPF_MAP_CREATE. The remaining fields are zero/default.
    attributes = (ctypes.c_uint32 * 36)(1, 4, 4, 1)
    ctypes.set_errno(0)
    result = libc.syscall(syscall_number("bpf"), 0, ctypes.byref(attributes), ctypes.sizeof(attributes))
    error = ctypes.get_errno()
    if result >= 0:
        os.close(result)
        if guest_kernel:
            # A VZ guest has its own kernel. Creating a map there does not
            # grant host-kernel access or restrict supported guest root.
            assert_host_canaries_absent()
            print("BPF_MAP_CREATE=guest-kernel descriptor closed", flush=True)
            return
    assert_refused(result, error, "BPF_MAP_CREATE")


def run_phase(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--share", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--phase", required=True, choices=("guest-agent", "guest-root"))
    parser.add_argument("--ipv4", default=os.environ.get("SAFEYOLO_BLACKBOX_RECEIVER_IPV4"))
    parser.add_argument("--ipv6", default=os.environ.get("SAFEYOLO_BLACKBOX_RECEIVER_IPV6"))
    parser.add_argument("--metadata-address", action="append",
                        default=json.loads(os.environ.get("SAFEYOLO_BLACKBOX_METADATA_ADDRESSES", "[]")))
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(arguments)
    assert args.command and args.command[0] == "--", "supply the existing guest phase command after --"
    assert args.share.name == "config-share", "select the installed agent's config-share"
    private = args.share.resolve().parents[2] / "data"
    repository = Path(__file__).resolve().parents[3]
    assert not private.is_relative_to(repository) and not args.output.resolve().is_relative_to(repository), (
        "host canaries and observations require an instance outside the guest workspace")
    private.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = {"status": "incomplete", "phase": args.phase,
              "run_id": os.environ.get("SAFEYOLO_BLACKBOX_RUN_ID"),
              "guest": json.loads(os.environ.get("SAFEYOLO_BLACKBOX_GUEST_IDENTITY", "null")),
              "receivers": [], "host_canaries": [],
              "limits": ["Receivers cover assigned non-loopback host addresses. Missing IPv4/IPv6 or owned metadata targets are incomplete coverage; host controls alone do not establish a guest route."]}
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    with ExitStack() as stack:
        network_supported = sys.platform == "linux"
        interfaces = json.loads(subprocess.check_output(["ip", "-json", "address", "show"])) if network_supported else []
        addresses = receiver_addresses(interfaces, args.ipv4, args.ipv6) if network_supported else []
        metadata = args.metadata_address if network_supported else []
        assert all(address in interface_addresses(interfaces) and ipaddress.ip_address(address).version == 4
                   and ipaddress.ip_address(address).is_link_local for address in metadata), (
            "select only an existing owned IPv4 link-local metadata alias; this runner creates no aliases")
        receivers = [stack.enter_context(DeliveryReceiver(address, transport))
                     for address in addresses for transport in ("tcp", "udp")]
        metadata_receivers = [stack.enter_context(DeliveryReceiver(address, "tcp", 80)) for address in metadata]
        resolver_address = next((address for address in addresses if ":" not in address), None)
        resolver = stack.enter_context(DeliveryReceiver(resolver_address, "udp", 53)) if resolver_address else None
        receivers += metadata_receivers + ([resolver] if resolver is not None else [])
        if not network_supported:
            report["limits"].append("No TCP/UDP/DNS observer is selected on this host. Named VZ exclusions are not containment evidence; the host canaries still run.")
        controls = [[receiver.control()] for receiver in receivers]
        scratch = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="containment-", dir=private)))
        marker = ("host-canary-" + uuid.uuid4().hex).encode()
        private_file = scratch / "private-canary"
        private_file.write_bytes(marker)
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)", marker.decode()])
        def stop_process():
            process.terminate()
            process.wait(timeout=5)
        stack.callback(stop_process)
        assert process.poll() is None and private_file.read_bytes() == marker
        canaries = [{"path": str(private_file), "sha256": digest(marker)},
                    {"path": f"/proc/{process.pid}/cmdline", "sha256": digest(marker)}]
        if sys.platform == "linux":
            assert marker in Path(canaries[1]["path"]).read_bytes(), "host process control failed"
        else:
            # macOS has no procfs. Check the actual host argv before supplying
            # its numeric PID to the guest namespace visibility probe.
            observed = subprocess.check_output(["ps", "-p", str(process.pid), "-o", "command="])
            assert marker in observed, "host process control failed"
        selected = {"receivers": [{**receiver.endpoint, "family": 6 if ":" in receiver.endpoint["address"] else 4,
                                   "metadata": receiver in metadata_receivers}
                                  for receiver in receivers if receiver is not resolver],
                    "resolver": resolver.endpoint if resolver else None, "host_canaries": canaries,
                    "network_supported": network_supported}
        if network_supported:
            oci = json.loads((args.share.parent / "config.json").read_text())
            selected["host_network"] = {"interfaces": interfaces,
                                         "namespace": os.readlink("/proc/self/ns/net"),
                                         "guest_namespaces": oci["linux"]["namespaces"]}
        path = args.share / MANIFEST.name
        path.write_text(json.dumps(selected) + "\n")
        path.chmod(0o444)
        stack.callback(path.unlink)
        report.update(selected)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        result = subprocess.run(args.command[1:], check=False)
        # A second independently observed marker orders the final receive
        # window after the guest command and proves the observer stayed live.
        for receiver, expected in zip(receivers, controls):
            expected.append(receiver.control())
        # Join every accepted request before judging the final observation.
        for receiver in receivers:
            receiver.close()
        report["host_canaries_live_after"] = process.poll() is None and private_file.read_bytes() == marker
        report["observations"] = [{"endpoint": receiver.endpoint, "rows": list(receiver.rows), "controls": expected}
                                  for receiver, expected in zip(receivers, controls)]
        report["guest_exit"] = result.returncode
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        assert report["host_canaries_live_after"], "host canary disappeared during the guest probe"
        for receiver, expected in zip(receivers, controls):
            receiver.assert_no_delivery(expected)
        report["status"] = "passed" if result.returncode == 0 else "guest_failed"
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        return result.returncode


if __name__ == "__main__":
    sys.exit(run_phase())
