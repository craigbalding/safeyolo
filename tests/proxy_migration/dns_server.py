"""Temporary BIND DNS zones for live proxy resolver tests."""

from __future__ import annotations

import re
import socket
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

_QUERY = re.compile(r"\bquery: ([^\s]+) IN ([A-Z0-9]+)\b")
_FIXTURE_ZONE = "dns-fixture.test"
_RESERVED = {"_safeyolo.proxy.internal", "_safeyolo.probe.internal"}


def _zone_header(zone):
    return (f"$TTL 30\n"
            f"@ IN SOA ns.{zone}. hostmaster.{zone}. (1 60 60 60 30)\n"
            f"@ IN NS ns.{zone}.\n"
            "ns IN A 127.0.0.1\n")


def _write_zones(root, names):
    fixture = []
    reserved = []
    for name in names:
        host = name.lower().removesuffix(".")
        if host in _RESERVED:
            reserved.append(host)
        elif host.endswith(f".{_FIXTURE_ZONE}"):
            label = host.removesuffix(f".{_FIXTURE_ZONE}")
            if not re.fullmatch(r"[a-z0-9-]{1,63}", label):
                raise ValueError(f"Invalid fixture DNS label: {name}")
            fixture.append(label)
        else:
            raise ValueError(f"DNS fixture cannot answer a non-fixture host: {name}")

    fixture_zone = root / "fixture.zone"
    fixture_zone.write_text(
        _zone_header(_FIXTURE_ZONE)
        + "".join(f"{label} IN A 127.0.0.1\n" for label in sorted(set(fixture)))
    )
    zones = [(_FIXTURE_ZONE, fixture_zone)]
    for index, host in enumerate(sorted(set(reserved))):
        zone_file = root / f"reserved-{index}.zone"
        zone_file.write_text(_zone_header(host) + "@ IN A 127.0.0.1\n")
        zones.append((host, zone_file))
    return zones


def _write_config(root, zones):
    config = root / "named.conf"
    config.write_text(f"""
options {{
    directory "{root}";
    listen-on port 53 {{ 127.0.0.1; }};
    listen-on-v6 {{ none; }};
    recursion no;
    dnssec-validation no;
    allow-query {{ 127.0.0.1; }};
    allow-transfer {{ none; }};
    notify no;
    check-names master ignore;
    pid-file "{root / 'named.pid'}";
    session-keyfile "{root / 'session.key'}";
}};
controls {{ }};
logging {{
    channel fixture_queries {{
        file "{root / 'queries.log'}";
        severity info;
        print-time yes;
    }};
    category queries {{ fixture_queries; }};
}};
""" + "".join(f'zone "{host}" {{ type primary; file "{zone_file}"; }};\n'
              for host, zone_file in zones))
    checked = subprocess.run(
        ["named-checkconf", "-z", str(config)], capture_output=True, text=True,
        check=False,
    )
    if checked.returncode:
        raise AssertionError(f"DNS fixture configuration failed:\n{checked.stdout}{checked.stderr}")
    return config


def _check_port():
    """Expose a missing port-53 capability before launching the server."""
    for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
        with socket.socket(socket.AF_INET, kind) as listener:
            listener.bind(("127.0.0.1", 53))


class DNSQueries:
    def __init__(self, process, query_log, process_log):
        self.process = process
        self.query_log = query_log
        self.process_log = process_log
        self._cleared = 0

    def _read(self):
        if self.process.poll() is not None:
            raise AssertionError(f"DNS fixture exited:\n{self.process_log.read_text()}")
        text = self.query_log.read_text() if self.query_log.exists() else ""
        return [
            (name.removesuffix(".").lower(), {"A": 1, "AAAA": 28}.get(qtype, qtype), "named")
            for name, qtype in _QUERY.findall(text)
        ]

    def queries(self):
        return self._read()[self._cleared:]

    def clear_queries(self):
        self._cleared = len(self._read())


@contextmanager
def dns_server(names):
    """Run isolated authoritative zones on loopback until fixture teardown."""
    _check_port()
    with tempfile.TemporaryDirectory(prefix="sy-proxy-dns-") as scratch:
        root = Path(scratch)
        zones = _write_zones(root, names)
        config = _write_config(root, zones)
        process_log = root / "process.log"
        with process_log.open("w") as output:
            process = subprocess.Popen(
                ["named", "-f", "-n", "1", "-c", str(config)],
                stdout=output, stderr=subprocess.STDOUT,
            )
        try:
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    raise AssertionError(f"DNS fixture failed to start:\n{process_log.read_text()}")
                try:
                    with socket.create_connection(("127.0.0.1", 53), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise AssertionError(f"DNS fixture did not bind:\n{process_log.read_text()}")
                    time.sleep(0.02)
            yield DNSQueries(process, root / "queries.log", process_log)
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise AssertionError("DNS fixture did not stop after SIGTERM")
