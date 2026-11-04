"""Free allocator pages must leave configured capture and transport intact."""

import base64
import hashlib
import http.client
import json
import os
import platform
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tests.proxy_contracts.harness import connection, launch_proxy, request
from tests.proxy_contracts.scenarios import POLICY


class BodyOrigin(BaseHTTPRequestHandler):
    """Hash actual forwarded bodies and hold one request across each trim."""

    def log_message(self, *_):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.bodies.append((self.path, hashlib.sha256(body).hexdigest()))
        if self.path == "/hold":
            self.server.held.set()
            if not self.server.release.wait(50):
                return
        answer = hashlib.sha256(body).hexdigest().encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)


def admin(proxy, path):
    port = json.loads(proxy.readiness_file.read_text())["admin_port"]
    client = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        client.request("GET", path, headers={"Authorization": "Bearer heap-test-operator"})
        response = client.getresponse()
        raw = response.read()
        assert response.status == 200, (path, response.status, raw[:200])
        return json.loads(raw)
    finally:
        client.close()


def captured(proxy, expected):
    rows = admin(proxy, "/admin/traffic/flows")["flows"]
    rows = [row for row in rows if "/memory-" in row["url"]]
    assert len(rows) == len(expected), rows
    for row in rows:
        body = admin(proxy, f"/admin/traffic/flows/{row['id']}/body?side=request")
        assert body["available"] and body["size"] == 2025012
        assert hashlib.sha256(base64.b64decode(body["data_base64"])).hexdigest() == expected[row["url"]]
    return {row["id"] for row in rows}, sum(row["request_body"]["size"] for row in rows)


def held_request(path, url):
    client = connection(path)
    client.sock.settimeout(50)
    try:
        client.request("POST", url, body=b"held-through-release")
        response = client.getresponse()
        return response.status, response.read()
    finally:
        client.close()


def samples(path, pid):
    # A live writer can leave a partial last row. Keep only complete records.
    rows = [json.loads(row) for row in path.read_bytes().split(b"\n")[:-1] if row]
    return [row for row in rows if row["pid"] == pid]


def stored(directory, count):
    deadline = time.monotonic() + 5
    while True:
        with sqlite3.connect(f"file:{directory / 'flows.sqlite3'}?mode=ro", uri=True) as database:
            rows = database.execute(
                "SELECT id, request_body_blob, response_body_blob, request_body_size, "
                "request_body_stored, request_body_truncated FROM flows WHERE path LIKE '/memory-%' ORDER BY id"
            ).fetchall()
        if len(rows) == count:
            assert all(row[4] > 0 for row in rows)
            return [(row[0], hashlib.sha256(row[1]).hexdigest(), hashlib.sha256(row[2]).hexdigest(),
                     *row[3:]) for row in rows]
        assert time.monotonic() < deadline, (count, len(rows))
        time.sleep(0.05)


@pytest.mark.skipif(sys.platform != "linux" or platform.libc_ver()[0] != "glibc",
                    reason="the correction uses GNU/Linux malloc_trim")
def test_periodic_release_preserves_capture_and_live_requests(tmp_path, monkeypatch):
    observer = tmp_path / "heap-observer.so"
    subprocess.run(["cc", "-shared", "-fPIC", "-pthread", "-Wall", "-Wextra", "-Werror",
                    str(Path(__file__).with_name("heap_observer.c")), "-o", str(observer)], check=True)
    sample_path = tmp_path / "heap.jsonl"
    monkeypatch.setenv("LD_PRELOAD", str(observer))
    monkeypatch.setenv("SAFEYOLO_HEAP_SAMPLE_PATH", str(sample_path))
    directory = tmp_path / "proxy"
    directory.mkdir()
    (directory / "data").mkdir()
    (directory / "data/instance_id").write_text("sy-0123456789abcdef0123456789abcdef")
    token = directory / "operator-token"
    token.write_text("heap-test-operator")
    origin = ThreadingHTTPServer(("127.0.0.1", 0), BodyOrigin)
    origin.bodies, origin.held, origin.release = [], threading.Event(), threading.Event()
    thread = threading.Thread(target=origin.serve_forever)
    thread.start()
    rounds, expected, retained = [], {}, set()
    payload = b'{"text":"' + b"x" * (2025012 - 11) + b'"}'
    digest = hashlib.sha256(payload).hexdigest()
    report = {"platform": platform.platform(), "libc": platform.libc_ver(), "rounds": rounds}
    try:
        with launch_proxy("rust", directory, POLICY, native_product=True, admin_port=0,
                          admin_api_token_file=token, flow_store_enabled=True) as proxy:
            binary = Path(os.readlink(f"/proc/{proxy.process.pid}/exe"))
            report.update(pid=proxy.process.pid, binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                          version=subprocess.check_output([str(binary), "--version"], text=True).strip(),
                          configuration=(directory / "config.toml").read_text())
            birth = Path(f"/proc/{proxy.process.pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
            url = f"http://127.0.0.1:{origin.server_port}"
            with ThreadPoolExecutor(max_workers=1) as clients:
                for epoch in range(2):
                    for index in range(40):
                        target = f"{url}/memory-{epoch}-{index}"
                        status, _, answer = request(proxy.paths["alice"], target, method="POST", body=payload,
                                                    headers={"Content-Type": "application/json",
                                                             "X-SafeYolo-Test-Context": f"run=heap-release;agent=alice;test={index}"})
                        assert status == 200 and answer == digest.encode()
                        expected[target] = digest
                    ids, body_bytes = captured(proxy, expected)
                    disk_before = stored(directory, len(expected))
                    assert retained <= ids
                    retained = ids
                    origin.held.clear()
                    origin.release.clear()
                    held = clients.submit(held_request, proxy.paths["alice"], url + "/hold")
                    assert origin.held.wait(5)
                    time.sleep(0.5)
                    before = samples(sample_path, proxy.process.pid)[-1]
                    # Keep ordinary traffic and denials running over a complete
                    # production scan interval. No test trim or capture change.
                    deadline = time.monotonic() + 33
                    while time.monotonic() < deadline:
                        assert request(proxy.paths["bob"], url + "/denied", method="POST", body=b"deny")[0] == 403
                        assert request(proxy.paths["alice"], url + "/small", method="POST", body=b"ok")[0] == 200
                        time.sleep(0.5)
                    after = samples(sample_path, proxy.process.pid)[-1]
                    assert not held.done()
                    origin.release.set()
                    assert held.result(timeout=5) == (200, hashlib.sha256(b"held-through-release").hexdigest().encode())
                    # Reloads keep capture settings and existing rows. A failed
                    # reload must leave the running process and worker intact.
                    if epoch == 0:
                        config_path = directory / "config.toml"
                        original = config_path.read_text()
                        ready_at = proxy.readiness_file.stat().st_mtime_ns
                        proxy.process.send_signal(signal.SIGHUP)
                        deadline = time.monotonic() + 5
                        while proxy.readiness_file.stat().st_mtime_ns == ready_at:
                            assert time.monotonic() < deadline
                            time.sleep(0.05)
                        config_path.write_text("invalid = [")
                        proxy.process.send_signal(signal.SIGHUP)
                        deadline = time.monotonic() + 5
                        while "configuration reload failed" not in (directory / "process.log").read_text():
                            assert time.monotonic() < deadline
                            time.sleep(0.05)
                        config_path.write_text(original)
                    observed_ids, observed_bytes = captured(proxy, expected)
                    assert observed_ids == ids and observed_bytes == body_bytes
                    assert stored(directory, len(expected)) == disk_before
                    assert not any(path == "/denied" for path, _ in origin.bodies)
                    assert Path(f"/proc/{proxy.process.pid}/stat").read_text().rsplit(")", 1)[1].split()[19] == birth
                    rounds.append({"before": before, "after": after, "rows": len(ids), "body_bytes": body_bytes,
                                   "stored_rows": len(disk_before), "same_birth": True,
                                   "all_rows_and_body_hashes_preserved": True})
            assert proxy.process.poll() is None
        assert proxy.process.returncode == 0
    finally:
        origin.release.set()
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=5)
        (tmp_path / "memory-result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report))
    for result in rounds:
        before, after = result["before"], result["after"]
        # Diagnostic thresholds distinguish released resident pages from live
        # allocated capture; they are not product retention limits.
        assert before["free"] >= 8 * 1024 * 1024, result
        assert before["rss_kib"] - after["rss_kib"] >= 8 * 1024, result
        assert abs(before["allocated"] - after["allocated"]) < 4 * 1024 * 1024, result
