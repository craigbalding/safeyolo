"""Check the actual outer page in Chromium with controlled noVNC observations.

These checks prove browser states, history and deadlines. The real desktop
journey separately uses the shipped noVNC library and native guest bridge.
Run with Playwright 1.55.0 and SAFEYOLO_TEST_CHROMIUM pointing to Chromium.
"""

from __future__ import annotations

import json
import os
import socket
import socketserver
import subprocess
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

import pytest

playwright = pytest.importorskip("playwright.sync_api")
SOURCE = Path(__file__).resolve().parents[2] / "proxy/src"
RFB = """
export default class RFB extends EventTarget {
    constructor(target, channel) {
        super(); window.viewers = (window.viewers || 0) + 1;
        window.activeViewers = (window.activeViewers || 0) + 1;
        window.viewer = this; this.channel = channel;
        target.append(document.createElement('canvas'));
        setTimeout(() => this.dispatchEvent(new Event('connect')), 10);
    }
    disconnect() { window.activeViewers--; this.channel.close(); }
    sendCredentials(value) { window.credentialsSent = value; }
    approveServer() { window.serverApproved = true; }
    sendKey(...value) { window.keySent = value; }
    sendCtrlAltDel() { window.ctrlAltDeleteSent = true; }
    clipboardPasteFrom(value) { window.clipboardSent = value; }
    focus() {}
}
"""


@contextmanager
def page_origin():
    state = {"tcp": "refused", "greeting": "not_checked", "runtime": "running",
             "disagreement": False, "session": "open", "access": 200, "requests": 0,
             "assets": True, "delay": 0, "drop": False, "malformed": False,
             "viewer": "connect"}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path, code, content_type = self.path, 200, "application/json"
            if path == "/_safeyolo_desktop/":
                content = (SOURCE / "desktop_page.html").read_bytes()
                content_type = "text/html"
            elif path == "/_safeyolo_desktop/page.js":
                content = (SOURCE / "desktop_page.js").read_bytes()
                content_type = "text/javascript"
            elif "/assets/" in path:
                content, content_type = RFB.encode(), "text/javascript"
                if state["viewer"] == "init_failure":
                    content = b"export default class RFB { constructor() { throw new Error('private init data'); } }"
                elif state["viewer"] == "handshake_hang":
                    content = RFB.replace("setTimeout(() => this.dispatchEvent(new Event('connect')), 10);", "").encode()
                code = 200 if state["assets"] else 404
            elif "/viewer?" in path:
                code, content = 502, b"{}"
            else:
                state["requests"] += 1
                if state["drop"]:
                    self.close_connection = True
                    return
                code = state["access"]
                if "/session?" in path:
                    value = {"state": state["session"], "age_ms": 40000,
                             "browser_pong_age_ms": 0, "relay_pong_age_ms": 0}
                else:
                    value = {"observed_at": state["requests"], "access": "valid",
                             "runtime": {"state": state["runtime"], "duration_ms": 1,
                                         "disagreement": state["disagreement"]},
                             "guest": {"tcp": state["tcp"], "greeting": state["greeting"],
                                       "duration_ms": 3000}}
                content = json.dumps(value).encode()
                if state["malformed"]:
                    content = b'{"unexpected":"private error data"}'
                if state["delay"]:
                    time.sleep(state["delay"])
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            try:
                self.wfile.write(content)
            except (BrokenPipeError, ConnectionResetError):
                pass  # The page cancels superseded checks.

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield state, f"http://127.0.0.1:{server.server_port}/_safeyolo_desktop/"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


@pytest.fixture
def browser():
    with playwright.sync_playwright() as tools:
        with tools.chromium.launch(executable_path=os.environ.get("SAFEYOLO_TEST_CHROMIUM", "/usr/bin/chromium"),
                                   headless=True) as opened:
            yield opened


def wait_status(page, text, timeout=20000):
    page.wait_for_function("text => document.querySelector('#status').textContent.includes(text)",
                           arg=text, timeout=timeout)


def test_silent_listener_recovers_in_same_page_with_live_history(browser):
    with page_origin() as (state, url):
        page = browser.new_page()
        page.add_init_script("crypto.randomUUID = undefined")
        page.goto(url)
        wait_status(page, "Desktop service has not started")
        assert not page.locator("#diagnostics").get_attribute("open")
        state.update(tcp="accepted", greeting="timeout")
        wait_status(page, "Desktop server is not responding")
        assert "guest-local checks" in page.inner_text("#explanation")
        page.click("#diagnostics summary")
        assert "Guest-local VNC greeting: timeout" in page.inner_text("#log")
        state["greeting"] = "valid"
        wait_status(page, "Desktop connected")
        assert page.url == url
        assert "Guest-local VNC greeting: timeout" in page.inner_text("#log")
        assert page.evaluate("activeViewers") == 1
        assert page.evaluate("viewer.resizeSession") is True
        page.click("#viewonly")
        assert page.evaluate("viewer.viewOnly") is True
        page.click("#ctrlaltdelete")
        assert page.evaluate("ctrlAltDeleteSent") is True
        page.click("#ctrl")
        assert page.evaluate("keySent") == [0xffe3, "ControlLeft", True]
        page.evaluate("viewer.dispatchEvent(new Event('disconnect'))")
        wait_status(page, "Desktop connected")
        assert page.evaluate("viewers") == 2
        assert page.evaluate("activeViewers") == 1
        assert page.locator("#ctrl").get_attribute("aria-pressed") == "false"


def test_hints_stalls_assets_access_and_log_bounds(browser):
    with page_origin() as (state, url):
        state.update(tcp="accepted", greeting="valid", assets=False)
        page = browser.new_page()
        page.goto(url)
        page.wait_for_function("document.querySelector('#log').textContent.includes('Viewer assets or initialization')")
        assert page.locator("#diagnostics").is_visible()
        state["assets"] = True
        page.click("#diagnostics summary")
        page.click("#retry")
        wait_status(page, "Desktop connected")
        before = page.evaluate("viewers")
        page.evaluate("Object.defineProperty(navigator, 'onLine', {get: () => false, configurable: true}); window.dispatchEvent(new Event('offline'))")
        page.wait_for_function("document.querySelector('#log').textContent.includes('offline; actual origin check required')")
        wait_status(page, "Desktop connected")
        assert page.evaluate("viewers") == before
        state["disagreement"] = True
        page.click("#retry")
        wait_status(page, "recorded agent state differs")
        state["access"] = 503
        page.evaluate("Object.defineProperty(navigator, 'onLine', {get: () => true, configurable: true})")
        page.click("#retry")
        wait_status(page, "SafeYolo diagnostics are unavailable")
        assert "stale" in page.inner_text("#contact")
        state["drop"] = True
        page.click("#retry")
        wait_status(page, "Cannot reach SafeYolo")
        page.evaluate("Object.defineProperty(navigator, 'onLine', {get: () => false, configurable: true}); window.dispatchEvent(new Event('offline'))")
        wait_status(page, "Your browser appears offline")
        state["drop"] = False
        state["access"] = 200
        page.click("#retry")
        wait_status(page, "recorded agent state differs")
        state["session"] = "closed"
        page.click("#retry")
        page.wait_for_function("document.querySelector('#log').textContent.includes('Existing viewer Ping/Pong: failed')")
        state["session"] = "open"
        wait_status(page, "Desktop connected")
        page.evaluate("for (let i=0; i<180; i++) window.dispatchEvent(new Event('online'))")
        assert len(page.inner_text("#log").splitlines()) <= 120
        assert page.evaluate("activeViewers") == 1
        state["access"] = 410
        page.click("#retry")
        wait_status(page, "removed or replaced")
        count = state["requests"]
        page.wait_for_timeout(6000)
        assert state["requests"] == count
        assert page.evaluate("activeViewers") == 0


@pytest.mark.parametrize(("code", "message"), [(401, "Preview unlock required"), (403, "Preview access refused")])
def test_authoritative_access_failure_stops_requests(browser, code, message):
    with page_origin() as (state, url):
        state.update(tcp="accepted", greeting="valid")
        page = browser.new_page()
        page.goto(url)
        wait_status(page, "Desktop connected")
        state["access"] = code
        page.click("#retry")
        wait_status(page, message)
        count = state["requests"]
        page.wait_for_timeout(5500)
        assert state["requests"] == count
        assert page.evaluate("activeViewers") == 0


def test_credentials_and_server_verification_keep_the_page_and_redact_copy(browser):
    with page_origin() as (state, url):
        state.update(tcp="accepted", greeting="valid")
        page = browser.new_page()
        page.goto(url)
        wait_status(page, "Desktop connected")
        page.evaluate("viewer.dispatchEvent(new Event('credentialsrequired'))")
        page.fill("#password", "private-desktop-password")
        page.click("#credentials button")
        assert page.evaluate("credentialsSent.password") == "private-desktop-password"
        assert page.input_value("#password") == ""
        page.evaluate("viewer.dispatchEvent(new CustomEvent('serververification', {detail:{type:'RSA', publickey:new Uint8Array([1,2,3])}}))")
        page.wait_for_selector("#verification", state="visible")
        assert len(page.inner_text("#fingerprint")) == 23
        page.click("#approve-server")
        assert page.evaluate("serverApproved") is True
        page.evaluate("viewer.dispatchEvent(new CustomEvent('clipboard', {detail:{text:'private-desktop-clipboard'}}))")
        page.click("#diagnostics summary")
        assert "private-desktop-password" not in page.inner_text("#log")
        assert "private-desktop-clipboard" not in page.inner_text("#log")


def test_unknown_inspection_stale_results_and_deliberate_close(browser):
    with page_origin() as (state, url):
        state["runtime"] = "unknown"
        page = browser.new_page()
        page.goto(url)
        wait_status(page, "Cause not yet identified")
        page.click("#diagnostics summary")
        assert "inspection failed" in page.inner_text("#explanation")
        state.update(runtime="running", tcp="timeout")
        page.click("#retry")
        page.wait_for_function("document.querySelector('#log').textContent.includes('TCP connection timed out; service cause unverified')")
        assert "guest-local VNC connection timed out" in page.inner_text("#explanation")
        state.update(runtime="running", tcp="accepted", greeting="valid", delay=3)
        page.click("#retry")
        page.wait_for_timeout(300)
        state.update(runtime="stopped", delay=0)
        page.evaluate("window.dispatchEvent(new Event('online'))")
        wait_status(page, "Agent runtime is stopped")
        page.wait_for_timeout(3500)
        assert page.evaluate("window.viewers || 0") == 0
        state.update(runtime="running", tcp="accepted", greeting="valid")
        page.click("#retry")
        wait_status(page, "Desktop connected")
        page.evaluate("viewer.dispatchEvent(new CustomEvent('securityfailure', {detail:{reason:'<img src=x onerror=window.hostile=1> Bearer SECRET'}}))")
        assert not page.evaluate("window.hostile")
        assert "SECRET" not in page.inner_text("#log")
        assert "<img" not in page.inner_text("#log")
        page.click("#close")
        wait_status(page, "Viewer closed")
        count = state["requests"]
        page.wait_for_timeout(6000)
        assert state["requests"] == count
        assert page.evaluate("activeViewers") == 0


@pytest.mark.parametrize("viewer", ["init_failure", "handshake_hang"])
def test_viewer_failures_reach_a_bounded_stage_and_leave_diagnostics(browser, viewer):
    with page_origin() as (state, url):
        state.update(tcp="accepted", greeting="valid", viewer=viewer)
        page = browser.new_page()
        page.goto(url)
        stage = "Viewer initialization" if viewer == "init_failure" else "WebSocket/relay establishment"
        page.wait_for_function("stage => document.querySelector('#log').textContent.includes(stage + ': failed')",
                               arg=stage, timeout=24000)
        page.click("#diagnostics summary")
        assert "private init data" not in page.inner_text("#log")
        assert page.url == url
        page.click("#close")
        assert page.locator("#screen canvas").count() == 0


def test_unusable_origin_observation_is_distinct_from_no_response(browser):
    with page_origin() as (state, url):
        state["malformed"] = True
        page = browser.new_page()
        page.goto(url)
        wait_status(page, "SafeYolo diagnostics are unavailable")
        assert "endpoint replied" in page.inner_text("#explanation")
        assert "stale" in page.inner_text("#contact")
        assert "private error data" not in page.inner_text("#log")
        state["malformed"] = False
        page.click("#retry")
        wait_status(page, "Desktop service has not started")


def native_browser_journey():
    """Called by the Rust desktop fixture; controls and port transport are real.

    The Rust fixture supplies owned runtime handles and a controlled runsc
    adapter. This is browser/desktop integration evidence, not a runsc boot.
    """
    root = Path(os.environ["SAFEYOLO_DESKTOP_FIXTURE"])
    url, code = os.environ["SAFEYOLO_DESKTOP_URL"], os.environ["SAFEYOLO_DESKTOP_CODE"]
    helper, assets = os.environ["SAFEYOLO_DESKTOP_GUEST"], os.environ["SAFEYOLO_NOVNC_ASSETS"]
    children, streams = [], []

    def start(arguments):
        stream = (root / f"desktop-child-{len(children)}.log").open("wb")
        streams.append(stream)
        child = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=stream, stderr=stream)
        children.append(child)
        return child

    def stop(child):
        if child.poll() is None:
            child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)

    def port_ready(port, child):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            assert child.poll() is None, "desktop child exited"
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.1)
        raise AssertionError("desktop listener did not become ready")

    class Silent(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(10)
            try:
                self.request.recv(1)
            except TimeoutError:
                pass

    class SilentServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    silent = SilentServer(("127.0.0.1", 5900), Silent)
    worker = threading.Thread(target=silent.serve_forever, daemon=True)
    worker.start()
    try:
        display = ":1902"
        x = start(["/usr/bin/Xvfb", display, "-screen", "0", "800x600x24", "-nolisten", "tcp"])
        deadline = time.monotonic() + 10
        while not Path("/tmp/.X11-unix/X1902").exists():
            assert x.poll() is None and time.monotonic() < deadline
            time.sleep(0.1)
        bridge = start([helper, "desktop-bridge", "--web", assets, "127.0.0.1:6080", "127.0.0.1:5900"])
        port_ready(6080, bridge)
        with playwright.sync_playwright() as tools:
            with tools.chromium.launch(executable_path="/usr/bin/chromium", headless=True) as browser:
                context = browser.new_context(permissions=["clipboard-read", "clipboard-write"])
                page = context.new_page()
                page.goto(url)
                page.fill("input[name=code]", code)
                page.click("button[type=submit]")
                wait_status(page, "Desktop server is not responding", 25000)
                page.click("#diagnostics summary")
                assert "Guest-local VNC greeting: timeout" in page.inner_text("#log")
                silent.shutdown()
                silent.server_close()
                worker.join(timeout=5)
                vnc = start(["/usr/bin/x11vnc", "-display", display, "-nopw", "-listen", "127.0.0.1",
                             "-rfbport", "5900", "-forever", "-shared", "-noxdamage", "-noxfixes",
                             "-noscr", "-nowf", "-threads"])
                port_ready(5900, vnc)
                wait_status(page, "Desktop connected", 30000)
                assert page.url == url
                assert page.locator("#screen canvas").count() == 1
                assert "Guest-local VNC greeting: timeout" in page.inner_text("#log")
                page.click("#copy")
                copied = page.evaluate("navigator.clipboard.readText()")
                assert code not in copied and "Bearer" not in copied and url not in copied

                # The authenticated presentation route reuses the same page
                # after the actual native CLI has returned and exited.
                import tomllib
                settings = tomllib.loads((root / "config.toml").read_text())
                token = (root / "token").read_text().strip()
                request = Request(f"http://127.0.0.1:{settings['admin_port']}/admin/agents/alice/desktop/present",
                                  method="POST", data=b"{}", headers={"Authorization": f"Bearer {token}"})
                with urlopen(request, timeout=10) as response:
                    presented = json.load(response)
                assert presented["url"] == url and presented["reused"] is True
                second = context.new_page()
                second.goto(url)
                wait_status(second, "Desktop connected", 20000)
                second.click("#diagnostics summary")
                # A false offline hint must not replace a healthy real viewer.
                handshakes = page.inner_text("#log").count("RFB handshake: connected")
                page.evaluate("Object.defineProperty(navigator, 'onLine', {get: () => false, configurable: true}); window.dispatchEvent(new Event('offline'))")
                page.wait_for_timeout(1500)
                assert page.inner_text("#status") == "Desktop connected"
                assert page.inner_text("#log").count("RFB handshake: connected") == handshakes
                page.evaluate("Object.defineProperty(navigator, 'onLine', {get: () => true, configurable: true}); window.dispatchEvent(new Event('online'))")
                # Freeze actual browser execution across a long gap. Resume
                # with fresh observations, without accumulated attempts.
                session = context.new_cdp_session(page)
                session.send("Page.setWebLifecycleState", {"state": "frozen"})
                time.sleep(32)
                session.send("Page.setWebLifecycleState", {"state": "active"})
                page.evaluate("window.dispatchEvent(new PageTransitionEvent('pageshow', {persisted:true}))")
                page.wait_for_function("document.querySelector('#log').textContent.split('Page restored: fresh checks requested').at(-1).includes('Browser → SafeYolo: intended endpoint replied HTTP 200')", timeout=20000)
                wait_status(page, "Desktop connected", 30000)
                (root / "blackhole").touch()
                page.wait_for_function("document.querySelector('#log').textContent.includes('failed; old viewer closed')", timeout=45000)
                (root / "blackhole").unlink()
                wait_status(page, "Desktop connected", 30000)
                assert second.inner_text("#status") == "Desktop connected"
                assert second.locator("#screen canvas").count() == 1
                assert page.url == url and page.locator("#screen canvas").count() == 1
                assert "fresh checks requested" in page.inner_text("#log")
                print("Real Chromium/noVNC/native bridge/X11: silent listener recovered in the same CLI page; approved presentation reused it; a false offline hint kept the healthy viewer; 32 seconds of frozen browser execution resumed with fresh checks; a silently stalled transport failed within 45 seconds and recovered; the second static viewer stayed connected.")
                second.click("#close")
                page.click("#close")
    finally:
        silent.shutdown()
        silent.server_close()
        worker.join(timeout=5)
        for child in reversed(children):
            stop(child)
        for stream in streams:
            stream.close()
        for port in (5900, 6080):
            with socket.socket() as check:
                check.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                check.bind(("127.0.0.1", port))
