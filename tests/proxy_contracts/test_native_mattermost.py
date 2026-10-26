"""Native #818 G6 exchange/actions through installed CLI, HTTPS and real NATS.

Reuse the owned native instance, pinned NATS and CONNECT parent. The controlled
Mattermost REST server supplies protocol shapes and uncertain outcomes. Python
is only the driver; the installed PATH contains native binaries and no Python.
No live account, public tunnel, model or guest matrix is used. Callback requests
retain five seconds and HTTPS retains fifteen seconds. The one-shot CLI driver
allows twenty seconds; large backlog recovery allows two minutes.
"""
from __future__ import annotations

import asyncio
import copy
import http.client
import json
import os
import signal
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from markdown_it import MarkdownIt

from tests.blackbox.harness.sinkhole_parent import Parent, Request
from tests.proxy_contracts import test_native_coord_operator as coord_fixture
from tests.proxy_contracts.harness import request
from tests.proxy_contracts.scenarios import origin_server
from tests.proxy_contracts.test_http2_contract import origin_certificate
from tests.proxy_contracts.test_native_coord_operator import (
    ROOM,
    agent_send,
    history,
    stream_control,
)

native_coord_instance = coord_fixture.instance

BOT = "b" * 26
HUMAN = "o" * 26
CHANNEL = "c" * 26
TOKEN = "synthetic-native-mattermost-token-never-in-diagnostics"
SCHEMA = "safeyolo.coord.mattermost.operator/v1"


class Mattermost(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, certificate):
        self.posts = []
        self.creates = 0
        self.fail_create = None
        self.fail_backend = False
        self.fail_patch = False
        self.get_faults = {}
        self.page_faults = {}
        self.requests = []
        self.timeout_release = threading.Event()
        self.create_attempts = []
        self.fail_create_channels = {}
        self.clock = None
        self.channels = {CHANNEL, "d" * 26}
        self.operator_verification_started = threading.Event()
        self.operator_verification_release = threading.Event()
        self.operator_verification_release.set()
        self.human = {"id": HUMAN, "delete_at": 0}
        self.lock = threading.RLock()
        super().__init__(("127.0.0.1", 0), MattermostRequest)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate)
        self.socket = context.wrap_socket(self.socket, server_side=True)

    def add(self, *, user=HUMAN, channel=CHANNEL, root="", body="", **extra):
        with self.lock:
            created = self.clock if self.clock is not None else int(time.time() * 1000)
            post = {"id": f"{len(self.posts) + 1:026d}", "user_id": user, "channel_id": channel,
                    "root_id": root, "message": body, "props": {}, "create_at": created,
                    "update_at": created, "edit_at": 0, "delete_at": 0, **extra}
            self.posts.append(post)
            return copy.deepcopy(post)

    def projected(self):
        with self.lock:
            return copy.deepcopy([post for post in self.posts if post["user_id"] == BOT])


class MattermostRequest(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def respond(self, status, body, *, retry_after=None):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        if retry_after is not None:
            self.send_header("Retry-After", retry_after)
        self.end_headers()
        self.wfile.write(payload)

    def handle_api(self):
        assert self.headers.get("Authorization") == f"Bearer {TOKEN}"
        assert TOKEN not in self.path
        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length)) if length else None
        path = urlsplit(self.path)
        remote = self.server
        query = parse_qs(path.query)
        with remote.lock:
            remote.requests.append((self.command, path.path, query, time.monotonic()))
            fault = remote.get_faults.get(path.path) if self.command == "GET" else None
            if self.command == "GET" and path.path.endswith("/posts"):
                fault = remote.page_faults.get((path.path.split("/")[-2], int(query.get("page", [0])[0])), fault)
        if callable(fault):
            fault = fault()
        if fault == "disconnect":
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        if fault == "timeout":
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            remote.timeout_release.wait(timeout=20)
            self.close_connection = True
            return
        if fault is not None:
            self.respond(fault, {"error": f"remote canary {TOKEN}"},
                         retry_after="2" if fault == 429 else None)
            return
        if (self.command == "GET" and path.path == f"/api/v4/users/{HUMAN}"
                and not remote.operator_verification_release.is_set()):
            remote.operator_verification_started.set()
            if not remote.operator_verification_release.wait(timeout=10):
                self.close_connection = True
                return
            with remote.lock:
                human = remote.human.copy()
            try:
                self.respond(200, human)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
                # The callback cancels its verification at the request deadline.
                self.close_connection = True
            return
        with remote.lock:
            if remote.fail_backend:
                self.respond(500, {"error": f"remote canary {TOKEN}"})
            elif self.command == "GET" and path.path == "/api/v4/users/me":
                self.respond(200, {"id": BOT, "is_bot": True, "delete_at": 0})
            elif self.command == "GET" and path.path == f"/api/v4/users/{HUMAN}":
                self.respond(200, remote.human)
            elif self.command == "GET" and path.path.startswith("/api/v4/channels/"):
                channel = path.path.split("/")[4]
                if channel not in remote.channels:
                    self.respond(404, {"error": "channel unavailable"})
                    return
                if not path.path.endswith("/posts"):
                    self.respond(200, {"id": channel, "delete_at": 0})
                    return
                posts = sorted((post for post in remote.posts if post["channel_id"] == channel),
                               key=lambda post: (post["create_at"], post["id"]), reverse=True)
                if "since" in query:
                    assert not {"page", "per_page", "before", "after"}.intersection(query)
                    posts = [post for post in posts if post["update_at"] >= int(query["since"][0])]
                    posts = posts[:1000]
                else:
                    page = int(query.get("page", [0])[0])
                    size = int(query.get("per_page", [60])[0])
                    posts = posts[page * size:(page + 1) * size]
                self.respond(200, {"order": [post["id"] for post in posts],
                                   "posts": {post["id"]: post for post in posts}})
            elif self.command == "POST" and path.path == "/api/v4/posts":
                assert parse_qs(path.query) == {"silent": ["true"]}
                assert set(payload) == {"channel_id", "message", "props"}
                remote.creates += 1
                remote.create_attempts.append(payload["channel_id"])
                outcome = remote.fail_create_channels.get(payload["channel_id"], remote.fail_create)
                if outcome == "absent":
                    self.respond(500, {"error": f"not accepted {TOKEN}"})
                    return
                post = remote.add(user=BOT, channel=payload["channel_id"], body=payload["message"],
                                  props=payload["props"])
                if outcome == "duplicate":
                    remote.add(user=BOT, channel=payload["channel_id"], body=payload["message"],
                               props=payload["props"])
                if outcome in {"lost", "duplicate"}:
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                else:
                    self.respond(201, post)
            elif self.command == "PUT" and path.path.startswith("/api/v4/posts/"):
                if remote.fail_patch:
                    self.respond(500, {"error": f"patch canary {TOKEN}"})
                    return
                identifier = path.path.split("/")[-2]
                post = next(post for post in remote.posts if post["id"] == identifier)
                post.update(payload)
                self.respond(200, post)
            else:
                self.respond(404, {"error": "fixture has no such route"})

    do_GET = handle_api
    do_POST = handle_api
    do_PUT = handle_api


@pytest.fixture
def exchange(native_coord_instance, tmp_path):
    instance = native_coord_instance
    pem, public = origin_certificate(tmp_path)
    remote = Mattermost(pem)

    class MappedRequest(Request):
        def _peer(self, host, port, *, tls_origin):
            assert tls_origin and host == "localhost" and port == 443, (host, port)
            return socket.create_connection(remote.server_address, timeout=5), False

    parent = Parent(None, None, request_handler=MappedRequest)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (remote, parent)]
    for thread in threads:
        thread.start()
    remote.parent = parent
    remote.parent_threads = [threads[1]]
    remote.parent_address = parent.server_address
    remote.parent_handler = MappedRequest
    # Add the controlled peer to inherited CA trust. The fixture route is an
    # existing CONNECT parent and never grants direct external network access.
    trust = tmp_path / "trust.pem"
    inherited = os.environ.get("SSL_CERT_FILE")
    trust.write_bytes((Path(inherited).read_bytes() if inherited else b"") + public.read_bytes())
    instance.environment.update(HTTPS_PROXY=f"http://127.0.0.1:{parent.server_address[1]}",
                                SSL_CERT_FILE=str(trust))
    (instance.root / "mattermost-token").touch(mode=0o600)
    (instance.root / "mattermost-token").write_text(TOKEN)
    with socket.socket() as port:
        port.bind(("127.0.0.1", 0))
        callback_port = port.getsockname()[1]
    config = instance.root / "coord-mattermost.toml"
    config.touch(mode=0o600)
    config.write_text(f'''version=1
server_url="https://localhost"
bot_token_file="mattermost-token"
bot_user_id="{BOT}"
operator_user_id="{HUMAN}"
state_file="mattermost.sqlite3"
poll_interval_seconds=0.5
action_listener_port={callback_port}
public_callback_base_url="https://actions.example/safeyolo"
trusted_action_agent_ids=["ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
[[rooms]]
coord_room="{ROOM}"
channel_id="{CHANNEL}"
backfill=true
''')
    instance.callback_port = callback_port
    try:
        yield instance, remote
    finally:
        remote.timeout_release.set()
        for server in (remote.parent, remote):
            if server is None:
                continue
            server.shutdown()
            server.server_close()
        for thread in [threads[0], *remote.parent_threads]:
            thread.join(timeout=5)
            assert not thread.is_alive()


def once(instance, *, check=False):
    arguments = ["coord", "mattermost", "check" if check else "run"]
    if not check:
        arguments.append("--once")
    result = instance.cli(*arguments, timeout=20)
    assert TOKEN not in result.stdout + result.stderr
    return result


def until(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if value := predicate():
            return value
        time.sleep(0.025)
    raise AssertionError("controlled Mattermost observation timed out")


@contextmanager
def daemon(instance):
    process = subprocess.Popen(
        [str(instance.root / "bin/safeyolo"), "--root", str(instance.root), "coord", "mattermost", "run"],
        cwd=instance.root.parent, env=instance.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
        stdout, stderr = process.communicate(timeout=10)
        assert TOKEN.encode() not in stdout + stderr
        process.captured = stdout + stderr


def proxy_online(remote, online):
    if not online:
        remote.parent.shutdown()
        remote.parent.server_close()
        remote.parent_threads[-1].join(timeout=5)
        assert not remote.parent_threads[-1].is_alive()
        remote.parent = None
    else:
        remote.parent = Parent(None, None, host=remote.parent_address[0],
                               port=remote.parent_address[1], request_handler=remote.parent_handler)
        thread = threading.Thread(target=remote.parent.serve_forever, daemon=True)
        remote.parent_threads.append(thread)
        thread.start()


def callback(instance, payload=None, *, raw=None, path="/safeyolo/mattermost/actions"):
    if raw is not None:
        with socket.create_connection(("127.0.0.1", instance.callback_port), timeout=6) as stream:
            stream.sendall(raw)
            response = http.client.HTTPResponse(stream)
            response.begin()
            return response.status, json.loads(response.read())
    connection = http.client.HTTPConnection("127.0.0.1", instance.callback_port, timeout=6)
    try:
        connection.request("GET" if payload is None else "POST", path,
                           body=json.dumps(payload) if payload is not None else None,
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def healthy(instance):
    try:
        status, body = callback(instance, path="/safeyolo/mattermost/healthz")
        return status == 200 and body
    except (ConnectionError, OSError):
        return None


def operator_requests(instance):
    return [message for message in history(instance) if message["sender_kind"] == "operator"]


def semantic_body():
    return json.dumps({"schema": "safeyolo.coord.operator-request/v1", "kind": "decision",
                       "title": "Native review ready", "summary": "Approve this bounded fixture",
                       "reference": "PR #818", "details": ["Controlled protocol"],
                       "allowed_actions": ["approve", "reject", "revise"]})


def failed_sync(instance):
    health = healthy(instance)
    if health and any(status["status"] != "connected" and status["last_error_category"]
                      for status in [health["synchronization"]["identity"],
                                     *health["synchronization"]["rooms"].values()]):
        return health
    return None


def connected(instance):
    health = healthy(instance)
    return health and health["synchronization"]["status"] == "connected" and health


def ledger(instance, statement):
    with sqlite3.connect(instance.root / "mattermost.sqlite3") as db:
        return db.execute(statement).fetchone()[0]


@pytest.mark.parametrize("stage", ["startup", "poll"])
@pytest.mark.parametrize("fault", [502, 429, 408, "connect", "timeout", "disconnect"])
def test_native_foreground_recovers_verification_and_poll_failures(exchange, stage, fault):
    instance, remote = exchange
    agent_send(instance, "recover without restarting")
    endpoint = "/api/v4/users/me" if stage == "startup" else f"/api/v4/channels/{CHANNEL}/posts"

    def fail():
        started = time.monotonic()
        if fault == "connect":
            proxy_online(remote, False)
        else:
            with remote.lock:
                remote.get_faults[endpoint] = fault
        return started

    failure_started = fail() if stage == "startup" else None
    with daemon(instance) as process:
        if stage == "poll":
            before = until(lambda: connected(instance))
            root = remote.projected()[0]["id"]
            failure_started = fail()
            remote.add(root=root, body="reply held during outage")
        health = until(lambda: failed_sync(instance), timeout=22)
        assert process.poll() is None and health["listener"] == "healthy"
        assert health["adapter"] in {"degraded", "retrying"}
        statuses = [health["synchronization"]["identity"], *health["synchronization"]["rooms"].values()]
        failed = next(status for status in statuses if status["status"] == "retrying" and status["last_error_category"])
        assert failed["retry_in_ms"] > 0 and failed["retry_at"] > int(time.time() * 1000) - 100
        assert failed["backlog_age_seconds"] >= 0
        assert operator_requests(instance) == []
        if stage == "poll":
            assert health["synchronization"]["last_success_at"] >= before["synchronization"]["last_success_at"]
            assert healthy(instance)["synchronization"]["last_success_at"] == health["synchronization"]["last_success_at"]
        if fault == 429:
            assert failed["retry_in_ms"] > 1500
            # Keep the refusal in place through a second request to exercise
            # Retry-After at the actual HTTP boundary, rather than just health.
            attempts = until(lambda: (values if len(values := [r[3] for r in remote.requests
                                                              if r[1] == endpoint and r[3] >= failure_started]) >= 2 else None), timeout=4)
            assert attempts[1] - attempts[0] >= 1.9
        if fault == "connect":
            proxy_online(remote, True)
        else:
            with remote.lock:
                remote.get_faults.clear()
            remote.timeout_release.set()
        recovered = until(lambda: connected(instance), timeout=10)
        assert recovered["synchronization"]["last_success_at"] is not None
        assert len(remote.projected()) == remote.creates == 1
        if stage == "poll":
            messages = until(lambda: operator_requests(instance))
            assert len(messages) == 1 and json.loads(messages[0]["body"])["text"] == "reply held during outage"
        assert process.poll() is None
    assert process.returncode == 0
    assert process.captured.count(b"Mattermost sync scope=") <= 10
    assert once(instance).returncode == 0 and remote.creates == 1


def test_native_outage_diagnostics_are_strict_and_stale_authority_cannot_accept(exchange):
    instance, remote = exchange
    agent_send(instance, semantic_body(), declared_content_type="text/plain")
    remote.fail_backend = True
    for check in (True, False):
        failed = once(instance, check=check)
        assert failed.returncode != 0 and "http_5xx" in failed.stderr
    remote.fail_backend = False
    with daemon(instance):
        until(lambda: connected(instance))
        post = remote.projected()[0]
        payload = {"user_id": HUMAN, "channel_id": CHANNEL, "post_id": post["id"],
                   "context": post["props"]["attachments"][0]["actions"][0]["integration"]["context"]}
        remote.fail_backend = True
        until(lambda: failed_sync(instance))
        remote.add(root=post["id"], body="authorized only after recovery")
        assert callback(instance, payload)[0] == 503
        assert operator_requests(instance) == []
        assert ledger(instance, "SELECT COUNT(*) FROM action_capability WHERE status='issued'") == 1
        remote.fail_backend = False
        until(lambda: connected(instance))
        until(lambda: len(operator_requests(instance)) == 1)
        assert callback(instance, payload)[0] == 200
        assert callback(instance, payload)[0] == 409
        assert len(operator_requests(instance)) == 2


@pytest.mark.parametrize("shutdown_signal", [signal.SIGINT, signal.SIGTERM])
def test_native_signal_interrupts_backoff_and_releases_listener_and_lease(exchange, shutdown_signal):
    instance, remote = exchange
    remote.get_faults["/api/v4/users/me"] = 429
    with daemon(instance) as process:
        until(lambda: failed_sync(instance))
        # A concurrent diagnostic cannot acquire the live adapter's state lease.
        assert "lease" in once(instance, check=True).stderr
        started = time.monotonic()
        process.send_signal(shutdown_signal)
        process.wait(timeout=2)
        assert time.monotonic() - started < 2 and process.returncode == 0
    with socket.socket() as released:
        # TIME_WAIT from a health connection does not imply a live listener.
        released.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        released.bind(("127.0.0.1", instance.callback_port))
    remote.get_faults.clear()
    assert once(instance, check=True).returncode == 0
    with daemon(instance):
        until(lambda: connected(instance))


@pytest.mark.parametrize("identity", ["deactivated", "different", "bot", "bot_identity", "ca"])
def test_native_invalid_identity_or_transport_configuration_is_terminal(exchange, identity):
    instance, remote = exchange
    if identity == "deactivated":
        remote.human["delete_at"] = 1
    elif identity == "different":
        remote.human["id"] = "x" * 26
    elif identity == "bot":
        remote.human["is_bot"] = True
    elif identity == "bot_identity":
        config = instance.root / "coord-mattermost.toml"
        config.write_text(config.read_text().replace(f'bot_user_id="{BOT}"', f'bot_user_id="{"q" * 26}"'))
    else:
        instance.environment["SSL_CERT_FILE"] = str(instance.root / "missing-ca.pem")
    with daemon(instance) as process:
        until(lambda: process.poll() is not None)
        assert process.returncode != 0 and operator_requests(instance) == []
    expected = b"configuration" if identity == "ca" else b"active bot" if identity == "bot_identity" else b"active human"
    assert expected in process.captured


def test_native_authorization_outage_between_backlog_appends_retains_unsent_replies(exchange):
    instance, remote = exchange
    agent_send(instance, "batch authorization question")
    assert once(instance).returncode == 0
    root = remote.projected()[0]["id"]
    for index in range(5):
        remote.add(root=root, body=f"authorized reply {index}")

    def unavailable_after_first_append():
        return 502 if ledger(instance, "SELECT COUNT(*) FROM inbound_post WHERE status='sent'") >= 1 else None

    remote.get_faults[f"/api/v4/users/{HUMAN}"] = unavailable_after_first_append
    with daemon(instance) as process:
        until(lambda: failed_sync(instance))
        assert ledger(instance, "SELECT COUNT(*) FROM inbound_post WHERE status='sent'") == 1
        assert ledger(instance, "SELECT COUNT(*) FROM inbound_post WHERE status='pending'") == 0
        assert len(operator_requests(instance)) == 1 and process.poll() is None
        remote.get_faults.clear()
        until(lambda: connected(instance))
        assert [json.loads(message["body"])["text"] for message in operator_requests(instance)] == [
            f"authorized reply {index}" for index in range(5)]


def second_mapping(instance):
    for arguments in (("room", "create", "safe-room"), ("grant", "safe-room", "alice")):
        result = instance.cli("coord", *arguments)
        assert result.returncode == 0, result.stderr
    with (instance.root / "coord-mattermost.toml").open("a") as config:
        config.write(f'\n[[rooms]]\ncoord_room="safe-room"\nchannel_id="{"d" * 26}"\nbackfill=true\n')


@pytest.mark.parametrize("failure", [502, 403, "lost", "absent", "duplicate"])
def test_native_mapping_failure_or_reconciliation_keeps_safe_mapping_and_callback(exchange, failure):
    instance, remote = exchange
    second_mapping(instance)
    agent_send(instance, "first mapping")
    agent_send(instance, semantic_body(), room="safe-room", declared_content_type="text/plain")
    if isinstance(failure, int):
        remote.get_faults[f"/api/v4/channels/{CHANNEL}"] = failure
    else:
        remote.fail_create_channels[CHANNEL] = failure
    with daemon(instance) as process:
        until(lambda: len([p for p in remote.projected() if p["channel_id"] == "d" * 26]) == 1)
        safe = next(post for post in remote.projected() if post["channel_id"] == "d" * 26)
        payload = {"user_id": HUMAN, "channel_id": "d" * 26, "post_id": safe["id"],
                   "context": safe["props"]["attachments"][0]["actions"][0]["integration"]["context"]}
        if failure == "lost":
            until(lambda: connected(instance))
        else:
            health = until(lambda: failed_sync(instance))
            assert health["adapter"] == "degraded" and health["listener"] == "healthy"
            if not isinstance(failure, int):
                assert health["pending_projection_reconciliation"] == 1
        assert callback(instance, payload)[0] == 200
        remote.add(channel="d" * 26, root=safe["id"], body="independent safe reply")
        until(lambda: len(history(instance, "safe-room")) == 3)
        assert operator_requests(instance) == [] and process.poll() is None
        if isinstance(failure, int):
            attempts = len([r for r in remote.requests if r[1] == f"/api/v4/channels/{CHANNEL}"])
            if failure == 403:
                assert healthy(instance)["synchronization"]["rooms"][ROOM]["status"] == "blocked"
                # Permanent permission failures do not loop as temporary outages.
                agent_send(instance, "more safe traffic", room="safe-room")
                until(lambda: len([p for p in remote.projected() if p["channel_id"] == "d" * 26]) == 2)
                assert len([r for r in remote.requests if r[1] == f"/api/v4/channels/{CHANNEL}"]) == attempts
        else:
            assert remote.create_attempts.count(CHANNEL) == 1
    with daemon(instance) as process:
        until(lambda: healthy(instance))
        assert callback(instance, payload)[0] == 409 and process.poll() is None
        assert remote.create_attempts.count(CHANNEL) <= 1


def test_native_long_outage_pages_equal_timestamps_partial_failure_and_restart(exchange):
    instance, remote = exchange
    remote.clock = int(time.time() * 1000) - 3600000
    agent_send(instance, "long outage question")
    assert once(instance).returncode == 0
    assert once(instance).returncode == 0
    root = remote.projected()[0]["id"]
    baseline = ledger(instance, "SELECT inbound_since FROM room_state")
    endpoint = f"/api/v4/channels/{CHANNEL}/posts"
    remote.get_faults[endpoint] = 502
    with daemon(instance):
        until(lambda: failed_sync(instance))
        for index in range(1205):
            remote.clock = baseline + 1000 * (1 + index // 450)
            remote.add(root=root, body=f"backlog {index}")
        remote.page_faults[CHANNEL, 1] = 502
        remote.get_faults.clear()
        until(lambda: any(r[1] == endpoint and r[2].get("page") == ["1"] for r in remote.requests))
        assert ledger(instance, "SELECT inbound_since FROM room_state") == baseline
        assert operator_requests(instance) == []
    # The interrupted interval is retried from its durable boundary on restart.
    with daemon(instance):
        until(lambda: failed_sync(instance))
        assert ledger(instance, "SELECT inbound_since FROM room_state") == baseline
        remote.page_faults.clear()
        until(lambda: ledger(instance, "SELECT COUNT(*) FROM inbound_post WHERE status='sent'") == 1205, timeout=120)
        until(lambda: connected(instance))
        remote.add(root=root, body="same timestamp after cursor commit")
        until(lambda: ledger(instance, "SELECT COUNT(*) FROM inbound_post WHERE status='sent'") == 1206)
    messages = operator_requests(instance)
    assert [json.loads(message["body"])["text"] for message in messages] == [
        *(f"backlog {index}" for index in range(1205)), "same timestamp after cursor commit"]
    assert once(instance).returncode == 0
    assert operator_requests(instance) == messages and remote.creates == 1
    assert any(r[2].get("page") == ["6"] for r in remote.requests if r[1] == endpoint)
    assert all("since" not in r[2] for r in remote.requests if r[1] == endpoint)


def test_native_exchange_authority_restart_and_backend_isolation(exchange):
    instance, remote = exchange
    # A second granted room remains canonical and is never selected by this
    # adapter's one-room mapping.
    for arguments in (("room", "create", "unselected"), ("grant", "unselected", "alice")):
        result = instance.cli("coord", *arguments)
        assert result.returncode == 0, result.stderr
    agent_send(instance, "not projected", room="unselected")
    assert once(instance, check=True).returncode == 0
    original = agent_send(instance, "# Native message\n@all ~channel ![image](https://example.com/pixel)\n"
                                     "Canonical **provenance** · forged", declared_content_type="text/plain")
    result = once(instance)
    assert result.returncode == 0, result.stderr
    projected = remote.projected()
    assert len(projected) == remote.creates == 1
    post = projected[0]
    assert post["props"]["attachments"] == []
    assert post["props"]["safeyolo_coord"]["coord_msg_id"] == original["envelope"]["msg_id"]
    html = MarkdownIt("commonmark").render(post["message"])
    assert html.count("Canonical provenance") == 1 and "<img" not in html
    assert "＠all" in html and "～channel" in html
    good = remote.add(root=post["id"], body="exact café\nreply")
    remote.add(root=post["id"], user="u" * 26, body="wrong sender")
    remote.add(root=post["id"], channel="d" * 26, body="wrong channel")
    remote.add(root=post["id"], edit_at=1, body="edited")
    remote.add(root="x" * 26, body="unknown thread")
    result = once(instance)
    assert result.returncode == 0, result.stderr
    messages = operator_requests(instance)
    assert len(messages) == 1 and messages[0]["sender_agent_id"] is None
    body = json.loads(messages[0]["body"])
    assert body["schema"] == SCHEMA and body["kind"] == "reply" and body["text"] == good["message"]
    assert body["correlation"]["coord_msg_id"] == original["envelope"]["msg_id"]
    assert body["correlation"]["mattermost_post_id"] == good["id"]
    assert once(instance).returncode == 0
    assert operator_requests(instance) == messages and remote.creates == 1
    with remote.lock:
        remote.fail_backend = True
    failed = once(instance)
    assert failed.returncode != 0 and "Mattermost" in failed.stderr
    assert operator_requests(instance) == messages
    with origin_server() as origin:
        status, _, payload = request(instance.paths["alice"], f"http://127.0.0.1:{origin.server_address[1]}/unrelated")
        assert status == 200 and payload == b"hello"
    # The failed projection cannot give a guest operator attribution.
    forged = agent_send(instance, "still guest", sender_kind="operator", sender_agent_id="operator")
    assert forged["envelope"]["sender_kind"] == "agent"


def test_native_listener_bind_failure_keeps_projection_and_replies_available(exchange):
    instance, remote = exchange
    agent_send(instance, semantic_body(), declared_content_type="text/plain")
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", instance.callback_port))
        occupied.listen()
        assert once(instance, check=True).returncode != 0
        with daemon(instance) as process:
            post = until(lambda: remote.projected())[0]
            assert post["props"]["attachments"][0]["actions"] == []
            remote.add(root=post["id"], body="reply without callback listener")
            messages = until(lambda: operator_requests(instance))
            assert json.loads(messages[0]["body"])["text"] == "reply without callback listener"
            assert messages[0]["sender_kind"] == "operator" and process.poll() is None


def test_native_uncertain_callback_stays_pending_while_routine_exchange_continues(exchange):
    instance, remote = exchange
    agent_send(instance, semantic_body(), declared_content_type="text/plain")
    with daemon(instance) as process:
        until(lambda: healthy(instance))
        post = until(lambda: remote.projected())[0]
        payload = {"user_id": HUMAN, "channel_id": CHANNEL, "post_id": post["id"],
                   "context": post["props"]["attachments"][0]["actions"][0]["integration"]["context"]}
        before = asyncio.run(stream_control(instance, no_ack=True))
        try:
            status, body = callback(instance, payload)
            assert status == 503, body
            assert asyncio.run(stream_control(instance)) == before + 1
            with sqlite3.connect(instance.root / "mattermost.sqlite3") as db:
                assert db.execute("SELECT status,selected_action,coord_action_msg_id FROM action_capability").fetchone() == ("pending", "approve", None)
        finally:
            asyncio.run(stream_control(instance, no_ack=False))
        assert callback(instance, payload)[0] == 503
        assert healthy(instance)["pending_action_reconciliation"] == 1
        agent_send(instance, "next routine message")
        until(lambda: len(remote.projected()) == 2)
        remote.add(root=post["id"], body="later independent reply")
        messages = until(lambda: len(operator_requests(instance)) == 2 and operator_requests(instance))
        assert [json.loads(message["body"])["kind"] for message in messages] == ["action", "reply"]
        assert process.poll() is None
    with daemon(instance) as process:
        until(lambda: healthy(instance))
        assert callback(instance, payload)[0] == 503
        assert healthy(instance)["pending_action_reconciliation"] == 1
        assert operator_requests(instance) == messages and remote.creates == 2
        assert process.poll() is None


def test_native_callback_operator_verification_timeout_does_not_publish(exchange):
    instance, remote = exchange
    agent_send(instance, semantic_body(), declared_content_type="text/plain")
    with daemon(instance) as process:
        until(lambda: healthy(instance))
        post = until(lambda: remote.projected())[0]
        payload = {"user_id": HUMAN, "channel_id": CHANNEL, "post_id": post["id"],
                   "context": post["props"]["attachments"][0]["actions"][0]["integration"]["context"]}
        remote.operator_verification_release.clear()
        try:
            status, body = callback(instance, payload)
            assert status == 503, body
            assert body == {"error": "request timed out; inspect pending actions before retrying"}
            assert remote.operator_verification_started.is_set()
            assert operator_requests(instance) == []
            with sqlite3.connect(instance.root / "mattermost.sqlite3") as db:
                assert db.execute("SELECT status,selected_action,coord_action_msg_id FROM action_capability").fetchone() == ("issued", None, None)
        finally:
            remote.operator_verification_release.set()
        assert callback(instance, payload)[0] == 200
        assert callback(instance, payload)[0] == 409
        assert len(operator_requests(instance)) == 1
        assert healthy(instance)["pending_action_reconciliation"] == 0
        assert process.poll() is None


def test_native_semantic_callback_authority_replay_and_restart(exchange):
    instance, remote = exchange
    agent_send(instance, semantic_body(), declared_content_type="text/plain")
    with daemon(instance) as process:
        until(lambda: healthy(instance))
        post = until(lambda: remote.projected())[0]
        button = post["props"]["attachments"][0]["actions"][0]
        assert button["integration"]["url"] == "https://actions.example/safeyolo/mattermost/actions"
        payload = {"user_id": HUMAN, "channel_id": CHANNEL, "post_id": post["id"],
                   "context": button["integration"]["context"]}
        for bad in ({}, {**payload, "user_id": 1}, {**payload, "context": []},
                    {**payload, "context": {**payload["context"], "action": []}}):
            assert callback(instance, bad)[0] == 400
        for field, value in (("user_id", "u" * 26), ("channel_id", "d" * 26),
                             ("post_id", "p" * 26), ("root_id", "p" * 26)):
            bad = copy.deepcopy(payload)
            bad[field] = value
            assert callback(instance, bad)[0] == 403
        for field, value in (("adapter_id", "bad"), ("projection_key", "0" * 64),
                             ("capability", "z" * 43), ("action", "publish")):
            bad = copy.deepcopy(payload)
            bad["context"][field] = value
            assert callback(instance, bad)[0] == 403
        assert operator_requests(instance) == []
        with remote.lock:
            remote.human["delete_at"] = 1
        assert callback(instance, payload)[0] == 503
        with remote.lock:
            remote.human["delete_at"] = 0
        with sqlite3.connect(instance.root / "mattermost.sqlite3") as db:
            db.execute("UPDATE action_capability SET expires_at=?", (int(time.time() * 1000) - 1,))
        assert callback(instance, payload)[0] == 410
        with sqlite3.connect(instance.root / "mattermost.sqlite3") as db:
            db.execute("UPDATE action_capability SET expires_at=?", (int(time.time() * 1000) + 60000,))
        # Cosmetic patch failure cannot undo an accepted canonical action.
        with remote.lock:
            remote.fail_patch = True
        assert callback(instance, payload)[0] == 200
        assert callback(instance, payload)[0] == 409
        messages = operator_requests(instance)
        assert len(messages) == 1 and messages[0]["sender_agent_id"] is None
        body = json.loads(messages[0]["body"])
        assert body["schema"] == SCHEMA and body["kind"] == "action" and body["action"] == "approve"
        assert body["correlation"]["mattermost_post_id"] == post["id"]
        health = healthy(instance)
        assert health["pending_action_reconciliation"] == 0
        assert payload["context"]["capability"] not in json.dumps(health)
        assert process.poll() is None
    with daemon(instance) as process:
        until(lambda: healthy(instance))
        assert callback(instance, payload)[0] == 409
        assert operator_requests(instance) == messages and remote.creates == 1
        assert process.poll() is None
    with sqlite3.connect(instance.root / "mattermost.sqlite3") as db:
        assert db.execute("SELECT status FROM action_capability").fetchone() == ("used",)
    assert payload["context"]["capability"].encode() not in (instance.root / "mattermost.sqlite3").read_bytes()


@pytest.mark.parametrize("outcome", ["lost", "absent", "duplicate"])
def test_native_uncertain_projection_reconciles_or_refuses_retry(exchange, outcome):
    instance, remote = exchange
    agent_send(instance, "projection receipt withheld")
    remote.fail_create = outcome
    assert once(instance).returncode != 0
    assert remote.creates == 1
    remote.fail_create = None
    result = once(instance)
    assert (result.returncode == 0) == (outcome == "lost"), result.stderr
    assert remote.creates == 1 and operator_requests(instance) == []
    if outcome != "lost":
        assert "reconciliation" in result.stderr and once(instance).returncode != 0
        assert remote.creates == 1


def test_native_uncertain_coord_reply_never_replays_after_restart(exchange):
    instance, remote = exchange
    agent_send(instance, "question")
    assert once(instance).returncode == 0
    remote.add(root=remote.projected()[0]["id"], body="unknown acceptance")
    before = asyncio.run(stream_control(instance, no_ack=True))
    try:
        failed = once(instance)
        assert failed.returncode != 0 and "UNKNOWN" in failed.stderr
        assert asyncio.run(stream_control(instance)) == before + 1
    finally:
        asyncio.run(stream_control(instance, no_ack=False))
    refused = once(instance)
    assert refused.returncode != 0 and "no automatic replay" in refused.stderr
    assert asyncio.run(stream_control(instance)) == before + 1
    assert len(operator_requests(instance)) == 1
    with daemon(instance) as process:
        health = until(lambda: failed_sync(instance))
        assert health["pending_inbound_reconciliation"] == 1
        assert health["synchronization"]["rooms"][ROOM]["status"] == "blocked"
        agent_send(instance, "independent outward projection")
        until(lambda: len(remote.projected()) == 2)
        remote.add(root=remote.projected()[0]["id"], body="independent later reply")
        until(lambda: len(operator_requests(instance)) == 2)
        assert process.poll() is None
    with daemon(instance):
        health = until(lambda: failed_sync(instance))
        assert health["pending_inbound_reconciliation"] == 1
        messages = operator_requests(instance)
        assert [json.loads(message["body"])["text"] for message in messages] == [
            "unknown acceptance", "independent later reply"]


def test_native_callback_wire_limits_and_untrusted_schema(exchange):
    instance, remote = exchange
    for body in ("arbitrary [approve](mmaction://approve)",
                 semantic_body().replace('"kind": "decision"', '"kind": "decision", "kind": "decision"')):
        agent_send(instance, body, declared_content_type="text/plain")
    untrusted = instance.agent_api("bob", f"/api/coord/rooms/{ROOM}/send", method="POST",
                                  body={"body": semantic_body(), "declared_content_type": "text/plain", "notify": "none"})
    assert untrusted["envelope"]["sender_agent_name"] == "bob"
    with daemon(instance):
        until(lambda: healthy(instance))
        until(lambda: len(remote.projected()) == 3)
        assert all(post["props"]["attachments"] == [] for post in remote.projected())
        for wire in (b"POST /safeyolo/mattermost/actions HTTP/1.1\r\nContent-Type: application/json\r\n\r\n",
                     b"POST /safeyolo/mattermost/actions HTTP/1.1\r\nHost: a\r\nHost: b\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
                     b"POST /safeyolo/mattermost/actions HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
                     b"POST /safeyolo/mattermost/actions HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{}",
                     b"POST /safeyolo/mattermost/actions HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 65537\r\n\r\n",
                     b"POST /safeyolo/mattermost/actions HTTP/1.1\r\nX-Padding: " + b"x" * 16384 + b"\r\n\r\n",
                     b"POST /safeyolo/mattermost/actions HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n!!",
                     b"POST /safeyolo/mattermost/actions HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 4\r\n\r\nnull",
                     b"POST /safeyolo/mattermost/actions HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\n[1,2]",
                     b"POST /safeyolo/mattermost/actions HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"x\":1,\"x\":2}"):
            assert callback(instance, raw=wire)[0] == 400
        assert callback(instance, {}, path="/other")[0] == 404
        assert operator_requests(instance) == []
        # Incomplete headers and bodies retain the existing five-second budget.
        for wire in (b"POST /safeyolo/mattermost/actions HTTP/1.1\r\n",
                     b"POST /safeyolo/mattermost/actions HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{"):
            assert callback(instance, raw=wire)[0] == 400
