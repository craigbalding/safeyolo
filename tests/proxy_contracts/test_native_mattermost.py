"""Native #818 G6 exchange/actions through installed CLI, HTTPS and real NATS.

Reuse the owned native instance, pinned NATS and CONNECT parent. The controlled
Mattermost REST server supplies protocol shapes and uncertain outcomes. Python
is only the driver; the installed PATH contains native binaries and no Python.
No live account, public tunnel, model or guest matrix is used. HTTP/CLI and
readiness deadlines use the existing 5/15/10-second focused fixture bounds.
"""
from __future__ import annotations

import asyncio
import copy
import http.client
import json
import os
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
        self.human = {"id": HUMAN, "delete_at": 0}
        self.lock = threading.RLock()
        super().__init__(("127.0.0.1", 0), MattermostRequest)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate)
        self.socket = context.wrap_socket(self.socket, server_side=True)

    def add(self, *, user=HUMAN, channel=CHANNEL, root="", body="", **extra):
        with self.lock:
            created = int(time.time() * 1000)
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

    def respond(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def handle_api(self):
        assert self.headers.get("Authorization") == f"Bearer {TOKEN}"
        assert TOKEN not in self.path
        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length)) if length else None
        path = urlsplit(self.path)
        remote = self.server
        with remote.lock:
            if remote.fail_backend:
                self.respond(500, {"error": f"remote canary {TOKEN}"})
            elif self.command == "GET" and path.path == "/api/v4/users/me":
                self.respond(200, {"id": BOT, "is_bot": True, "delete_at": 0})
            elif self.command == "GET" and path.path == f"/api/v4/users/{HUMAN}":
                self.respond(200, remote.human)
            elif self.command == "GET" and path.path == f"/api/v4/channels/{CHANNEL}":
                self.respond(200, {"id": CHANNEL, "delete_at": 0})
            elif self.command == "GET" and path.path == f"/api/v4/channels/{CHANNEL}/posts":
                query = parse_qs(path.query)
                posts = remote.posts
                if "since" in query:
                    posts = [post for post in posts if post["update_at"] >= int(query["since"][0])]
                else:
                    posts = posts[-int(query.get("per_page", [200])[0]):]
                self.respond(200, {"order": [post["id"] for post in posts],
                                   "posts": {post["id"]: post for post in posts}})
            elif self.command == "POST" and path.path == "/api/v4/posts":
                assert parse_qs(path.query) == {"silent": ["true"]}
                assert set(payload) == {"channel_id", "message", "props"}
                remote.creates += 1
                if remote.fail_create == "absent":
                    self.respond(500, {"error": f"not accepted {TOKEN}"})
                    return
                post = remote.add(user=BOT, channel=payload["channel_id"], body=payload["message"],
                                  props=payload["props"])
                if remote.fail_create == "duplicate":
                    remote.add(user=BOT, channel=payload["channel_id"], body=payload["message"],
                               props=payload["props"])
                if remote.fail_create in {"lost", "duplicate"}:
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
        for server in (parent, remote):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)
            assert not thread.is_alive()


def once(instance, *, check=False):
    arguments = ["coord", "mattermost", "check" if check else "run"]
    if not check:
        arguments.append("--once")
    result = instance.cli(*arguments)
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
            assert callback(instance, payload)[0] == 503
            assert asyncio.run(stream_control(instance)) == before + 1
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
                     b"POST /safeyolo/mattermost/actions HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 65537\r\n\r\n",
                     b"POST /safeyolo/mattermost/actions HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\n[1,2]",
                     b"POST /safeyolo/mattermost/actions HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"x\":1,\"x\":2}"):
            assert callback(instance, raw=wire)[0] == 400
        assert callback(instance, {}, path="/other")[0] == 404
        assert operator_requests(instance) == []
        # An incomplete whole request reaches the existing five-second budget.
        assert callback(instance, raw=b"POST /safeyolo/mattermost/actions HTTP/1.1\r\n")[0] == 400
