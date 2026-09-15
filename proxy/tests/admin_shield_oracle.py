"""Pinned source shield hooks and an owned local transport-hole witness."""

# ruff: noqa: E402 -- Isolated source import root is established before imports.

import asyncio
import hashlib
import importlib.metadata
import json
import logging
import platform
import socket
import sys
import unicodedata
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO), str(REPO / "cli/src")]

from mitmproxy import connection, http
from mitmproxy.proxy import commands, server_hooks
from mitmproxy.proxy.layers.http import _hooks
from mitmproxy.proxy.server import ConnectionHandler
from mitmproxy.test import taddons, tflow

from safeyolo.mitm_addons import admin_shield

HOSTS = [
    "localhost",
    "LOCALHOST",
    "a.localhost",
    ".localhost",
    "localhost.",
    "a.localhost.",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "0:0:0:0:0:0:0:1",
    "::ffff:127.0.0.1",
    "127.1",
    "127.0.0.2",
    "2130706433",
    "0x7f000001",
    "0177.0.0.1",
    "host.docker.internal",
    "safeyolo",
    "remote.invalid",
    "203.0.113.8",
    "аpi.localhost",
]
EXTRAS = [
    "",
    "9091,9092",
    " 9091 ,9091, ",
    "-1,+9091,909_1",
    "junk,,9091,",
    "\x1c9091\x1f",
    "٩٠٩١",
    "９０９１",
    "²",
    "٩²",
    "²x",
    "½",
    "Ⅻ",
    "65536,0,0009091",
    "0" * 4300,
    "0" * 4301,
    "1" * 4301,
]


def context(port=9090, extras=""):
    return SimpleNamespace(options=SimpleNamespace(admin_port=port, shield_extra_ports=extras))


def observe(shield, host, port, hook="request", extras="", admin_port=9090, prior=False):
    flow = tflow.tflow()
    flow.request.host, flow.request.port = host, port
    flow.response = http.Response.make(418, b"earlier") if prior else None
    flow.metadata.clear()
    with patch.object(admin_shield, "ctx", context(admin_port, extras)):
        try:
            getattr(shield, hook)(flow)
            result = {
                "blocked": flow.metadata.get("blocked_by") == "admin-shield",
                "metadata": flow.metadata,
                "response": None
                if flow.response is None
                else {
                    "status": flow.response.status_code,
                    "headers": [[k.decode("ascii"), v.decode("ascii")] for k, v in flow.response.headers.fields],
                    "body_hex": flow.response.content.hex(),
                },
            }
        except Exception as error:
            result = {"error": type(error).__name__}
    return {
        "host": host,
        "port": port,
        "hook": hook,
        "extras": extras,
        "admin_port": admin_port,
        "prior": prior,
        **result,
    }


def source_rows():
    shield = admin_shield.AdminShield()
    rows = [observe(shield, host, port) for host in HOSTS for port in [80, 9090, 9091]]
    rows += [observe(shield, "localhost", port, extras=extras) for extras in EXTRAS for port in [9090, 9091]]
    rows += [observe(shield, host, 9090, hook="http_connect") for host in HOSTS]
    rows += [observe(shield, "localhost", 9090, prior=True), observe(shield, "remote.invalid", 9090, prior=True)]
    forms = []
    for url in [
        "http://localhost:9090/x",
        "https://localhost:9090/x",
        "http://LOCALHOST:9090/x",
        "http://localhost.:9090/x",
        "http://[::1]:9090/x",
        "http://[0:0:0:0:0:0:0:1]:9090/x",
        "http://127.1:9090/x",
        "http://remote.invalid:9090/x",
        "http://localhost/x",
        "https://localhost/x",
    ]:
        request = http.Request.make("GET", url)
        forms.append(
            {
                "url": url,
                "extracted_host": request.host,
                "extracted_port": request.port,
                "observation": observe(shield, request.host, request.port),
            }
        )
    backstop = []
    for address in [None, ("localhost", 9090), ("remote.invalid", 9090), ("localhost.", 9090), ("localhost", 80)]:
        server = connection.Server(address=address)
        data = server_hooks.ServerConnectionHookData(server, tflow.tflow().client_conn)
        with patch.object(admin_shield, "ctx", context()):
            shield.server_connect(data)
        backstop.append({"address": address, "error": server.error})
    scalar = hashlib.sha256()
    ranges = []
    for codepoint in range(0x110000):
        value = chr(codepoint).isdigit() and not chr(codepoint).isdecimal()
        scalar.update(bytes([value]))
        if value:
            if ranges and ranges[-1][1] == codepoint - 1:
                ranges[-1][1] = codepoint
            else:
                ranges.append([codepoint, codepoint])
    return {
        "hooks": rows,
        "forms": forms,
        "server_hooks": backstop,
        "nondecimal_digit_ranges": ranges,
        "nondecimal_digit_all_scalars_sha256": scalar.hexdigest(),
    }


async def transport_witness(numeric_errors=False, extra_port=False):
    accepted = []
    handlers = []

    async def owned(reader, writer):
        accepted.append(True)
        try:
            await reader.read(128)
        finally:
            writer.close()
            await writer.wait_closed()

    def accept(reader, writer):
        task = asyncio.create_task(owned(reader, writer))
        handlers.append(task)

    peer = await asyncio.start_server(accept, "127.0.0.1", 0)
    port = peer.sockets[0].getsockname()[1]
    shield = admin_shield.AdminShield()
    configured_port = (port + 1 if port < 65535 else port - 1) if extra_port else port
    witnesses = []
    try:
        cases = [
            (host, "")
            for host in [
                "localhost",
                "127.0.0.1",
                "localhost.",
                "127.1",
                "2130706433",
                "0x7f000001",
                "0177.0.0.1",
                "::ffff:127.0.0.1",
                "owned-alias.invalid",
                "alias-unspecified.invalid",
                "other-local.invalid",
            ]
        ]
        if numeric_errors:
            cases = [("127.0.0.1", "²"), ("127.0.0.1", "1" * 4301)]
        elif extra_port:
            cases = [("owned-alias.invalid", str(port))]
        for host, extras in cases:
            events = []
            before = len(accepted)
            target = connection.Server(address=(host, port))
            receiver = SimpleNamespace(
                client=tflow.tflow().client_conn,
                transports={},
                max_conns=defaultdict(lambda: asyncio.Semaphore(1)),
                log=lambda *_a, **_k: None,
            )

            async def hook(value, events=events, receiver=receiver):
                events.append(type(value).__name__)
                if numeric_errors:
                    await receiver.addon_manager.handle_lifecycle(value)
                elif isinstance(value, server_hooks.ServerConnectHook):
                    shield.server_connect(value.data)

            async def server_event(value, events=events):
                events.append(type(value).__name__)

            async def handle_connection(conn, receiver=receiver):
                writer = receiver.transports[conn].writer
                writer.write(b"synthetic-shield-probe")
                await writer.drain()
                writer.close()
                await writer.wait_closed()

            def resolve(name, service, *_args, host=host, events=events, **_kwargs):
                assert name == host and service == port, "unexpected resolver target"
                events.append("resolve")
                address = (
                    "0.0.0.0"
                    if host == "alias-unspecified.invalid"
                    else "127.0.0.2"
                    if host == "other-local.invalid"
                    else "127.0.0.1"
                )
                return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port))]

            receiver.handle_hook, receiver.server_event, receiver.handle_connection = (
                hook,
                server_event,
                handle_connection,
            )
            with taddons.context(shield, loadcore=False) as addon_context:
                manager = addon_context.master.addons
                receiver.addon_manager = manager
                with (
                    patch.object(admin_shield, "ctx", context(configured_port, extras)),
                    patch("socket.getaddrinfo", side_effect=resolve),
                ):
                    if numeric_errors:
                        ingress_flow = tflow.tflow()
                        ingress_flow.request.host, ingress_flow.request.port = host, port
                        ingress_flow.response = None
                        await manager.handle_lifecycle(_hooks.HttpRequestHook(ingress_flow))
                        ingress = {"blocked": ingress_flow.metadata.get("blocked_by") == "admin-shield"}
                    else:
                        ingress = observe(shield, host, port, admin_port=configured_port, extras=extras)
                    await ConnectionHandler.open_connection(receiver, commands.OpenConnection(target))
                    await asyncio.sleep(0)
            witnesses.append(
                {
                    "host": host,
                    "port": port,
                    "extras": extras,
                    "ingress_blocked": ingress["blocked"],
                    "events": events,
                    "server_error": target.error,
                    "peer": target.peername,
                    "owned_accepts": len(accepted) - before,
                }
            )
        with patch.object(admin_shield, "ctx", context(port + 1 if port < 65535 else port - 1)):
            changed = observe(shield, "127.0.0.1", port, admin_port=port + 1 if port < 65535 else port - 1)
        ephemeral = observe(shield, "127.0.0.1", port, admin_port=0)
        assert not changed["blocked"] and not ephemeral["blocked"]
        if numeric_errors or extra_port:
            assert all(not row["ingress_blocked"] and row["owned_accepts"] == 1 for row in witnesses)
        else:
            assert all(row["owned_accepts"] == 0 for row in witnesses[:2])
            assert all(row["owned_accepts"] == 1 for row in witnesses[2:10])
            assert witnesses[10]["owned_accepts"] == 0
        return {
            "listener": ["127.0.0.1", port],
            "configured_admin_port": configured_port,
            "cases": witnesses,
            "changed_option_old_bound_port": changed,
            "configured_zero_actual_ephemeral_port": ephemeral,
            "scope": "actual ConnectionHandler.open_connection and shield hook; controlled DNS; owned inert listener only",
        }
    finally:
        peer.close()
        await peer.wait_closed()
        await asyncio.gather(*handlers)


def main():
    logging.disable(logging.CRITICAL)
    if "--extras" in sys.argv:
        result = asyncio.run(transport_witness(extra_port=True))
        Path(__file__).with_name("admin_shield_extra_source.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"extra_port_alias_reaches": len(result["cases"])}))
        return
    if "--failures" in sys.argv:
        result = asyncio.run(transport_witness(numeric_errors=True))
        Path(__file__).with_name("admin_shield_failure_source.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"numeric_failopen_cases": len(result["cases"])}))
        return
    rows = source_rows()
    if "--rows" in sys.argv:
        json.dump(rows, sys.stdout)
        return
    rows["transport"] = asyncio.run(transport_witness())
    rows["provenance"] = {
        "source_commit": "838319a1a6a97a5317350e678fda6abc5a44fed1",
        "python": platform.python_version(),
        "unicode": unicodedata.unidata_version,
        "mitmproxy": importlib.metadata.version("mitmproxy"),
        "source_sha256": {
            name: hashlib.sha256((REPO / name).read_bytes()).hexdigest()
            for name in ["cli/src/safeyolo/mitm_addons/admin_shield.py", "cli/src/safeyolo/mitm_addons/admin_api.py"]
        },
        "server_sha256": hashlib.sha256(
            Path(sys.modules[ConnectionHandler.__module__].__file__).read_bytes()
        ).hexdigest(),
        "external_network_attempts": 0,
        "operational_credentials": False,
    }
    Path(__file__).with_name("admin_shield_source.json").write_text(json.dumps(rows, indent=2) + "\n")
    print(
        json.dumps(
            {
                "hooks": len(rows["hooks"]),
                "forms": len(rows["forms"]),
                "server_hooks": len(rows["server_hooks"]),
                "transport_cases": len(rows["transport"]["cases"]),
            }
        )
    )


if __name__ == "__main__":
    main()
