"""Source header hygiene at the real HTTP boundary, before origin forwarding."""

import http.client
import socket

from tests.proxy_migration.scenarios import POLICY
from tests.proxy_migration.test_native_network_policy import policy_proxy, raw_parent

CASES = [
    ("nominated", [(b"Connection", b"X-Drop, close"),
                   (b"X-Drop", b"synthetic-drop"), (b"X-Keep", b"retained")],
     {b"x-keep": [b"retained"]}),
    ("duplicate-connection", [(b"Connection", b"X-Drop"), (b"X-Drop", b"synthetic-drop"),
                              (b"Connection", b"X-Other"), (b"X-Other", b"synthetic-other"),
                              (b"X-Keep", b"retained")],
     {b"x-keep": [b"retained"]}),
    ("unicode-whitespace", [(b"Connection", "\u00a0X-Drop\u2003, close".encode()),
                            (b"X-Drop", b"synthetic-drop"), (b"X-Keep", b"retained")],
     {b"x-keep": [b"retained"]}),
    ("unicode-lowercase", [(b"Connection", "X-\u212aey, close".encode()),
                           (b"X-Key", b"synthetic-drop"), (b"X-Keep", b"retained")],
     {b"x-keep": [b"retained"]}),
    ("invalid-byte-token", [(b"Connection", b"\xffX-Drop, close"),
                            (b"X-Drop", b"retained"), (b"X-Keep", b"\xffkept\xc3")],
     {b"x-drop": [b"retained"], b"x-keep": [b"\xffkept\xc3"]}),
    ("correlation-and-hop", [(b"Connection", b"close"), (b"X-SafeYolo-Trace", b"1"),
                             (b"X-SafeYolo-Request-Id", b"req-forged"),
                             (b"Proxy-Authorization", b"synthetic-hop"),
                             (b"X-Keep", b"first"), (b"x-keep", b"second")],
     {b"x-keep": [b"first", b"second"]}),
    ("ordinary-upgrade", [(b"Connection", b"Upgrade, close"), (b"Upgrade", b"h2c"),
                           (b"X-Keep", b"retained")],
     {b"x-keep": [b"retained"]}),
]


def send(path, authority, name, fields):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(path)
        head = f"GET http://{authority}/{name} HTTP/1.1\r\nHost: {authority}\r\n".encode()
        head += b"".join(key + b": " + value + b"\r\n" for key, value in fields)
        client.sendall(head + b"\r\n")
        response = http.client.HTTPResponse(client)
        response.begin()
        try:
            return response.status, response.read(), response.getheader("X-SafeYolo-Request-Id")
        finally:
            response.close()


def test_source_header_hygiene_reaches_owned_origin(proxy_backend, tmp_path):
    with raw_parent() as origin:
        authority = f"127.0.0.1:{origin.server_address[1]}"
        with policy_proxy(proxy_backend, tmp_path / proxy_backend, POLICY) as proxy:
            identifiers = []
            for name, fields, expected in CASES:
                status, body, identifier = send(proxy.paths["alice"], authority, name, fields)
                assert status == 200, (name, status, body)
                assert body == b"hello"
                assert identifier and identifier != "req-forged"
                identifiers.append(identifier)
                forwarded = {}
                for line in origin.heads[-1].split(b"\r\n")[1:]:
                    if not line:
                        continue
                    key, value = line.split(b":", 1)
                    key = key.lower()
                    if key.startswith(b"x-") or key in {b"proxy-authorization", b"upgrade"}:
                        forwarded.setdefault(key, []).append(value.strip(b" \t"))
                assert forwarded == expected, (name, forwarded)
            assert len(set(identifiers)) == len(CASES)
            before = origin.accepts
            status, _, _ = send(proxy.paths["bob"], authority, "denied", CASES[0][1])
            assert status == 403
            assert origin.accepts == before
        assert origin.accepts == len(origin.heads) == len(CASES)
        assert len(proxy.events("proxy.egress")) == len(CASES)
        events = proxy.events("proxy.request")
        assert len(events) == len(CASES) + 1
        assert [event["status"] for event in events] == [200] * len(CASES) + [403]
        assert not proxy.readiness_file.exists()
