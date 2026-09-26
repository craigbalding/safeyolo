"""Loopback DNS answers for live proxy resolver tests."""

from __future__ import annotations

import socketserver
import struct
import threading
from contextlib import contextmanager


class _DNSAnswers:
    def __init__(self, names):
        self.names = {name.lower().removesuffix(".") for name in names}
        self._queries = []
        self._lock = threading.Lock()

    def queries(self):
        with self._lock:
            return list(self._queries)

    def clear_queries(self):
        with self._lock:
            self._queries.clear()

    def reply(self, packet, transport):
        """Answer one standard question; never consult another resolver."""
        if len(packet) < 12:
            return b""
        identifier, _, questions, _, _, _ = struct.unpack_from("!HHHHHH", packet)
        try:
            if questions != 1:
                raise ValueError("expected one question")
            offset = 12
            labels = []
            while True:
                length = packet[offset]
                offset += 1
                if length == 0:
                    break
                if length > 63 or offset + length > len(packet):
                    raise ValueError("invalid DNS label")
                labels.append(packet[offset:offset + length].decode("ascii"))
                offset += length
            if offset + 4 > len(packet):
                raise ValueError("missing question type or class")
            name = ".".join(labels)
            qtype, qclass = struct.unpack_from("!HH", packet, offset)
            question = packet[12:offset + 4]
        except (IndexError, UnicodeDecodeError, ValueError):
            return struct.pack("!HHHHHH", identifier, 0x8401, 0, 0, 0, 0)

        with self._lock:
            self._queries.append((name, qtype, transport))
        known = name.lower() in self.names
        # A known AAAA request receives an authoritative empty answer.
        answer = (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4)
                  + b"\x7f\x00\x00\x01") if known and qtype == 1 and qclass == 1 else b""
        rcode = 0 if known else 3
        header = struct.pack("!HHHHHH", identifier, 0x8400 | rcode, 1, bool(answer), 0, 0)
        return header + question + answer


class _UDPServer(socketserver.UDPServer):
    allow_reuse_address = True
    max_packet_size = 4096


class _TCPServer(socketserver.TCPServer):
    allow_reuse_address = True
    request_queue_size = 2


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        reply = self.server.answers.reply(packet, "udp")
        if reply:
            sock.sendto(reply, self.client_address)


class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(1)
        length = self.request.recv(2)
        if len(length) != 2:
            return
        remaining = struct.unpack("!H", length)[0]
        if remaining > 4096:
            return
        packet = bytearray()
        while len(packet) < remaining:
            part = self.request.recv(remaining - len(packet))
            if not part:
                return
            packet.extend(part)
        reply = self.server.answers.reply(packet, "tcp")
        if reply:
            self.request.sendall(struct.pack("!H", len(reply)) + reply)


@contextmanager
def dns_server(names):
    """Serve only named fixture hosts on loopback port 53 until teardown."""
    answers = _DNSAnswers(names)
    with _UDPServer(("127.0.0.1", 53), _UDPHandler) as udp:
        with _TCPServer(("127.0.0.1", 53), _TCPHandler) as tcp:
            udp.answers = tcp.answers = answers
            threads = [threading.Thread(target=server.serve_forever, daemon=True)
                       for server in (udp, tcp)]
            for thread in threads:
                thread.start()
            try:
                yield answers
            finally:
                for server in (udp, tcp):
                    server.shutdown()
                for thread in threads:
                    thread.join(timeout=2)
