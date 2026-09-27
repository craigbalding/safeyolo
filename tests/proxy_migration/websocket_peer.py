"""Raw WebSocket peer shared by the proxy contract and installed guest pilot."""

from __future__ import annotations

import struct
import zlib


def exact(stream, length):
    """Read exactly the requested finite fixture bytes or expose premature EOF."""
    result = bytearray()
    while len(result) < length:
        piece = stream.recv(length - len(result))
        if not piece:
            raise EOFError("WebSocket peer ended before the expected bytes")
        result.extend(piece)
    return bytes(result)


def read_head(stream):
    result = bytearray()
    while not result.endswith(b"\r\n\r\n"):
        result.extend(exact(stream, 1))
    lines = result.decode("latin1").split("\r\n")
    headers = {}
    for line in lines[1:]:
        if line:
            name, value = line.split(":", 1)
            headers.setdefault(name.lower(), []).append(value.strip())
    return lines[0], headers


def frame(opcode, payload, *, final=True, compressed=False, masked=False):
    first = (0x80 if final else 0) | (0x40 if compressed else 0) | opcode
    mask_bit = 0x80 if masked else 0
    length = len(payload)
    if length < 126:
        head = bytes([first, mask_bit | length])
    elif length < 65536:
        head = bytes([first, mask_bit | 126]) + struct.pack("!H", length)
    else:
        head = bytes([first, mask_bit | 127]) + struct.pack("!Q", length)
    if masked:
        mask = b"\x12\x34\x56\x78"
        head += mask
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return head + payload


class Peer:
    """Finite test peer preserving distinct send/receive compression dictionaries."""

    def __init__(self, stream, *, client, compressed):
        self.stream = stream
        self.client = client
        self.compressed = compressed
        self.encoder = zlib.compressobj(wbits=-15)
        self.decoder = zlib.decompressobj(wbits=-15)
        self.controls = []
        self.data_frames = 0

    def send(self, opcode, payload, *, fragmented=False, control=None):
        encoded = payload
        if self.compressed:
            encoded = (self.encoder.compress(payload) + self.encoder.flush(zlib.Z_SYNC_FLUSH))[:-4]
        if fragmented:
            split = len(encoded) // 2
            wire = frame(opcode, encoded[:split], final=False,
                         compressed=self.compressed, masked=self.client)
            if control is not None:
                wire += frame(control, b"control", masked=self.client)
            wire += frame(0, encoded[split:], masked=self.client)
        else:
            wire = frame(opcode, encoded, compressed=self.compressed, masked=self.client)
        self.stream.sendall(wire)

    def close(self, code=1000, reason=b"fixture complete"):
        self.stream.sendall(frame(8, struct.pack("!H", code) + reason, masked=self.client))

    def receive_control(self):
        """Read one idle control frame and answer a Ping like a real peer."""
        first, second = exact(self.stream, 2)
        final, opcode = bool(first & 0x80), first & 15
        assert final and not first & 0x40 and opcode in (8, 9, 10)
        assert bool(second & 0x80) != self.client
        length = second & 127
        assert length <= 125
        mask = exact(self.stream, 4) if second & 0x80 else None
        payload = exact(self.stream, length)
        if mask:
            payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.controls.append((opcode, payload))
        if opcode == 9:
            self.stream.sendall(frame(10, payload, masked=self.client))
        return opcode, payload

    def receive(self):
        pieces = bytearray()
        message_opcode = None
        compressed = False
        while True:
            first, second = exact(self.stream, 2)
            final, opcode = bool(first & 0x80), first & 15
            assert not first & 0x30, "Unnegotiated reserved frame bits"
            assert bool(second & 0x80) != self.client, "Incorrect peer masking direction"
            length = second & 127
            if length == 126:
                length = struct.unpack("!H", exact(self.stream, 2))[0]
                assert length >= 126
            elif length == 127:
                length = struct.unpack("!Q", exact(self.stream, 8))[0]
                assert 65536 <= length < 2**63
            mask = exact(self.stream, 4) if second & 0x80 else None
            payload = exact(self.stream, length)
            if mask:
                payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            if opcode in (8, 9, 10):
                assert final and not first & 0x40 and length <= 125
                if opcode == 8:
                    return opcode, payload
                self.controls.append((opcode, payload))
                if opcode == 9:
                    self.stream.sendall(frame(10, payload, masked=self.client))
                continue
            if opcode in (1, 2):
                assert message_opcode is None
                message_opcode, compressed = opcode, bool(first & 0x40)
                assert self.compressed or not compressed
            else:
                assert opcode == 0 and message_opcode is not None and not first & 0x40
            self.data_frames += 1
            pieces.extend(payload)
            if final:
                decoded = bytes(pieces)
                if compressed:
                    decoded = self.decoder.decompress(decoded + b"\x00\x00\xff\xff")
                if message_opcode == 1:
                    decoded.decode("utf-8")
                return message_opcode, decoded
