"""Finite controls for the installed HTTPX Brotli response decoder."""

import brotlicffi
import httpx
import httpx._decoders
import pytest

DECODED = b"HTTPX Brotli dependency control.\n"
ENCODED = bytes.fromhex("0b108048545450582042726f746c6920646570656e64656e637920636f6e74726f6c2e0a03")


@pytest.mark.parametrize("chunk_size", [1, len(ENCODED)])
def test_httpx_decodes_brotlicffi_response(chunk_size):
    assert httpx._decoders.brotli is brotlicffi
    chunks = (ENCODED[offset:offset + chunk_size] for offset in range(0, len(ENCODED), chunk_size))
    response = httpx.Response(200, headers={"Content-Encoding": "br"}, content=chunks)
    assert response.read() == DECODED


def test_httpx_preserves_body_without_content_encoding():
    response = httpx.Response(200, content=ENCODED)
    assert response.content == ENCODED


def test_httpx_rejects_malformed_brotli_response():
    with pytest.raises(httpx.DecodingError):
        httpx.Response(200, headers={"Content-Encoding": "br"}, content=b"not a brotli response")
