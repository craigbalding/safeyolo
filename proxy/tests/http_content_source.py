"""Finite controls against installed, unmodified mitmproxy Message.content."""

import argparse
import base64
import bz2
import codecs
import gzip
import hashlib
import importlib.metadata
import json
import sys
import zlib
from pathlib import Path

import brotli
import zstandard
from mitmproxy import http
from mitmproxy.net import encoding


def cases():
    body = '{"value":"α😀plain","complete":true}'.encode()
    second = b'{"second":true}'
    yield "absent", b"", body
    yield "none", b"none", body
    yield "identity", b"identity", body
    yield "identity_upper", b"IDENTITY", body
    yield "unknown", b"not-a-codec", body
    yield "identity_space", b" identity ", body
    yield "encoding_nonascii", b"\xff", body
    yield "encoding_nul", b"identity\x00", body
    yield "encoding_list", b"gzip, br", gzip.compress(body, mtime=0)
    encoders = {
        "gzip": lambda value: gzip.compress(value, mtime=0),
        "deflate": zlib.compress,
        "raw": lambda value: zlib.compress(value, wbits=-15),
        "br": brotli.compress,
        "zstd": zstandard.ZstdCompressor().compress,
    }
    for name, encode in encoders.items():
        encoded = encode(body)
        content_encoding = b"deflate" if name == "raw" else name.encode()
        for label, data in (
            ("valid", encoded),
            ("empty", b""),
            ("concatenated", encoded + encode(second)),
            ("trailing", encoded + b"garbage"),
            ("trailing_zero", encoded + b"\x00\x00"),
            ("truncated_one", encoded[:-1]),
            ("truncated_half", encoded[: len(encoded) // 2]),
            ("bad_last", encoded[:-1] + bytes([encoded[-1] ^ 255])),
        ):
            yield f"{name}_{label}", content_encoding, data
    yield "gzip_zlib", b"gzip", zlib.compress(body)
    yield "gzip_raw", b"gzip", zlib.compress(body, wbits=-15)
    yield "gzip_upper", b"GZIP", gzip.compress(body, mtime=0)
    yield "deflateraw_zlib", b"deflateraw", zlib.compress(body)
    yield "deflateraw_raw", b"deflateraw", zlib.compress(body, wbits=-15)
    yield "zstd_unknown_size", b"zstd", zstandard.ZstdCompressor(write_content_size=False).compress(body)
    yield "gzip_late_bad_crc", b"gzip", gzip.compress(b"A" * 20000, mtime=0)[:-8] + b"\x00" * 8
    yield "gzip_large", b"gzip", gzip.compress(b"A" * 20000, mtime=0)
    yield "br_large", b"br", brotli.compress(b"A" * 20000)
    yield "zstd_large", b"zstd", zstandard.ZstdCompressor().compress(b"A" * 20000)
    for name in (
        "base64",
        "base64_codec",
        "base-64",
        "base64 codec",
        "hex",
        "hex_codec",
        "bz2",
        "bz2_codec",
        "zlib",
        "zlib_codec",
        "quopri",
        "quopri_codec",
        "uu",
        "uu_codec",
    ):
        try:
            encoded = codecs.encode(body, name)
        except LookupError:
            encoded = body
        yield f"alias_{name}", name.encode(), encoded
    yield "base64_ignored_junk", b"base64", b"!?" + base64.b64encode(body) + b"%"
    yield "base64_truncated", b"base64", b"YQ"
    yield "hex_odd", b"hex", b"abc"
    for index, name in enumerate(
        (b" HEX ", "hexé".encode(), "héex".encode(), "hex😀".encode(), b"hex\xff", b"hex\x00")
    ):
        yield f"codec_name_{index}", name, b"41"
    yield "bz2_concatenated", b"bz2", bz2.compress(body) + bz2.compress(second)
    for label, data in (
        ("empty", b""),
        ("trailing", bz2.compress(body) + b"garbage"),
        ("truncated", bz2.compress(body)[:-1]),
        ("truncated_second", bz2.compress(body) + bz2.compress(second)[:-1]),
        ("corrupt_second", bz2.compress(body) + bz2.compress(b"A" * 20000)[:-8] + b"\x00" * 8),
    ):
        yield f"bz2_{label}", b"bz2", data
    for index, data in enumerate(
        (
            b"",
            b"=",
            b"===",
            b"=YQ==",
            b"Y=Q==",
            b"YQ=!=",
            b"YQ==ignored",
            b"YQ===",
            b"YR==",
            b"YWI=",
            b"YWJ=",
            b"YWJj=",
            b"YWJj====",
            b"YWJjA",
            b"YQ=A=",
            b"YQ=A",
            b"YWJj\xff",
            b"YQ\n==",
            b"Y===",
            b"\xff==",
        )
    ):
        yield f"base64_padding_{index}", b"base64", data
    for index, data in enumerate(
        (
            b"",
            b"=",
            b"==",
            b"===",
            b"=4",
            b"=4Z",
            b"=41",
            b"=ff",
            b"a=\nb",
            b"a=\r\nb",
            b"a=\rb",
            b"a=\rgarbage\nb",
            b"a_b\xff",
        )
    ):
        yield f"quopri_controls_{index}", b"quopri", data
    for index, data in enumerate(
        (
            b"",
            b"begin\nend\n",
            b"beginxxx\nend\n",
            b"prefix\nbegin\nend\n",
            b"begin\n!00\nend\n",
            b"begin\n!00garbage\nend\n",
            b"begin\n!\nend\n",
            b"begin\nend",
            b"begin\nend\r\n",
            b"begin\n\nend\n",
            b"begin\n!\xff\nend\n",
            b"begin\n`\nend\n",
        )
    ):
        yield f"uu_controls_{index}", b"uu", data
    for name in ("utf8", "latin1", "unicode_escape", "rot_13", "ascii"):
        yield f"text_codec_{name}", name.encode(), b"plain"


def observe():
    rows = []
    for name, content_encoding, encoded in cases():
        message = http.Response.make(200)
        message.raw_content = encoded
        if content_encoding:
            message.headers["content-encoding"] = content_encoding
        encoding._cache = encoding.CachedDecode(None, None, None, None)
        try:
            decoded = message.content
        except (ValueError, TypeError) as error:
            result = {"error": type(error).__name__}
        else:
            assert isinstance(decoded, bytes)
            result = {"decoded_hex": decoded.hex()}
        assert message.raw_content == encoded
        rows.append({"name": name, "encoding_hex": content_encoding.hex(), "encoded_hex": encoded.hex(), **result})
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = {
        "python": sys.version.split()[0],
        "versions": {name: importlib.metadata.version(name) for name in ("mitmproxy", "Brotli", "zstandard")},
        "source_hashes": {
            module.__name__: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
            for module in (http, encoding)
        },
        "rows": observe(),
    }
    if args.check:
        assert json.loads(args.output.read_text()) == result
    else:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"rows": len(result["rows"]), "successful": sum("decoded_hex" in row for row in result["rows"])}))


if __name__ == "__main__":
    main()
