"""Finite retained-body framing fixtures from actual Python gzip.decompress."""

import gzip
import json
import zlib


def cases():
    valid = gzip.compress(b"owned synthetic body", mtime=0)
    second = gzip.compress(b" second", mtime=0)
    values = {
        "valid": valid,
        "empty": b"",
        "concat": valid + second,
        "padding": valid + b"\0\0" + second + b"\0\0",
        "leading_zero": b"\0" + valid,
        "junk_tail": valid + b"x",
        "raw_zlib": zlib.compress(b"owned"),
        "bad_magic": b"xx",
        "bad_method": valid[:2] + b"\0" + valid[3:],
        "reserved_flags": valid[:3] + b"\xe0" + valid[4:],
        "invalid_deflate": valid[:10] + b"\x07" + valid[-8:],
        "bad_crc": valid[:-8] + bytes([valid[-8] ^ 1]) + valid[-7:],
        "bad_size": valid[:-4] + bytes([valid[-4] ^ 1]) + valid[-3:],
        "ignored_header_crc": valid[:3] + b"\2" + valid[4:10] + b"\0\0" + valid[10:],
        "extra": valid[:3] + b"\4" + valid[4:10] + b"\3\0abc" + valid[10:],
        "filename": valid[:3] + b"\x08" + valid[4:10] + b"owned\0" + valid[10:],
        "comment": valid[:3] + b"\x10" + valid[4:10] + b"owned\0" + valid[10:],
        "unterminated_filename": valid[:3] + b"\x08" + valid[4:10] + b"owned",
        "truncated_extra": valid[:3] + b"\4" + valid[4:10] + b"\3\0a",
        "truncated_header_crc": valid[:3] + b"\2" + valid[4:10] + b"\0",
    }
    values.update({f"prefix_{index}": valid[:index] for index in range(1, len(valid))})
    rows = []
    for name, compressed in values.items():
        row = {"name": name, "compressed_hex": compressed.hex()}
        try:
            row["body_hex"] = gzip.decompress(compressed).hex()
        except (gzip.BadGzipFile, EOFError, zlib.error) as error:
            row["error"] = type(error).__name__
        rows.append(row)
    return rows


if __name__ == "__main__":
    print(json.dumps(cases(), ensure_ascii=True))
