# Pinned host-name codec data

These files support the native [host-name codec](../../src/host_names.rs). The
codec reproduces Python's IDNA2003 encoding and decoding. IDNA means
Internationalizing Domain Names in Applications. HTTP authority validation,
inspection presentation and routing remain separate responsibilities.

## Regenerate the Nameprep tables

From the repository root, use the project's Python **3.12.14** environment.
The generator checks the Python source hashes and Unicode versions before it
overwrites `proxy/data/host_names/nameprep.json`. It performs no network access.

```sh
.venv/bin/python proxy/tools/generate_host_name_data.py
```

The expected file is 151,952 bytes, with SHA-256
`29609073d4782258343336e4dc895c56e9604554478563f7f6cc84aeb646196a`.
Its contents are:

| Data | Rows |
| --- | ---: |
| Python B.1/B.2 character mappings | 2,082 |
| Full compatibility decompositions, excluding algorithmic Hangul | 5,143 |
| Nonzero combining classes | 327 |
| Canonical composition pairs | 917 |
| Prohibited-character ranges | 33 |
| Right-to-left bidirectional ranges | 34 |
| Left-to-right bidirectional ranges | 360 |

Python uses `ucd_3_2_0` for normalization, categories and bidirectional checks.
Its stringprep B.3 fallback calls `str.lower`, which uses Unicode 15.0.0 in this
runtime. The generator captures both inputs. It does not substitute current
Unicode normalization or reject characters merely because Unicode 3.2 considered
them unassigned. The codec composes across characters after decomposition and
combining-class ordering; per-character normalization alone is insufficient.

The pinned Python source hashes are embedded in the generated file:

- `encodings/idna.py`: `9ca58e82d12b171f25d57239ad237dae5c44214a70f2f4f39358c2759b8b9013`
- `stringprep.py`: `60b6c83581093029312efb6670b11c540090b3f78bcf72264467b494f02f21a5`

Python-derived code/data retain the [Python license](licenses/PYTHON.txt).
Unicode-derived tables retain the [Unicode license](licenses/UNICODE.txt).

## Punycode source

[punycode.rs](../../src/host_names/punycode.rs) comes from the maintained
[rust-url v2.5.7 source](https://github.com/servo/rust-url/blob/v2.5.7/idna/src/punycode.rs),
under its [MIT license](licenses/RUST-URL-MIT.txt). Its unmodified SHA-256 is
`0cc6fa84989898ccf6de0a665a287d7488a6eba4b178bea065d311ecabd81604`.

The local copy changes `alloc` imports to `std`, replaces the decoder's SmallVec
storage with Vec, and applies repository Rust formatting. It omits the upstream
ignored test that iterates over more than four billion characters, so running
the historical tests with `--include-ignored` does not start that unrelated test.
Algorithms, checked arithmetic and external-caller case behavior are retained.
The adapted SHA-256 is
`0511570f68649cfc7184742d356e5ae732147af9787c35a049acf5425a7490fd`.
No UTS46 conversion or additional dependency is included.

The host codec wrapper also consumes a last Punycode delimiter at offset zero,
as Python does. For example, raw payload `-a` decodes to U+0080. The vendored
decoder alone rejects that framing. Strict IDNA roundtrip checks still reject
the corresponding noncanonical ACE label.

`decode_punycode_label` accepts the payload after an ACE prefix. ACE means ASCII
Compatible Encoding. This helper omits Nameprep and roundtrip validation so the
caller can inspect source-admitted uppercase ACE labels consistently. Raw Python
Punycode can produce lone surrogate code points; Rust strings cannot represent
them. The helper returns an explicit error for that case. The caller must handle
errors and must not fall back to uninspected ASCII text.

## Source request-form witnesses

[source-host-witnesses.json](source-host-witnesses.json) contains 155 portable
rows from Python 3.12.14 and mitmproxy 12.2.3. Each row includes the original host
and authority bytes in hex, request form, source validation result and, when
accepted, the policy hostname and sensor fields. The rows cover 31 host spellings
across HTTP/1 absolute-form, CONNECT, origin-form, H2 authority and H2 Host fallback.

The [host-name tests](../../tests/host_names.rs) re-execute the actual Python
parsers, HttpStream and policy sensor against every row. Separate differential
tests compare all Unicode scalar Nameprep results, combining sequences, codec
length/error cases and raw Punycode. Set `SAFEYOLO_POLICY_PYTHON` to the historical
environment's Python executable when running the ignored source comparisons.
These tests perform no DNS or upstream network access.

The witnesses preserve source quirks, including case-sensitive ACE decoding and
different Host-header handling. They are a baseline for explicit transport
repairs, not a reason to bypass the configured homoglyph inspection control.
