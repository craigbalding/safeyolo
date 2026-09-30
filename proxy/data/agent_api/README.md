# Pinned Agent API scalar data

The native [Agent API](../../src/agent_api.rs) and
[policy method conditions](../../src/policy.rs) use these tables through the
shared [Python text helpers](../../src/python_text.rs). The tables preserve
Python's method uppercasing, decimal port digits and invalid-port error strings.
Policy host matching is separate and does not use these tables.

## Regenerate the data

From the repository root, use the existing Python **3.12.14** environment with
Unicode **15.0.0**. The generator checks both versions and the reviewed output
hash before replacing `unicode.json`. It performs no network access.

```sh
.venv/bin/python proxy/tools/generate_agent_api_data.py
```

The expected file is 37,016 bytes, with SHA-256
`2607b7554a81a6449bd48ab4c48ad724ffccbfca01773d6d7909f1680080ebd1`.
It contains 1,525 nonidentity uppercase mappings, 68 decimal-zero code points
and 713 nonprintable ranges. Surrogate code points are excluded because the
native policy API accepts Unicode scalar strings.

The generation inputs are CPython 3.12.14's `str.upper`, `str.isprintable` and
`unicodedata.decimal`. In the source environment these functions are built into
the Python executable. That executable has SHA-256
`8f7e5df472f8db8bc5ebb7cb888199365c6443f7af1788240885da075cd40415`.
The generator reports the executing binary's hash so another build can retain
its own provenance while producing the same semantic data.

Source behavior is pinned by
`cli/src/safeyolo/mitm_addons/agent_api.py` at commit
`22c9a008227235d117f17c158c41f8adf2676994`, file SHA-256
`ab52434f28e82c9cc5f7ce32bf0b69ff6dcd3158e5e5fd5a446e4a747942e378`.
This module uses Python's default 4,300-digit integer-conversion limit. A source
process configured with a different Python integer limit remains a documented
compatibility gap in this development slice.

## Verify against the source runtime

With the same Python environment and cached Rust dependencies, from the
repository root:

```sh
SAFEYOLO_POLICY_PYTHON="$PWD/.venv/bin/python" \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 \
  cargo test --offline --manifest-path proxy/Cargo.toml --lib \
  agent_api::tests::scalar_upper_decimal_and_repr_match_every_python_scalar \
  -- --include-ignored
```

The test compares actual native uppercase, decimal and Python-style string
representation results with the pinned Python runtime for all 1,112,064 Unicode
scalars. It hashes the complete operation outputs, including characters that
need no mapping. The separate [handler tests](../../tests/agent_api.rs) compare
real Python API handlers and the native facade.

## Licenses

Python-derived data retains the [Python license](LICENSE-Python.txt). The
underlying Unicode character data retains the
[Unicode license](LICENSE-Unicode.txt). The generator and native integration
use the repository's MIT license.
