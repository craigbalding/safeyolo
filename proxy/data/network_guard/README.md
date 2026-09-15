# Network guard Unicode data

The inactive Rust network guard uses `unicode.json` to preserve the existing
Python detector and audit sanitizer. The binary includes this file at build
time. It does not download Unicode data or read package files at runtime.

## Reproduce

From the repository root, use the existing Python 3.12 environment with
`confusable-homoglyphs==3.3.1` and `unicodedata.unidata_version == "15.0.0"`:

```sh
.venv/bin/python proxy/tools/generate_network_guard_data.py
```

The generator rejects different versions or source hashes. It overwrites only
`unicode.json` and reports its SHA-256 hash. The expected generated hash is
`5186366e7e1689b997a5fac0ded648e68f942032dd3518e5cebc9118fbcbe7eb`.

## Inputs and transformations

| Input | Version / SHA-256 | Transformation |
| --- | --- | --- |
| `confusable_homoglyphs/categories.json` | 3.3.1 / `804570f15edd97f7cd15f4458cea45bd7df2c1a0d179a7975ed7edb32b1cc9c9` | Merge adjacent ranges with the same script alias; retain gaps as Unknown. |
| `confusable_homoglyphs/confusables.json` | 3.3.1 / `2d8b4774cd9dc6f233a18681bc00423ae270037437f276fc6a8b80630941fe7d` | Retain single-scalar keys with nonempty values; group adjacent keys. |
| CPython `unicodedata.category` | Python 3.12, Unicode 15.0.0 | Group the categories admitted by `core/audit_schema.py` into adjacent scalar ranges. |

These transformations produce 953 script ranges, 2,499 confusable ranges and
769 sanitizer ranges. The package's script data is separate from CPython's
Unicode database. Do not substitute Rust's current Unicode categories or a
different script table during a dependency upgrade.

The detector preserves the package's default `is_dangerous` call: it requires
more than one script after excluding COMMON, plus any confusable character.
This is not an IDN validity check. In particular, a COMMON character can satisfy
the confusable condition, and Unknown counts as a script.

## Licenses

The installed [confusable-homoglyphs source](https://github.com/vhf/confusable_homoglyphs)
uses the [included MIT license](LICENSE-confusable-homoglyphs.txt).
CPython's installed [license and notices](LICENSE-Python.txt) accompany the
derived category data. Original package data is transformed, not modified in
place. The generated file contains data only; the generator and native code
use this repository's MIT license.
