# Credential routing catalogue

Generated from [`credential_catalog.py`](../../../cli/src/safeyolo/detection/credential_catalog.py)
by [`generate_credential_guard_data.py`](../../tools/generate_credential_guard_data.py).
The source and generated data are covered by the repository [MIT license](../../../LICENSE).
No external provider lookup runs during generation or request inspection.

- Source SHA-256: `e07c212a4d1c4c97b8c01d22109101b6a2d51602faf4852004b89d10a752d041`
- Generated SHA-256: `a6c48b30028ad8606948b6336baf35496a6918bbd36701227d790476f7d25b94`
- Routing rules: 17
- Input: `build_default_rule_configs()` in source order. DLP-only patterns are excluded.

Regenerate from the repository root:

```sh
python proxy/tools/generate_credential_guard_data.py
```

The Rust historical oracle compares this snapshot to the actual Python catalogue.
