# Credential routing catalogue

Generated from [`credential_catalog.py`](../../../cli/src/safeyolo/detection/credential_catalog.py)
by [`generate_credential_guard_data.py`](../../tools/generate_credential_guard_data.py).
The source and generated data are covered by the repository [MIT license](../../../LICENSE).
No external provider lookup runs during generation or request inspection.

- Source SHA-256: `89828e42d654f1a444f9c10c277a0417b8ba7424487e19ff19a2158d5cdd53e3`
- Generated SHA-256: `ce8909b110d69c667734a1cc26ddb3828bc58b40dc300c19fce2356096da7355`
- Routing rules: 17
- Input: `build_default_rule_configs()` in source order. DLP-only patterns are excluded.

Regenerate from the repository root:

```sh
python proxy/tools/generate_credential_guard_data.py
```

The Rust historical oracle compares this snapshot to the actual Python catalogue.
