# Pinned scanner Unicode categories

The native pattern scanner uses these generated ranges for Python's `\w` and
`\d` categories. Rust's regex tables can move ahead of the Python runtime used
by SafeYolo, so using its properties directly would make a newly assigned
Unicode scalar match in native while Python 3.12 does not. The ranges include
letters, numbers and underscore for `\w`, and decimal-number scalars for
`\d`. `\s` remains the existing explicit Python whitespace set.

## Regenerate

Use the existing Python 3.12.14 environment; the generator rejects another
Python or Unicode version and checks the reviewed output hash:

```sh
.venv/bin/python proxy/tools/generate_inspection_data.py
```

The output is 10,926 bytes with SHA-256
`2c3271da5c3d9aac327ec5fc8bf3f775348d1342626969cfafb61f32a1b169c1`.
It contains 748 `\w` ranges and 64 `\d` ranges from
`unicodedata.category` in Unicode 15.0.0. Surrogate code points are not
included because scanner inputs are Unicode scalar strings.

This is derived CPython Unicode data. The repository's existing Python and
Unicode license notices apply; the generator and native integration use the
repository MIT license.
