# Pinned scanner Unicode data

The native pattern scanner uses this generated data for Python's `\w` and
`\d` categories and `\N{...}` character-name escapes. Rust's regex tables can
move ahead of the Python runtime used by SafeYolo, so using its properties
directly would make a newly assigned Unicode scalar match in native while
Python 3.12 does not. The ranges include letters, numbers and underscore for
`\w`, and decimal-number scalars for `\d`. `\s` remains the existing explicit
Python whitespace set.

`names.txt` contains 143,041 canonical scalar names from
`unicodedata.name()` plus the 473 verified scalar aliases from the pinned
Unicode `NameAliases-15.0.0.txt` file. Ordinary names and aliases are matched
case-insensitively, while CPython's finite algorithmic Hangul and CJK names
require their uppercase spelling. Named sequences are deliberately absent
because Python's regular-expression parser rejects them; such source-invalid
rules are skipped individually by the scanner loader.

## Regenerate

Use the existing Python 3.12.14 environment; the generator rejects another
Python or Unicode version and checks the reviewed output hash:

```sh
.venv/bin/python proxy/tools/generate_inspection_data.py
```

The category output is 10,926 bytes with SHA-256
`2c3271da5c3d9aac327ec5fc8bf3f775348d1342626969cfafb61f32a1b169c1`.
It contains 748 `\w` ranges and 64 `\d` ranges from
`unicodedata.category` in Unicode 15.0.0. Surrogate code points are not
included because scanner inputs are Unicode scalar strings.

The name output is 4,672,182 bytes with SHA-256
`30014b8c739ba8ad18acc09e603798ba74645297b702cec10018b9fb9c122766`.
The alias input is Unicode 15.0.0 `NameAliases.txt`, SHA-256
`3e39509e8fae3e5d50ba73759d0b97194501d14a9c63107a6372a46b38be18e8`.

This is derived CPython and Unicode data. The repository's existing Python and
Unicode license notices apply; the generator and native integration use the
repository MIT license.
