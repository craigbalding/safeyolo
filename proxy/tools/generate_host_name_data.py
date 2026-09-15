"""Generate exact IDNA2003 data from the pinned Python runtime; no network I/O.

Run from the checkout with its Python 3.12.14 environment. Nameprep uses the
runtime's str.lower fallback (Unicode 15) and ucd_3_2_0 normalization/categories.
Do not replace these with a modern Unicode or UTS46 data source.
"""

import encodings.idna
import hashlib
import inspect
import json
import stringprep
import sys
import unicodedata
from pathlib import Path
from unicodedata import ucd_3_2_0 as u32


def ranges(points):
    result = []
    for point in points:
        if result and result[-1][1] + 1 == point:
            result[-1][1] = point
        else:
            result.append([point, point])
    return result


def main():
    if sys.version_info[:3] != (3, 12, 14) or unicodedata.unidata_version != "15.0.0":
        raise RuntimeError("generation requires Python 3.12.14 / Unicode 15.0.0")
    if u32.unidata_version != "3.2.0":
        raise RuntimeError("generation requires ucd_3_2_0")
    source_hashes = {
        "idna.py": "9ca58e82d12b171f25d57239ad237dae5c44214a70f2f4f39358c2759b8b9013",
        "stringprep.py": "60b6c83581093029312efb6670b11c540090b3f78bcf72264467b494f02f21a5",
    }
    for module in (encodings.idna, stringprep):
        path = Path(inspect.getsourcefile(module))
        if hashlib.sha256(path.read_bytes()).hexdigest() != source_hashes[path.name]:
            raise RuntimeError(f"unexpected source hash: {path.name}")
    data = {
        "schema": 1,
        "python": "3.12.14",
        "lowercase_unicode": "15.0.0",
        "normalization_unicode": "3.2.0",
        "source_hashes": source_hashes,
        "mapping": [],
        "decomposition": [],
        "combining": [],
        "composition": [],
        "prohibited": [],
        "bidi_ral": [],
        "bidi_l": [],
    }
    prohibited = (
        stringprep.in_table_c12,
        stringprep.in_table_c22,
        stringprep.in_table_c3,
        stringprep.in_table_c4,
        stringprep.in_table_c5,
        stringprep.in_table_c6,
        stringprep.in_table_c7,
        stringprep.in_table_c8,
        stringprep.in_table_c9,
    )
    for point in range(0x110000):
        if 0xD800 <= point <= 0xDFFF:
            continue  # Rust strings contain Unicode scalars, not lone surrogates.
        c = chr(point)
        mapped = "" if stringprep.in_table_b1(c) else stringprep.map_table_b2(c)
        if mapped != c:
            data["mapping"].append([point, mapped])
        decomposed = u32.normalize("NFKD", c)
        if not 0xAC00 <= point <= 0xD7A3 and decomposed != c:
            data["decomposition"].append([point, decomposed])
        combining = u32.combining(c)
        if combining:
            data["combining"].append([point, combining])
        decomposition = u32.decomposition(c).split()
        if len(decomposition) == 2 and not decomposition[0].startswith("<"):
            pair = [int(n, 16) for n in decomposition]
            if u32.normalize("NFC", "".join(chr(n) for n in pair)) == c:
                data["composition"].append([*pair, point])
        if any(check(c) for check in prohibited):
            data["prohibited"].append(point)
        if stringprep.in_table_d1(c):
            data["bidi_ral"].append(point)
        if stringprep.in_table_d2(c):
            data["bidi_l"].append(point)
    data["composition"].sort()
    for key in ("prohibited", "bidi_ral", "bidi_l"):
        data[key] = ranges(data[key])
    target = Path(__file__).resolve().parents[1] / "data" / "host_names" / "nameprep.json"
    content = (json.dumps(data, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
    target.write_bytes(content)
    print(f"{target.name}: sha256 {hashlib.sha256(content).hexdigest()}, {len(content)} bytes")
    print({key: len(value) for key, value in data.items() if isinstance(value, list)})


if __name__ == "__main__":
    main()
