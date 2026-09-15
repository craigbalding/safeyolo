"""Generate pinned Python scalar operations for the native Agent API."""

import hashlib
import json
import platform
import sys
import unicodedata
from pathlib import Path


def ranges(points):
    result = []
    for point in points:
        if result and result[-1][1] + 1 == point:
            result[-1][1] = point
        else:
            result.append([point, point])
    return result


def main():
    if platform.python_version() != "3.12.14" or unicodedata.unidata_version != "15.0.0":
        raise RuntimeError("requires Python 3.12.14 with Unicode 15.0.0")
    points = [point for point in range(0x110000) if not 0xD800 <= point <= 0xDFFF]
    data = {
        "python": platform.python_version(),
        "unicode": unicodedata.unidata_version,
        "uppercase": [[point, chr(point).upper()] for point in points if chr(point).upper() != chr(point)],
        "decimal_zero": [point for point in points if unicodedata.decimal(chr(point), -1) == 0],
        "nonprintable": ranges(point for point in points if not chr(point).isprintable()),
    }
    path = Path(__file__).resolve().parents[1] / "data" / "agent_api" / "unicode.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    content = (json.dumps(data, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
    if hashlib.sha256(content).hexdigest() != "2607b7554a81a6449bd48ab4c48ad724ffccbfca01773d6d7909f1680080ebd1":
        raise RuntimeError("scalar operations differ from the reviewed Python 3.12.14 input")
    path.write_bytes(content)
    print(
        json.dumps(
            {
                "path": str(path),
                "sha256": hashlib.sha256(content).hexdigest(),
                "bytes": len(content),
                "uppercase": len(data["uppercase"]),
                "decimal_zero": len(data["decimal_zero"]),
                "nonprintable": len(data["nonprintable"]),
                "python_executable_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
            }
        )
    )


if __name__ == "__main__":
    main()
