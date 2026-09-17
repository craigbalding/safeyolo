"""Small source-runtime oracle for surrogateescape regex escape parity."""

import json
import re


CASES = [
    (r"key-\udcff", b"key-\xff"),
    (r"key-\\udcff", b"key-\\udcff"),
    (r"key-\\udcff", b"key-\xff"),
    (r"key-\\\udcff", b"key-\\\xff"),
    (r"key-\U0000dcff", b"key-\xff"),
    (r"key-\\U0000dcff", b"key-\\U0000dcff"),
    (r"key-\\U0000dcff", b"key-\xff"),
    (r"key-\\\U0000dcff", b"key-\\\xff"),
]


def main() -> None:
    rows = []
    for pattern, raw in CASES:
        subject = raw.decode("utf-8", "surrogateescape")
        rows.append(
            {
                "pattern": pattern,
                "bytes": list(raw),
                "matched": bool(re.search(pattern, subject)),
            }
        )
    print(json.dumps(rows))


if __name__ == "__main__":
    main()
