"""Small source-runtime oracle for surrogateescape regex escape parity."""

import json
import re

# Keep the hand-written parity cases for both escape spellings and slash
# runs. The generated rows then exercise every source-byte identity accepted
# by surrogateescape, rather than selecting only one malformed byte.
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
CASES.extend(
    (rf"key-\uDC{byte:02X}", b"key-" + bytes([byte]))
    for byte in range(0x80, 0x100)
)


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
