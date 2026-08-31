#!/usr/bin/env python3
"""Redact credential-shaped values from lab text streams.

This is defense in depth. Do not intentionally feed credential files or
interactive login output to this program.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import TextIO

REDACTED = "[REDACTED_CREDENTIAL]"

PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?i)((?:authorization|proxy-authorization)\s*[:=]\s*"
            r"(?:bearer|basic)\s+)[^\s\",}]+"
        ),
        rf"\1{REDACTED}",
    ),
    (
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\."
            r"[A-Za-z0-9_-]{10,}\b"
        ),
        REDACTED,
    ),
    (
        re.compile(
            r"\b(?:sk-(?:proj-|ant-oat01-|ant-api03-)?|sgw_)"
            r"[A-Za-z0-9_-]{16,}\b"
        ),
        REDACTED,
    ),
    (
        re.compile(
            r'(?i)("(?:access_token|refresh_token|id_token|token|api_key|'
            r'session_key|oauth_token|authorization|proxy-authorization|'
            r'cookie|set-cookie|client_secret|password)"\s*:\s*")[^"]*(")'
        ),
        rf"\1{REDACTED}\2",
    ),
    (
        re.compile(
            r"(?i)((?:OPENAI_API_KEY|ANTHROPIC_API_KEY|CODEX_API_KEY|"
            r"CLAUDE_CODE_OAUTH_TOKEN|AGENT_TOKEN|ADMIN_TOKEN)\s*=\s*)\S+"
        ),
        rf"\1{REDACTED}",
    ),
)

PRIVATE_BEGIN = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|NATS USER JWT|USER NKEY SEED)-----"
)
PRIVATE_END = re.compile(
    r"-----END (?:[A-Z0-9 ]*PRIVATE KEY|NATS USER JWT|USER NKEY SEED)-----"
)


def redact_stream(source: TextIO, destination: TextIO) -> None:
    in_private_block = False
    for line in source:
        if in_private_block:
            if PRIVATE_END.search(line):
                in_private_block = False
            continue
        if PRIVATE_BEGIN.search(line):
            destination.write(REDACTED + "\n")
            in_private_block = True
            continue
        for pattern, replacement in PATTERNS:
            line = pattern.sub(replacement, line)
        destination.write(line)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Redact credential-shaped values from text evidence."
    )
    parser.add_argument("input", nargs="?", help="Input file; default stdin")
    parser.add_argument("output", nargs="?", help="Output file; default stdout")
    parser.add_argument(
        "--check-text",
        metavar="FILE",
        help="Validate the entire file as UTF-8 text and exit without output",
    )
    return parser.parse_args()


def check_text_file(path: Path) -> tuple[bool, str]:
    data = path.read_bytes()
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        return False, f"not valid UTF-8: {error}"

    allowed_controls = {"\t", "\n", "\r", "\f", "\x1b"}
    for character in text:
        codepoint = ord(character)
        if (codepoint < 32 and character not in allowed_controls) or codepoint == 127:
            return False, f"contains control character U+{codepoint:04X}"
    return True, ""


def paths_refer_to_same_file(input_path: Path, output_path: Path) -> bool:
    if input_path.resolve() == output_path.resolve():
        return True
    if output_path.exists():
        return input_path.samefile(output_path)
    return False


def main() -> int:
    args = parse_args()
    if args.check_text:
        if args.input or args.output:
            print("--check-text cannot be combined with input/output", file=sys.stderr)
            return 2
        path = Path(args.check_text)
        if not path.is_file():
            print(f"Not a regular file: {path}", file=sys.stderr)
            return 2
        safe, reason = check_text_file(path)
        if not safe:
            print(f"Refusing non-text file: {path}: {reason}", file=sys.stderr)
            return 4
        return 0

    if args.input:
        input_path = Path(args.input)
        if not input_path.is_file():
            print(f"Not a regular file: {input_path}", file=sys.stderr)
            return 2
    if args.input and args.output:
        output_path = Path(args.output)
        if paths_refer_to_same_file(input_path, output_path):
            print("Refusing identical input and output paths", file=sys.stderr)
            return 2

    source: TextIO = sys.stdin
    destination: TextIO = sys.stdout
    close_source = False
    close_destination = False
    try:
        if args.input:
            source = Path(args.input).open("r", encoding="utf-8", errors="strict")
            close_source = True
        if args.output:
            destination = Path(args.output).open("w", encoding="utf-8")
            close_destination = True
        redact_stream(source, destination)
    finally:
        if close_source:
            source.close()
        if close_destination:
            destination.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
