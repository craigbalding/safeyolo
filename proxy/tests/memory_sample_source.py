"""Observe actual source proc-memory parsing with owned in-memory input only."""

from __future__ import annotations

import argparse
import io
import json
import logging
import os
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(os.environ.get('SAFEYOLO_SOURCE_ROOT', Path(__file__).resolve().parents[2]))
sys.path[:0] = [str(ROOT / 'cli' / 'src'), str(ROOT)]
logging.disable(logging.CRITICAL)
from safeyolo.mitm_addons import memory_monitor as monitor  # noqa: E402


class FailedRead(io.RawIOBase):
    def __init__(self, content):
        self.sent = False
        self.content = content

    def readable(self):
        return True

    def readinto(self, target):
        if self.sent:
            raise OSError('owned read failure')
        self.sent = True
        content = self.content
        target[:len(content)] = content
        return len(content)


def observe(name, content, expected, *, failed=False):
    def owned_open(path):
        assert path == '/proc/self/status'
        data = io.BufferedReader(FailedRead(content)) if failed else io.BytesIO(content)
        return io.TextIOWrapper(data, encoding='utf-8', newline=None)

    with patch.object(monitor, 'open', side_effect=owned_open, create=True):
        try:
            result = {'values': list(monitor._read_proc_memory())}
        except IndexError:
            result = {'exception': 'IndexError'}
    assert result == expected, (name, result, expected)
    return {'name': name, 'result': result}


def capture():
    rows = []
    for name, content, rss, peak in [
        ('empty', '', 0, 0),
        ('ordinary', 'Name: owned\nVmRSS: 2048 kB\nVmHWM: 4096 kB\n', 2048, 4096),
        ('missing_peak_ignored_unit', 'VmRSS: 2048 ignored-unit\n', 2048, 2048),
        ('peak_lower_bound', 'VmHWM: 2 kB\nVmRSS: 8 kB\n', 8, 8),
        ('negative', 'VmRSS: -2 kB\nVmHWM: -3 kB\n', -2, -2),
        ('exact_prefix_repeated', ' VmRSS: 99 kB\nVmRSS: 1 kB\nVmRSS: 4 kB\n', 4, 4),
        ('value_partial', 'VmRSS: 8 kB\nVmHWM: invalid\nVmRSS: 99 kB\n', 8, 8),
        ('unicode_integer_newlines', 'VmRSS:\u2003+٢_٤ kB\r\nVmHWM: 30 kB\r', 24, 30),
    ]:
        rows.append(observe(name, content.encode(), {'values': [rss, peak]}))
    rows.append(observe('missing_token', b'VmRSS:\n', {'exception': 'IndexError'}))
    rows.append(observe('decode_before_lines', b'VmRSS: 8 kB\n\xff', {'values': [0, 0]}))
    later = b'VmRSS: 8 kB\n'.ljust(8191, b' ') + b'\n\xff'
    rows.append(observe('decode_after_reached_chunk', later, {'values': [8, 8]}))
    rows.append(observe('read_failure_after_partial', b'VmRSS: 8 kB\n', {'values': [8, 8]}, failed=True))
    rows.append(observe('pending_cr_before_read_failure', b'VmRSS: 8 kB\r', {'values': [0, 0]}, failed=True))
    return {'source_sample_rows': len(rows), 'rows': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    output = parser.add_mutually_exclusive_group()
    output.add_argument('--check', type=Path)
    output.add_argument('--write', type=Path)
    args = parser.parse_args()
    result = capture()
    if args.check:
        assert result == json.loads(args.check.read_text()), 'source sample observations changed'
        print(json.dumps({'source_sample_rows': len(result['rows'])}))
    elif args.write:
        args.write.write_text(json.dumps(result, indent=2) + '\n')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
