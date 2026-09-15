"""Actual Python JSON and circuit persistence, using only caller-owned files."""

import json
import pathlib
import sys
from unittest.mock import patch

from safeyolo.mitm_addons.circuit_breaker import CircuitBreaker, InMemoryCircuitState

STATE_TEXT = r'''{
  "zeta": {"state": "closed", "failure_count": Infinity, "failure_streak": 0,
    "unknown": {"nested": [NaN, Infinity, -Infinity, {"NaN": "Infinity"}],
      "$serde_json::private::Number": "NaN", "yaml_date": "2001-02-03",
      "duplicate": 1, "last": 2, "duplicate": 3,
      "unicode": "café\n\u2028", "zero": -0.0}},
  "api": {"state": "half_open", "failure_count": NaN,
    "failure_streak": NaN, "success_count": -Infinity}
}'''


def cases():
    valid = [
        'NaN', 'Infinity', '-Infinity', '1e999', '-1e999', '-0.0',
        'true', 'false', 'null', '18446744073709551617', '1.2345678901234567',
        '"NaN Infinity -Infinity"', r'"escaped \"NaN\""',
        r'{"NaN":"NaN","nested":[NaN,{"value":-Infinity}]}',
        r'{"a":NaN,"z":1,"a":Infinity,"a":-Infinity}',
        r'{"$serde_json::private::Number":"NaN","yaml_date":"2001-02-03"}',
        r'{"a\u0062":1,"ab":2,"tail":NaN}',
        r'[[],{},[1,2],{"z":3}]', r'"\ud83d\ude00 café\n\t\u2028"',
        ' \t\n { "x" : NaN } \r', STATE_TEXT,
        '[' * 256 + 'NaN' + ']' * 256,
    ]
    invalid = [
        '', 'nan', 'NAN', '+Infinity', '-NaN', 'Inf', 'Infinityx', 'NaN0',
        '[NaN,]', '{"x":NaN,}', '{NaN:1}', '[NaN Infinity]', '{}[]',
        'NaN false', '01', '+1', '1.', '1e', '.5', '/*x*/NaN',
        r'"\x41"', r'"\uZZZZ"', '"NaN', '[NaN', '{"x" NaN}',
    ]
    output = []
    for text in valid + invalid:
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            output.append({"source": text, "accepted": False})
        else:
            output.append({"source": text, "accepted": True,
                           "compact": json.dumps(value), "pretty": json.dumps(value, indent=2)})
    return output


def source_state(path=None):
    with patch.object(InMemoryCircuitState, '_start_snapshots'):
        state = InMemoryCircuitState(path)
    if path is None:
        state._states = json.loads(STATE_TEXT)
    return state


def workflow():
    cb = CircuitBreaker()
    cb._state = source_state()
    events = []
    cb._log_circuit_event = lambda name, domain, flow=None, **details: events.append(
        {"event": name, "domain": domain, "details": details or None})
    with (
        patch('safeyolo.mitm_addons.circuit_breaker.time.time', return_value=100.0),
        patch('safeyolo.mitm_addons.circuit_breaker.random.uniform', return_value=0.0),
    ):
        cb._reconcile_stale_circuits()
        status = cb.record_failure('api')
        status_dict = vars(status).copy()
        status_dict['state'] = status.state.value
        return {"status": json.dumps(status_dict), "events": [json.dumps(event) for event in events],
                "stats": json.dumps(cb.get_stats()),
                "snapshot": json.dumps({"states": cb._state._states, "saved_at": 100.0})}


def main():
    if len(sys.argv) == 1:
        json.dump({"cases": cases(), "state": STATE_TEXT, "workflow": workflow(),
                   "inherited_gap": {"source": r'"\ud800"',
                                     "compact": json.dumps(json.loads(r'"\ud800"'))}}, sys.stdout)
        return
    mode, path = sys.argv[1], pathlib.Path(sys.argv[2])
    if mode == 'create':
        state = source_state()
        state._state_file = path
        with patch('safeyolo.mitm_addons.circuit_breaker.time.time', return_value=100.0):
            state._save_state()
    elif mode == 'inspect':
        state = source_state(path)
        json.dump({"states": state._states, "saved_at": 100.0}, sys.stdout, indent=2)
    else:
        raise ValueError('unknown oracle operation')


if __name__ == '__main__':
    main()
