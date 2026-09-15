"""Actual local policy/logger controls, synthetic values and no network workload."""

import argparse
import copy
import json
import logging
import os
import socket
import tempfile
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from pdp.client import LocalPolicyClient, PolicyClientConfig
from safeyolo.core.utils import sanitize_for_log
from safeyolo.mitm_addons.request_logger import RequestLogger
from safeyolo.policy import engine as engine_module
from safeyolo.policy import loader as loader_module

HERE = Path(__file__).resolve().parent


def cases():
    rows = [("omitted", "json", "{}", "api.fixture.invalid", "/a")]

    def add(name, quiet, host="api.fixture.invalid", path="/a"):
        rows.append((name, "json", json.dumps({"addons": {"request_logger": {"quiet_hosts": quiet}}}), host, path))

    add("exact_lower", {"hosts": ["API.FIXTURE.INVALID"]})
    add("host_question_literal", {"hosts": ["api.?ixture.invalid"]})
    add("host_bracket_literal", {"hosts": ["api.[f]ixture.invalid"]})
    add("wildcard_host", {"hosts": ["*.fixture.invalid"]})
    add("wildcard_crosses_labels", {"hosts": ["*.fixture.invalid"]}, "x.y.fixture.invalid")
    add("unicode_lower", {"hosts": ["İΣ.FIXTURE.INVALID"]}, "i\u0307ς.fixture.invalid")
    for name, pattern, path in [
        ("path_star_slash", "/a*", "/a/b"),
        ("path_case", "/A*", "/a"),
        ("path_question", "/?", "/é"),
        ("path_class", "/[a-c]", "/b"),
        ("path_negated", "/[!a-c]", "/z"),
        ("path_literal_close", "/[]]", "/]"),
        ("path_unclosed_class", "/[abc", "/[abc"),
        ("path_newline", "/*", "/a\nb"),
    ]:
        add(name, {"paths": {"api.fixture.invalid": [pattern]}}, path=path)
    add("hosts_not_list", {"hosts": "wrong"})
    add("paths_not_dict", {"paths": []})
    add("path_list_not_list", {"paths": {"api.fixture.invalid": 2}})
    add("host_integer", {"hosts": [7]})
    add("host_container", {"hosts": [["*"]]})
    add("host_mapping", {"hosts": [{"*": True}]})
    add("quiet_scalar", None)
    add("lazy_bad_pattern_unreached", {"paths": {"other.invalid": [3]}})
    add("lazy_bad_pattern_reached", {"paths": {"api.fixture.invalid": [3]}})
    add("lazy_bad_pattern_after_match", {"paths": {"api.fixture.invalid": ["/*", 3]}})
    add("host_match_before_bad_pattern", {"hosts": ["api.fixture.invalid"], "paths": {"api.fixture.invalid": [3]}})
    for name, source in [
        ("unrelated_timestamp", "addons: {request_logger: {quiet_hosts: {hosts: [api.fixture.invalid]}}, other: {observed: 2001-02-03}}"),
        ("hosts_date", "addons: {request_logger: {quiet_hosts: {hosts: 2001-02-03}}}"),
        ("paths_datetime", "addons: {request_logger: {quiet_hosts: {paths: 2001-02-03T04:05:06Z}}}"),
        ("host_date", "addons: {request_logger: {quiet_hosts: {hosts: [2001-02-03]}}}"),
        ("path_date_reached", "addons: {request_logger: {quiet_hosts: {paths: {api.fixture.invalid: [2001-02-03]}}}}"),
        ("temporal_key", "addons: {request_logger: {quiet_hosts: {paths: {2001-02-03: ['/*']}}}}"),
        ("temporal_key_invalid_list", "addons: {request_logger: {quiet_hosts: {paths: {2001-02-03: 2}}}}"),
        ("authored_date_object", "addons: {request_logger: {quiet_hosts: {hosts: {yaml_date: '2001-02-03'}}}}"),
        ("nested_settings_ignored", "addons: {request_logger: {settings: {quiet_hosts: {hosts: [api.fixture.invalid]}}}}"),
        ("disabled_ignored", "addons: {request_logger: {enabled: false, quiet_hosts: {hosts: [api.fixture.invalid]}}}"),
    ]:
        rows.append((name, "yaml", source, "api.fixture.invalid", "/a"))
    rows.append(("hosts_time", "toml", "[addons.request_logger.quiet_hosts]\nhosts=04:05:06\n", "api.fixture.invalid", "/a"))
    return rows


def run():
    logging.disable(logging.CRITICAL)
    rows = []
    with tempfile.TemporaryDirectory(prefix="request-logger-source-") as temporary, ExitStack() as stack:
        root = Path(temporary)
        stack.enter_context(patch.dict(os.environ, {"SAFEYOLO_DATA_DIR": temporary, "SAFEYOLO_LOG_PATH": str(root / "audit")}))
        stack.enter_context(patch.object(loader_module.PolicyLoader, "start_watcher"))
        for module in (loader_module, engine_module):
            stack.enter_context(patch.object(module, "write_event"))
        for name in ("getaddrinfo", "create_connection"):
            stack.enter_context(patch.object(socket, name, side_effect=AssertionError("no network in source oracle")))
        for index, (name, format_name, source, host, path) in enumerate(cases()):
            file = root / f"{index}.{format_name}"
            file.write_text(source)
            client = LocalPolicyClient(PolicyClientConfig(baseline_path=file))
            try:
                core = client._pdp._engine
                assert core.get_baseline() is not None, name
                before = copy.deepcopy(core._budget_tracker._budgets), core._evaluations, client._pdp.policy_hash
                sensor = client.get_sensor_config()
                addon = RequestLogger()
                error = message = quiet = None
                try:
                    addon._load_quiet_hosts_from_pdp(sensor)
                except (ValueError, TypeError, AttributeError) as exception:
                    error, message = type(exception).__name__, sanitize_for_log(str(exception)) if isinstance(exception, ValueError) else None
                match_error = None
                if error is None:
                    try:
                        quiet = addon._should_quiet(host, path)
                    except (TypeError, AttributeError) as exception:
                        match_error = type(exception).__name__
                assert before == (core._budget_tracker._budgets, core._evaluations, client._pdp.policy_hash)
                rows.append({"case": name, "format": format_name, "source": source, "host": host, "path": path,
                             "hash": sensor["policy_hash"], "load_error": error, "message": message,
                             "match_error": match_error, "quiet": quiet, "state_unchanged": True})
            finally:
                client.shutdown()
    durations = []
    for start, now in [(None, 100.0), (0.0, 100.0), (99.87655, 100.0), (100.12345, 100.0),
                       (0.001, 0.00105), (0.001, 0.00115), (0.001, 0.00125), (0.001, 0.000999),
                       (0.1, 0.3), (1e20, 1.0), (1.0, 1e20)]:
        value = round((now - start) * 1000, 1) if start else None
        durations.append({"start": start, "now": now, "value": value, "hex": value.hex() if value is not None else None})
    sanitation = [{"input": value, "output": sanitize_for_log(value)} for value in
                  ["ordinary", "a\nb\t\x00c", "\x1b[31mred\x1b[0m", "é\u0301界", "x" * 205, "a\u202eb\u200dc", "x\x01\x02?y"]]
    return {"quiet": rows, "durations": durations, "sanitize": sanitation, "network_calls": 0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = run()
    target = HERE / "request_logger_source.json"
    if args.write:
        target.write_text(json.dumps(result, indent=2, ensure_ascii=True) + "\n")
    if args.check:
        assert json.loads(target.read_text()) == result
    print(json.dumps({"quiet": len(result["quiet"]), "durations": len(result["durations"]), "sanitation": len(result["sanitize"]), "network_calls": 0}))


if __name__ == "__main__":
    main()
