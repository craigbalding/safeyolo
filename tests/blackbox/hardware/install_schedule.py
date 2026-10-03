"""Install and read back the operator account's paired hardware cron entry.

Run on the control host with existing Rundeck, Tart, Bristol and publication
bindings. This changes only the marked entry and preserves unrelated cron work.
Installation and trigger observations do not accept either hardware lane.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import pwd
import shlex
import subprocess
import sys
import time
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "cli/src"))
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from tests.blackbox.hardware import attempt_results, paired
else:
    from . import attempt_results, paired

START = "# safeyolo hardware blackbox:start"
END = "# safeyolo hardware blackbox:end"


def current_crontab() -> str:
    result = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=30, check=False)
    if result.returncode == 0:
        return result.stdout
    if result.returncode == 1 and not result.stdout and result.stderr.strip().startswith("no crontab for "):
        return ""
    raise ValueError("cannot inspect operator crontab")


def replace_entry(previous: str, entry: str) -> str:
    if previous.count(START) != previous.count(END) or previous.count(START) > 1:
        raise ValueError("ambiguous existing hardware cron markers")
    if START in previous:
        start, finish = previous.index(START), previous.index(END) + len(END)
        if finish < start:
            raise ValueError("reversed existing hardware cron markers")
        previous = previous[:start] + previous[finish:].lstrip("\n")
    return previous.rstrip("\n") + ("\n" if previous.strip() else "") + entry


def install(config_path: Path, cron_path: Path, hour: int, minute: int) -> dict:
    if not 0 <= hour <= 23 or not 0 <= minute <= 59:
        raise ValueError("cron hour/minute are outside their ranges")
    if sys.version_info[:2] not in {(3, 12), (3, 13)}:
        raise ValueError("the trusted controller needs Python 3.12 or 3.13")
    config = attempt_results.read_json(config_path)
    paired.checked_controller(paired.ROOT, config["controller_revision"])
    attempts = Path(config["attempts"])
    attempts.mkdir(mode=0o700, parents=True, exist_ok=True)
    log = attempts / "cron.log"
    command = ("PATH=" + shlex.quote(os.environ["PATH"]) + " "
               + paired.shell([sys.executable, paired.ROOT / "tests/blackbox/hardware/paired.py", "overnight",
                            "--config", config_path.resolve()]) + " >>" + shlex.quote(str(log)) + " 2>&1")
    if "\n" in command or "\r" in command or "%" in command:
        raise ValueError("cron paths contain unsupported newline or percent characters")
    timezone = time.strftime("%Z%z")
    account = pwd.getpwuid(os.getuid()).pw_name
    entry = (f"{START}\n# Host: {platform.node()}\n# Account: {account}\n"
             f"# Timezone: host local time ({timezone} at installation)\n"
             f"{minute} {hour} * * * {command}\n{END}\n")
    before = current_crontab()
    expected = replace_entry(before, entry)
    subprocess.run(["crontab", "-"], input=expected, capture_output=True, text=True, timeout=30, check=True)
    observed = current_crontab()
    if observed != expected:
        raise ValueError("installed cron entry could not be read back exactly")
    cron_path.write_text(entry)
    return {"host": platform.node(), "account": account, "timezone": timezone,
            "controller_revision": config["controller_revision"], "cron": str(cron_path), "entry": entry}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--cron-file", type=Path, required=True, help="retain the actual read-back entry for the deployment README")
    parser.add_argument("--hour", type=int, default=2)
    parser.add_argument("--minute", type=int, default=17)
    args = parser.parse_args()
    result = install(args.config, args.cron_file, args.hour, args.minute)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
