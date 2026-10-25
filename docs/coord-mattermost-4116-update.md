# Flat conversation on the historical Mattermost host adapter

This procedure changes only the Python adapter loaded by the reported
`4116c7ee` host. It adds new top-level channel input without a full host upgrade.
The maintained native adapter and its setup are in
[Mattermost Coord adapter](coord-mattermost.md).

Sylab owns host inspection, installation, restart, and the live conversation.
Apply this procedure only after independent review of the compatibility delta
and this procedure. Source tests do not prove installed delivery.

The supported source is `4116c7ee3d44c623e9d89ae60c14ce671d0f295d`.
The compatibility commit is
[`ea2c0bb4189ec04a3d069d2662794333c1bdc0d5`](https://github.com/craigbalding/safeyolo/commit/ea2c0bb4189ec04a3d069d2662794333c1bdc0d5),
on `forge/issue-442-mattermost-4116`. Its production delta changes only
`cli/src/safeyolo/coord/mattermost.py`. The other changed file contains focused
tests. Do not switch the production checkout to that branch or apply its tests.

## Bind the installed source

On the operator host, use the account and environment of the running adapter.
Identify that process's launcher, Python interpreter, source checkout, adapter
configuration path, and stop/start method. Preserve its configured proxy,
Certificate Authority (CA), `SAFEYOLO_CONFIG_DIR`, and Coord data settings.
Do not print tokens, private configuration values, or the full environment.

The procedure supports a Python installation that imports the four files below
from that checkout with their exact supported contents. Other dirty files do
not block the update. An unsupported relevant-file change needs examination
of that specific diff; do not discard local changes or infer a full-upgrade
prerequisite. A different loaded layout needs a procedure bound to that layout.

Before the commands below, set these shell variables to the observed absolute
paths: `adapter_python` is the running launcher's interpreter;
`adapter_checkout` is its source checkout; `adapter_config` is its existing
external Mattermost TOML file; and `adapter_patch` is a small disposable patch
file outside the checkout. Keep the running adapter unchanged during inspection.
Fetch only the compatibility branch into the existing Git database:

```sh
compat_base=4116c7ee3d44c623e9d89ae60c14ce671d0f295d
compat_head=ea2c0bb4189ec04a3d069d2662794333c1bdc0d5
git -C "$adapter_checkout" fetch origin forge/issue-442-mattermost-4116
git -C "$adapter_checkout" cat-file -e "$compat_head^{commit}"
```

With the same interpreter and import environment as the adapter, check both
the loaded paths and their source bytes. This read-only check prints only
supported file paths. It refuses before any patch write if a relevant file
differs, including a previously applied patch:

```sh
"$adapter_python" - "$adapter_checkout" "$compat_base" <<'PY'
import importlib
import pathlib
import subprocess
import sys

checkout = pathlib.Path(sys.argv[1]).resolve(strict=True)
base = sys.argv[2]
for name in ("coord.mattermost", "coord.mattermost_actions", "coord.api", "commands.coord"):
    module = importlib.import_module("safeyolo." + name)
    relative = "cli/src/safeyolo/" + name.replace(".", "/") + ".py"
    loaded = pathlib.Path(module.__file__).resolve(strict=True)
    expected_path = (checkout / relative).resolve(strict=True)
    if loaded != expected_path:
        raise SystemExit("Unsupported loaded path: " + str(loaded))
    expected = subprocess.check_output(["git", "-C", str(checkout), "show", base + ":" + relative])
    if loaded.read_bytes() != expected:
        raise SystemExit("Unsupported local change: " + str(loaded))
    print("Supported:", loaded)
PY
```

## Apply and restart the adapter

Stop only the owned adapter through its observed supervisor, or send SIGTERM
to that verified process. Wait for it to exit and release its SQLite lease and
callback socket. Leave Coord, NATS, the proxy, guests, and the HTTPS tunnel
running. Repeat the read-only check immediately before applying the patch.
If that check fails, stop here and return the exact path and relevant diff.

Generate and check the single-file delta. Run the apply command once only
after the preceding checks succeed:

```sh
git -C "$adapter_checkout" diff "$compat_base" "$compat_head" -- \
  cli/src/safeyolo/coord/mattermost.py > "$adapter_patch"
git -C "$adapter_checkout" apply --check "$adapter_patch"
git -C "$adapter_checkout" apply "$adapter_patch"
"$adapter_python" - "$adapter_checkout" "$compat_head" <<'PY'
import pathlib
import subprocess
import sys

relative = "cli/src/safeyolo/coord/mattermost.py"
expected = subprocess.check_output(["git", "-C", sys.argv[1], "show", sys.argv[2] + ":" + relative])
if (pathlib.Path(sys.argv[1]) / relative).read_bytes() != expected:
    raise SystemExit("Installed adapter differs from the reviewed candidate")
print("Reviewed adapter source installed")
PY
"$adapter_python" -m safeyolo.cli coord mattermost check --config "$adapter_config"
"$adapter_python" -m safeyolo.cli coord mattermost run --config "$adapter_config"
```

The check must print `Mattermost adapter configuration is valid.` The final
command runs in the foreground. If an existing host supervisor owns the
adapter, use that supervisor's observed start command with the same interpreter,
arguments, and environment instead. Do not start a second process.

No operator-owned configuration file needs an edit. Keep the existing adapter
TOML at `adapter_config`, its `bot_token_file`, and its `state_file` unchanged.
All keys retain their values: `version`, `server_url`, `bot_token_file`,
`bot_user_id`, `operator_user_id`, `state_file`, `poll_interval_seconds`,
each room's `coord_room`, `channel_id`, and `backfill`, and any configured
`action_listener_host`, `action_listener_port`, `public_callback_base_url`,
`action_capability_ttl_seconds`, and `trusted_action_agent_ids`.
No new secret, guest file, principal, grant, or tunnel setting is required.
The only operator-owned source file changed is the checked `mattermost.py`.
Remove the disposable patch file after a verified installation.

Preserve the SQLite database, its write-ahead log, and its sibling lease file.
The patch changes no database schema or adapter identity. If an append is
pending or its outcome is uncertain, inspect canonical room history before
recovery. Restart still refuses automatic replay. Do not delete state, reset a
cursor, or repeat the append. If a patch command's outcome is uncertain, inspect
the source against the base and candidate before another write.

## Observe the installed exchange

After the adapter is running, the configured human sends a **new top-level**
text post in the existing mapped channel. Sylab must receive one canonical
operator message with the original text and that Mattermost post ID. No prior
projection is needed. Sylab replies through the existing mapped room; the bot
must create a readable **new post in the same channel**. A thread exchange
does not prove this result.

Let normal polling continue, then restart only the adapter with the same state
and check that the incoming post still has only one canonical append. Include
a new flat post beginning `!safeyolo approve`: its body must have
`kind="message"`, `action=null`, and no `coord_msg_id`. Record the input post
ID, canonical message ID, reply post ID/channel, installed compatibility commit,
and observed results. Do not include credentials or private configuration.
