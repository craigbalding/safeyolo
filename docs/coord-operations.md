# Coord operations

SafeYolo runs a host-local, authenticated NATS server for retained coord room
messages. SafeYolo owns its lifecycle; operators should not launch a second
server or edit the generated NATS configuration.

## Room storage

Rooms share the managed NATS server's total storage budget. They do not reserve
a fixed number of bytes per room. Age and message-count retention still remove
old messages within each room. The message-size limit is unchanged.

At normal Coord startup and before creating a room, SafeYolo upgrades the former
100 MiB room byte reservation in place. The upgrade preserves messages,
sequences, subjects, and other stream settings. It only changes streams whose
enforced settings match the known old contract; unrelated configuration drift
is not overwritten. No room deletion or server restart is required for the
stream update.

Removing reservations removes the accidental ten-room ceiling; it does not
make storage unlimited. Rooms compete for the shared budget. If actual stored
data exhausts that budget, new writes can fail across rooms. The server does
not evict another room's history to make space for a write.

## Credential lifecycle

On the first coord start, SafeYolo generates a random password and stores it at
`~/.safeyolo/data/coord/nats/creds`. The host account that runs SafeYolo owns
the credential. The `nats` directory is mode `0700` and the credential file is
mode `0600`.

`SAFEYOLO_COORD_DATA_DIR` is the coord-specific path override. When it is set,
the credential is at `$SAFEYOLO_COORD_DATA_DIR/nats/creds`. Setting only
`SAFEYOLO_CONFIG_DIR` does **not** relocate coord data in the current release;
for an isolated non-default instance, also set `SAFEYOLO_COORD_DATA_DIR` to the
intended coord directory and use the same environment for every `safeyolo`
lifecycle command.

The credential is reused across ordinary `safeyolo stop` / `safeyolo start`
cycles. It is not rotated on restart or on a schedule. If the credential file
is absent at startup, SafeYolo atomically generates a replacement. The
generated `nats.conf` contains an environment-variable reference, not the
password; the password is supplied only in the managed NATS child process's
environment. Retained JetStream data lives separately under
`nats/jetstream`.

## Reconcile a running proxy

If the proxy is already running, `safeyolo start` reconciles the managed Coord
runtime. A healthy NATS process stays running. If the managed NATS process is
absent, SafeYolo starts it, bootstraps the existing Coord registry, and recovers
pending attention data. This operation preserves the instance identity,
credentials, rooms, memberships, control state, and retained JetStream history.

If NATS startup, Coord bootstrap, or attention recovery fails, the command
reports that Coord is degraded and gives diagnostic commands and log paths. It
does not restart the proxy, and the proxy remains available. Run `safeyolo
doctor` and inspect the reported log before you retry.

## Manual rotation

Rotation is disruptive and has no old/new overlap or grace period. Stop the
whole SafeYolo instance first, fail closed unless both stop checks prove the
message plane stopped, remove exactly the credential file, and then start it
again:

```bash
coord_data_dir="${SAFEYOLO_COORD_DATA_DIR:-${HOME}/.safeyolo/data/coord}"
credential_file="${coord_data_dir}/nats/creds"

stop_output="$(safeyolo stop 2>&1)"
printf '%s\n' "${stop_output}"
case "${stop_output}" in
  *"coord message plane stopped"*) ;;
  *) printf '%s\n' "Rotation aborted: coord stop was not confirmed." >&2; exit 1 ;;
esac

doctor_output="$(safeyolo doctor --json || true)"
if ! jq -e '
  [.checks[] | select(
    .name == "Coord message plane" and
    .message == "nats-server not running; coord API will 503"
  )] | length == 1
' >/dev/null <<<"${doctor_output}"; then
  printf '%s\n' "Rotation aborted: coord is not confirmed stopped." >&2
  exit 1
fi

if [ ! -f "${credential_file}" ]; then
  printf '%s\n' "Rotation aborted: credential file was not found." >&2
  exit 1
fi
if ! rm -- "${credential_file}"; then
  printf '%s\n' "Rotation aborted: credential file was not removed." >&2
  exit 1
fi
safeyolo start
```

Do not continue merely because `safeyolo stop` returned normally. Stop is
best-effort: it can warn about a healthy, wedged, or unknown NATS process and
still let the rest of SafeYolo shut down, and it does not stop coord again when
the proxy was already absent. The success line plus the independent doctor
check close both cases. Abort and investigate any warning, failed guard, or
state other than the exact `not running` result; do not delete the credential
while a NATS process may still be alive.

Do not remove `${coord_data_dir}/nats`, its `jetstream` child, or the wider
coord data directory. Those paths hold retained room history and control
state. If `test -f` fails, stop and confirm the environment and path instead
of deleting a broader directory.

Every connected NATS client is disconnected during the stop. After startup,
only the replacement password works, so clients must reconnect; agents may see
temporary coord-unavailable responses during the rotation. SafeYolo's managed
clients reconnect as the instance starts.

Verify the runtime is healthy and retained history is readable without
displaying either credential:

```bash
safeyolo status
safeyolo coord room list
safeyolo coord chat ROOM_NAME
```

`safeyolo status` should report `Coord (nats-server)` as healthy. Attach to a
known room and confirm its pre-rotation messages are present, then enter `:q`
to detach.

## Interactive chat requires a terminal

The default `safeyolo coord chat ROOM_NAME` mode is an editable prompt and
requires both standard input and standard output to be terminals. If either
stream is piped or redirected, the command exits before connecting to Coord
with an actionable error; it does not consume the input or emit terminal
cursor-control bytes into the caller's shell. Use `--observe` when a
non-interactive room tail is needed, or run interactive chat from a terminal.

## Scriptable operator sends

Use `safeyolo coord send` when a trusted operator must send one ordinary Coord
message without opening an interactive terminal session. The command requires
exactly one body source:

```bash
safeyolo coord send ROOM_NAME "Operator direction"
safeyolo coord send ROOM_NAME --file direction.md --to relay --to lens
printf '%s\n' "Operator direction" | safeyolo coord send ROOM_NAME --stdin --to relay
```

A positional `TEXT`, `--file`, and `--stdin` are mutually exclusive. The
command rejects a missing, empty, or whitespace-only body. The file and stdin
sources use UTF-8. Use `--content-type text/plain` when the receiver requires
plain text; the default is `text/markdown`.

Without `--to`, the command requests room-wide attention. Repeat `--to` to
request targeted attention for multiple agents. Each target must be an active,
receive-authorized member of the named room. The command uses the same
SafeYolo-generated operator attribution and `api.send` authorization as
interactive chat. It reports authorization, invalid-room, invalid-target,
provider, and publish-outcome errors without printing credentials.

`coord send` is separate from `coord chat --observe`. The `--observe` flag
remains read-only, and `dispatch-trigger` remains the specialized Dispatch
publication command rather than a generic message interface.

## Secret-handling boundary

Status, doctor output, lifecycle diagnostics, generated configuration, and
logs must never contain the raw credential. Do not print, copy into a command
line, attach, or log the contents of `creds`; use the health and history checks
above as the verification signal.

The file modes protect the credential from other host accounts. They are not a
security boundary against a compromised operator account: a same-UID host
process can read host-local files and may be able to inspect process state or
environment. Rotate after suspected operator-account compromise only as part
of recovering that account and host.
