# Coord operations

SafeYolo runs a host-local, authenticated NATS server for retained coord room
messages. SafeYolo owns its lifecycle; operators should not launch a second
server or edit the generated NATS configuration.

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
