#!/usr/bin/env bash
# SafeYolo host setup script for OpenAI Codex CLI.
#
# Runs on the host (macOS or Linux), as you, when `safeyolo agent add
# <name> <folder> --host-script contrib/codex-host-setup.sh` is
# invoked. Stages SafeYolo-owned Codex settings into the agent's persistent
# home without importing host credentials, and writes a foreground command
# script that installs codex via mise on first boot and
# runs it with Codex sandboxing disabled thereafter. SafeYolo remains
# the outer containment boundary.
#
# See contrib/HOST_SCRIPT_GUIDE.md for the contract.

set -euo pipefail

: "${SAFEYOLO_AGENT_NAME:?must be run via 'safeyolo agent add --host-script'}"
: "${SAFEYOLO_AGENT_HOME:?must be run via 'safeyolo agent add --host-script'}"

AGENT_HOME="$SAFEYOLO_AGENT_HOME"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=lib/stage-safeyolo-context.sh
. "$SCRIPT_DIR/lib/stage-safeyolo-context.sh"

# --- Stage SafeYolo baseline + shared skill ---------------------------------
# The baseline is injected as Codex developer instructions at launch. The
# shared skill is linked into ~/.agents/skills/ for automatic discovery.
stage_safeyolo_context "$AGENT_HOME" codex

# The curated @codex-coord wrapper opts into a deterministic guest-side
# supervisor. Normal @codex runs never enter this branch.
if [ "${SAFEYOLO_CODEX_COORD_SUPERVISOR:-0}" = "1" ]; then
    SUPERVISOR_SRC="$SCRIPT_DIR/codex-coord-supervisor.py"
    if [ ! -f "$SUPERVISOR_SRC" ]; then
        echo "codex-host-setup: expected supervisor at $SUPERVISOR_SRC" >&2
        exit 1
    fi
    install -m 0755 "$SUPERVISOR_SRC" "$AGENT_HOME/.safeyolo/codex-coord-supervisor.py"
    if [ -n "${SAFEYOLO_CODEX_FACTORY_SNAPSHOT:-}" ]; then
        : "${SAFEYOLO_CODEX_FACTORY_ROLE:?set the factory role}"
        python3 - \
            "$AGENT_HOME/.safeyolo/codex-coord-supervisor.json" \
            "$AGENT_HOME/.safeyolo/AGENTS.md" \
            "$SAFEYOLO_AGENT_NAME" \
            "$SAFEYOLO_CODEX_FACTORY_SNAPSHOT" \
            "$SAFEYOLO_CODEX_FACTORY_ROLE" <<'PY'
import hashlib
import json
import os
import re
import sys
import tempfile

config_path, instructions_path, agent_name, snapshot_path, role_name = sys.argv[1:]
name_re = re.compile(r"[A-Za-z0-9_.-]+")
type_re = re.compile(r"[A-Z][A-Z0-9_]*")
if name_re.fullmatch(agent_name) is None or name_re.fullmatch(role_name) is None:
    raise SystemExit("codex-host-setup: invalid factory agent or role name")
try:
    snapshot_bytes = open(snapshot_path, "rb").read()
    snapshot = json.loads(snapshot_bytes)
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    raise SystemExit(f"codex-host-setup: cannot read factory snapshot: {exc}")
if not isinstance(snapshot, dict) or set(snapshot) != {
    "schema", "name", "room", "roles", "handoffs", "operator_input"
}:
    raise SystemExit("codex-host-setup: invalid factory snapshot shape")
if snapshot.get("schema") != "safeyolo.factory/v1":
    raise SystemExit("codex-host-setup: unsupported factory snapshot schema")
room = snapshot.get("room")
roles = snapshot.get("roles")
handoffs = snapshot.get("handoffs")
operator_input = snapshot.get("operator_input")
if name_re.fullmatch(str(room)) is None or not isinstance(roles, dict) or role_name not in roles:
    raise SystemExit("codex-host-setup: factory role or room is invalid")
role = roles[role_name]
if not isinstance(role, dict) or set(role) != {
    "agent", "contract", "contract_bytes", "contract_sha256", "contract_text"
}:
    raise SystemExit("codex-host-setup: factory role binding is invalid")
if role.get("agent") != agent_name or not isinstance(role.get("contract_text"), str):
    raise SystemExit("codex-host-setup: factory role is not bound to this agent")
contract_hash = hashlib.sha256(role["contract_text"].encode()).hexdigest()
if role.get("contract_bytes") != len(role["contract_text"].encode()):
    raise SystemExit("codex-host-setup: factory role contract byte count does not match")
if role.get("contract_sha256") != contract_hash:
    raise SystemExit("codex-host-setup: factory role contract hash does not match")
snapshot_id = hashlib.sha256(
    (json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
).hexdigest()
role_agents = {}
for key, value in roles.items():
    if name_re.fullmatch(str(key)) is None or not isinstance(value, dict):
        raise SystemExit("codex-host-setup: invalid factory role map")
    bound_agent = value.get("agent")
    if name_re.fullmatch(str(bound_agent)) is None:
        raise SystemExit("codex-host-setup: invalid factory agent binding")
    role_agents[key] = bound_agent
if not isinstance(handoffs, list) or not handoffs:
    raise SystemExit("codex-host-setup: factory has no handoffs")
runtime_handoffs = []
coordinators = []
handoff_types = set()
handoff_edges = []
for handoff in handoffs:
    required_handoff_keys = {"request", "from", "to", "responses"}
    if not isinstance(handoff, dict) or set(handoff) not in (
        required_handoff_keys,
        required_handoff_keys | {"response_to"},
    ):
        raise SystemExit("codex-host-setup: invalid factory handoff")
    request = handoff.get("request")
    source = handoff.get("from")
    destination = handoff.get("to")
    responses = handoff.get("responses")
    response_to = handoff.get("response_to", [source])
    if (
        type_re.fullmatch(str(request)) is None
        or source not in role_agents
        or destination not in role_agents
        or not isinstance(responses, list)
        or not responses
        or any(type_re.fullmatch(str(item)) is None for item in responses)
        or not isinstance(response_to, list)
        or not response_to
        or len(set(response_to)) != len(response_to)
        or any(role not in role_agents for role in response_to)
        or source not in response_to
    ):
        raise SystemExit("codex-host-setup: invalid factory handoff values")
    runtime_handoffs.append(
        {
            "request": request,
            "from": source,
            "to": destination,
            "responses": responses,
            "response_to": response_to,
        }
    )
    handoff_edges.append((source, destination))
    handoff_types.add(request)
    handoff_types.update(responses)
    if request == "TASK" and role_agents[source] not in coordinators:
        coordinators.append(role_agents[source])
if not coordinators:
    raise SystemExit("codex-host-setup: factory must declare a TASK coordinator handoff")
if not isinstance(operator_input, dict) or set(operator_input) != {"to", "types"}:
    raise SystemExit("codex-host-setup: invalid factory operator input")
operator_role = operator_input.get("to")
operator_types = operator_input.get("types")
if (
    operator_role not in role_agents
    or not isinstance(operator_types, list)
    or not operator_types
    or any(type_re.fullmatch(str(item)) is None for item in operator_types)
    or len(set(operator_types)) != len(operator_types)
    or handoff_types.intersection(operator_types)
):
    raise SystemExit("codex-host-setup: invalid factory operator input values")
reachable = {operator_role}
while True:
    expanded = reachable | {
        destination for source, destination in handoff_edges if source in reachable
    }
    if expanded == reachable:
        break
    reachable = expanded
unreachable = sorted(set(role_agents) - reachable)
if unreachable:
    raise SystemExit(
        "codex-host-setup: factory roles are unreachable from operator input: "
        + ", ".join(unreachable)
    )

config = {
    "agent_name": agent_name,
    "agent_room": f"{agent_name}-agent",
    "rooms": [room],
    "coordinators": coordinators,
    "workspace": "/workspace",
    "factory": {
        "schema": snapshot["schema"],
        "name": snapshot["name"],
        "role": role_name,
        "roles": role_agents,
        "handoffs": runtime_handoffs,
        "operator_input": {"to": operator_role, "types": operator_types},
        "contract_sha256": contract_hash,
        "snapshot_id": snapshot_id,
    },
}


def atomic_write(path, value):
    directory = os.path.dirname(path)
    fd, temporary = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


atomic_write(config_path, json.dumps(config, sort_keys=True, separators=(",", ":")) + "\n")
with open(instructions_path) as handle:
    baseline = handle.read()
atomic_write(
    instructions_path,
    baseline.rstrip() + "\n\n---\n\n" + role["contract_text"].lstrip(),
)
PY
    else
        : "${SAFEYOLO_CODEX_COORD_ROOMS:?set a comma-separated receive room list for @codex-coord}"
        : "${SAFEYOLO_CODEX_COORDINATORS:?set a comma-separated coordinator name list for @codex-coord}"
        python3 - \
            "$AGENT_HOME/.safeyolo/codex-coord-supervisor.json" \
            "$SAFEYOLO_AGENT_NAME" \
            "$SAFEYOLO_CODEX_COORD_ROOMS" \
            "$SAFEYOLO_CODEX_COORDINATORS" <<'PY'
import json
import os
import re
import sys
import tempfile

path, agent_name, room_text, coordinator_text = sys.argv[1:]


def names(label, value):
    result = []
    for item in value.split(","):
        item = item.strip()
        if not item or re.fullmatch(r"[A-Za-z0-9_.-]+", item) is None:
            raise SystemExit(f"codex-host-setup: invalid {label} name {item!r}")
        if item not in result:
            result.append(item)
    if not result:
        raise SystemExit(f"codex-host-setup: {label} list cannot be empty")
    return result


config = {
    "agent_name": names("agent", agent_name)[0],
    "rooms": names("room", room_text),
    "coordinators": names("coordinator", coordinator_text),
    "workspace": "/workspace",
}
directory = os.path.dirname(path)
fd, temporary = tempfile.mkstemp(prefix=".codex-coord-supervisor.", dir=directory)
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(config, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
except BaseException:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    raise
PY
    fi
fi

# --- Write the foreground command --------------------------------------------
cat > "$AGENT_HOME/.safeyolo-command" <<'EOF'
#!/usr/bin/env bash
set -e

export CODEX_HOME=/home/agent/.codex
: "${SAFEYOLO_CODEX_NODE_SPEC:=node@22}"
: "${SAFEYOLO_CODEX_NPM_SPEC:=npm:@openai/codex@latest}"
: "${SAFEYOLO_CODEX_NPM_PACKAGE:=@openai/codex@latest}"
# Do not rely on a login shell or BASH_ENV here. Linux launches this file
# through runsc exec, and /etc/environment may have reset PATH before this
# child shell starts. Keep mise's persistent per-agent layout explicit so a
# tool installed below is immediately executable in this same process.
export MISE_DATA_DIR="${MISE_DATA_DIR:-$HOME/.mise}"
export MISE_CONFIG_DIR="${MISE_CONFIG_DIR:-$HOME/.mise}"
export MISE_CACHE_DIR="${MISE_CACHE_DIR:-$HOME/.mise/cache}"
export MISE_OVERRIDE_CONFIG_FILENAMES="/etc/safeyolo/mise-project-config-disabled.toml"
export MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES="none"
export PATH="$HOME/.local/bin:$MISE_DATA_DIR/shims:${PATH}"

# --- version policy ---------------------------------------------------------
# Delayed deployment: do not pick up a release published minutes ago. Newer
# mise applies min_release_age to transitive npm dependencies too, which is
# the protection we want. Older mise does not have the setting at all, so
# verify that it took rather than assuming the default is there.
: "${SAFEYOLO_MIN_RELEASE_AGE:=24h}"
if mise settings get min_release_age >/dev/null 2>&1; then
    export MISE_MIN_RELEASE_AGE="$SAFEYOLO_MIN_RELEASE_AGE"
else
    echo "codex-host-setup: mise has no min_release_age setting;" \
         "no delayed-deployment protection on this build" >&2
fi

# `mise use -g <tool>@latest` is NOT a remote upgrade -- mise resolves
# `latest` against what is already installed. That matters on the repair
# path: a wrapper whose platform-native binary has gone still fails its
# probe, but mise can decide the existing install already satisfies
# `latest` and do nothing, leaving the agent unable to launch. Resolve the
# remote version explicitly and install that exact value.
sy_remote_version() { mise latest "$1" 2>/dev/null | tail -1; }
sy_local_version()  { mise latest --installed "$1" 2>/dev/null | tail -1; }

# Validate an existing command as well as its absence: the CLI is an npm
# wrapper plus a platform-native optional dependency, so the launcher can
# survive while the native binary does not (mise declining npm lifecycle
# scripts, or macOS Gatekeeper trashing the vendored Mach-O over a revoked
# signing cert). `command -v` alone still succeeds in that state and the
# install below is skipped, leaving the agent permanently unable to launch.
if ! command -v codex >/dev/null 2>&1 || ! codex --version >/dev/null 2>&1; then
    if [ -f /etc/alpine-release ]; then
        if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
            sudo -n apk add nodejs npm >&2
        fi
        npm install --global --prefix /home/agent/.local "$SAFEYOLO_CODEX_NPM_PACKAGE" >&2
    else
        mise use -g "$SAFEYOLO_CODEX_NODE_SPEC" >&2
        sy_tool="${SAFEYOLO_CODEX_NPM_SPEC%@*}"
        sy_target="$(sy_remote_version "$sy_tool")"
        if [ -n "$sy_target" ]; then
            mise use -g --force "${sy_tool}@${sy_target}" >&2
        else
            # Remote lookup failed (offline, registry down). Fall back to the
            # configured spec rather than refusing to start.
            echo "codex-host-setup: could not resolve a remote version for" \
                 "$sy_tool; falling back to $SAFEYOLO_CODEX_NPM_SPEC" >&2
            mise use -g "$SAFEYOLO_CODEX_NPM_SPEC" >&2
        fi
    fi
fi

# Report the version actually about to run, and say when a newer one exists
# without silently taking it. A pinned artifact ageing in place is fine; a
# pinned artifact ageing *invisibly* is what left an agent dead for months.
sy_tool="${SAFEYOLO_CODEX_NPM_SPEC%@*}"
sy_running="$(sy_local_version "$sy_tool")"
if [ -n "$sy_running" ]; then
    echo "codex-host-setup: codex $sy_running" >&2
    sy_available="$(sy_remote_version "$sy_tool")"
    if [ -n "$sy_available" ] && [ "$sy_available" != "$sy_running" ]; then
        echo "codex-host-setup: codex $sy_available is available; not upgrading" \
             "automatically (run: mise use -g ${sy_tool}@${sy_available})" >&2
    fi
fi

# Codex has no dedicated append-system-prompt flag, but its generic config
# override supports developer_instructions. Encode the Markdown as a TOML basic
# string without depending on jq/python inside custom rootfs images.
toml_string_from_file() {
    local value
    value="$(cat "$1")"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\b'/\\b}"
    value="${value//$'\f'/\\f}"
    value="${value//$'\t'/\\t}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\n'/\\n}"
    printf '"%s"' "$value"
}

args=(-s danger-full-access -a never)
supervised_args=(--dangerously-bypass-approvals-and-sandbox)
if [ -f "$HOME/.safeyolo/AGENTS.md" ]; then
    args+=(-c "developer_instructions=$(toml_string_from_file "$HOME/.safeyolo/AGENTS.md")")
    supervised_args+=(-c "developer_instructions=$(toml_string_from_file "$HOME/.safeyolo/AGENTS.md")")
fi

exec codex "${args[@]}" "$@"
EOF
chmod +x "$AGENT_HOME/.safeyolo-command"

if [ "${SAFEYOLO_CODEX_COORD_SUPERVISOR:-0}" = "1" ]; then
    python3 - "$AGENT_HOME/.safeyolo-command" <<'PY'
import sys

path = sys.argv[1]
with open(path) as handle:
    body = handle.read()
interactive = 'exec codex "${args[@]}" "$@"\n'
supervised = (
    'exec python3 "$HOME/.safeyolo/codex-coord-supervisor.py" '
    '-- "${supervised_args[@]}" "$@"\n'
)
if body.count(interactive) != 1:
    raise SystemExit("codex-host-setup: cannot install the supervised foreground command")
with open(path, "w") as handle:
    handle.write(body.replace(interactive, supervised))
PY
fi

# --- Stage and register the coord MCP server ---------------------------------
# This runs after the foreground command is written so the shared bootstrap can
# inject its guarded dependency setup immediately before the harness exec.
"$SCRIPT_DIR/coord-mcp-bootstrap.sh" --home "$AGENT_HOME" --harness codex

echo "codex-host-setup: $SAFEYOLO_AGENT_NAME ready at $AGENT_HOME"
