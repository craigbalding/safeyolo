# Selected #1552 native execution recipe

Source: the immutable PR #1573 candidate named by the accompanying native output.
Ground truth: canonical operator backlog15953,15956,15957 and the shared native-input-inventory.json/gvisor-binding.json.
Native binaries remain b827, corrected Python checkers remain f427, and the prior
package/Work witness scripts remain d3. This update supplies fixture configuration
and replaces the old existing-factory assumption; it does not rebuild those bytes.
The native Work and packaging scripts come from that source. The operational
scope/revocation helpers are retained here and reuse the existing runner and
TOMLKit writer. Their exact bytes are bound by this archive's identity.
These are prepared commands, not a receipt of protected execution or feature acceptance.
Sequence this run after the active #1550 native command reaches its real boundary.

## Executor and remaining operands

Sylab executes on the existing Ubuntu x86_64 guest sy-239-clean-6728,
192.168.122.100, UID1000, glibc2.39, using its existing protected transport.
Forge supplies these scripts. The native venue supplies /usr/bin/tmux and its
ldd-resolved closure. No new host, root access, login or broad grant is needed.

The selected gVisor input is /home/agent/1452-native-bundle/libexec.
Read-only execution17820 verified its patched release-20261005.0-safeyolo.1 and
all four required files as UID1000. gvisor.sha256 retains the supplied exact
hashes. The other ~/.safeyolo/libexec input lacks the required patch suffix.
Use independent packaged copies and preserve the original1452 private modes.
Before construction, compare the input sizes and modes with the same receipt:

| Input relative to GVISOR_ROOT | Bytes | Mode |
| --- | ---: | --- |
| runsc | 109963262 | 0755 |
| gvisor-bin/gvisor-sentry-prewarmer | 1392 | 0755 |
| gvisor-bin/gvisor_sentry | 52149776 | 0755 |
| gvisor-bin/runsc-fd-parking | 1272 | 0755 |

The new disposable installed root is /home/agent/ha1552. Operator15957 checked
its absence. Preserve q1452b,1452-native-bundle and production backlog. This
recipe supplies the new ha1552 factory/room fixture; no preexisting test factory
or room is needed. The configured identities are explicit in fixture/policy.toml
and resolve through the current host_agents and native room mechanisms.
Canonical grant/status readback must match those IDs before the witness uses
them. A prepared identity file is not a claim that membership is already active.
Sylab supplies the existing authorized GitHub read credential under the local
reference live-github using the existing private provisioner. No secret is in
these recipes. Preserve native proxy/CA environment and private token handling.

Read current free space and active commands before allocating. The dated guest
receipt had about11GiB free. The archive, extraction and package are reproducible
outputs for this current consumer. Apply the existing 5GiB nested floor and
storage policy; do not purge another consumer or start a runtime source build.

## Package on the native venue

Transport these recipes and both archives through the existing protected route.
The first archive is already shared at
/evidence/operator/1552/inputs-b8272ea8/1552-linux-x86_64-b8272ea8.tar.gz:
118655011bytes, SHA256a744fe13c8f58d576def3786bb97a322606f88cdb19223cc5d47dfad3fe2000a.
The small corrected checker archive is
/home/agent/safeyolo-rust-620-evidence/1552-f4275ba6-checker-update.tar.gz on Forge:
3880bytes, SHA256b233a410eb20efd16d8013134d088c8e30f245bff1e0b5e3bc43f0a1eee95b81.
That is an owner backing path for Sylab's copy/readback, not a peer mount.

On the native guest, put the inputs and scripts under /home/agent/1552-inputs.
The commands below bind the exact supplied complete native payload. Run them
from /home/agent. Choose a new stage directory if the named path already exists.
The script preserves the original archive and uses umask022 for package files;
its separate diagnostics directory is0700. It performs no installation.

```bash
set -euo pipefail
packet=/home/agent/1552-inputs/1552-linux-x86_64-b8272ea8.tar.gz
update=/home/agent/1552-inputs/1552-f4275ba6-checker-update.tar.gz
recipes=/home/agent/1552-inputs/recipes
stage=/home/agent/1552-package-ready
GVISOR_ROOT=/home/agent/1452-native-bundle/libexec
(cd "$GVISOR_ROOT" && sha256sum -c "$recipes/fixture/gvisor.sha256")
stat -c '%n %s %a' "$GVISOR_ROOT/runsc" \
  "$GVISOR_ROOT/gvisor-bin/"{gvisor-sentry-prewarmer,gvisor_sentry,runsc-fd-parking}
bash "$recipes/package_hyperlight_adoption.sh" "$packet" "$update" "$GVISOR_ROOT" "$stage"
```

Expected: all four input hashes, sizes and modes match the table and receipt.
The ordinary build_host_packages.sh and verify_native_package checks
pass and report the selected package path. The source checkout and all native
executables remain b8272ea837a62240fec92a8f4e9263c2a650bbcd/debug. The optional
checker component is source f4275ba656f38a22b5215caab25217355dad04eb. Only the two
Python files and their two architecture-specific pinned definitions change in
that component. Core ELF, helper, Python CPIO, runtime.json and notices remain
unchanged. The script binds --hyperlight-artifacts explicitly and never relabels
b827 native executables as a later commit. The packet's actual top-level name is
safeyolo-1552-b8272ea8. A source or package identity check must not be bypassed.

## Install and prepare both engines

Sylab uses the selected new root /home/agent/ha1552 and a separate command
directory and runs the package's ordinary installer. For the host/native-API witness, its existing
--no-guest-download option is sufficient. This does not prove managed guest or
coding-client discovery. For that separate criterion, use the existing qualified
compatible platform assets or ordinary guest acquisition and exercise actual
Codex/Claude discovery in the resulting managed guest. Preserve their accepted
client choices, credentials, proxy and CA. Do not count repository lookup as
installed discovery.

```bash
root=/home/agent/ha1552
# Stop here if this root now exists; inspect that consumer before another effect.
if [[ -e $root || -L $root ]]; then
  echo "Inspect the existing selected root before installation: $root" >&2
  exit 1
fi
bash "$stage/package/install_native.sh" --root "$root" --bundle "$stage/package" \
  --command-dir "$stage/commands" --no-guest-download
cli=$root/bin/safeyolo
"$cli" --root "$root" status
```

## Prepare the task-local native factory

This follows proxy/tests/native_coord/supervision.rs::ReviewRun::start and
factory.rs::selected_work: host-owned agent metadata, named Unix listeners,
managed NATS, explicit room grants and an approved native Work policy. It adds
no controller, alternate queue, scheduler or model invocation. Only the new
instance's configuration is selected. The base policy denies unselected egress;
the installed authoring helper proposes the existing repository-scoped GitHub
grant and automatic admission/output bindings for operator adoption.

| Role | Native authority | Completion and evidence |
| --- | --- | --- |
| ha1552-creator/coordinator | Create assigned Work and amend requirements | Canonical admission and exact checked snapshot |
| ha1552-owner/owner | Claim, publish immutable artifact, complete execution | Exact output generation; no self-review |
| ha1552-reviewer/reviewer | Answer selected check and decide acceptance | Lens's independent exact-output judgment; automatic requirements remain |

```mermaid
flowchart LR
  C[Creator Unix listener] -->|admit_issue automatic check| W[Canonical native Work]
  W --> O[Owner consumes checked snapshot]
  O -->|immutable output| V[verify_output automatic check]
  V --> R[Selected independent reviewer]
  R -->|native check and decision| A[Exact output acceptance]
```

Run these host commands as UID1000 after installation and before starting the
new proxy. The explicit identities and listeners in the fixture are the actual
selected configuration; they do not copy any production identity. Retain the
installer defaults privately before selecting these task-local files:

```bash
fixture=$recipes/fixture
factory=ha1552
room=ha1552
credential=live-github
cp "$root/config.toml" "$stage/diagnostics/installed-config.toml"
cp "$root/policy.toml" "$stage/diagnostics/installed-policy.toml"
install -m 0600 "$fixture/config.toml" "$root/config.toml"
install -m 0600 "$fixture/policy.toml" "$root/policy.toml"
"$cli" --root "$root" policy check "$root/policy.toml"
"$cli" --root "$root" factory check "$fixture/factory.toml"
# Sylab's existing operator authority approves this exact disposable selection.
"$cli" --root "$root" factory approve "$fixture/factory.toml" --yes
# Verify ports18452/18453/18454 are free before this first runtime start.
# The ordinary native runtime reuses or acquires its reviewed pinned NATS binary.
"$cli" --root "$root" coord start --client-port 18453 --monitor-port 18454
"$cli" --root "$root" coord room create "$room"
for participant in ha1552-creator ha1552-owner ha1552-reviewer; do
  "$cli" --root "$root" coord grant "$room" "$participant" receive send \
    --operation-id "ha1552-grant-$participant-1"
done
snapshot=$(cat "$root/factories/ha1552/approved")
creator_socket=$root/creator.sock
owner_socket=$root/owner.sock
reviewer_socket=$root/reviewer.sock
creator_id=ag-ba78f4c34ded4a0295c682f4061adbf6
owner_id=ag-a8f92b091dae4fa08da0fb2835ff0956
reviewer_id=ag-2dc62d4650ea4ec981151bcef62308e0
```

Expected: factory check validates the complete contract and approval retains its
immutable snapshot. Each grant receipt identifies the selected configured ID. The room
readback below verifies active send/receive rights before the witness uses them. No page_operator permission, guest creation, factory prepare/run or paid
coding-client call is needed for this native-client witness. This is the same
qualification boundary as the maintained authenticated native Factory fixture;
it does not establish managed coding-client discovery or model behavior.

Sylab provisions live-github privately through the existing credentials add
--stdin path and records only the nonsecret reference. Before coord start, verify local ports18452/18453/18454 are available.
NATS uses18453/18454 and the proxy Admin API uses18452. The named Unix listeners are
relative to /home/agent/ha1552. Preserve any required proxy/CA settings in the
selected config; the existing sy-239-clean-6728 transport used for1550 remains
the venue. After startup, inspect native status and the actual socket paths:

```bash
"$cli" --root "$root" start
"$cli" --root "$root" status
"$cli" --root "$root" coord status "$room" --json > "$stage/diagnostics/room.json"
for listener in "$creator_socket" "$owner_socket" "$reviewer_socket"; do
  test -S "$listener"
done
```

A failed readback or startup stops the affected attempt and retains its receipt.
Room creation has no operation-ID option. After an uncertain reply, inspect
coord room list and the named ha1552 room before deciding another effect. Grant
operations use the chosen IDs above; recover their original inputs/IDs before
retrying. Never create a replacement room to avoid that readback. Approval
and source preparation alone do not claim a running factory or independent
acceptance. No production factory or1452 input is changed.

Before applying either example, prepare both candidates against the same
unmodified baseline with the installed helper. Use the room/factory/credential values selected above. The live issue is1552, author123607 in
craigbalding/safeyolo. PR1573 is the same author's existing pull request and is a
negative type control. No live GitHub issue is created or edited by these tests.
Use uv and the helper's declared pinned authoring dependencies through the
normal proxy/CA; product runtime remains the native installation.

```bash
for engine in hyperlight hyperlight-unikraft; do
  uv run --script "$root/assets/skills/job-authoring/scripts/prepare.py" \
    --root "$root" --engine "$engine" --repository craigbalding/safeyolo \
    --author-id 123607 --issue 1552 --room "$room" --factory "$factory" \
    --credential "$credential" --output "$stage/candidate-$engine" \
    > "$stage/diagnostics/prepare-$engine.json"
  "$cli" --root "$root" services check "$stage/candidate-$engine/github.yaml"
  "$cli" --root "$root" policy check "$stage/candidate-$engine/candidate.toml"
done
```

Inspect proposed authority and the helper's exact service_target before
activation. The installed walkthrough retains the authorship/autonomy explanation.
A file write alone is not adoption. Select hyperlight for the first qualification
and finish its useful witness before selecting hyperlight-unikraft. The second
engine is a qualification run; normal operation can select one implementation.
For each deliberate selection, run from the same native host shell:

```bash
engine=hyperlight
# Use engine=hyperlight-unikraft for the separate second-engine qualification.
service_target=$(python3 - "$stage/diagnostics/prepare-$engine.json" <<'TARGET'
import json,sys
print(json.load(open(sys.argv[1]))['service_target'])
TARGET
)
if [[ -e $service_target ]]; then
  cp "$service_target" "$stage/diagnostics/github-before-$engine.yaml"
fi
install -m 0600 "$stage/candidate-$engine/github.yaml" "$service_target"
"$cli" --root "$root" policy apply "$stage/candidate-$engine/candidate.toml"
"$cli" --root "$root" policy show
"$cli" --root "$root" services authorized gate:hyperlight-service-check
```

Expected: saved_matches_active=true, the selected repository-scoped read
capability, and both automatic bindings active for ha1552/ha1552. A failed
activation is not saved-as-active success. Inspect actual state before another
effect after a lost reply. This selection changes only the disposable instance.

The shipped job definitions currently select5seconds and the prepared named
check permits10seconds. Execution17813 observed Unikraft jobs taking about7–8s
with a30second selected job limit, and a5second deadline expired before the held
provider. Those were #1550 driver observations, not #1552 automatic-admission
results. Retain the actual selected limits and any failed installed result. Do
not silently extend them and call the default installed journey proved.

## Native admission, checked-input consumption and output replacement

Use the creator_socket/owner_socket and creator_id/owner_id selected above,
after their canonical membership and live listeners have been checked. The witness reads the selected root's agent token in
memory and uses the existing per-agent Unix route. No token enters argv or
retained request/response files. Scratch is new, private and disk-backed.

```bash
common=(--root "$root" --room "$room" --factory "$factory" --snapshot "$snapshot"
  --creator-socket "$creator_socket" --creator-id "$creator_id"
  --owner-socket "$owner_socket" --owner-id "$owner_id"
  --repository craigbalding/safeyolo --author-id 123607 --issue 1552)
python3 "$recipes/hyperlight_adoption.py" admit "${common[@]}" \
  --rejected-issue 1573 --run-id "1552-$engine-admit-1" --scratch "$stage/diagnostics/$engine-admit"
# work is the canonical work_id printed by that successful admission.
python3 "$recipes/hyperlight_adoption.py" publish "${common[@]}" --work-id "$work" \
  --artifact-status ready --run-id "1552-$engine-ready-1" --scratch "$stage/diagnostics/$engine-ready"
```

Expected: required admission selects the approved factory despite omission of a
selector; verdict/identity injection and wrong snapshot selection are refused;
the API alias for PR1573 is refused by the automatic requirement. The worker
verifies and consumes the retained checked_input bytes, then publishes an exact
ready artifact made from its title and body digest. Digest substitution and
stale publication expectations are refused. The automatic requirement is
satisfied and a current independent check is still required. Execution is
explicitly completed. The script never answers that check or decides acceptance.

Lens independently reads the actual fixture artifact, canonical selected check,
subject and retained checked_input, then supplies the exact judgment. Sylab may
transport that judgment using the configured reviewer listener; neither the
witness nor the protected executor invents or automatically approves a verdict.
The installed native client provides the existing authenticated operations:

```bash
# review-request.json contains the exact room_name/work_id printed by publication.
SAFEYOLO_COORD_SOCKET="$reviewer_socket" \
SAFEYOLO_COORD_TOKEN_PATH="$root/data/agent_token" \
  "$root/bin/safeyolo-coord" call read_work < "$stage/diagnostics/review-request.json"
```

Use claim_work, answer_check and decide_work_acceptance only with the resulting
current versions and Lens's actual exact-output judgment, chosen operation IDs
and the selected contract. These are named native mutations, not text replies.
No owner-authored PASS or publication result supplies independent acceptance. Keep that parent
pending until the canonical result exists. If independently accepted, inspect
that fact and then replace the output with draft:

```bash
python3 "$recipes/hyperlight_adoption.py" inspect "${common[@]}" --work-id "$work" \
  --expect-accepted --run-id "1552-$engine-read-1" --scratch "$stage/diagnostics/$engine-accepted"
python3 "$recipes/hyperlight_adoption.py" publish "${common[@]}" --work-id "$work" \
  --artifact-status draft --run-id "1552-$engine-draft-1" --scratch "$stage/diagnostics/$engine-draft"
```

Expected: a new output generation and independent check, an unsatisfied automatic
requirement, and acceptance no longer accepted. A further ready publication
uses another deliberate run_id/scratch path and requires its own exact review.
Prior output acceptance cannot supply the new obligation.

For the grant control, the packet's source/uv.lock supplies the existing host
TOMLKit tool. The following commands prepare a candidate that removes only the
selected example's GitHub grant, then activate and test it. They preserve the
checker and spec bytes. Sylab owns these protected policy activations:

```bash
packet_source=$stage/inputs/safeyolo-1552-b8272ea8/source
baseline=$stage/candidate-$engine/candidate.toml
revoked=$stage/diagnostics/revoked-$engine.toml
uv run --project "$packet_source" --frozen python3 "$recipes/revoke_example_grant.py" \
  --baseline "$baseline" --output "$revoked"
"$cli" --root "$root" policy check "$revoked"
"$cli" --root "$root" policy apply "$revoked"
"$cli" --root "$root" policy show
python3 "$recipes/hyperlight_adoption.py" admit "${common[@]}" --expect-denied \
  --run-id "1552-$engine-revoked-1" --scratch "$stage/diagnostics/$engine-revoked"
"$cli" --root "$root" policy apply "$baseline"
"$cli" --root "$root" services authorized gate:hyperlight-service-check
```

Expected: automatic admission is held while the grant is revoked, and no new
Work is created. Read effective restored authority before another positive run.
A failing activation stops this sequence; do not treat a saved candidate as
active. The scripts perform no automatic retry or policy restoration.

For a refreshed relevant issue revision, retain the prior capture digest from
the admitted Work. After an actual relevant upstream change, the following host
command reassigns that same Work to the same owner with current expectations.
It must perform a fresh admission read. Run from the native venue as the instance
owner; use a new private refresh_dir and choose refresh_operation before writing.

```bash
umask 077
refresh_dir=$stage/diagnostics/$engine-refresh
mkdir "$refresh_dir"
"$cli" --root "$root" coord work show "$room" "$work" > "$refresh_dir/before.json"
mapfile -t expectations < <(python3 - "$refresh_dir/before.json" <<'STATE'
import json,sys
value=json.load(open(sys.argv[1]))
value=value.get('work',value)
print(value['version'])
print(value['claim_generation'])
STATE
)
refresh_operation=1552-$engine-refreshed-delegation-1
"$cli" --root "$root" coord work reassign "$room" "$work" --agent-id "$owner_id" \
  --expected-version "${expectations[0]}" --expected-generation "${expectations[1]}" \
  --operation-id "$refresh_operation" > "$refresh_dir/receipt.json"
python3 "$recipes/hyperlight_adoption.py" inspect "${common[@]}" --work-id "$work" \
  --prior-input-sha256 "$prior_input_sha256" --run-id "1552-$engine-refreshed-read-1" \
  --scratch "$refresh_dir/after"
```

The inspect command fails visibly if the consumed bytes did not change. A fresh
observation with unchanged bytes is not changed-input proof. This recipe makes
no upstream edit and promises no unchanged future GitHub state. Do not repeat
an uncertain reassign with a new operation ID. Read current Work and recover the
same original operation first.

## Off-scope controls without repeating held-call tests

The small probe_scopes.py reuses only Instance.run_job and output from the
retained hyperlight_services.py. Its imports of job_network/job_sandbox come
from the exact packet source. It uses the source's locked host Python environment.
It does not initialize, restart or change the selected installed instance.
Run after positive admission with the restored scoped grant:

```bash
uv run --project "$packet_source" --frozen python3 "$recipes/probe_scopes.py" \
  --root "$root" --packet-source "$packet_source" --engine "$engine" \
  --scratch "$stage/diagnostics/$engine-scopes"
```

Expected: four typed ok=false responses for POST on the selected issue,
GET on the repository pulls route, GET in another repository and GET to a
non-GitHub destination. The existing observer also checks actual CLI status,
complete typed job result and observation status. Retain each actual runtime
and delegated evidence record. The direct probes use the runner's explicit
30second qualification limit in each saved spec. They do not alter the adopted
automatic-check limit or prove default authoring usability. Reuse unchanged #1550
held-call, reload and shutdown proof instead of replaying those controls.

## Recovery, remaining scope and retention

Each script invocation is one attempt. It chooses operation IDs before writes
and saves the private original request before sending. After a timeout or lost
reply, inspect current Work and recover that same original operation before
another effect. An exception or stopped process does not prove a remote rollback.
Keep useful pending native reviews; do not replace them with shell narration.

Retain package/checker/runtime/source identities and compact actual results for
Lens. Private diagnostics can contain captured issue bodies and remain private.
The native product output/check records are the lifecycle; these scratch files
are test inputs/results, not another queue or assignment log. Installed two-engine
execution, actual factory use, refreshed input, independent postcondition
acceptance and comparisons stay unproved until observed and independently judged.
Physical Apple-silicon HVF remains required separately; the Linux packet and
Linux helper do not qualify macOS. Reuse existing Bristol sy-agent/Sylab authority
and component proof, with no root or personal-account access.

The exact same workload comparison still needs the actual selected gVisor/VZ
consumer and native macOS inputs. No performance or managed-client result is
claimed by this source preparation. Preserve criteria9/10 acceptance; the other
nine criteria remain unchecked.

Output groups for normal retention are the original b827 packet, small checker
update, these recipes, and the native guest's task-local inputs/package/runtime
and private diagnostics. Protect only current consumers under the existing
storage policy; preserve source, identities and compact results after retirement.
