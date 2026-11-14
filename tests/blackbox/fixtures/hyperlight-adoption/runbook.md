# Selected #1552 native execution recipe

Use the immutable PR #1573 candidate named by the accompanying native output.
This recipe resumes the installed disposable instance on sy-239-clean-6728,
Ubuntu x86_64, UID1000, glibc2.39. Sylab owns protected execution through the
existing transport. Forge prepares source; Lens supplies independent judgment.
No new host, login, root access, model or broader service grant is needed.

## Reuse the installed consumer

Canonical operator backlog15963/15965 and the shared receipts under
/evidence/operator/1552/runtime-d3c1e8c2 establish the completed packaging,
installation, fixture setup and core admission/publication. Preserve those
results. Do not repeat them to apply this recipe correction. The retained root
is /home/agent/ha1552; the package stage is /home/agent/1552-package-d3c1e8c2.
Preserve q1452b,1452-native-bundle and production backlog.

Native executables remain b8272ea837a62240fec92a8f4e9263c2a650bbcd/debug.
The corrected optional Python checkers remain
f4275ba656f38a22b5215caab25217355dad04eb. The package/Work witness scripts remain
d3c1e8c2; the three-role factory contracts remain the 230db88d fixture. This
correction changes configuration and guidance, not those executable inputs.
The accepted #1551 base is integrated separately; it does not relabel the
retained native package. Use package_hyperlight_adoption.sh only when a new
consumer actually needs packaging, with its exact existing inputs.

The gVisor input remains /home/agent/1452-native-bundle/libexec. Execution17820
verified patched release-20261005.0-safeyolo.1 and the four files with mode 0755 below.
Their exact hashes remain in gvisor.sha256 and the shared gvisor-binding.json:

| Input relative to GVISOR_ROOT | Bytes |
| --- | ---: |
| runsc | 109963262 |
| gvisor-bin/gvisor-sentry-prewarmer | 1392 |
| gvisor-bin/gvisor_sentry | 52149776 |
| gvisor-bin/runsc-fd-parking | 1272 |

The retained original packet is 1552-linux-x86_64-b8272ea8.tar.gz,
118655011 bytes, SHA256 a744fe13c8f58d576def3786bb97a322606f88cdb19223cc5d47dfad3fe2000a.
Its extracted source is under the retained stage's inputs/safeyolo-1552-b8272ea8.
The corrected checker update is 1552-f4275ba6-checker-update.tar.gz,3880 bytes,
SHA256 b233a410eb20efd16d8013134d088c8e30f245bff1e0b5e3bc43f0a1eee95b81.
Both originals are shared under /evidence/operator/1552/inputs-b8272ea8.
Core ELF, helper, Python CPIO, runtime.json and notices stay unchanged.

Sylab stages only the new small recipe archive into the selected directory
/home/agent/1552-inputs/recipes-adoption-fixed. Inspect any existing directory
before choosing another effect. Use the existing native host shell, preserve
proxy/CA variables and private credentials, and read current free space and
active commands before allocating. The existing 5 GiB floor and storage policy
apply. The following commands only read the selected installed state:

```bash
set -euo pipefail
root=/home/agent/ha1552
stage=/home/agent/1552-package-d3c1e8c2
recipes=/home/agent/1552-inputs/recipes-adoption-fixed
fixture=$recipes/fixture
cli=$root/bin/safeyolo
factory=ha1552
room=ha1552
credential=live-github
packet_source=$stage/inputs/safeyolo-1552-b8272ea8/source
creator_socket=$root/creator.sock
owner_socket=$root/owner.sock
reviewer_socket=$root/reviewer.sock
creator_id=ag-ba78f4c34ded4a0295c682f4061adbf6
owner_id=ag-a8f92b091dae4fa08da0fb2835ff0956
reviewer_id=ag-2dc62d4650ea4ec981151bcef62308e0
snapshot=$(cat "$root/factories/ha1552/approved")
"$cli" --root "$root" status
"$cli" --root "$root" factory doctor "$factory"
"$cli" --root "$root" coord status "$room" --json
"$cli" --root "$root" services authorized gate:hyperlight-service-check
for listener in "$creator_socket" "$owner_socket" "$reviewer_socket"; do
  test -S "$listener"
done
```

Expected: the three exact configured identities/listeners, active room rights
and approved snapshot 625b28c460bea73ce3e81acecefe8aef3336bb48b740a620b6c5ac3960c3fb1d.
The installed configuration must retain gateway_builtin_services_dir=assets/services
and gateway_services_dir=data/services. These are the actual installer bindings;
the fixture now includes them. Operator15965 reports their completed correction
and restart. Do not overwrite configuration, reinstall, reapprove, recreate the
room, regrant membership or restart a healthy consumer for this source change.
A failed state read stops the affected attempt and retains its receipt.

The factory selects its creator as coordinator, a separate owner and Lens's
independent reviewer. Automatic admit_issue/github_issue and
verify_output/published_artifact requirements remain policy-owned. The producer
publishes/completes; the reviewer answers/decides. Sylab may transport Lens's
explicit judgment through the reviewer listener, never invent one. No
page_operator permission, factory prepare/run or paid client call is needed
for this native-client witness. This does not prove managed-client discovery.

The existing live-github reference was provisioned privately. Never print or
retain its value. Execution 18093 admitted parent
work-484b55e3234a4619804a1b5e7ddfd792; execution 18094 published its ready output 1 with target
sha256:e84d817d4a2e5ffd0952e7bb8a795dc1b0264492782b76c4662807b12665d531.
Independent check work-48b7881b96fb49a8b71a11c17ccc7adb remains Lens-owned.
Read its current state before continuing; do not create another parent or
publish ready again to replace the pending review. Exact subject/artifact/input
bytes are in core-review-230db88d.json,
SHA256 70aba60c89015c38dde715a7f8b31580e2d1f24d7f0af0ee9e3705fb75e9a968.

## Prepare and adopt only the remaining selection

Both engine proposals were prepared and validated in execution 18084. Reuse them under
$stage/candidate-hyperlight and $stage/candidate-hyperlight-unikraft. Core
adoption and its successful windows are complete. The commands below explain
the remaining second-engine selection. Preserve the completed effects.

The actual venue lacks uv. Use Python 3.12+ with the existing task-local
authoring-deps environment from execution 18084, which supplies TOMLKit 0.14.0
and PyYAML 6.0.3. Preserve that environment through every python3 invocation below.
Before preparation, verify those imports in that same shell. An import failure
requires inspection of the retained authoring-deps setup, not a native product
rebuild. This path does not prove the default uv launcher is usable:

```bash
python3 -c 'import sys,tomlkit,yaml; assert sys.version_info >= (3,12); assert tomlkit.__version__ == "0.14.0"; assert yaml.__version__ == "6.0.3"'
```

Use the existing proposal and preparation-receipt paths below. If a required
path is unavailable, recover its actual output location from execution 18084
before continuing. Do not regenerate a proposal merely because its path was
forgotten. The installed walkthrough describes fresh preparation separately.

The expected issue is 1552, author 123607 in craigbalding/safeyolo. PR 1573 is the
same author's existing pull request and is a negative type control. The check
reads live GitHub evidence; these tests create or edit no GitHub issue. Inspect
the printed proposed authority and service_target before adoption. The installed
walkthrough retains the authorship/autonomy explanation.

For a deliberate remaining engine selection, use its retained proposal and
preparation receipt. Select engine=hyperlight-unikraft in the same host shell.
Back up any current override privately, then install only the reviewed service
file to its reported path:

```bash
engine=hyperlight-unikraft
service_target=$(python3 - "$stage/diagnostics/prepare-$engine.json" <<'TARGET'
import json,sys
print(json.load(open(sys.argv[1]))['service_target'])
TARGET
)
if [[ -e $service_target ]]; then
  cp "$service_target" "$stage/diagnostics/github-before-$engine.yaml"
fi
install -m 0600 "$stage/candidate-$engine/github.yaml" "$service_target"
"$cli" --root "$root" services show github > "$stage/diagnostics/catalogue-$engine.json"
```

Continue only when definition.capabilities.read_example_issues.routes in that
readback contains exactly GET /repos/craigbalding/safeyolo/issues/*. Repeat only
the services show read while the watcher loads the override. A read failure or
a different definition requires inspection of the selected path and
configuration-error evidence. services check validates a file but does not load
it. Policy apply compiles against the loaded catalogue; it does not reload a
new override first. The independent service watcher checks every 2 seconds.
Once the selected capability is loaded, apply and inspect the exact authority:

```bash
"$cli" --root "$root" policy apply "$stage/candidate-$engine/candidate.toml"
"$cli" --root "$root" policy show
"$cli" --root "$root" services authorized gate:hyperlight-service-check
```

Expected: saved_matches_active=true and github's capability=read_example_issues,
credential=live-github, host=api.github.com and routes containing only that GET
issue route. Empty routes is not usable authority. If readback differs, stop
before admission, retain the failed result and inspect current policy/catalogue.
Do not blindly revoke/reissue, widen access or retry admission. A lost reply
requires current-state inspection before another effect.

Operator15965 retains failed automatic create 18086 and its 403/service-gateway
response, empty routes and later exact grant repair 18092. No credential/risk
approval was pending. A local b827 probe reproduced empty routes when policy
was applied before its new capability loaded; the watcher then supplied the
correct route. That establishes an ordering failure in this recipe, not the
cause of any persistent empty-route state after catalogue publication. Further
diagnosis of that state needs the original failed attempt's timestamped loaded
catalogue, effective policy/grant projection and configuration-error evidence.
The reached successful core windows need no replay for that diagnosis.

The shipped jobs select 5 seconds and the prepared named check permits 10 seconds.
Execution 17813 observed Unikraft jobs taking about 7–8 seconds with a 30 second selected
job limit; a 5 second deadline expired before the held provider. Those are #1550
driver observations, not #1552 automatic-admission results. Retain actual limits
and failures. Do not silently extend them and call default usability proved.

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
the API alias for PR 1573 is refused by the automatic requirement. The worker
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

For the grant control, use the same prepared Python/TOMLKit environment.
The following commands prepare a candidate that removes only the
selected example's GitHub grant, then activate and test it. They preserve the
checker and spec bytes. Sylab owns these protected policy activations:

```bash
packet_source=$stage/inputs/safeyolo-1552-b8272ea8/source
baseline=$stage/candidate-$engine/candidate.toml
revoked=$stage/diagnostics/revoked-$engine.toml
python3 "$recipes/revoke_example_grant.py" \
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
from the exact packet source. It uses the same prepared host Python environment.
It does not initialize, restart or change the selected installed instance.
Run after positive admission with the restored scoped grant:

```bash
python3 "$recipes/probe_scopes.py" \
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
are test inputs/results, not another queue or assignment log. Preserve the
supplied core admission/publication and pending exact-output review. Complete
two-engine factory execution, refreshed input, independent postcondition
acceptance and comparisons need their remaining observations and judgment.
Physical Apple-silicon HVF remains required separately; the Linux packet and
Linux helper do not qualify macOS. Reuse existing Bristol sy-agent/Sylab authority
and component proof, with no root or personal-account access.

The exact same workload comparison still needs the actual selected gVisor/VZ
consumer and native macOS inputs. No performance or managed-client result is
claimed by this source preparation. Preserve criteria 9/10 acceptance; the other
nine criteria remain unchecked.

Output groups for normal retention are the original b827 packet, small checker
update, these recipes, and the native guest's task-local inputs/package/runtime
and private diagnostics. Protect only current consumers under the existing
storage policy; preserve source, identities and compact results after retirement.
