# Trusted Claude event installation

This entry connects the existing GitHub nightly/manual controls and successful
default-branch push checks to the installed Claude caller. It uses Rundeck's
existing schedule and harness. GitHub Actions publishes only nonsecret event
operands. It receives no Rundeck or provider credential. Pull requests do not
publish Claude events.

## Install in the trusted accounts

Sylab installs the independently reviewed source in devstack's existing
`rundeck` account and configures the owned Ubuntu controller. This procedure
enables real credentialed tasks and production package dispatches. Complete the
private bindings before importing the scheduled job.

On devstack, install a clean checkout of the reviewed commit at
`/var/lib/rundeck/harness/claude-events/source`, readable by `rundeck`. Python 3.12 or 3.13,
Bash, Git, `gh`, and the existing harness jobs must be available. No Python
package installation or product build is required for this entry. Keep the
controller's frozen environment and existing runtime prerequisites intact.

Create `/var/lib/rundeck/harness/claude-events/events.env`, readable only by the trusted account.
Set its actual `PATH` and, when needed, `CLAUDE_EVENTS_PYTHON`. Bind `gh` to the
existing authorized repository principal using the supported private service
binding. The principal needs repository/Actions read access and Actions write
access for the existing production dispatch. Do not put that credential in
source, JSON configuration, GitHub Actions or returned reports.

On the owned Ubuntu host, create a private shell binding at an operator-selected
absolute path. The binding sets `CLAUDE_PROVISION` to the existing helper and
`CLAUDE_CREDENTIAL` to its existing credential name. It supplies the existing
per-attempt private `SAFEYOLO_CLAUDE_PROVISION_DIR` binding and host-process
GitHub/registry access. The binding must prepare fresh applicable provisioning
input for each invocation; dated input is not current authentication proof.
It can use the exported `CLAUDE_EVENT_RUN` and `CLAUDE_EVENT_OUTPUT` operands
to bind that private input to the new attempt.
Keep secrets and provisioning output private. The entry sources that file in
the SSH child, then runs the unchanged caller with its own new output directory.

Create `/var/lib/rundeck/harness/claude-events/events.json` in the `rundeck` account. Replace
`PRIVATE_BINDING_PATH` with that remote file and `ACTIVATION_UTC` with the actual
UTC activation timestamp, such as `2026-11-04T20:00:00Z`. The timestamp excludes
older historical events from automatic admission. The current nonsecret
deployment receipt supplies these controller operands:

```json
{
  "host": "192.168.122.109",
  "controller": "/home/agent/375-build-storage-d62/claude356-caller-9c67/source",
  "controller_revision": "9c67c5171ff61d8cc684de45639a54368473ca95",
  "binding": "PRIVATE_BINDING_PATH",
  "remote_attempts": "/home/agent/claude356-events",
  "attempts": "/var/lib/rundeck/harness/evidence/issue356",
  "enabled_since": "ACTIVATION_UTC"
}
```

Protect both config files at mode `0600` and their parent at `0700`. Ensure the
two attempt parents are private, disk-backed and writable in their respective
accounts. The inner controller remains pinned independently of the selected
product. Its caller SHA-256 is
`218890e4ddaef26d7d86a67784a447d3c40640eda4abe1c16a2243880c7e803b`.
Verify the deployed commit, clean source, caller hash and private binding before
activation. A different controller requires its own verified revision in config.

Through the existing authenticated Rundeck API 59 service binding, import the
complete [job YAML](claude-events-job.yaml) with this request:

```http
POST /api/59/project/acceptance/jobs/import?dupeOption=update
Content-Type: application/yaml

<the exact contents of tests/blackbox/claude-events-job.yaml>
```

The import updates the named job and enables a five-minute schedule. Read the
import response and the installed job back before retrying an uncertain import.
Verify `multipleExecutions=false` and the installed script. The job runs the same
entry used by the existing `run/script` interface. It supplies no new scheduler,
worker runner or task queue. Keep job configuration and control credentials
outside tested product authority.
The [Rundeck import API](https://docs.rundeck.com/docs/api/#importing-jobs)
accepts the YAML body directly; its
[job format](https://docs.rundeck.com/docs/manual/document-format-reference/job-yaml-v12.html)
defines the schedule and script interpreter used here.

## Invoke and inspect

After the workflow is integrated on the default branch, its existing 03:17 UTC
schedule emits a nightly event. From an authorized repository account, request
the existing manual workflow with:

```sh
gh workflow run blackbox.yml --repo craigbalding/safeyolo --ref master
```

Optional `-f host_run=RUN_ID -f guest_index=sha256:DIGEST` selects exact qualified
inputs for that manual event. Replace both operands with existing retained
identities. Omit them for newest-completed compatible selection.

A successful `Native proxy contracts` default-branch push emits a merge event
for its full source SHA. The Rundeck consumer first looks for matching
scheduled/dispatched production. If no matching producer is running or ready,
it dispatches `proxy-rust.yml` once with `packages_only=true`, the full
`source_revision` and `package_architecture=amd64`. Dispatch requires that SHA
to remain the default-branch head. A missing exact artifact for an older head
fails the attempt before SSH or provisioning. A qualified run supplies the
literal `merge --source-revision SHA --host-run RUN_ID` invocation. The inner
selector still verifies original artifact bytes, producer identity and guest
compatibility; it never treats newest-completed input as that merge.

The consumer waits up to 7200 seconds for production input. The existing SSH
deadline is 7200 seconds. Optional positive `production_timeout` and
`execution_timeout` config fields select different deadlines. Neither deadline
adds a model retry. An explicit failed producer or missing exact input cannot
fall back to older source.

To consume one emitted run immediately, use the following script through the
existing `POST /api/59/project/acceptance/run/script` binding. Replace
`EVENT_RUN_ID` with the actual blackbox Actions run ID. Run it in devstack's
`rundeck` account after the same private setup; it can dispatch production and
run the credentialed task once.

```sh
set -euo pipefail
umask 077
source /var/lib/rundeck/harness/claude-events/events.env
cd /var/lib/rundeck/harness/claude-events/source
exec "${CLAUDE_EVENTS_PYTHON:-python3}" scripts/claude_blackbox_events.py --config /var/lib/rundeck/harness/claude-events/events.json --event-run EVENT_RUN_ID
```

Each admitted attempt has one private directory at
`attempts/EVENT_RUN_ID-EVENT_ATTEMPT`.
`transport.json` records the canonical event, exact production run when needed,
decoded guest exit, timeout and report-transfer result. `result.json` contains
the fetched original caller report bytes. A completed caller failure still
returns that report and the actual failing exit. Rundeck output includes
`CLAUDE_RESULT:` with the report and `CLAUDE_TRANSPORT:` with transport status.
Wrapper success alone cannot pass. Missing/truncated reports, invalid base64,
hash mismatch, timeout or inconsistent report operands remain failed outcomes.

## Recover without replay

An existing event attempt prevents another submission, even after interruption
or a lost GitHub/SSH response. Inspect the original Rundeck execution, private
attempt and remote output before taking another action. A manual workflow
rerun of all jobs creates a new Actions attempt; a new workflow dispatch creates
a new run. Inspect any uncertain original execution before requesting either.

For a completed remote caller whose observation was lost, use the existing
`ssh_fetch.sh HOST REMOTE_OUTPUT/result.json 8388608` through `run/script`.
Decode its `HARNESS_JSON` only after wrapper success and `truncated=false`;
verify `content_b64` against `sha256`. Keep the original caller exit and reports.
Do not launch the caller again to repair transfer bookkeeping. Retain raw
wrapper/GitHub logs privately; export only the maintained report and transport
receipt, never provisioning output, instance state, vaults or credentials.

Source review and job installation do not establish criterion 4. The protected
automatic attempt still needs its event/run identity, selected artifact tuple,
actual guest exit, original report and verified transfer. The retained manual
execution and its original failure remain separate evidence.
