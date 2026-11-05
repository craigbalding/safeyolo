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
binding. Reuse an installed binding and Sylab's existing `github-repository`
credential; do not repeat a completed private delivery or request a new login.
The principal needs repository/Actions read access and Actions write
access for the existing production dispatch. Do not put that credential in
source, JSON configuration, GitHub Actions or returned reports.

On the owned Ubuntu host, install the reviewed
[access producer](../../scripts/prepare_claude_access.py) and
[shell binding](../../scripts/claude_access_binding.sh) together in a separate
clean source checkout readable by UID 1000. Keep the accepted controller at
`/home/agent/375-build-storage-d62/claude356-caller-9c67/source` unchanged.
The producer uses Python 3.12 or 3.13 and the existing `cryptography` dependency
used by the provisioner. No product build or model call is needed for setup.

Sylab supplies an encrypted access-only source directory on that Ubuntu host.
Reuse the accepted RSA/Fernet handoff. The directory contains the receiver-owned
RSA key `transport-private.pem` and encrypted `sealed-access.json`; it contains
no plaintext access JSON. Protect the directory at `0700` and both files at
`0600`, owned by UID 1000. Keep the receiver's private key on Ubuntu. Give only
its public key to the original operator host through the existing private route.

On the original operator host, Sylab selects the current access value and actual
finite expiry from its encrypted store. In memory, seal exactly `value`,
`expires_at` and `source_expires_at` using Fernet. Wrap the Fernet key with the
receiver's RSA public key using OAEP with SHA-256 for both OAEP and MGF1. The
envelope JSON contains base64 `wrapped_key` and the Fernet `ciphertext` string,
as consumed by the accepted provisioner. Both expiry fields are timezone-aware
ISO 8601 timestamps. Set `source_expires_at` to the actual source credential
expiry; `expires_at` may be the same or an earlier lease expiry. Do not extend
either timestamp when copying the lease. Deliver only the sealed envelope and
replace that complete file atomically when Sylab supplies new applicable access.
Do not write the decrypted payload to a file. Do not supply a full client login,
refresh token, client secret or vault. Renewal material stays in the original
host's encrypted store.

The existing Agent API `GET /gateway/services` binding supplies an agent-scoped
`sgw_` token for its own proxy. It does not export the provider credential or
this helper's sealed input. That token cannot replace the provider access
value imported into the separate installed instance. See the
[gateway credential contract](../../docs/credentials.md#store-a-local-credential).

Create a private shell binding at an operator-selected absolute path on Ubuntu,
owned by UID 1000, with mode `0600` and a `0700` parent. Before using the following
contents, replace each uppercase placeholder: `SEALED_SOURCE` is the absolute
encrypted source directory, `PYTHON` is the provisioner's existing Python executable
with `cryptography`, `PROVISION_HELPER` is the accepted executable helper,
`CREDENTIAL_NAME` is its selected credential name, and `BINDING_SOURCE` is the
absolute path of the new source checkout. Include the existing private
host-process GitHub/registry binding in this file as required by the caller.
Keep credentials out of these placeholders and disable shell tracing before
the private binding reads any secret.

```sh
set +x
CLAUDE_ACCESS_SOURCE='SEALED_SOURCE'
CLAUDE_ACCESS_PYTHON='PYTHON'
CLAUDE_PROVISION='PROVISION_HELPER'
CLAUDE_CREDENTIAL='CREDENTIAL_NAME'
source 'BINDING_SOURCE/scripts/claude_access_binding.sh'
```

For each admitted event, the unchanged SSH payload exports `CLAUDE_EVENT_RUN`
and `CLAUDE_EVENT_OUTPUT`, then sources the private binding under `set -euo
pipefail`. The binding rereads and decrypts the sealed source in memory.
The binding creates a new private `${CLAUDE_EVENT_OUTPUT}.provision` directory
beside the caller output. Keep
their shared parent at `0700`. Fresh RSA/Fernet transport keys seal the existing
helper's exact `value`, `expires_at`, `source_expires_at` payload. Both expiry
fields retain their source values. Decrypted access exists only in the trusted
processes' memory and the provisioner's stdin. The reusable source and the
per-attempt transport retain only ciphertext and protected local keys.
The binding exports
`SAFEYOLO_CLAUDE_PROVISION_DIR`, `CLAUDE_PROVISION` and `CLAUDE_CREDENTIAL` for
the unchanged caller. The helper imports through stdin only after the caller's
credential-free readiness succeeds. It removes both transport files on success.

A missing, public, malformed, altered or expired source fails before the caller starts.
The helper requires more than ten minutes of remaining access; the producer
applies the same condition. The helper checks expiry again at import, so access
that expires during selection/readiness also fails closed. Fresh transport
files do not renew the access lease or extend its expiry. Scheduled use can
continue only while Sylab supplies applicable access input. This setup does
not establish indefinite automatic readiness or refresh copied credentials.

An existing provisioning directory refuses preparation, including after a
failed or interrupted attempt. Do not remove it to retry. Inspect the original
execution and `provision-result.json` first. An unfinished receipt with
`credential_add_exit: null` can represent an uncertain import. Keep the helper's
existing refusal and recovery behavior. Do not export the source file,
transport files, provisioner output or private logs.

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
