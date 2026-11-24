# Deploy and use host operations

Use a standalone `safeyolo-host-executor` on the target and an issuing SafeYolo
instance on a supported Linux or macOS host. The target needs no full SafeYolo
installation, Python, Rust toolchain or WSL. Windows starter operations use the
inbox Windows PowerShell 5.1 and its named Windows modules. The server itself
does not require PowerShell.

The target operator selects the account, executable definitions, local ceiling
and enrolled issuer keys. The issuing instance owns agent/run/task policy,
signing credentials, private assessment and approvals. Installation grants no
agent access. An operation proposal cannot adopt code, change the ceiling or
enrol an issuer.

On Linux, the operation's process limit includes bubblewrap's monitor and
namespace init; the Unix starter reserves three processes for its native
inspection program. Adopted Linux commands can also use selected
[`filesystem.write` paths](host-execution-contract.md#linux-writable-paths)
and descendants under the same authority. File results stay at those host
paths after job cleanup; the Output route returns stdout/stderr only.
For TCP clients or listeners, an adopted Linux operation can select
[broader TCP authority](host-execution-contract.md#linux-broader-tcp-authority).
The operator must assess its account-wide address/port exposure. Discovery and
proposals show the target's actual network boundary before invocation. The
starter's ordinary narrow definitions remain disconnected. Its Unix
`endpoint-inspect` operation uses a separate fixed native inspection helper,
as described below.
On macOS, custom definitions can select [writable paths and broader IP socket
authority](host-execution-contract.md#macos-writable-paths-and-broader-network-authority).
The operator selects the actual write roots and assesses Seatbelt's loopback or
all-address class at each permitted port. The existing issuer and target scopes
bind that operation; covered invocations need no recurring human decision.
The macOS adapter still denies fork to ordinary programs. Resolving an adopted
read/write path permits metadata reads of its ancestors, with no sibling file
contents or ancestor directory listing. File results remain at the selected
host paths; the Output route returns stdout/stderr.

## Acquire and prepare the target

Download the standalone ZIP for the required OS/architecture and selected source
from the native proxy workflow. The archive includes `host-executor.json`, this
guide, the Windows authoring source and `agent/host-operation.py`. Compare the
binary SHA-256 and `--version` source/target with the archive metadata before
running it. The [platform table](host-execution-contract.md#standalone-binary-and-build-dependencies)
identifies required OS facilities and the qualified component boundaries.
A workflow artifact is an acquisition input; it does not establish that the
installed target, gateway or starter operations have passed qualification.

Extract the binary into a directory protected from workload replacement. Keep
configuration, keys and ledger in a separate private directory. Put investigation
evidence in another directory readable by the workload. Do not mount the
configuration/key/ledger directory into an operation's read scope.

The following commands run on the **target**, as its executor account. On Unix,
make the executable executable and create a private state directory first. On
Windows, use `.\safeyolo-host-executor.exe` in place of
`./safeyolo-host-executor`. Its private directories must have access control
lists (ACLs) that prevent workload modification. The TLS key must also deny the
workload read access.

For the runnable synthetic case below, use `/home/hostop/case` on Linux,
`/Users/hostop/case` on macOS, or `C:\SafeYolo\Case` on Windows. Replace the
example account paths with the actual executor account paths before running.
The `demo` directory must be new. It creates synthetic relocated-file metadata,
selected application/system log files and an empty snapshot directory. These
are test observations, not real evidence of an earlier disappearance.

```sh
./safeyolo-host-executor --version
./safeyolo-host-executor demo --directory /home/hostop/case
./safeyolo-host-executor starter --root /home/hostop/case --service demo.service --output starter.json
```

On macOS, the service selector is the actual loaded launchd service, for example
`user/501/com.example.demo`. On Windows, select the fixed Windows service name
and add `--credential host-workload`. That credential must already select the
separate ordinary workload account described below. The starter command reads
real executable hashes and the actual workload identity. It writes a package;
it executes no operation and grants no permission. A changed executable needs
a new preparation and adoption. Modules, libraries, service definitions and
object permissions retain the declared dependency limits.

## Select authority and enrol an issuer

Use one versioned package and the existing native configuration/policy owners.
The generated package contains stable operation/resource IDs, typed arguments,
fixed recipes, effect descriptions and enforcement disclosures. The
[authoring reference](service-authoring.md#author-host-operation-packages)
explains projections and composed effect assessment.

On the **issuing operator host**, create a new private directory and generate
an issuer key. Keep its private file outside agents. Import that base64 file
through the existing credential store; select the already adopted storage type
or make the first storage choice explicitly. The following example selects local
storage. Move only `issuer-public.base64` to the target operator through the
existing trusted transfer route. Compare its SHA-256 through that route.
Set the selected instance root before importing the credential. Replace the
example root and private-key paths with the actual paths on this host.

```sh
export SAFEYOLO_CONFIG_DIR=/absolute/issuing-instance-root
safeyolo-host-executor key-create --directory /home/issuer/private-host-key
safeyolo credentials add host-signing --type api_key --value-file /home/issuer/private-host-key/issuer-key.base64 --storage local
```

The private bootstrap file remains after import. Remove it through the
operator's normal secret-file procedure when the vault import is verified.
The encrypted store and its access controls remain the credential owner.

### Read the issuing identity and activate its task

Continue on the **issuing operator host**, outside any agent sandbox. The
installed issuing instance and the selected agent must already be running.
Use that instance's host root and local Admin API address. This example uses
agent `investigator`, task `investigation`, and service `case-host`; keep those
names consistent with the target grant and binding below.

Save this complete task document as `host-task.json` in your private working
directory. Add any other permissions the selected task needs before registering
it. Registration replaces that task's registered document; activation selects it
for this issuing instance. Do not select an unrelated instance or overwrite
another task's document.

```json
{
  "metadata": {"description": "Investigate the selected application using bounded host operations"},
  "permissions": [
    {"action": "gateway:request", "resource": "case-host:/v1/host-execution/*", "effect": "allow", "condition": {"agent": "investigator"}}
  ]
}
```

Run the following with Python 3 on the issuing operator host. Replace the
Admin API port with that of your selected instance first. The exported
`SAFEYOLO_CONFIG_DIR` from credential import keeps these reads and the later
policy commands on the same root. The
code reads its host-held Admin token into memory, reads the trusted identities,
registers and activates the task through the existing Admin API, and saves
only nonsecret context. It does not copy the Admin token or signing key into
an agent or target. Stop on an error; registration alone is not activation.

```sh
umask 077
python3 - <<'PY_HOST_CONTEXT'
import hashlib
import http.client
import json
import os
from pathlib import Path

root = Path(os.environ["SAFEYOLO_CONFIG_DIR"])
admin_port = 9090
admin_token = (root / "data/admin_token").read_text().strip()
def call(method, path, value=None):
    data = None if value is None else json.dumps(value).encode()
    connection = http.client.HTTPConnection("127.0.0.1", admin_port, timeout=15)
    try:
        connection.request(method, path, body=data,
                           headers={"Authorization": "Bearer " + admin_token,
                                    "Content-Type": "application/json"})
        response = connection.getresponse()
        result = json.load(response)
        if response.status != 200:
            raise RuntimeError((method, path, response.status, result))
        return result
    finally:
        connection.close()

instance = call("GET", "/admin/instance")["safeyolo_instance_id"]
assert instance == (root / "data/instance_id").read_text().strip()
agents = call("GET", "/admin/agents")["agents"]
selected = [agent for agent in agents if agent["name"] == "investigator"]
assert len(selected) == 1 and selected[0]["runtime_state"] == "running"
agent = selected[0]
assert agent["agent_id"] and agent["run_id"]
task = json.loads(Path("host-task.json").read_text())
assert call("PUT", "/admin/policy/task/investigation", {"policy": task})["status"] == "updated"
assert call("POST", "/admin/policy/task/investigation/activate", {})["status"] == "activated"
registered = call("GET", "/admin/policy/task/investigation")["policy"]
canonical = json.dumps(registered, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False).encode()
context = {"issuer_id": instance,
           "principal": {"run": {"agent": agent["name"], "agent_id": agent["agent_id"],
                                  "run_id": agent["run_id"]}, "task_id": "investigation"},
           "task_revision": hashlib.sha256(canonical).hexdigest()}
Path("issuer-context.json").write_text(json.dumps(context, indent=2) + "\n")
print(json.dumps(context, indent=2))
PY_HOST_CONTEXT
```

Expected: the registered task is activated and `issuer-context.json` contains
the durable instance ID, current host-observed agent/run and the digest of
the complete registered task document. Keep `host-task.json` for re-registration
after an issuer restart; task registration is runtime state. A new agent run
or task change needs new context and explicit target adoption before use.
Transfer `issuer-context.json` and `issuer-public.base64` to the target operator
through the existing trusted route. Neither file contains a private key.
Use their actual values in `issuer-settings.json` below.

On the **target**, write `selection.json` with the exact desired resources,
complete typed argument choices (including permitted defaults), and finite
budgets. This example grants only one metadata operation. Use the same form
for the separate application/system logs, snapshot listing and each fixed
service action. Source membership alone gives no invocation scope.

```json
{
  "bundle-metadata": {
    "resources": ["evidence:bundle-metadata"],
    "arguments": {"limit": [50]},
    "budgets": {"calls": 20, "concurrent": 1, "timeout_seconds": 10, "output_bytes": 65536}
  }
}
```

```sh
./safeyolo-host-executor scopes --package starter.json --selection selection.json --output scopes.json
```

The scope writer supplies each exact implementation digest. It neither adopts
nor expands the selection. Review all selected effect and account permissions
before using the file as a grant or ceiling.

Create `issuer-settings.json` with these fields. `issuer_id` is the issuing
instance's durable ID. `principal.run` comes from that instance's current
host-observed agent/run, and `task_id` names its registered and activated task.
`operations` names the reviewed scope file. `public_key_file` names the
transferred public key. Times are UTC Unix seconds. Choose future finite grant
and authority expiry, with `not_before` no later than the intended admission.
`assessment_revision` identifies the actual adopted issuer policy/check inputs.
Do not substitute an agent-provided identity or explanation.

```json
{
  "issuer_id": "issuer-instance",
  "key_id": "host-key-1",
  "public_key_file": "/home/hostop/issuer-public.base64",
  "grant_id": "investigation-1",
  "principal": {"run": {"agent": "investigator", "agent_id": "ag-actual", "run_id": "actual-run"}, "task_id": "investigation"},
  "operations": "/home/hostop/scopes.json",
  "verbs": ["discover", "propose", "invoke", "job", "output", "file", "cancel"],
  "not_before": 0,
  "expires_at": 1,
  "authority_valid_until": 1,
  "assessment_revision": "actual-adopted-input-revision"
}
```

This is a field reference: replace the identities, paths, times and assessment
revision with the selected owner's actual values before the next command.
The deliberately expired reference values cannot create a usable grant.

```sh
./safeyolo-host-executor prepare-issuer --settings issuer-settings.json --output issuers.json
```

Create `target-settings.json` with the fields below. All paths must be actual
absolute paths. `package`, `issuers` and `ceiling` name the prepared JSON files.
Use `{}` files for issuers/ceiling when preparing a target without access.
The operator explicitly chooses the ceiling; selecting the same `scopes.json`
as the issuer grant is appropriate only when that is the desired local maximum.
No issuer can override it.

| Field | Input |
|---|---|
| `target_id` | Stable target ID, retained across upgrade/restart. |
| `package`, `issuers`, `ceiling` | Paths to the selected files. |
| `allowed_verbs` | Explicit protocol actions, such as the six in the issuer example. |
| `max_authority_age_seconds` | Finite maximum issuer-observation age, for example 600. |
| `connections`, `connection_timeout_seconds` | Positive listener count and whole-request deadline, for example 4 and 10. |
| `ledger` | `jobs`, `mutation_records`, `output_bytes`, `database_bytes`, `request_bytes`; the native limits in the contract apply. |
| `native` on Linux | `platform: "linux"`, actual pinned `bubblewrap` path/hash, delegated cgroup v2 `cgroup` path, positive `executable_bytes`. |
| `native` on macOS | `platform: "macos"`, positive `executable_bytes`. The package explicitly declares the memory/restart limits. |
| `native` on Windows | `platform: "windows"`, executor-owned workload `credential` name, positive `executable_bytes`. |
| `https` | `listen`, `certificate`, `private_key`; use `null` for the protected local socket/pipe. |

For remote use, create a target certificate in the existing private state
folder. Replace `target.example.net` with the DNS name or IP that the issuer
will actually connect to. The native command prints its public fingerprint.
Adopt that exact certificate on the issuer through the trusted transfer route.
A matching target label in a response is insufficient identity verification.
No system certificate or trust store is changed.

```sh
./safeyolo-host-executor tls-create --name target.example.net --directory /home/hostop/private-state
./safeyolo-host-executor prepare --settings target-settings.json --output target.json
./safeyolo-host-executor check --config /home/hostop/target.json --state /home/hostop/private-state
./safeyolo-host-executor serve --config /home/hostop/target.json --state /home/hostop/private-state
```

`prepare` saves a candidate configuration and reports `activated: false`.
`check` validates all adopted implementations and native dependencies without
launching them. For Linux TCP operations, it also prints the selected directions
and broader address/port exposure from the same target-generated disclosure
used by discovery and proposals. `serve` prints the selected target and ready listener only after
validation, ledger reconciliation and binding. A saved file is not evidence of
running-target readiness.

Linux requires an operator-delegated cgroup v2 subtree with memory/pids controls
and permission to migrate jobs from the executor's current cgroup. A user
systemd service can supply delegation; placing only the jobs directory in a
delegation is insufficient when the executor cannot write its common ancestor's
`cgroup.procs`. Keep bubblewrap and the account's systemd manager channel pinned.
Use the existing host's service configuration to start this exact foreground
command. On macOS, use a LaunchAgent for the selected account. Keep the same
configuration, state, account and explicit lifetime under service management.
The foreground server and managed service enforce the same native contract.

## Windows foreground and Windows Service

Use native Windows 11 x86-64 with the prebuilt executable. The executor account
must be protected from workload impersonation/modification and have
`SeImpersonatePrivilege`, or the assign-primary-token/quota privileges required
by the chosen native launch. Use a separate ordinary workload account. Its ACLs
and OS permissions remain material authority: Job Objects do not confine its
filesystem, registry, network/IPC or service access. Grant only the intended
fixed service control, Event Log, registry, task and evidence permissions to
that account. Reads can fail with access denied without implying absence.

As the **executor account**, store the workload password in that account's
Windows Credential Manager. In the following Windows PowerShell 5.1 commands,
replace `HOST\workload` with the existing ordinary workload account. The OS
credential prompt hides the password; UTF-8 pipe encoding preserves non-ASCII
characters. The native command receives the password only on stdin. Never put
it in an argument, JSON, transcript or package.

```powershell
$workload = Get-Credential -UserName 'HOST\workload' -Message 'Host-operation workload account'
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$workload.GetNetworkCredential().Password | .\safeyolo-host-executor.exe credential-store --name host-workload --account HOST\workload
```

For noninteractive use, supply UTF-8 stdin from the existing credential owner.
The command adds no recurring prompt. `identity --credential host-workload`
returns the observed workload SID and stable groups used by `starter`. The
server and credential command also accept the noninteractive native path.

The Windows starter declares `TEMP` and `TMP` as `Temp` beneath the selected
`--root`. Before running its PowerShell operations, create that directory and
give the workload account Modify access. PowerShell startup uses writable
temporary storage for policy probes; an absent or unwritable location can
leave the workload in ConstrainedLanguage even when the executor account's
PowerShell session uses FullLanguage. The executor passes only the declared
environment.

As the **target directory owner**, use the same root and stored credential
selected for `starter`. This example uses `C:\SafeYolo\Demo` and grants access
only to its temporary directory; private target configuration and state must
remain protected from the workload.

```powershell
$identity = .\safeyolo-host-executor.exe identity --credential host-workload | ConvertFrom-Json
New-Item -ItemType Directory -Path 'C:\SafeYolo\Demo\Temp' | Out-Null
icacls.exe 'C:\SafeYolo\Demo\Temp' /grant ('*' + $identity.principal + ':(OI)(CI)(M)')
```

For an existing directory, verify its workload access before reuse. When
adapting an already adopted package, regenerate and explicitly select the
operation scopes for the changed environment through the existing owners.

For service installation, run an elevated operator terminal. The selected
service account must own that same workload credential and have **Log on as a
service** plus its documented native launch privileges. The native installer
creates a demand-start service, reads the service account password from stdin,
and does not grant account rights or start it. Replace the named account and
paths with the configured executor account and actual protected files.
Use Windows PowerShell 5.1's OS credential prompt to supply the service password
privately. The command writes no plaintext password file.

```powershell
$serviceAccount = Get-Credential -UserName 'HOST\executor' -Message 'Executor Windows Service account'
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$serviceAccount.GetNetworkCredential().Password | .\safeyolo-host-executor.exe service-install --name SafeYoloHost --config C:\SafeYolo\Private\target.json --state C:\SafeYolo\Private\state --account HOST\executor
sc.exe start SafeYoloHost
sc.exe query SafeYoloHost
```

`RUNNING` means the listener started, not that an operation succeeded. Preserve
state and admitted-job deadlines when stopping or upgrading. Do not use the
workload account as the executor service account.

## Bind the issuing gateway and observe active revisions

On the **issuing operator host**, adopt the prepared target through the existing
`host_bindings` policy table. The binding fields remain defined by
`host_execution_binding` in installed policy-capability discovery. Its `target`
is the complete prepared target, with the selected native grant and trust.
Use the current instance, current run, activated task and registered task
JSON digest as `task_revision`. Select the vault reference `host-signing`,
enrolled `key_id`, native `grant_id`, service name and finite transport limits.

For remote targets the endpoint is:

```json
{"transport":"https","host":"target.example.net","port":44323,"certificate_pem":"-----BEGIN CERTIFICATE-----\n...actual transferred target certificate...\n-----END CERTIFICATE-----\n"}
```

For a Unix target on the same host it is:

```json
{"transport":"unix","socket":"/actual/private-state/control.sock","executor_uid":1000}
```

`host_bindings.NAME` is the JSON-encoded binding string in the existing TOML
policy. Give the activated operator task explicit `gateway:request` permission
for the selected service's native paths. For a binding with service `case-host`
and agent `investigator`, the task's IAM `permissions` array includes:

```json
{"action":"gateway:request","resource":"case-host:/v1/host-execution/*","effect":"allow","condition":{"agent":"investigator"}}
```

The task registration and activation sequence above supplies `task_revision`
in `issuer-context.json`. A host policy with a `hosts` table compiles host rules;
appending an IAM `permissions` array there does not add these task permissions.
A policy using the IAM form without `hosts` can carry them directly.

Return the target's validated configuration and public TLS certificate through
the trusted operator route. Save the configuration as `adopted-target.json`
and the certificate as `target.pem` in the issuing operator's working directory.
The configuration carries public authority and credential references, not the
Windows workload password. Do not transfer the target's TLS private key,
Windows credential store or issuer vault.

The following creates the complete `case` binding for that adopted target.
Replace the HTTPS host/port with the endpoint selected during target setup.
For a same-host Unix target, use the Unix endpoint form above instead.
The credential reference `host-signing`, key `host-key-1`, grant
`investigation-1` and service `case-host` refer to the earlier selections.

```sh
python3 - <<'PY_HOST_BINDING'
import json
from pathlib import Path

context = json.loads(Path("issuer-context.json").read_text())
target = json.loads(Path("adopted-target.json").read_text())["target"]
grant = target["issuers"][context["issuer_id"]]["authority"]["grants"]["investigation-1"]
assert grant["principal"] == context["principal"]
binding = {"target": target, "issuer_id": context["issuer_id"],
           "grant_id": "investigation-1", "key_id": "host-key-1",
           "credential": "host-signing", "service": "case-host",
           "task_revision": context["task_revision"],
           "endpoint": {"transport": "https", "host": "target.example.net", "port": 44323,
                        "certificate_pem": Path("target.pem").read_text()},
           "timeout_ms": 10000, "request_bytes": 1048576, "response_bytes": 1048576}
Path("host-binding.json").write_text(json.dumps(binding, indent=2) + "\n")
row = "case = " + json.dumps(json.dumps(binding, ensure_ascii=False)) + "\n"
Path("host-binding-row.toml").write_text(row)
print("Saved host-binding.json and the case row in host-binding-row.toml")
PY_HOST_BINDING
```

Copy the selected issuing instance's complete policy to `policy-candidate.toml`.
The command below uses the standard root's `policy.toml`. If this instance's
`config.toml` selects another `policy_file`, copy that configured file instead.

```sh
cp "$SAFEYOLO_CONFIG_DIR/policy.toml" policy-candidate.toml
```

Insert the generated row into its existing `[host_bindings]` table, replacing
only `case` if it already exists. Add that table only when absent. Preserve
all other policy, agent identities and bindings. `host-binding-row.toml` is a
row to insert, not a complete policy to apply.

Check and privately assess the complete candidate through the existing
[policy-authoring controls](../cli/src/safeyolo/agent_context/skills/policy-authoring/SKILL.md).
When using `policy assess`, its snapshot request ID is the already approved
snapshot from that workflow. Assessment does not grant authority or activate
the candidate. Apply only the reviewed complete policy on the same selected
issuing instance:

```sh
safeyolo policy check policy-candidate.toml
safeyolo policy apply policy-candidate.toml
safeyolo policy show
```

Expected: check reports a valid policy; apply/show confirm the candidate is
active and saved source matches active state. If confirmation times out,
inspect that state before another apply. The gateway rechecks the active task,
current run, grant, vault and route/check policy before every dispatch.

Remote transport validates the adopted certificate chain and endpoint name
before sending any signed request. There are no redirects or automatic retries.
The target independently checks the signature, principal, expiry, revisions,
ceiling and budgets. Updating an issuer snapshot requires adoption at both
owners; it is not implicitly synchronized by a request.

## Run and inspect the synthetic investigation

Inside the **authorized agent sandbox**, use Python 3 and the installed helper
from this skill's `scripts/host-operation.py`, or the identical archive helper
transferred through the operator's existing approved input route. Resolve that
script's installed path before calling it. Set `HOST_CLIENT` to the script path
and replace `case` with the discovered binding. The helper reads the ordinary
Agent API token from `/app/agent_token` for each call. It never prints the token,
accepts issuer keys, requests adoption or retries a failed call.

```sh
python3 "$HOST_CLIENT" bindings
python3 "$HOST_CLIENT" discover case --request-id discover-case-1
python3 "$HOST_CLIENT" propose case --request-id metadata-proposal-1 --operation bundle-metadata --resource evidence:bundle-metadata > metadata-prepared.json
python3 "$HOST_CLIENT" invoke case --request-id metadata-invoke-1 --prepared metadata-prepared.json > metadata-admission.json
```

`propose` only prepares typed arguments and current revision pins. Inspect its
normalized invocation, intersected budgets, validity and assessment digest
before invoking. An operator can run the same commands in that agent's existing
authorized guest shell. Operator possession of a target config alone does not
supply an agent identity.

Retain the original invocation request ID and returned `receipt.job_id`. Replace
`JOB_ID` below with that literal returned ID. A request that loses its reply
needs the original job inspection before any repeated effect.

```sh
python3 "$HOST_CLIENT" job case --request-id metadata-status-1 --job JOB_ID
python3 "$HOST_CLIENT" output case --request-id metadata-output-1 --job JOB_ID --offset 0 --bytes 65536
```

For authorised file-producing Unix jobs, use the same helper's `file` command.
The grant and target must explicitly permit `file`; `output` alone grants no
file access. `prepared.file_roots` records the adopted writable paths. Select a
regular file within both the admitted and current writable scope. Replace
`/selected/result` with its actual target path and use the retained job ID:

```sh
python3 "$HOST_CLIENT" file case --request-id file-read-1 --job JOB_ID --path /selected/result --offset 0 --bytes 4096
```

The response reports base64 bytes, observed total length, a chunk SHA256,
observation time and `file_revision`. For later chunks, pass that revision with
`--file-revision REVISION` and advance by the decoded chunk length. Replacement
or observed modification returns a stale result. Reads are live observations,
not atomic snapshots or proof that the job produced every byte. Symlinks below
a selected root and special files are refused. Missing or unreadable files are
unavailable, including after host storage failure. Windows file retrieval is
not implemented; its existing job/stream inspection remains available.

Selected files stay at their host paths after completion, failure, cancellation
and restart. The target operator controls their retention/removal. This route
adds no artifact copy, lifetime extension, rollback or file-storage quota.
Current file and operation/resource authority must still permit retrieval;
revocation/expiry can remove agent access without deleting the files. Inspect
partial files separately from job failure, stream truncation and termination.

If the helper reports an uncertain invocation or cancellation, its error JSON preserves
`possible_job_id`, the original request ID and selected target context. Use `job`
with that possible job ID before another invocation. A possible ID does not
prove admission or execution. If the binding changed or current access no
longer permits the read, ask the original target operator to inspect its ledger.

Repeat the proposal/invocation/read sequence for `application-log`, `system-log`
and `snapshot-list`, with their `evidence:OPERATION` resource IDs. The fixture
contains no earlier snapshots and no original removal record. Report that gap.
Do not infer the original cause from current location or reinstall behavior.
Observation JSON includes UTC time, source, limit unit and completeness. Output
is base64 bytes; preserve the receipt, offsets and retained-output digest when
transferring authorized evidence into the sandbox. The receipt's
`output_truncated` is separate from an operation's own bounded `partial` result.

For `service-status`, `service-start`, `service-stop` and `service-restart`, use
resource `service:demo` on Unix and the package's listed resource on Windows.
Grant each action separately. The OS service definition, code, account and
configuration are not granted by those actions. Service processes and persistent
effects are outside the helper's lifecycle controls. On macOS, stopping sends
SIGTERM; a configured KeepAlive service can restart. Do not describe that as
disabling or removing the service.

The macOS starter permits up to 30 seconds for start/restart because launchd can
throttle rapid restarts. The selected grant and local ceiling still determine
the actual deadline; a smaller task budget can time out the helper while the
service manager continues its separately governed work. Inspect service status
before another effect after a timeout.

## Starter index and adaptation

| Task | Linux/macOS starter | Windows starter |
|---|---|---|
| Fixed service | Separate status/start/stop/restart; Linux user systemd, macOS loaded launchd label | Enumerate/filter, details/dependencies, separate status/start/stop/restart; no definition changes. |
| Application investigation | Relocated metadata, selected bounded application/system logs, snapshot listing | Same native bounded evidence operations. |
| OS logs | Selected approved log files; broader journal/APFS collection needs separately reviewed definitions | `event-log-query`: channel/provider, UTC since/until, count, record IDs; no clearing/configuration. |
| Registry | No OS registry counterpart | Machine/workload-user hive, selected key/value and 32/64 view; value type; absent differs from denied. |
| Processes, system, software, updates | Adapt a fixed installed tool, such as the hostctl `host-memory` or `host-cpu` recipe, to actual supported bounds | Process parent/start/resource observations; OS/hostname/uptime; bounded uninstall-registry and update inventories with source limits. |
| Files | Native bounded directory/content evidence | Directory/metadata/hash/bounded-content commands, selected literal paths. |
| Network | `endpoint-inspect` checks only adopted endpoint choices. Starter workload definitions retain socket denial. Custom Linux definitions can select broader TCP authority. Custom macOS definitions can select broader TCP/UDP direction, port and loopback/all-address authority. | Interface/routes/listeners in `network-inspect`; separately granted destination/port probe in `network-diagnostics`. No reconfiguration. |
| Scheduled tasks | No general scheduler authority in this starter | Enumerate/filter tasks; selected definitions/principal/actions/recent status. No execution, registration or modification. |
| Fixed installed executable | The content-pinned executor's inspection commands; typed limits and exact environment | `fixed-executable` runs pinned `whoami.exe`; typed allowed argument, exact account/environment, native deadline/output/status. |

PowerShell query results use UTF-8 JSON with `{operation,status,observedAtUtc,
timeZone,count,limitReached,data}`. A reached count limit reports `partial`.
Permission errors, including registry `SecurityException` results, report
`access_denied` and exit 2. Other failed queries report `unavailable` and exit 2.
A registry observation can report `absent` in its data. The user-registry
recipe opens the actual workload SID under `HKEY_USERS`. If that hive is not
loaded, the recipe reports `unavailable` and exits 2. It does not load a user
profile or read the operator or SYSTEM default hive instead.
File content explicitly reports a bounded prefix.
Task run-time fields remain `null` when the OS supplies no value.
Software rows identify their uninstall `registryKey`; `Name` and `Version`
remain `null` when the corresponding registry values are absent.
The software inventory covers the selected uninstall registry view, not all
portable/per-user software. Hotfix inventory is the OS provider's view, not a
complete patch-vulnerability assessment. Missing executable paths or fields in
process output retain their OS permission/availability limits.

To adapt an operation, edit the common package source, add a literal reviewed
executable/recipe or script, declare its dependencies/effects/privileges, and
prepare its actual content hash and workload identity. Typed arguments enter
Windows commands through environment data, never source interpolation. On
Unix, fixed argv words remain separate arguments. Run `scopes` against the
new package, review the authority change, and adopt through the same target
and issuing policy owners. A hash identifies bytes; it does not prove arbitrary
code behavior or make agent-writable service dependencies trustworthy.

The Windows source also contains separately governed write/transmit/reviewer
composition examples. They have no implicit grant from query access. Select
only the operations and scope intended for the current task.

## Inspect a selected endpoint on Unix

On the target, `starter` includes `endpoint-inspect`, with resource
`endpoint:selected`. The example selects TCP IPv4 loopback and a kernel-chosen
port. That example is not a product restriction. Before adoption, replace or
extend `arguments.endpoint.options` with the complete choices required by the
task. Select the same choices in the existing issuer grant and target ceiling
through `scopes`. Loading a definition grants no access.

Each choice is a typed JSON object. `candidates` contains the permitted
alternatives in the order to try. Each candidate declares `transport` (`tcp`
or `udp`), `family` (`ipv4` or `ipv6`), `address`, `interface`, `port`,
`ipv6_only`, `reuse_address` and `reuse_port`. For example:

```json
{"candidates":[{"transport":"tcp","family":"ipv4","address":"127.0.0.1","interface":null,"port":8080,"ipv6_only":false,"reuse_address":false,"reuse_port":false}]}
```

An explicit address must match its family. To resolve a current address on a
selected interface, set `address` to `null` and supply that target's interface
name. With both fields supplied, the helper verifies that the address belongs
to that interface. It returns only the selected interface and address, without
other inventory. An interface identifies the source of the address; it is not
an enforced ingress device restriction. A wildcard address with an interface
selector is unsupported because this helper does not enforce device binding.
An explicit wildcard with `interface: null` remains a valid choice. IPv6
link-local resolution carries the interface index. IPv4 requires
`ipv6_only: false`.

Inside the authorised agent sandbox, propose `endpoint-inspect` using resource
`endpoint:selected` and the chosen object as the `endpoint` argument. Use the
same proposal, invocation, job and output commands described above. The normal
signature, run/task, revision, argument, ceiling and budget checks apply before
the helper observes the target. No recurring confirmation is added.

For the example above, save `{"endpoint": CHOICE}` as `endpoint-arguments.json`,
replacing `CHOICE` with the complete object. With the same `HOST_CLIENT` and
authorised `case` binding used above, prepare the inspection:

```sh
python3 "$HOST_CLIENT" propose case --request-id endpoint-proposal-1 --operation endpoint-inspect --resource endpoint:selected --arguments endpoint-arguments.json > endpoint-prepared.json
python3 "$HOST_CLIENT" invoke case --request-id endpoint-invoke-1 --prepared endpoint-prepared.json > endpoint-admission.json
```

Expected: a proposal followed by an admitted job. Read that job and its retained
output through the same `job` and `output` commands. A completed inspection job
can report a conflict or denial; completion means the observation completed,
not that the endpoint is available.

The retained output is an `EndpointObservation` JSON object. It reports
`available_at_observation`, `conflict`, `denied`, `unavailable` or `unknown`,
with the observation time, selected candidate, concrete binding, selected
interface when requested, and a scoped reason. Native permission failures and
incomplete observations do not report availability. The trusted native helper
filters host facts before output; it returns no unrelated listener, port,
process, route or interface inventory. Its exact executable and empty
environment are validated before launch. Arbitrary adopted programs receive
no inspection exception.

The helper tests a real bind with the selected reuse and IPv6-only options.
TCP also tests listen; UDP tests bind. All probe sockets close before the
result returns. Port zero returns the endpoint allocated for that observation.
With `reuse_port`, a TCP probe can briefly share an existing listener and receive
queued connections; the helper does not accept them. Select reuse options only
when that observation matches the intended service operation.
Only explicitly authorised alternatives are tried. A check is not a
reservation: a later competing bind can win, and the service's actual bind
remains authoritative. A probe does not grant service start, replacement,
termination, firewall or publication authority.

Binding, application readiness and audience reachability are separate facts.
`reservation` is false; `application_ready` and `reachable_audience` remain
null. The helper does not observe forwarding, firewall, authentication,
application TLS or VPN/tunnel protection. The operator's intended audience
and the agent's rationale do not become observations. Broader standing grants
still require assessment through the existing effect and policy owners.

## Update, recover, revoke and uninstall

| Observation | Next action for the selected owner |
|---|---|
| Quiet authorized catalogue update | Inspect the target and issuer catalogue owners' desired/observed/qualified/active revisions. Refresh the stored binding to the already adopted target as described below, then rediscover. Keep the stable IDs and approved update bounds; no routine per-command prompt is added. |
| Scope/effect/dependency expansion | Privately assess the complete candidate. Use the existing adoption/approval path only where required; an assessment grants no permission. |
| Missing operation | Submit an untrusted definition/scope proposal through existing policy-capability and private assessment tools. Discovery/proposal runs no proposed code. The operator adopts reviewed package bytes, ceiling and issuer policy explicitly. |
| Revoked or expired grant | Refresh or revoke the issuer's actual grant through its owner and update the target snapshot. No automatic renewal. Revocation stops new admissions/reads; admitted effects/deadlines are retained. |
| Required check unavailable | Follow the adopted fallback. The checker remains optional by policy, supplementary and fallible. Inspect the private finding/challenge; revise/abandon or explicitly escalate through the existing approval owner. No automatic allow or retry. |
| Lost reply | Inspect the original request's possible job ID/receipt. Identical retained mutation IDs deduplicate; changed content conflicts. If read authority is revoked, the target operator inspects the ledger. |
| Stale catalogue/revisions | Rediscover that target, compare active package/authority with desired inputs, and prepare a new proposal. Preserve the original operation result. |
| Unsupported version/feature/native guarantee | Upgrade the matching target/gateway/package or select an explicitly supported profile. Do not silently omit required enforcement. |
| Changed TLS certificate/key, listener or runtime | Stop at a safe boundary, preserve state and restart the selected executor. Adopt the new target certificate at the issuer. Saved TLS paths do not prove the running listener changed. |
| Upgrade failure | Keep the previous verified binary, config and ledger; inspect the original process/listener and jobs before restarting or restoring. Never launch a second executor against the same state. |

After a quiet update, both catalogue owners can have adopted the new package
while `host_bindings.case.target` still names the previous package. Rediscovery
or a new proposal cannot change that stored binding. On the issuing operator
host, compare both active catalogue revisions and inspect the target's adopted
package, authority and ceiling against the approved update bounds. Use the
material-expansion path if the change exceeds those bounds.

For an already authorized update, transfer the current validated target
configuration as `adopted-target.json` through the same trusted route. Rerun the
binding-generation block above with that file and the retained current
`issuer-context.json` and certificate. Preserve the selected issuer, key,
credential, grant, task and transport limits. Replace only the `case` row in a
copy of the complete issuer policy, then check, privately assess and apply it
through the same policy owner. Use `policy show` to verify activation.

Return to the agent's existing `discover case` call. Compare its active package
with the refreshed binding before preparing a new operation. This read adds no
job. If an earlier invocation had an uncertain reply, inspect its original
job/receipt before another invocation; binding recovery does not authorize
replaying that effect.

A discovery `HOST_RESPONSE_MISMATCH` reports `expected_package_sha256` and
`observed_package_sha256` for comparison by the gateway and target owners.
Its `execution_outcome: unavailable` describes the failed read; discovery
does not dispatch an invocation. An uncertain invocation or cancellation
instead retains the original job to inspect before another effect.

`status --config ABSOLUTE_JSON --state ABSOLUTE_DIRECTORY` reports saved target
identity, desired package/catalogue and native validation. It explicitly reports
that running-target state was not observed. Use authenticated discovery for the
active target and `job`/`output` for the original execution.

For issuer-key rotation, generate/import a new key through the existing vault,
adopt its public key and new trust revision at the target, then select that key
in the gateway policy. Remove the old key when it should no longer authorize
requests. Removing a gateway binding or vault key is issuer-side revocation;
removing the target issuer/key is target-side revocation. Neither undoes effects.
Use `credential-store` to replace or `credential-remove` to remove a Windows
workload credential under the executor account; it is separate from issuer-key
rotation.

For uninstall, revoke admissions first, inspect admitted jobs and stop the
selected process/service. On Windows use `sc.exe stop NAME`, observe its stopped
state, then `service-remove --name NAME`. The latter marks the service for
deletion; it does not stop jobs or delete data. Remove the selected systemd user
service/LaunchAgent through the host's existing owner. The binary, definitions,
configuration, ledger, evidence, TLS files, issuer vault credentials, Windows
Credential Manager entry and workload account remain until explicitly removed
by their owners. Retain required receipts and privacy controls when removing
those files. No guest-side daemon, second issuer policy editor or mandatory
central catalogue is installed.
