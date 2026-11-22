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

```sh
safeyolo-host-executor key-create --directory /home/issuer/private-host-key
safeyolo credentials add host-signing --type api_key --value-file /home/issuer/private-host-key/issuer-key.base64 --storage local
```

The private bootstrap file remains after import. Remove it through the
operator's normal secret-file procedure when the vault import is verified.
The encrypted store and its access controls remain the credential owner.

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
  "verbs": ["discover", "propose", "invoke", "job", "output", "cancel"],
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
launching them. `serve` prints the selected target and ready listener only after
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
policy. Add explicit `gateway:request` permission for the selected service's
native paths using the existing policy owner. Check and privately assess the
complete candidate policy before `safeyolo policy apply FILE`. Do not replace
unrelated policy with a binding fragment. The gateway rechecks the active task,
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

## Starter index and adaptation

| Task | Linux/macOS starter | Windows starter |
|---|---|---|
| Fixed service | Separate status/start/stop/restart; Linux user systemd, macOS loaded launchd label | Enumerate/filter, details/dependencies, separate status/start/stop/restart; no definition changes. |
| Application investigation | Relocated metadata, selected bounded application/system logs, snapshot listing | Same native bounded evidence operations. |
| OS logs | Selected approved log files; broader journal/APFS collection needs separately reviewed definitions | `event-log-query`: channel/provider, UTC since/until, count, record IDs; no clearing/configuration. |
| Registry | No OS registry counterpart | Machine/workload-user hive, selected key/value and 32/64 view; value type; absent differs from denied. |
| Processes, system, software, updates | Adapt a fixed installed tool, such as the hostctl `host-memory` or `host-cpu` recipe, to actual supported bounds | Process parent/start/resource observations; OS/hostname/uptime; bounded uninstall-registry and update inventories with source limits. |
| Files | Native bounded directory/content evidence | Directory/metadata/hash/bounded-content commands, selected literal paths. |
| Network | The current Unix executor profile denies direct probes; no implicit counterpart | Interface/routes/listeners in `network-inspect`; separately granted destination/port probe in `network-diagnostics`. No reconfiguration. |
| Scheduled tasks | No general scheduler authority in this starter | Enumerate/filter tasks; selected definitions/principal/actions/recent status. No execution, registration or modification. |
| Fixed installed executable | The content-pinned executor's inspection commands; typed limits and exact environment | `fixed-executable` runs pinned `whoami.exe`; typed allowed argument, exact account/environment, native deadline/output/status. |

PowerShell query results use `{operation,status,observedAtUtc,timeZone,count,
limitReached,data}`. A reached count limit reports `partial`; access errors
report `access_denied` or `unavailable` and exit 2. A registry observation can
report `absent` in its data. File content explicitly reports a bounded prefix.
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

## Update, recover, revoke and uninstall

| Observation | Next action for the selected owner |
|---|---|
| Quiet authorized catalogue update | Keep the existing catalogue adoption's stable IDs and approved update bounds. Discovery shows desired/observed/qualified/active revisions. No routine per-command prompt is added. |
| Scope/effect/dependency expansion | Privately assess the complete candidate. Use the existing adoption/approval path only where required; an assessment grants no permission. |
| Missing operation | Submit an untrusted definition/scope proposal through existing policy-capability and private assessment tools. Discovery/proposal runs no proposed code. The operator adopts reviewed package bytes, ceiling and issuer policy explicitly. |
| Revoked or expired grant | Refresh or revoke the issuer's actual grant through its owner and update the target snapshot. No automatic renewal. Revocation stops new admissions/reads; admitted effects/deadlines are retained. |
| Required check unavailable | Follow the adopted fallback. The checker remains optional by policy, supplementary and fallible. Inspect the private finding/challenge; revise/abandon or explicitly escalate through the existing approval owner. No automatic allow or retry. |
| Lost reply | Inspect the original request's possible job ID/receipt. Identical retained mutation IDs deduplicate; changed content conflicts. If read authority is revoked, the target operator inspects the ledger. |
| Stale catalogue/revisions | Rediscover that target, compare active package/authority with desired inputs, and prepare a new proposal. Preserve the original operation result. |
| Unsupported version/feature/native guarantee | Upgrade the matching target/gateway/package or select an explicitly supported profile. Do not silently omit required enforcement. |
| Changed TLS certificate/key, listener or runtime | Stop at a safe boundary, preserve state and restart the selected executor. Adopt the new target certificate at the issuer. Saved TLS paths do not prove the running listener changed. |
| Upgrade failure | Keep the previous verified binary, config and ledger; inspect the original process/listener and jobs before restarting or restoring. Never launch a second executor against the same state. |

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
