# Hardware deployment inputs and recovery

These are the inputs for the two independent entries in the
[deployment guide](README.md). Craig owns installing cron after Relay supplies
the reviewed candidate and deployment prerequisites. Complete retained
Kernel-based Virtual Machine (KVM) and physical Apple Virtualization.framework
(VZ) consumers are accepted at the separate selections linked in that guide.
Installed hardware cron, automatic selection through these entries, deployed
publication and email delivery remain unproved. Missing artifacts or staging
receipts fail the attempt. No build-on-Tart preparation belongs in this nightly
consumer path.

## Bind the trusted configuration

The installed Bash entries source private, operator-owned shell files at
`/etc/safeyolo-hardware/kvm.env` and `/etc/safeyolo-hardware/vz.env`.
`KVM_DEPLOYMENT_ENV` and `VZ_DEPLOYMENT_ENV` can select other absolute config
paths. Set each account's actual tool `PATH` in its config file; cron does not
inherit an interactive shell's setup.
Keep those files and all control/publication credentials outside candidate
authority. Both trusted accounts need Bash, Git, `gh`, `jq`, ORAS and a Python
3.12 or 3.13 environment containing the controller's frozen development
dependencies. Set `HARDWARE_PYTHON` to that environment's actual interpreter.
The GitHub principal needs repository Actions read access and #889 comment
write/read access. It never reaches the tested guest or `sy-agent` environment.
ORAS needs pull access to the staged guest repository. These entries do not
need registry write access.

The default-branch native producer runs at 03:23 UTC. Hosted blackbox runs at
03:17 UTC. Each consumer selects an already completed build by run/artifact ID;
there is no dependency on those schedules starting or finishing in order.

Each entry calls `scripts/select_blackbox_artifacts.py` once, then transfers
the frozen selection, host archive, guest archive and pinned controller. The
execution path is `run-hardware-lane.sh` → `retained_inputs.py run` →
`run-installed-package.sh --package ... --guest-archive ...` →
`run-installed.sh --prepared-config ...`. The wrapper filters credentials with
`env -i`. The installed runner gives every section separate writable state;
neither entry calls the held paired controller.

### Devstack KVM account

Use devstack's `rundeck` account and its existing `acceptance` project script
interface. No GitHub hardware runner is involved. The wrapper runs the installed
harness jobs locally in that account.

| Value | Required input |
|---|---|
| `HARNESS_JOBS` | Existing deployed jobs; default `/var/lib/rundeck/harness/jobs` |
| `KVM_ATTEMPTS` | Private attempt parent; default `/var/lib/rundeck/harness/evidence/issue889` |
| `HARDWARE_PYTHON` | Trusted controller Python with the frozen development dependencies |
| `KVM_LANE_TIMEOUT` | Optional positive SSH execution deadline; default 7200 seconds |

The harness must supply `_common.sh`, `list_guests.sh`, `provision.sh`,
`ssh_exec.sh`, `ssh_fetch.sh` and `teardown.sh`, with its existing private SSH
key and libvirt/pool permissions. The wrapper uses `--flavor bare --reuse`.
The harness's `full` flavor builds SafeYolo and is not a valid retained consumer.
Bare provisions only the operating system and ordinary tools. The wrapper
transfers the pinned controller and frozen host/guest bytes, prepares test
dependencies, then invokes all maintained KVM sections once.

Before deployment, verify that the independently reviewed
[console-lock correction](https://github.com/craigbalding/safeyolo-harness/pull/6/commits/e9ad4f8fabfa723e388cbfd8f01a8ac54f1046f3)
is installed. The fresh-guest entry checks for four CPUs, 10 GiB available
memory and 90 GiB pool space, then requests that allocation. These are entry
guards, not measured product minima. It also checks actual KVM capability.
The harness logs in as `agent`; its bare user setup does not add `kvm`
membership. If that membership is missing, the entry adds only `agent` to
`kvm`. It starts the probe and runner as `agent` with refreshed groups and
preserves the remote environment before the existing credential filter.
The ordinary user must open `/dev/kvm` read/write and obtain API version 12.
Device modes stay unchanged. Check guest fixture ports 8180, 9190, 8181,
18080, 18443 and 19999 before execution. Existing provision/attempt locks,
exact early lease, domain/disk checks, owned teardown and foreign-resource
preservation remain in use.

Accepted Rundeck run 7089 reused a separately prepared host with two CPUs and
4 GiB memory through the inner wrapper. It did not prove this entry's fresh
provisioning or installed schedule. Its
[corrected runnable recipe](https://github.com/craigbalding/safeyolo/issues/1105#issuecomment-6243870729)
keeps parent/state setup at umask `077`, the private log at mode `0600`, and the
wrapper child at umask `022` for the Debian workloads fixture. The fresh entry
sets `022` inside that remote child, before both the probe and maintained runner.

For reuse of unchanged Python 3.13 tools in that recipe, use
`cp -a --reflink=auto` into an actual ignored `source/.venv` directory. Do not
use a `.venv` symlink or change ignore rules. Verify clean source after the
copy. Successful run 7089 needed no `uv sync` or product build. The current
fresh-guest entry instead prepares test tools with `uv sync --frozen --group
dev --python 3.13`; that command does not build product binaries.

### Bristol trusted account and confined execution

The trusted cron account runs on Bristol and uses its existing SSH binding to
that same machine's `sy-agent` account. Record the trusted account's actual name
when Craig installs cron. Obtain the verified server host key, endpoint and
authorized public key through the
[Seatbelt SSH setup](../../../contrib/macos-seatbelt-agent/README.md#3-give-the-connection-instructions-to-your-agent).
The private SSH key stays in the trusted account. Transfer uses SSH stdin.

| Value | Required input |
|---|---|
| `VZ_ATTEMPTS` | Private result parent outside `sy-agent` authority; use `$HOME/hardware-attempts` for the cron recipe below |
| `VZ_SSH_CONFIG` | Absolute path to the existing batch SSH configuration with alias `seatbelt-mac` |
| `VZ_PYTHON` | Existing offline Python in `sy-agent`, able to run the trusted read-only probes |
| `VZ_TEST_ENV` | Existing verified development Python environment for the pinned controller and its `uv.lock`; no product binaries or credentials |
| `VZ_OFFLINE_TEST_INPUTS` | Existing architecture-matched Debian packages, locked wheels and verified `mise-node/` Node 22 installation/configuration for the maintained guest tests |
| `VZ_NATS_BINARY` | Existing verified NATS test executable, available offline to `sy-agent` |
| `VZ_RUNTIME_PATH` | Verified PATH for Bash, Git, tar and the offline Python/test tools |
| `VZ_CA_BUNDLE` | Readable public CA bundle for absent inherited trust settings |
| `VZ_LOCK` | Persistent host-local lock file, readable but protected from replacement by `sy-agent` |
| `VZ_HELPER_TIMEOUT` | Positive per-helper deadline; set `900` to match the accepted full consumer; entry default is `120` seconds |
| `VZ_OBSERVER_TIMEOUT` | Optional observer deadline; default 10800 seconds |

Prepare and verify test instruments separately. The wrapper links the existing
Python environment and copies guest test inputs into the disposable checkout.
The guest installs those test dependencies offline, as recorded in
`retained-run.json`. The entry compiles no product on Bristol. The raw retained guest
archive is verified by digest before extraction. The host bundle's matching
signed helper, guest helpers and package checksums are verified before use.

`run-vz.sh` copies `VZ_OFFLINE_TEST_INPUTS` into a real `source/offline`
directory, then passes `/workspace/offline` to the guest. The copy follows input
symlinks so their files remain available through the checkout mount. It
preserves file bytes and modes. Verify the supplier's checksums and readable
fixture modes before staging. Guest package hash checks remain enabled. Keep
logs and state private. The existing [guest preparation instructions](../README.md#run-installed-sections-with-one-preparation)
describe the guest-visible inputs. The accepted inner consumer used a real,
readable directory; it did not prove the complete cron entry's staging.

The trusted checkout must also be readable by `sy-agent` for its fixed wrapper,
port and process-inspection commands. `sy-agent` needs the existing
`/Users/sy-agent/bin/run-vz-test`, process-argument inspection and allocated TCP
ports 46370–46375 plus 46377–46378. The wrapper checks the actual physical Mac,
all eight ports, its SSH host binding and the protected local lock. It preserves
the CA variables. Default run/state parents are short
`/Users/sy-agent/hw` and `/Users/sy-agent/s`; optional `VZ_RUNS` and `VZ_STATES`
must keep maintained Unix socket paths within macOS's 104-byte limit.

## Install the existing independent cron recipes

These are the maintained installation recipes, not installed schedules. Craig
installs each entry in its stated account. Before enabling an entry,
create its private log directory, configure the actual tools' PATH, replace
`REPLACE_WITH_OPERATOR_EMAIL`, and verify working `/usr/bin/mail` transport.
Confirm the host's current timezone. These entries do not install themselves.

On devstack as `rundeck`, with the default `KVM_ATTEMPTS` path:

```sh
mkdir -p /var/lib/rundeck/harness/evidence/issue889
chmod 700 /var/lib/rundeck/harness/evidence/issue889
touch /var/lib/rundeck/harness/evidence/issue889/cron.log
chmod 600 /var/lib/rundeck/harness/evidence/issue889/cron.log
crontab -e
```

Use 03:17 in the host's local timezone, including seasonal changes:

```cron
MAILTO=REPLACE_WITH_OPERATOR_EMAIL
17 3 * * * /bin/bash /usr/local/lib/safeyolo-hardware/tests/blackbox/hardware/run-kvm.sh overnight >> /var/lib/rundeck/harness/evidence/issue889/cron.log 2>&1 || /usr/bin/mail -s 'SafeYolo KVM failed or incomplete' "$MAILTO" < /var/lib/rundeck/harness/evidence/issue889/cron.log
```

On Bristol as its existing trusted operator account, with `VZ_ATTEMPTS` set to
`$HOME/hardware-attempts`:

```sh
mkdir -p "$HOME/hardware-attempts"
chmod 700 "$HOME/hardware-attempts"
touch "$HOME/hardware-attempts/cron.log"
chmod 600 "$HOME/hardware-attempts/cron.log"
crontab -e
```

Use 03:43 in Bristol's host timezone, last observed as UTC:

```cron
MAILTO=REPLACE_WITH_OPERATOR_EMAIL
43 3 * * * /bin/bash /usr/local/lib/safeyolo-hardware/tests/blackbox/hardware/run-vz.sh overnight >> "$HOME/hardware-attempts/cron.log" 2>&1 || /usr/bin/mail -s 'SafeYolo VZ failed or incomplete' "$MAILTO" < "$HOME/hardware-attempts/cron.log"
```

Read back each account's `crontab -l`. Installation alone proves neither email
delivery nor real hardware execution. The cadence tables remain unscheduled
until deployed scheduling/publication evidence is accepted under #889.

## Recover an attempt

Keep the printed private attempt directory and all original failures. Do not
repeat a hardware launch to repair an observation or publication failure.
On devstack, reconciliation acquires the existing locks and reclaims only the
exact owned inactive guest. An active or foreign owner remains untouched.
Replace `ATTEMPT_DIRECTORY` with this entry's original directory:

```sh
/usr/local/lib/safeyolo-hardware/tests/blackbox/hardware/run-kvm.sh reconcile ATTEMPT_DIRECTORY
```

On Bristol, a lost SSH observer leaves execution unknown. The local session
keeps its lock, owner, exit and reports. After inspecting that session, collect
the same attempt; this command does not launch it again:

```sh
/usr/local/lib/safeyolo-hardware/tests/blackbox/hardware/run-vz.sh collect ATTEMPT_DIRECTORY
```

A live or uninspectable owned process, occupied fixture port or unverified
cleanup leaves the attempt failed. Use the existing host operator's exact
argv/start-identity inspection and maintained owned cleanup. Do not signal a
process by broad name or delete unknown state. Host death or `SIGKILL` cannot
promise shell cleanup.
When manual recovery needs the installed CLI, stop the owned proxy/Coord and
separately stop disposable agents. `safeyolo stop` alone leaves agents running.
The KVM entry also owns its exact harness guest, disks, seed and lease; it must
preserve unrelated guests. Keep VZ fixture cleanup scoped to its recorded
process identities and allocated ports.

For a known existing publication index, the trusted account can publish the
retained selected result again without running tests:

```sh
python3 /usr/local/lib/safeyolo-hardware/tests/blackbox/hardware/publish_results.py publish --attempt ATTEMPT_DIRECTORY
```

An uncertain initial comment write is held for inspection of its unique
`Hardware attempt` marker. It is not automatically posted again. Raw logs,
captures, inspector exports, vaults, keys and instance state are never selected
for publication. Missing, partial or mismatched reports remain failures.
