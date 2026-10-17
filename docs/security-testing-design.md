# SafeYolo security testing design

Installed blackbox tests exercise the installed native proxy, actual guest
bridge, host/operator APIs, origins and lifecycle. Native process/protocol
contracts live in `tests/proxy_contracts/` and own their processes, UDS,
policy, audit and upstream fixtures. A component test proves its observed
boundary; it cannot substitute for an installed guest/operator composition.
Runner self-tests exercise selection, failure and cleanup controls separately.

Nightly blackbox installs retained default-branch production host/helper bundles
and the newest complete compatible staged guest. The
[retained-input procedure](../tests/blackbox/README.md#test-retained-nightly-inputs)
freezes artifact and producer identities once. It records build age, the
captured default-branch head and the separate test controller. Product builders
run in producers. Missing or invalid selected inputs fail without source or
older-green substitution. Testing a quarantined guest does not promote it.

For a contributor build, from a clean exact checkout on a disposable Linux host
with uv, Cargo and the bootstrap prerequisites, run the software-isolation lane:

```sh
./tests/blackbox/run-installed.sh systrap
```

The [blackbox README](../tests/blackbox/README.md) supplies KVM, physical Apple
Silicon VZ, host-only package and already-prepared commands; it also names
host prerequisites, installation effects, reports, exit codes and cleanup.
The [generated coverage inventory](blackbox-coverage.md) reads native pytest
owners and actual procedural selections. It is a source inventory, not a
passing receipt. The existing [assurance map](assurance-map.toml) connects
security decisions to implementation symbols and their test owners.

## Execution boundaries

| Selection | Observation boundary |
|---|---|
| Native component contracts | Real native process, UDS, local API, protocol, policy/audit and owned upstream; no guest claim |
| Short installed host package | Installed host bundle, exact authenticated native identity, allowed/denied HTTP origins, selected packaged HTTPS and owned stop; guest isolation unproved |
| Installed isolation | Native host ingress/security/identity/lifecycle plus ordinary and guest-root probes in an actual systrap, KVM-backed gVisor or VZ guest |
| Installed ingress | Actual KVM guest/forwarder and correlated allowed-origin/denied-no-origin/local API observations |
| Installed workloads | Linux guest package, Git, SSE, WS/WSS and pinned SSH through CONNECT |
| Installed access | Two live guests, operator approvals, service/contract/credential effects, populated owner-scoped flow access, NATS/Coord/attention, Plumb and inspector |
| Installed lifecycle | Live listener/policy changes, all five guest-default-trust TLS cases, mixed drain, three subject cycles and a separate live owner |

`run-installed.sh` prepares one compatible installed bundle, or reuses the
verified archive installation supplied by the retained runner. The locked
test environment and kernel/rootfs/helper inputs are prepared once. Each independent
section borrows only those preparation outputs. Agents, configuration, data,
logs, fixture certificates/keys, overlays, origins, captures, approvals, tokens
and writable state stay separate. Access retains its two guests/operator/NATS
composition; lifecycle retains its live owner. Preparation and assertion
failures are attributed separately. Continuation requires successful owned
cleanup; failed cleanup prevents the next section from starting.

## Cadence and real platform evidence

Normal PRs use quick checks, adding relevant platform tests for platform
changes. Complete retained tests run overnight across supported platforms;
next-morning discovery is accepted. Full-suite success is not a routine PR
requirement. Full macOS native protocol contracts run once overnight. The
separate installed Mac witness checks the package without repeating that matrix.

The approved overnight scope includes all three isolation mechanisms. Current
GitHub automation covers systrap and hosted component/package checks; hardware
automation/publication remains [#889](https://github.com/craigbalding/safeyolo/issues/889).

<!-- blackbox-cadence-contract:start -->
| Lane | Execution host | Scheduled | Current cadence | Evidence |
|---|---|---|---|---|
| `systrap` | GitHub-hosted Ubuntu | yes | Overnight and trusted manual dispatch | Exact installed/platform result and sanitized failure artifacts |
| `kvm` | Fresh libvirt guest through the acceptance harness | no | Manual/on-demand until #889 automation | Exact candidate/binary, actual KVM result and owned cleanup |
| `vz` | Physical Apple Silicon Mac | no | Manual/on-demand until #889 automation | Exact candidate/binary, actual VZ result and owned cleanup |
<!-- blackbox-cadence-contract:end -->

Hosted Mac package/proxy checks are not physical VZ evidence. Hosted nested-KVM
availability is not an acceptance guarantee. Hardware observations require a
fresh host, trusted trigger, public-PR isolation, resource/owner prechecks,
exact host/helper artifacts and guest digest, separate controller source,
actual platform, result, owned cleanup and sanitized publication.
An occupied shared resource, stale ref or another owner's process is not a
valid setup. Release acceptance retains exact-release-commit results for each
actual mechanism. The [independent hardware entries](../tests/blackbox/hardware/README.md)
do not establish deployed schedules or reopen historical #640 acceptance.

## Security observations

Guest egress goes through its real localhost forwarder: mounted per-agent UDS
for gVisor, vsock for VZ. The guest has no ordinary external network path. Tests
observe direct attempts at network, known-live host listeners and protected
management/control endpoints rather than attributing containment to a host
firewall. The operator can inspect the owned origin/control API independently;
the guest cannot acquire that operator authority by sending an HTTP header.

Guest root is intentional for package administration and repair. The default
shell is UID 1000; guest sudo and operator-mediated `agent shell --root` reach
UID 0 inside the sandbox. Linux maps it to subordinate host UID 100000; VZ
contains it inside the microVM. Tests positively observe root and a local
package transaction, then probe host configuration/key/device, filesystem and
egress boundaries under that identity. A UID transition alone is not an escape.
The root pass repeats private-key scans so ordinary-user permissions cannot hide
fixture private material. Approved operator mounts remain outside any claim
that arbitrary writable workspace data is harmless.

Private fixture keys are generated in disposable config outside the mounted
repository. Only public certificates and the guest trust fixture are exposed
read-only. TLS checks use a dedicated owned CA and actual certificate validation,
with default guest trust on installed paths. Wrong-SAN, self-signed, future and
expired origins must receive no request and must not silently become passthrough;
a scoped ignore-host case is a separate explicit observation. See the
[certificate fixtures](../tests/blackbox/certs/README.md).

Origin capture is the delivery witness. It preserves lossless bytes, raw
request targets/query spelling, ordered duplicate headers and body completion
versus early close. Receiver readiness includes a directly observed positive
probe, cleared before denied-no-origin checks. A connection alone is not a
captured request. Process, guest, listener, NATS and fixture cleanup are owned;
a local fixture stop cannot establish a physical Mac's ports are free.

Current installed continuity owns flow/body/tag/audit, circuit,
catalog/revocation/grant, Coord/attention/provider lease/Plumb, private file
modes, OAuth stored use and task reset. The named installed sections retain
their guest/operator boundaries. Completed comparator executors, migration
wrappers and frozen defaults are retired after Lens's bounded replacement
assessments, under the
[approved finite disposition](https://github.com/craigbalding/safeyolo/issues/320#issuecomment-5942642868).
The [state inventory](state-compatibility.md) preserves historical writers,
receipts and explicit package recovery; it does not add recurring migration
gates. Physical observations and their unexecuted assertions remain attributed
in the [VZ replacement assessment](https://github.com/craigbalding/safeyolo/issues/320#issuecomment-5961923767).
