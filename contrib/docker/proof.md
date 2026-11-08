# Real Docker boundary proof

Use an operator-owned disposable Linux venue and the matching candidate source
and binaries. The witness covers the inherited #1437 transport and #1438 request
enforcement together. The independent operator walkthrough below adds #1440
onboarding, coadministration and a seeded host-consumer check. The external
witness does not establish installed nested-Docker containment for #1436 or
project visibility for #1439.

Before running the witness, the operator checks the existing venue inventory.
Reuse its owned daemon and prepared clients when available. Do not install a
second daemon merely because the coding agent has no default Docker socket.
The supplied daemon must be disposable and contain no unrelated workloads.

## Reuse the observed result

The external workload test `real_docker_compose_enforcement_and_persistent_effects`
passed at `67cdb27209d5245b3120921605b0d9448c878f78` on 7 November 2026
(operator execution 15475). It used Docker CLI 29.1.3, Compose 2.40.3 and
standalone Linux Engine 29.1.3 with API 1.45. The aggregate run later failed in
the separate project test. The project test subsequently passed at
`a72c6477c3c6b37923c767d55e1ec61dcfc5d2d0` (execution 15482). These observations
do not establish independent acceptance for #1437 or #1439.

The [public onboarding walkthrough result](https://github.com/craigbalding/safeyolo/issues/1440#issuecomment-6713346918)
was observed on 7 November 2026 (execution 15505, completed at 21:32:21 UTC).
It followed documentation `20122bb6d4eae037d7dab52e4a216020c220f128` with proxy
`232ab6aed74d32ab9c65b40321baaf6c91bd7b50` (debug) and retained CLI
`90545121efc91bedcd779c13eb9259e8c856eab4`. Docker CLI and Engine were 29.1.3,
Compose was 2.40.3, and the client used API 1.45. The endpoint was authenticated
HTTPS with certificate verification retained.

Service checking, adoption and readback, encrypted credential addition through
`--value-file`, ordinary authorization, agent service discovery and private
Docker configuration passed. An initial credential-policy 428 was resolved
through the documented fingerprint approval for the intended endpoint bearer.
The operator resumed the same fixture; no credential guard was disabled.

The pre-existing fixture's full ID, ordinary name and empty labels stayed equal
across agent copy/restart, operator stop/start and agent reinspection. The first
gateway copy changed the fixed host-consumed script to `changed-through-mount`.
After the operator wrote the consumer's input outside the sole delegated
`shared` source, a second gateway copy changed the shared input to
`changed-after-mitigation`; the relocated consumer still printed
`operator-approved`. The observer retained distinct-file and outside-grant
facts and these markers. Raw inode numbers and `realpath` command output were
not retained before cleanup. Those checks cannot be claimed from this result.

Cleanup readback confirmed the named fixture, walkthrough directories, service
definition and caller scratch were absent. The scoped authorization was revoked,
the walkthrough credential removed, the caller and proxy stopped, and the
operator policy and donor binaries restored. No daemon, build, image pull or
passed workload/project suite was repeated for this walkthrough.

These execution observations do not substitute for independent reader usability
and exact-candidate acceptance. Reuse the results at their actual revisions for
a documentation-only change. The commands below support
reproduction or qualification of changed behavior; they do not require a replay
of passed work solely to update documentation or collect omitted observer output.

## Inputs and authority

The existing operator wrapper supplies these private inputs as paths or process
environment values. No input requires broad host access for Forge.

| Input | Required value |
|---|---|
| `SAFEYOLO_DOCKER_ENDPOINT` | Existing authenticated HTTPS Engine origin, without credentials, path or query. |
| `SAFEYOLO_DOCKER_CA_FILE` | Private path to the CA that validates the endpoint certificate and name/IP. |
| `SAFEYOLO_DOCKER_CREDENTIAL_FILE` | Private file containing the endpoint bearer credential. The test reads it in memory and passes it to the encrypted test store. Fixture operator curl calls send it on stdin. |
| `SAFEYOLO_DOCKER_PROOF_ROOT` | Existing owned, disk-backed scratch directory with capacity for the small client instance, build context and diagnostics. |
| `SAFEYOLO_DOCKER_IMAGE` | Optional pullable BusyBox image with `sh`, `sleep`, `httpd`, `wget`, `tar` and `cat`. Default: `busybox:1.36`. |

The venue needs Docker CLI and Compose v2, curl, the candidate's Rust toolchain
and a compatible warm Cargo target for that venue's architecture. Transfer the
exact committed source when the coding agent and venue architectures differ;
rebuild the required tests there. Engine must support API 1.45 and Linux.
This defaulted-build fixture needs a private default cgroup namespace
(`name=cgroupns` in Engine `SecurityOptions`), `runc` as the default runtime and
`json-file`, `local` or `none` as the default logging driver. Check these actual
consumer settings before dispatch. The test pulls the selected image using the
daemon's existing network authority. It does not add outbound permissions.

An operator-managed TLS/bearer reverse proxy to an owned daemon socket is one
fixture option. An existing endpoint with those semantics is sufficient. The
wrapper retains its secret material and records the actual endpoint/CA identity,
Engine/CLI/Compose versions and candidate revision in its normal run result.
Do not disable TLS verification, log bearer values or publish private files.

## Run

In the candidate checkout's `proxy` directory, use the wrapper-bound warm Cargo
target and its existing profile, features and flags. The commands below use an
unoptimized test profile, debug information off, one job and incremental on.
Reuse the matching target for this profile. Set `SAFEYOLO_BUILD_REVISION` to the
exact candidate commit when the wrapper binds the source revision.
Inspect free space and forecast compilation/link growth first. Keep the factory's
10 GiB build-filesystem reserve and the operator's 20 GiB backing reserve.
Run these checks in order. If a check fails, retain its output and diagnose the
failure before proceeding. Start with the request checks, including the captured
ordinary-client defaults and create/update resource sentinels:

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=1 SAFEYOLO_CARGO_RESERVE_GIB=10 \
  ../scripts/cargo_with_space.sh test --locked --config profile.dev.debug=0 \
  --lib services::docker::enforcement
```

Run the controlled request/transport regressions from the same source:

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=1 SAFEYOLO_CARGO_RESERVE_GIB=10 \
  ../scripts/cargo_with_space.sh test --locked --config profile.dev.debug=0 \
  --test docker_transport --test contracts --test gateway_snapshot --test grants
```

The approval-interface check uses the existing native operator CLI fixture:

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=1 SAFEYOLO_CARGO_RESERVE_GIB=10 \
  ../scripts/cargo_with_space.sh test --locked --config profile.dev.debug=0 \
  --test native_operator_cli \
  docker_file_access_approval_shows_the_enforced_source_and_write_bounds
```

After the private inputs are bound, run the single real boundary witness:

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=1 SAFEYOLO_CARGO_RESERVE_GIB=10 \
  ../scripts/cargo_with_space.sh test --locked --config profile.dev.debug=0 \
  --test docker_real_daemon real_docker_compose_enforcement_and_persistent_effects -- --ignored --nocapture
```

Successful output names the actual client/server versions, one unique owned
resource prefix and the passed lifecycle/refusal checks. The witness starts
isolated candidate proxy instances through the production `Proxy` entry point.
Ordinary Docker/Compose clients use their protected Unix sockets and scoped
gateway headers. The proxy uses the operator credential for authenticated HTTPS
to the real Engine. The fixture preauthorizes the workload capability; it does
not substitute for independent approval-interface acceptance.

The one lifecycle pulls and builds an image, runs two communicating Compose
services, follows logs, executes commands, attaches interactively, copies files,
recreates the services while retaining volume data and tears them down. The
adversarial cases require gateway refusal and verify absence at the actual
daemon. Fixture-only operator calls create stopped unsafe containers, a local
volume with host-bind options and an unstarted privileged exec. Gateway calls
must refuse direct and indirect use before those forbidden effects occur.

The witness adds a native grant requirement for one container's rename route.
The live grant first permits a rename. The same grant then expires, and another
rename must return 428. An independent Engine inspection verifies that the
allowed name remains. The bearer credential and static workload authorization
stay unchanged during this expiry check. The witness then removes the original
client's service authorization and requires a rename to return 403. A separately
authorized observer verifies that the earlier name and volume data remain after
revocation. Expiry and revocation do not undo persistent effects. The witness
never retries an uncertain mutation automatically.

## Independent operator walkthrough

Use the same owned venue, authenticated endpoint, prepared clients and passing
candidate binaries. Reuse the real witness's lifecycle result when the runtime
source is unchanged; do not rebuild or repeat it for a documentation-only delta.
An independent operator must also follow [the Docker guide](../../docs/docker.md)
through service adoption, credentials, approval and agent client setup. The
witness's preauthorized private socket alone does not establish that reader path.
Keep the private inventory, credentials and client configuration with their
respective operator or agent, outside the checkout and public results.
Run the blocks in order and stop at the first unexpected result. Inspect the
actual state before retrying an interrupted mutation. An unrun block remains
unproved.

The wrapper supplies three additional nonsecret values. Verify them before
running any command:

- `SAFEYOLO_DOCKER_WALKTHROUGH_DIR`: a new, owned, absolute directory on the
  **daemon host**, below its existing disposable proof storage. It must not
  already exist or contain a symlink. Its `shared` subdirectory will be mounted
  writable; its `operator` subdirectory must remain outside every delegated mount.
- `SAFEYOLO_DOCKER_EXISTING_CONTAINER`: an unused name for one owned fixture
  container. Create it before gateway authorization, then preserve that name,
  ID and labels through the walkthrough. This is a fixture choice, not a naming
  requirement for existing environments.
- `SAFEYOLO_DOCKER_IMAGE`: the exact reusable image from the real witness, already
  present at this daemon. The following commands never pull another image.

In the daemon host's operator terminal, select its existing Docker context.
Keep that operator terminal separate from the agent terminal configured for
the gateway. Confirm the directory is absent, the image is already present and
the exact container-name filter returns no container before creating anything:

```sh
test -n "${SAFEYOLO_DOCKER_WALKTHROUGH_DIR:?}"
test -n "${SAFEYOLO_DOCKER_EXISTING_CONTAINER:?}"
test -n "${SAFEYOLO_DOCKER_IMAGE:?}"
test ! -e "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR"
test ! -L "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR"
docker image inspect --format '{{.Id}}' "$SAFEYOLO_DOCKER_IMAGE"
docker container ls -a --filter "name=^/${SAFEYOLO_DOCKER_EXISTING_CONTAINER}$" --format '{{.Names}}'
```

Create the disposable source and a fixed harmless script. The only host script
execution in this walkthrough is the fixed `printf` content shown here; no
production script, credential, privileged host command or new host access is used.
The container sleeps on Docker's `none` network until owned cleanup.

```sh
install -d -m 700 "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/shared"
printf '%s\n' "printf '%s\n' operator-approved" > "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/shared/report.sh"
docker run -d --pull=never --network none --name "$SAFEYOLO_DOCKER_EXISTING_CONTAINER" --mount "type=bind,src=$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/shared,dst=/shared" "$SAFEYOLO_DOCKER_IMAGE" sleep 3600
docker inspect --format '{{.Id}} {{.Name}} {{json .Config.Labels}}' "$SAFEYOLO_DOCKER_EXISTING_CONTAINER" > "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/identity-before.txt"
cat "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/identity-before.txt"
sh "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/shared/report.sh"
```

Expect `operator-approved`. Run the guide's read-only inventory and identify the
writable source. Name the seeded host consumer: the operator's `sh` invocation
reads that mounted script as executable code. The inventory cannot discover
this future host invocation by itself.

For this disposable demonstration only, adopt `workloads` with exactly
`$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/shared` expanded to its absolute path and
`read_only: false`. Do not put the variable expression in the service YAML.
The operator deliberately approves this known fixture risk after reviewing the
displayed bounds. Keep the `operator` directory and all production paths outside
the capability. Follow the guide to connect the contained agent to the gateway.
Give that agent only the existing fixture container name and its task, not the
operator's whole-daemon inventory or daemon credential.
In a noninteractive operator wrapper, the guide's `credentials add` can read the
existing `SAFEYOLO_DOCKER_CREDENTIAL_FILE` through `--value-file`. Select the
instance's existing storage type; if it has no store, the operator selects
`--storage local` or `--storage passphrase` as documented. Do not manufacture a
new endpoint credential or preauthorize by editing the authorization store.
Use the contained caller's current Agent API token for service discovery, then
prepare its private Docker client configuration as the guide describes.

In the configured agent terminal, set `SAFEYOLO_DOCKER_EXISTING_CONTAINER` to that
same name. From an owned workspace scratch directory, write the fixed replacement
and copy it through the gateway into the existing mounted container:

```sh
docker inspect --format '{{.Id}} {{.Name}} {{json .Config.Labels}}' "$SAFEYOLO_DOCKER_EXISTING_CONTAINER"
printf '%s\n' "printf '%s\n' changed-through-mount" > walkthrough-report.sh
docker cp walkthrough-report.sh "$SAFEYOLO_DOCKER_EXISTING_CONTAINER:/shared/report.sh"
docker exec "$SAFEYOLO_DOCKER_EXISTING_CONTAINER" cat /shared/report.sh
docker restart "$SAFEYOLO_DOCKER_EXISTING_CONTAINER"
```

In the operator terminal, execute the same fixed script again:

```sh
sh "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/shared/report.sh"
```

Expect `changed-through-mount`. This demonstrates control of host-executed input
through an ordinary writable mount without requesting a privileged container.
The second administrator must still be able to inspect, stop and start the
container using its existing direct context:

```sh
docker stop "$SAFEYOLO_DOCKER_EXISTING_CONTAINER"
docker start "$SAFEYOLO_DOCKER_EXISTING_CONTAINER"
docker inspect --format '{{.Id}} {{.Name}} {{json .Config.Labels}}' "$SAFEYOLO_DOCKER_EXISTING_CONTAINER" > "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/identity-after.txt"
diff -u "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/identity-before.txt" "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/identity-after.txt"
```

Compare the ID, name and labels with the initial values. Agent inspection after
the operator's start must still find the same container. Do not rename or relabel
it to satisfy gateway checks.

```sh
docker inspect --format '{{.Id}} {{.Name}} {{json .Config.Labels}}' "$SAFEYOLO_DOCKER_EXISTING_CONTAINER"
```

Mitigate the seeded risk by moving the host consumer's input outside the writable
source. Still on the daemon host, write a fresh, operator-controlled script with
the known content, not a hard link or unreviewed copy of the changed input:

```sh
install -d -m 700 "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/operator"
printf '%s\n' "printf '%s\n' operator-approved" > "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/operator/report.sh"
sh "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/operator/report.sh"
```

The host consumer must now use only `operator/report.sh`. In the agent terminal,
change the shared script again:

```sh
printf '%s\n' "printf '%s\n' changed-after-mitigation" > walkthrough-report.sh
docker cp walkthrough-report.sh "$SAFEYOLO_DOCKER_EXISTING_CONTAINER:/shared/report.sh"
docker exec "$SAFEYOLO_DOCKER_EXISTING_CONTAINER" cat /shared/report.sh
```

Expect the shared file to contain the fixed `changed-after-mitigation` script.
On the daemon host, verify the two distinct source paths and run the relocated
consumer:

```sh
realpath "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/shared/report.sh" "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/operator/report.sh"
stat --format '%d:%i %n' "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/shared/report.sh" "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/operator/report.sh"
sh "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/operator/report.sh"
```

Expect different files and `operator-approved`. Confirm that the adopted sources
and actual mounts expose only `shared`, not its parent or `operator`. An alternative
for inputs that need no agent writes is a read-only adopted source and a recreated
read-only mount. Read-only access would still expose any secret in that source.

Compose lifecycle, streaming/copy, volume persistence and expiry/refusal evidence
come from the retained real witness. This walkthrough exercises the guide's
public connection and ordinary Docker client against the existing fixture; it
does not repeat the passed Compose/build/pull suites. Record any missing
instruction or unsupported operation instead of working around it silently.
If the optional build exception
is exercised, use the guide's existing challenge flow and verify the reported
run/method/path and unchanged Docker bounds. Do not treat approval as a guarantee
about one Dockerfile or as rollback after expiry.

Retain a short result with the exact candidate/runtime source, endpoint identity,
actual CLI/Compose/Engine/API versions, unchanged fixture identity, both admin
results, before/after markers and mitigation result. Keep each unrun or failed
step explicit. Lens owns independent reader acceptance and exact-candidate review.

After the observations, remove only this named fixture container with the
operator's existing context. Save the relevant observations in the normal run
result first. Remove only the named files, then empty directories; unexpected
contents remain available for inspection:

```sh
docker rm -f "$SAFEYOLO_DOCKER_EXISTING_CONTAINER"
rm -- "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/shared/report.sh" "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/operator/report.sh" "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/identity-before.txt" "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/identity-after.txt"
rmdir -- "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/shared" "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR/operator" "$SAFEYOLO_DOCKER_WALKTHROUGH_DIR"
```

In the agent's scratch directory, remove `walkthrough-report.sh`. Revoke only
the walkthrough service authorization, remove its newly added definition and
restore any operator configuration changed for the walkthrough. Keep shared
credentials and prepared binaries. No daemon-wide prune or other
administrator's resources are part of cleanup. Preserve reached state and
diagnostics before cleanup on failure.

## Diagnostics and owned cleanup

Each client action has a 180-second deadline. Prerequisite resource reads have a
15-second deadline and the existing 10 MiB inspection bound. Normal test output
and audit diagnostics are sufficient; no additional transcript or evidence
database is created. On success, the witness removes its Compose resources,
standalone attach container, unsafe fixture resources, built image and private
scratch directory. The pulled base image remains reusable.

On failure, the witness leaves the printed unique resource prefix and private
scratch directory available for diagnosis. Inspect actual daemon state before
retrying or cleaning up an interrupted mutation. Through the existing operator
wrapper, remove only the Compose project with that exact prefix, its volumes,
the standalone `<prefix>-attach` and `<prefix>-unsafe-existing` containers,
`<prefix>-unsafe-volume`, and `<prefix>:proof` image when present. Then stop the
owned test process and remove its printed scratch directory. Preserve relevant
failure output first. Do not select unrelated daemon resources for cleanup.

Forge hands the exact source commit and bundle to Sylab using the configured
shared namespace. A compiled executable is reusable only when its source,
architecture and runtime dependencies match the venue. A source-only or
controlled-origin test result does not complete real Engine acceptance. Lens
independently judges the exact candidate and any inherited behavior before
integration.

## Internal Docker management connection

Execution 16006 reused the repaired four-file runtime from producer 42482622552
and the existing driver at `232ab6aed74d32ab9c65b40321baaf6c91bd7b50`.
The debug proxy at `e340a934` has the same Docker, host and provider source as
`ae76f656`; their proxy source differences are confined to Coord supervisor
modules. This is mixed-input debug proof, not shipping-package acceptance.
Docker CLI/Engine 26.1.5 with API 1.45 passed internal create/start/inspect,
16-byte exec output, 27-byte attach output and removal. The exact container from
the interrupted execution 15490 was absent before these writes.

The stopped-daemon phase returned only `Error response from daemon: \n\n` on
stderr. The fixture then failed its literal `502`/`503` CLI assertion. Raw HTTP
status and body were not collected; no HTTP status is established by that
client output. Closed-port and stopped-provider phases did not run. All owned
processes stopped and the original four runtime files, modes, checksum file,
policy, service, configuration and binary selection were restored. Retain the
positive results and run only the missing negative controls below.

Docker 26.1.5's [API error decoder](https://github.com/moby/moby/blob/v26.1.5/client/request.go#L188-L221)
reads JSON failures from `message`. SafeYolo adds that field to its local Docker
failure replies while retaining their existing fields, status and attribution
headers. It uses the existing sanitized diagnostic, or a local refusal message
when the error is structured. Daemon responses pass through unchanged. The
client check requires nonzero exit and diagnostic text beyond Docker's generic
prefix; it does not require HTTP numbers in stderr. Each negative phase retains
the actual exit, stderr and a separate read-only HTTP status/body capture before
checking the diagnostic.

The [provider diagnosis](https://github.com/craigbalding/safeyolo/issues/1437#issuecomment-6713267349)
bound the failure to deployed runsc source
`97e8e896904cb364319cd9758241d3f0bd27a6f4`. In execution 15499, a controlled
origin received 16 bytes, observed input EOF and sent 16 bytes in both controls.
The direct client received all 16; the donated runsc stream received none.
This establishes the provider defect without excluding further Docker defects.

### Qualify the repaired provider first

The existing runtime builder applies both
[`nofollow.patch`](../../scripts/gvisor/nofollow.patch) and
[`portforward.patch`](../../scripts/gvisor/portforward.patch) to that pinned
upstream source. The second patch keeps the reverse copy alive after orderly
EOF and cancels both copies on a real error or shutdown. Its focused upstream
tests include response after EOF in either direction, buffered final bytes,
write/read/shutdown errors, and the three connection adapters.

For a hosted native build, use the existing `installed-arm64.yml` workflow with
`mode=runsc-build`. Select `runsc_architecture=amd64` for the AMD64 provider
fixture; the default remains `arm64`. This input affects only the runtime build
job. Relay admits one selected run at the candidate branch and verifies its
actual head against the candidate commit. The hosted build is independent of
the protected provider fixture's execution slot.

The workflow runs the focused tests, builds the four runtime files and qualifies
the selected native payload on both guest filesystems. Its artifact is named
`runsc-ARCHITECTURE-SOURCE-RUN-ATTEMPT`. With `runsc_build_run`, reuse selects
that architecture's artifact and compares the builder, both patches, packaging
helper and qualification inputs before checking the output hashes. Reached
logs, downloaded operands and test results are retained on failure. Preserve
those results before deciding whether another acquisition or build is needed.
Hosted qualification does not replace the provider and Docker controls below.

For a build on the owned Linux venue, obtain the factory's serialized build
slot and inspect the retained upstream checkout and compatible Bazel outputs.
Preserve active source, prepared runtime and the existing disk reserves. If the
checkout is clean at the pinned revision, invoke the candidate's
`scripts/build_runsc.sh UPSTREAM_SOURCE NEW_RUNTIME_DIRECTORY`. For a retained
checkout that already has the unchanged nofollow patch, verify that delta and
apply only the new portforward patch. Do not reset the warm checkout. Resume the
builder's focused tests and four-target build with its existing Bazel output
root, architecture configuration, opt profile and one job.

The compatible runtime version marker remains
`release-20261005.0-safeyolo.1`. Record the actual SafeYolo source, both patch
inputs and all four output hashes; that version string alone does not distinguish
the repaired runtime from the defective donor. Acquisition now includes the new
patch in its cache key. Do not relabel or reuse an unmodified runtime as repaired.

The response-after-EOF control passed in execution 16003: the origin and both
clients received the expected 16 bytes and exited successfully. Reuse that
result and its actual four-file hashes for the unchanged payload. When a changed
runtime needs qualification, use the existing operator wrapper to select it in
an isolated installation. Preserve the donor bytes and original runtime
selection. Reuse the retained response-after-EOF control from execution 15499
through its actual `nsenter`/`runsc port-forward --stream` route. Run no Docker
operation during this control. Require the origin to receive the 16-byte marker,
observe EOF and then send its 16-byte response. Require both the direct client
and provider client to receive that exact response, and both origin and runsc to
exit 0. Record the selected runtime path, version and hash with that result.
Restore the selection and stop the fixture on failure. Direct TCP or source
tests alone do not establish that this runtime defect is repaired.

After qualifying a changed runtime, use that selected runtime for the finite
Docker management check below. For the current correction, reuse the qualified
payload and select the corrected debug proxy. No gVisor rebuild is needed.

Reuse the stopped, qualified Linux/gVisor fixture from #1436. This check adds
only the missing Docker management connection through its existing provider
route. Do not repeat the accepted application lifecycle or external Engine
witness. The retained fixture must have its `notes` provider, `dockercaller`
caller, their workspaces, and qualified Docker image data. Both agents must be
stopped before starting this check.

On that owned Linux venue, prepare a task-owned installation directory. Reuse
the qualified CLI, guest and assets. Select the complete repaired runtime as
described above. Put the current candidate proxy in that directory's `bin`; copy binaries into the overlay rather
than overwriting a donor or writing through a symlink. Verify source identities
and current capacity first. Reuse the compatible warm Cargo target when a current
proxy must be built. Preserve the original installation and useful warm outputs.
The venue also needs its prepared Python environment. The check copies the
provider guest's installed Docker client into the caller workspace.

From #1437's matching candidate checkout, substitute the prepared overlay, retained instance,
new private output directory, retained guest Docker data path, and actual source
revisions below. `CLI_REVISION` and `GUEST_REVISION` identify the reused #1436
binaries; `CANDIDATE` identifies the current proxy. These inputs do not require
the external endpoint's private CA or bearer credential.

```sh
python3 -m tests.blackbox.installed_docker_preflight \
  --prepared-config PREPARED_OVERLAY --root RETAINED_INSTANCE \
  --output NEW_PRIVATE_OUTPUT --revision CLI_REVISION \
  --guest-revision GUEST_REVISION --proxy-revision CANDIDATE \
  --nested-docker --reuse-root --docker-data RETAINED_GUEST_DATA \
  --gateway --gateway-failures-only
```

The check temporarily selects the overlay's binaries and a Docker service for
the existing provider. It restores lost guest packages through the existing
proxy and policy, then uses guest root to expose the inner daemon's Unix socket
on guest loopback port 2375. The caller uses its scoped gateway token and ordinary Docker TCP
configuration. The check records client/server versions and refuses an
unapproved caller. With `--gateway-failures-only`, it skips container operations
and checks requests with a stopped daemon, closed port and stopped provider.
Without that option, it also creates and inspects one uniquely named container,
exercises exec/attach with stdin closure and removes it. The normal result must
report `gateway-passed`, `gateway_failures_only` for the selected mode and cleanup
`stopped`. A failure-only result supplements the retained positive witness.

After stopping the proxy, the check restores the original service, policy and
binary directory or link. The original prepared binary bytes remain unchanged.
The operator wrapper must also restore its original runtime selection. Retain
the complete `gateway.docker_stream.end` details, including request ID,
uploaded/downloaded bytes, outcome and error, plus daemon/closed-port/stopped-
provider diagnostics from the existing audit log. On failure, keep the original
result, private rollback inputs, audit log, printed container name and guest
state. Inspect the actual daemon before removing or retrying an uncertain
operation. No automatic mutation replay or broad cleanup is performed.

### #1437 evidence and remaining acceptance

All eight issue criteria remain subject to independent exact-candidate review.
Reuse each result only at its actual source and runtime boundary.

| Criterion | Retained evidence and remaining work |
|---|---|
| 1. Multi-service lifecycle | Execution 15475 at `67cdb272` passed pull/build, two communicating Compose services, inspect/logs/follow, exec, interactive attach, archive copy, recreation, persistent data and teardown. CLI/Engine 29.1.3, API 1.45, Compose 2.40.3. The later project phase failed; the workload itself passed. |
| 2. Streams and payloads | That workload and the controlled transport tests cover admitted exec/attach, builds and archives. Execution 16006 passed internal-provider exec/attach with the repaired payload at the debug source boundary described above. |
| 3. Before-effect checks | Accepted #1438 enforcement and controlled negative/body-bound tests refuse forbidden dispatch and unavailable inspection. No new enforcement policy is added here. |
| 4. Mandatory mediation | Retained token, path/version, opaque-tunnel and TLS/credential controls cover the configured endpoint. The external workload uses scoped tokens and operator-held credentials. |
| 5. Connections | The authenticated HTTPS workload and execution 15505 walkthrough are retained. #1436 supplies internal runtime/application-provider proof. Execution 16006 passed Docker management through the repaired provider at its recorded source/runtime boundary. |
| 6. Failure diagnostics | Controlled truncation and uncertain-mutation tests remain applicable. Execution 16006 exposed a blank stopped-daemon diagnostic. Corrected daemon/closed-port/stopped-provider client controls and their raw responses/audit details remain required. Provider EOF proof from execution 16003 is retained. No real interrupted mutation is claimed. |
| 7. Setup and matrix | [Docker guidance](../../docs/docker.md) defines the client setup, API 1.45 matrix, unsupported operations and limits. Transport does not establish project isolation or host-risk enforcement. |
| 8. Independent acceptance | Lens review of the corrected immutable candidate and the real client/daemon results is pending. The shared project result at `a72c6477` (execution 15482) stays separate from #1437 acceptance. |

## Project scope witness

For #1439, reuse the same protected venue and private inputs after the active
workload witness returns. Reuse a prepared qualified BusyBox image instead of
repeating its build/pull suite. The project test creates two unrelated projects,
ordinary selected existing resources and a shared network through its explicit
operator connection. It then exercises the project gateway. It retains its
printed prefix and scratch on failure. Inspect that run's actual IDs and effects
before cleanup or retry.

In the matching candidate's `proxy` directory, keep the warm target's existing
profile, features and flags. Preserve the same build/backing reserves. First
compile and run the focused project checks and controlled interrupted-creation
regression. Stop on the first failure:

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=1 SAFEYOLO_CARGO_RESERVE_GIB=10 \
  ../scripts/cargo_with_space.sh test --locked --config profile.dev.debug=0 \
  --lib docker
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=1 SAFEYOLO_CARGO_RESERVE_GIB=10 \
  ../scripts/cargo_with_space.sh test --locked --config profile.dev.debug=0 \
  --test docker_transport project_reconciles_an_interrupted_creation
```

With those checks passing and the operator-bound Engine inputs available, run
only the project Engine witness:

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=1 SAFEYOLO_CARGO_RESERVE_GIB=10 \
  ../scripts/cargo_with_space.sh test --locked --config profile.dev.debug=0 \
  --test docker_real_daemon real_docker_project_lifecycle_and_identity -- --ignored --nocapture
```

Record actual Engine/CLI/Compose versions and the exact candidate. This witness
covers selected resources, shared dependencies, Compose creation/recreation,
persistent data, direct/indirect refusals, management metadata, restart,
co-administrator rename/replacement and explicit volume re-adoption. The
controlled HTTP regression exercises an origin that applies creation and then
interrupts its response. It must observe reconciliation and exactly one mutation.
Neither source checks nor a controlled origin establish real Engine acceptance.
