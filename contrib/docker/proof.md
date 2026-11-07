# Real Docker boundary proof

Run this finite witness after the factory's current heavy build slot returns.
Use the operator-owned disposable Linux venue and the matching candidate source
and binaries. The witness covers the inherited #1437 transport and #1438 request
enforcement together. It does not establish installed nested-Docker containment
for #1436 or project visibility for #1439.

Before running the witness, the operator checks the existing venue inventory.
Reuse its owned daemon and prepared clients when available. Do not install a
second daemon merely because the coding agent has no default Docker socket.
The supplied daemon must be disposable and contain no unrelated workloads.

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
target, unchanged release profile/features/flags, one job and incremental off.
Inspect free space and forecast compilation/link growth first. Keep the factory's
10 GiB build-filesystem reserve and the operator's 20 GiB backing reserve.
Run these checks in order. If a check fails, retain its output and diagnose the
failure before proceeding. Start with the request checks, including the captured
ordinary-client defaults and create/update resource sentinels:

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 SAFEYOLO_CARGO_RESERVE_GIB=10 \
  ../scripts/cargo_with_space.sh test --release --locked \
  --lib services::docker::enforcement
```

Run the controlled request/transport regressions from the same source:

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 SAFEYOLO_CARGO_RESERVE_GIB=10 \
  ../scripts/cargo_with_space.sh test --release --locked \
  --test docker_transport --test contracts --test gateway_snapshot --test grants
```

The approval-interface check uses the existing native operator CLI fixture:

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 SAFEYOLO_CARGO_RESERVE_GIB=10 \
  ../scripts/cargo_with_space.sh test --release --locked \
  --test native_operator_cli \
  docker_file_access_approval_shows_the_enforced_source_and_write_bounds
```

After the private inputs are bound, run the single real boundary witness:

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 SAFEYOLO_CARGO_RESERVE_GIB=10 \
  ../scripts/cargo_with_space.sh test --release --locked \
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

The witness also tries expired credentials and revokes a live gateway token.
Future mutations must fail. A separately authorized observer checks that existing
workloads and volume data remain. Expiry and revocation do not undo persistent
effects. The witness never retries an uncertain mutation automatically.

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
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 SAFEYOLO_CARGO_RESERVE_GIB=10 \
  ../scripts/cargo_with_space.sh test --release --locked \
  --lib docker
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 SAFEYOLO_CARGO_RESERVE_GIB=10 \
  ../scripts/cargo_with_space.sh test --release --locked \
  --test docker_transport project_reconciles_an_interrupted_creation
```

With those checks passing and the operator-bound Engine inputs available, run
only the project Engine witness:

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 SAFEYOLO_CARGO_RESERVE_GIB=10 \
  ../scripts/cargo_with_space.sh test --release --locked \
  --test docker_real_daemon real_docker_project_lifecycle_and_identity -- --ignored --nocapture
```

Record actual Engine/CLI/Compose versions and the exact candidate. This witness
covers selected resources, shared dependencies, Compose creation/recreation,
persistent data, direct/indirect refusals, management metadata, restart,
co-administrator rename/replacement and explicit volume re-adoption. The
controlled HTTP regression exercises an origin that applies creation and then
interrupts its response. It must observe reconciliation and exactly one mutation.
Neither source checks nor a controlled origin establish real Engine acceptance.
