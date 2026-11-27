# Qualification and adoption

Run discovery as the selected authoring agent. Run target code only in its
authorized guest or owned acceptance environment. Host installation and
activation use the existing owning host account. Keep large test outputs on
disk-backed storage outside the source checkout. The helper needs Python 3.12
or 3.13 and no third-party package. Source tests use the repository's frozen
development environment and matching native binaries.

## Evidence states

The helper reports a specific boundary, not a global support badge:

| State | Meaning |
|---|---|
| `unsupported` | The helper has no parser for the requested protocol. Other integration paths may still be possible. |
| `not_tested` | A version was observed or evidence is incomplete; no successful task/recovery proof. |
| `fixture_passing` | Captured structured events match the selected parser. Their origin has not been proved by this read. |
| `installed_qualified` | The installed probe ran two real native turns in this guest, observed successful tool use and exact file effects, and resumed the same session after process restart. This qualifies only `ordinary.task_and_resume`. |
| `failed` | The selected check failed. Inspect its single `reason` and retained inputs before another attempt. |

Reports are producer claims for independent review. Neither a supplied trace
nor a named executable can establish trustworthy provenance by itself. Review
source/package identity and raw output. The installed probe cannot declare
Factory, platform isolation, login UX or the full matrix qualified.

In a guest, replace `SCRIPT`, `TARGET` and `TRACE` with the installed
`/safeyolo/skills/harness-authoring/scripts/qualify.py`, the selected executable
and a retained native JSON-lines capture respectively. These commands do not
invoke a model:

```sh
python3 "$SCRIPT" probe --harness codex --binary "$TARGET"
python3 "$SCRIPT" trace --harness codex --events "$TRACE"
```

Expected states are `not_tested` and, for a valid successful trace,
`fixture_passing`. Use `--harness pi` for Pi JSON output. A harness with no
helper parser returns `unsupported`; a malformed trace returns `failed`.
Trace validation requires a session, successful terminal event and successful
tool event. A successful process exit or final prose alone cannot pass.

For a candidate that deliberately implements an existing command/event
protocol, use `--protocol codex` or `--protocol pi` while retaining its actual
name in `--harness`. This selects only the helper's comparison; it does not
register a new supported Factory harness. With `TARGET` naming the constrained
executable and `PROOF` a new output directory, this runs its two local turns
without claiming installed model evidence:

```sh
python3 "$SCRIPT" fixture --harness ember --protocol codex --binary "$TARGET" --output "$PROOF"
```

Expected state: `fixture_passing`. The fixture executes its file task and
resume implementation; the fixture supplies its own events and has no model,
canonical Coord identity or policy implementation.

For installed ordinary proof, select the existing authorized model access and
complete executable. Choose a new private disk-backed output path `PROOF`
outside the checkout. The following command makes two model requests and
creates a small file in `PROOF/workspace`. It writes private native outputs and
a report under `PROOF`. It uses existing authentication and changes no policy:

```sh
python3 "$SCRIPT" installed --harness codex --binary "$TARGET" --output "$PROOF"
```

The probe is guest-only. Codex runs with its inner sandbox disabled, as in the
normal SafeYOLO command; the SafeYOLO outer boundary remains enforced. The
probe retains native configuration and credentials in their existing owners.
Optional `--model` selects a model; omission preserves the native preference.
For Pi, use `--harness pi` and, when needed, `--provider` and `--model` together.
The default per-turn deadline is 120 seconds; `--timeout` selects another
positive finite deadline. The helper terminates its owned process group on
timeout and retains failed output. Inspect a failed output directory before
retrying with a new path; the helper never overwrites a previous attempt.

Success reports the same session ID across separately started processes,
successful tool events and the observed exact file bytes. It does not prove
recovery from a mid-effect crash. Use the existing supervisor recovery controls
for that stronger claim. Keep optional or unrun matrix rows visible.

## Acceptance matrix

Select the applicable rows before building. Record capability classification,
state, exact revision/version, command, platform, identity and evidence for
each selected row in the existing PR or issue. Do not invent a new task store.

| Boundary | Required observation | Existing implementation or test driver |
|---|---|---|
| Install, preflight and login | Clean package with required companions; selected login/provider usable without exposing secrets; missing executable/version gives a targeted error | `tests/test_host_packages.py`, `cli/tests/test_host_setup_scripts.py`; installed `safeyolo-coord preflight --` after explicit staging |
| Ordinary task | Noninteractive start, real model turn and successful tool effect attributable to the observed session | Helper `installed`; normal guest command and `client-exec` |
| Bounds and cleanup | Timeout, cancel, crash, stalled/malformed stream and owned children; unrelated process preserved | `cli/tests/test_codex_coord_supervisor.py`, especially interrupted-turn, escaped-child and narration controls |
| Resume and checkpoint | Exact retained session, dirty checkout and claim; no duplicate effect after lost reply or restart | Same supervisor controls; a real installed recovery observation for the changed boundary |
| Coord | Canonical sender, durable identity and attention cursor; unauthorized or malformed input cannot advance delivery | `tests/proxy_contracts/test_native_harness_attention.py`; select its opt-in real model variable only within existing authority |
| Native Work | Read/claim assignment, immutable output publication, explicit execution completion, independently attributed acceptance; model exit cannot substitute | `proxy/tests/native_coord/factory.rs`, `outputs.rs`, `reviews.rs`, `supervision.rs`; installed Factory observation when Factory support is claimed |
| Visibility | Actual `agent watch`, `agent diagnostics` and `factory doctor` distinguish runtime, coding client, saved/staged configuration and unavailable reads | Existing installed CLI/blackbox lanes and `cli/tests/test_codex_coord_supervisor.py` telemetry controls |
| Security refusals | Selected credential, network and policy refusals remain enforced and actionable; no credential custody change | Existing `tests/blackbox` installed lanes and `tests/proxy_contracts` credential/service controls |
| Versions/platforms | Tested target and SafeYOLO identities, supported floor/range, native package/platform inputs and missing-version refusal | Package/setup tests and each claimed platform's installed lane; do not infer macOS host proof from a Linux guest |
| Mixed harnesses | Same native Work contract across selected different role harnesses | Existing native Factory tests plus the installed composition when supported; otherwise mark unverified/unsupported |

The repository's acceptance graph selects trusted tools and environments.
Deterministic tests do not replace installed security or recovery evidence.
Do not repeat accepted model/platform proof for unchanged behavior.

## Exercise an unfamiliar target

Use a deliberately constrained fixture before provider acquisition when that
resolves the integration question. For example, propose an ordinary JSON-turn
target that writes a file and stores a session but has no attention primitive.
Start from the target executable and protocol, not a claim of parity. Adapt
the guest command or a small reviewed shim only if needed. Reuse the
supervisor's deterministic model seam instead of adding a plugin loader.

The maintained `tests/test_harness_authoring.py` exercise supplies such a
target, drives its task and resume output through the shipped helper, and
keeps it `fixture_passing`. It also checks malformed output, a false success
claim, mismatched session identity, crashes, stalls and missing versions.
Run that module in the frozen source test environment. Its fixture target is
never installed as a supported harness or granted host authority.

For current Codex/Pi supervisor controls, run the existing relevant nodes
from `cli/tests/test_codex_coord_supervisor.py` with
`SAFEYOLO_COORD_TEST_BINARY` naming the matching native helper. A proposed
protocol parser must also pass its actual supervisor controls; this helper's
trace reader is only an evidence comparison, not the production parser.
Claude ordinary/attention regressions remain applicable. Claude Factory
promotion waits for its separate accepted implementation and installed proof.

## Review and activate

The ordinary PR contains resulting behavior, tested-version report, source and
installed executable identities, meaningful positive/negative results, unrun
rows and a short operator summary. Include the exact changed setup/command,
package inputs and saved/staged configuration. Explain why each added
dependency or capability is necessary. Add deterministic controls to the
existing CI collection and applicable installed checks to the existing
blackbox approach; do not create a new provider matrix or release gate.

The adoption plan names the owning instance and stopped worker, reviewed
commit/package, affected files, retained rollback package/configuration and
activation command. Stage at the existing safe stopped boundary. Verify the
consumed bytes and actual runtime after restart. Rollback restores that saved
selection through the same host lifecycle while retaining current homes,
claims and checkpoints. Inspect uncertain activation before repeating it.
Independent review and existing approval owners decide adoption; the helper
does not update an approved Factory or make an agent-authored claim trusted.
