# SafeYolo assurance

## Approach

> I understand and own the security design and its critical implementation paths; source analysis and calibrated checks challenge those paths; changes to authority and enforcement are explicitly reviewed and independently checked; and users can constrain the remaining risk.

This is Craig Balding's maintainer commitment and the v1 assurance target.
The [v1 assurance baseline epic](https://github.com/craigbalding/safeyolo/issues/837)
tracks delivery. The new work below is open; existing source references and
accepted results provide its starting point.

The aim is informed ownership of the implementation, supported by independent
analysis and demonstrated detection of harmful changes. Complete correctness,
absence of all malicious logic, and independent audit or accreditation are not
claims of this approach.

| Commitment | Supporting practices | Existing basis | V1 delivery |
|---|---|---|---|
| Understand and own the security design | Explicit trust boundaries and security decisions, checked against implementation rather than accepted from an agent's description. | [Security model](../SECURITY.md), [verification reference](security-verification.md), and [native inventory recorded under #621](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5801132524). | [Implementation map and protected drift detection #838](https://github.com/craigbalding/safeyolo/issues/838); [Craig-vetted talks and walkthroughs #844](https://github.com/craigbalding/safeyolo/issues/844). |
| Understand the critical implementation paths | Trace authority and data from sources through decisions, callers and library handoffs to sinks. Include failure paths, exceptions and alternative routes. | [Native request path](https://github.com/craigbalding/safeyolo/blob/b0b27c1594bac9f0d003a32c895c278badfd2c22/proxy/src/http.rs), [policy runtime](https://github.com/craigbalding/safeyolo/blob/b0b27c1594bac9f0d003a32c895c278badfd2c22/proxy/src/policy_runtime.rs), [approvals](https://github.com/craigbalding/safeyolo/blob/b0b27c1594bac9f0d003a32c895c278badfd2c22/proxy/src/approvals.rs), and [local-patch validation #636](https://github.com/craigbalding/safeyolo/issues/636). These are source checkpoints for the map. | [#838](https://github.com/craigbalding/safeyolo/issues/838) and [#844](https://github.com/craigbalding/safeyolo/issues/844). |
| Challenge the paths with source analysis | Select useful independent analysis of data flow, authority, capability use and implementation properties. Test the selected rules and assumptions. | [Rust workflow with Clippy](https://github.com/craigbalding/safeyolo/blob/b0b27c1594bac9f0d003a32c895c278badfd2c22/.github/workflows/proxy-rust.yml); [CodeQL workflow at the same checkpoint](https://github.com/craigbalding/safeyolo/blob/b0b27c1594bac9f0d003a32c895c278badfd2c22/.github/workflows/codeql.yml), which selects Python only. | [Rust CodeQL #839](https://github.com/craigbalding/safeyolo/issues/839), [Kani #840](https://github.com/craigbalding/safeyolo/issues/840), [Cackle #841](https://github.com/craigbalding/safeyolo/issues/841), and [Miri #842](https://github.com/craigbalding/safeyolo/issues/842). |
| Calibrate the checks against harmful changes | Use effective deliberately compromised candidates, clean and benign controls, and independent observations. Record detections and misses by class. | [Black-box sensitivity work, #621 §6](https://github.com/craigbalding/safeyolo/issues/621); [accepted patch-validator failure/clean controls](https://github.com/craigbalding/safeyolo/issues/636#issuecomment-5736479281). Native chaos calibration remains with [#831 C7](https://github.com/craigbalding/safeyolo/issues/831). | [Shared compromised-candidate and coding-agent calibration #843](https://github.com/craigbalding/safeyolo/issues/843), reused by the tool owners. |
| Review and independently check changes to authority and enforcement | Automatically detect drift. Protect the accepted baseline, analysis configuration and acceptance path from unilateral candidate changes. | [Repository role separation](../AGENTS.md) and [reviewer contract](agent-roles/independent-reviewer.md) are existing process references. The protected automatic mechanism is new work. | [#838](https://github.com/craigbalding/safeyolo/issues/838), exercised under the compromised-coding-agent threat model in [#843](https://github.com/craigbalding/safeyolo/issues/843). |
| Let users constrain the remaining risk | Document deployment boundaries, scoped credentials and permissions, and the residual authority of the host-side components. | [Security model](../SECURITY.md), [verification procedures](security-verification.md), and [recorded installed/ingress results under #637](https://github.com/craigbalding/safeyolo/issues/637#issuecomment-5794507027). | Reuse existing deployment work and the selected release's operating instructions. This assurance scope does not add a new host-containment product. |

## V1 work

### Implementation map and protected drift detection

[#838](https://github.com/craigbalding/safeyolo/issues/838) connects the critical
security decisions to source symbols, callers, input trust, output sinks,
checks, library APIs and relevant build or feature paths. It includes the
shipped helper boundaries and local dependency changes, not just the proxy's
central policy function.

The automatic process must report new or changed sensitive operations, changes
to mapped security-critical code that introduce no new sink, relevant
library/build changes, and stale map references. Its accepted baseline and
required analysis configuration remain outside the candidate's unilateral
write authority. Legitimate changes have an explicit approval path.

The initial map can support tool experiments and walkthrough preparation before
all drift automation is complete. Useful tool output feeds the same map.

### Independent tools: learn, experiment, implement

Each tool issue includes capability discovery, a source-linked shortlist,
structured configuration comparisons and a useful maintained v1 implementation.
Craig selects the initial questions and scope after reviewing the experiments.
The exact CodeQL queries are deliberately not selected in advance.

| Tool and owner | Question to investigate | Selection and implementation focus |
|---|---|---|
| [CodeQL #839](https://github.com/craigbalding/safeyolo/issues/839) | Which mapped security questions can Rust source/data-flow analysis answer usefully? | Compare built-in coverage and candidate SafeYolo-specific queries/models. Implement the selected custom set in the existing local and continuous-integration paths. Start with the [Rust guide](https://codeql.github.com/docs/codeql-language-guides/codeql-for-rust/) and [data-flow documentation](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-rust/). Reuse [versioning #393](https://github.com/craigbalding/safeyolo/issues/393) and [local-platform work #396](https://github.com/craigbalding/safeyolo/issues/396). |
| [Kani #840](https://github.com/craigbalding/safeyolo/issues/840) | Which bounded production-code properties benefit from model checking? | Compare suitable functions, harnesses, bounds and assumptions. Maintain the selected proof cut, with counterexamples and unsupported behaviour explicit. Use the [Kani documentation](https://model-checking.github.io/kani/) and [feature limits](https://model-checking.github.io/kani/rust-feature-support.html). |
| [Cackle #841](https://github.com/craigbalding/safeyolo/issues/841) | Where can crate/API or build-access controls reveal unexpected authority? | Compare relevant API definitions, permissions, feature/profile scope and sandbox settings. Maintain a demonstrated useful policy. Investigate misuse of already-permitted authority as a separate limitation. See [Cackle's goals and constraints](https://github.com/cackle-rs/cackle). |
| [Miri #842](https://github.com/craigbalding/safeyolo/issues/842) | Which suitable components benefit from interpreted checks for Rust implementation defects? | Compare relevant model, seed, isolation or target choices on real code. Maintain a finite useful check selection with execution and system-interface limits explicit. See [Miri's documentation](https://github.com/rust-lang/miri). |

Each experiment batch has a finite selection, meaningful configuration
comparisons, clean and harmful controls, expected observations and an effort
budget. Findings, missed cases and operational cost determine the first cut.
The owners share calibration fixtures and results. If a tool cannot provide a
useful supported cut, Craig makes the scope decision; a comparison report alone
does not complete the planned implementation.

### Compromised candidates and coding-agent acceptance

[#843](https://github.com/craigbalding/safeyolo/issues/843) owns one fixed catalogue
and its passage through the actual acceptance process. Its initial classes are
selective authorization bypass, cross-agent confusion, secret disclosure through
permitted channels, new unauthorized effects, release-configuration-only harm,
and acceptance tampering. Exact sites and variants follow the map and tool
experiments. The catalogue is bounded to six to eight harmful variants, with
the clean candidate and two benign changes.

The coding actor is treated as an adversarial proposer. A controlled agent
session or deterministic substitution at its candidate-submission boundary
supplies the harmful output. The experiment records which method was used and
which tools, reviewer findings and gate decisions detected, prevented,
escalated or missed the change. This does not require successful real-world
prompt injection. Harmful candidates never enter a real release.

### Maintainer understanding

[#844](https://github.com/craigbalding/safeyolo/issues/844) is Craig-owned. Technical
talks and/or walkthrough videos will trace the map's critical decisions,
including relevant source, assumptions, error paths and counterexamples.
Craig personally vets agent-supplied explanations against the implementation
and appropriate checks.

The published index will link sections or timestamps to the source revision and
decisions covered. Existing material can count when applicable. Corrections
follow changes to the covered security decisions; unchanged material does not
need to be recorded again for every release.

## Existing acceptance and product ownership

| Owner or accepted result | Scope reused by this work |
|---|---|
| [#621 acceptance, 26 September 2026](https://github.com/craigbalding/safeyolo/issues/621#issuecomment-5849605308) | Shared instruments, product promises and library-handoff coverage, §§3–5, in the Linux in-guest pre-cutover lane at `e46b25b8`. The issue also owns its inventory and sensitivity checks. |
| [#636 acceptance at `ae85c918`](https://github.com/craigbalding/safeyolo/issues/636#issuecomment-5736479281) | Focused local-patch validation, controlled failure/clean control and selected feature builds for patched dependencies. |
| [Native policy-chaos restoration #831](https://github.com/craigbalding/safeyolo/issues/831) | Generated histories, transaction/fault/crash work and its three additional calibration families. Its own acceptance remains the delivery record. See the [policy-assurance threat model](policy-assurance-threat-model.md). |
| [Installed ingress #637](https://github.com/craigbalding/safeyolo/issues/637), [state #638](https://github.com/craigbalding/safeyolo/issues/638), [workloads #639](https://github.com/craigbalding/safeyolo/issues/639), and [cutover #640](https://github.com/craigbalding/safeyolo/issues/640) | Existing accepted results and remaining proxy-migration obligations stay with their owners. This assurance epic does not reopen their completed work. |
| [Native product phase #815](https://github.com/craigbalding/safeyolo/issues/815) and [release #822](https://github.com/craigbalding/safeyolo/issues/822) | Product scope, fresh installation, final installed integration and the existing release lanes. The assurance map follows the implementation selected for v1, including changing CLI/helper responsibilities. |

The initial document uses default-branch checkpoint
`68108a2748fd1e64129d21e5c9c43f6f31d69f50` and native source checkpoint
`b0b27c1594bac9f0d003a32c895c278badfd2c22`. These are reference points, not a
selected v1 release. The linked acceptance records retain their own tested
revisions and limitations.

## Release use and limitations

For each release, link the applicable implementation map, selected tool and rule
versions, calibration outcomes, Craig-vetted material, and material remaining
gaps to the actual source and published artefacts. Keep the summary short and
reuse the underlying issue/PR results. Reassess affected evidence when its
inputs or assumptions change. The existing release owner's final-lane rules
remain in force.

This supports evaluation of SafeYolo for research, practitioner use and
controlled organisational pilots. It does not claim suitability for every
high-consequence deployment or satisfaction of a purchaser's assurance policy.
Users select exposure and credentials within the documented deployment model.
The host-side proxy's legitimate access to plaintext, credentials and permitted
connections remains relevant even when agent isolation works as intended.

The work is maintainer-operated assurance using third-party tooling and
separately controlled checks, not an independent third-party audit. Coverage
remains bounded by the mapped implementation, selected rules, proof assumptions,
executed cases and supported configurations. Undetected malicious use of existing
authority, untested triggers and compromise of the trusted acceptance/build
infrastructure remain explicit residual concerns.
