---
name: harness-authoring
description: Discover, implement and qualify a coding harness integration for SafeYolo using the operator's preferred authoring agent, current launch and attention adapters, and installed proof. Use for adding or assessing harness support; ordinary use of an existing harness does not need this workflow.
---

# Author a harness integration

Keep the operator's authoring agent distinct from the target harness. Use the
operator's chosen authoring agent and saved preferences. This skill grants no
host access, provider access or permission to activate a candidate.

## Discover before building

Recover the selected host, instance/root, agent and intended use: ordinary
interactive launch, external conversation attention, supervised Factory turns,
or a combination. These are different capabilities. Inspect readable installed
versions, setup scripts, platform/package inputs, configured provider names and
credential custody. Do not print secret values. An unavailable inventory is
unknown, not an empty installation. Do not change active instances, install a
target or invoke a model during discovery.

Read [the integration contract](references/contract.md) for the relevant
boundaries and existing examples. In a guest with Python 3.12 or 3.13, probe an
already installed target without a model request:

```sh
python3 /safeyolo/skills/harness-authoring/scripts/qualify.py probe --harness codex --binary /absolute/path/to/codex
```

Replace the example harness name and executable with the selected target.
The JSON report identifies the observed version; `not_tested` means no task
was qualified. A successful version probe is not a login or capability test.
Check the target's own help and official protocol documentation at the exact
version. Preserve proxy and certificate settings. Use the installed SafeYolo
diagnostic interfaces for unavailable host information; request only an exact
missing operand from its authorized owner.

Ask only material unanswered questions, together where possible. Show a short
before-building proposal: desired operator workflow, existing adapter to reuse,
required changes, credentials and authority, platform/version limits, risks,
staged proof and rollback. Explain any unsupported capability and its effect.
Reuse already agreed scope and authority; do not introduce a routine approval.

## Implement the smallest complete candidate

Use the current host setup, guest command and native attention or supervisor
path. Do not add a supervisor, inbox, adapter registry or authorization model.
For an unfamiliar target, first try an ordinary guest command and then the
needed structured interface. A target that lacks a required primitive stays
unsupported for that use; do not silently replace its semantics.

Prepare changes in the source checkout. An adapter and generated tests are
proposals until independently reviewed. Never execute an unreviewed adapter
with host privileges. Keep host setup outside guest-writable shares. Use the
existing agent-local login or explicitly selected service gateway; approval of
an integration does not approve capabilities or credential copying.

## Qualify and propose adoption

Use [qualification and adoption](references/qualification.md) for the acceptance
matrix, constrained-target exercise, installed task/recovery probe and existing
test drivers. Run the smallest checks that address the changed boundaries.
Record `required`, `optional`, `unsupported` and `unverified` capabilities
separately from evidence states. A passing fixture is not installed evidence.

Retain exact source and executable identities, commands, tested versions,
actual results and unrun gaps in the normal review. The helper emits a
machine-readable report; it does not confer authority or independently accept
its own result. Keep raw native session output private because it can contain
task content. Reuse valid existing proof for unchanged behavior.

Publish one coherent candidate with tests, the short operator report and exact
change/rollback steps. Independent review and applicable installed/blackbox
checks precede promotion to supported. Activate through the existing owning
host and stopped-worker staging path. Preserve identities, checkpoints, login
state and active work. After an uncertain effect, inspect the original result
and current state before retrying.
