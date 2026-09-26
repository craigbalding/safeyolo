---
name: lens-hypothesis
description: "Use for Lens adversarial review of structured inputs or meaningful request/state sequences: parsers, normalization, paths, headers, tokens, credentials, authorization, proxy forwarding, and protocol state. Build Hypothesis generators, drive the real boundary, check independent effects, and shrink failures. Skip pure lifecycle or resource checks with no useful input grammar."
---

# Hypothesis in Lens reviews

Use this skill to find defects in a feature or fix, not to produce a scan badge or an evidence pack. The default for a reviewable structured input or request sequence is an actual Hypothesis test. A few handwritten payloads or `random.choice` under a “Hypothesis” label do not provide its generation and shrinking. If generation adds no meaningful variation, use a direct probe and say why in the normal review result.

## Design the property

Start from a working request or sequence through the same entry point users or agents reach. State the requirement as an observable property before choosing payloads. Identify the attacker-controlled fields, the trust boundary, and an oracle independent of the candidate implementation. The HTTP status alone is usually insufficient: inspect the caller-visible response **and** the effect that matters, such as the upstream sinkhole request, authorization decision, stored state, or connection state. For Python/Rust parity, replay the same generated case against both, but also check the requirement; two implementations can agree on a wrong result.

Build a small, valid grammar around that baseline, then vary the dimensions that could change the decision:

- Values and structure: absent, empty, null, type changes, lengths near a boundary, nested fields, duplicate fields, and incompatible combinations.
- Representation: raw versus encoded bytes, case, whitespace, Unicode, percent encoding, separator placement, content type, and parser disagreement across layers.
- Authority and context: which field or header supplies identity, credential, route, origin, or destination; substitute one principal or target when the test fixtures permit it.
- Sequence and failure: reuse a connection, repeat or reorder a request, send a malformed item before a valid one, or fail an upstream step; check what state carries into the next decision.

Use the project's locked Python environment for `hypothesis.strategies`, `@given`, and Hypothesis shrinking. In the current Lens workspace, `/workspace/.venv/bin/python` imports the locked package; `tools/acceptance/.venv` does not. Seed known edge cases with `@example`; do not make the strategy only a sampled list of already-known cases. Choose a useful run size from the cost of the real boundary: cheap local tests should cover many combinations, while expensive probes stay bounded. Avoid arbitrary tiny caps that turn property testing back into a handful of examples. Reset mutable fixtures between examples or make each case independent. Do not mistake a malformed harness request, a stale sinkhole observation, or a shared Python/Rust dependency for a product result.

When a property fails, reproduce the minimized example against the real boundary, inspect both response and effect, and give Forge the shortest payload or sequence and its consequence. When it passes, state the property, generated dimensions, actual boundary, approximate example count, and material limits in Lens's ordinary disposition. No transcript archive, hash list, or extra CI run is required. Add a focused regression test when a real defect is found or the property should remain guarded.

Read [proxy review examples](references/proxy-review-examples.md) for practical query/header, credential, and connection-sequence patterns. Adapt them to the current feature; they are leads, not a mandatory catalog.
