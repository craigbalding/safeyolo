---
name: policy-authoring
description: Turn an operator's cyber brief or research workload and risk choices into a reviewable SafeYolo policy, source and check configuration. Use on the host that owns the selected instance; use existing policy authority and keep administrative credentials outside the research workload.
---

# Author a research policy

Use the installed `safeyolo` commands and the selected instance's current
configuration. This skill supplies the first cyber research recipe. It grants
no host or policy access. Inside an ordinary guest, prepare the proposed
choices and ask the existing host owner to perform host operations.

Read [the walkthrough](references/recipe.md) for the complete first run,
host discovery, prerequisites, helper commands and saved-choice updates.
Read [sources and controls](references/sources-and-controls.md) when choosing
a provider or explaining coverage, disclosure, precedence or unsupported cases.

Discover before authoring. Identify the installed executable/version and the
intended root, `config.toml`'s selected `policy_file`, saved policy, active
`policy show`, `policy feeds status`, service catalogue, relevant grants and
saved preferences. An unavailable read remains unknown. A directory name or
successful compile does not establish activation or a usable provider.

Resolve only material missing choices: focused or periodic work, required
reporting destinations, exclusions versus advisory findings, registration-age
threshold, evidence freshness, unavailable/error actions, privacy/cost limits
and relative advisory priorities. Preserve existing controls and reuse current
authorization. The bundled preferences are an optional example, not defaults
for all operators. A bounded change can reuse saved choices without repeating
the questionnaire or adding a confirmation ritual.

Research providers from primary documentation. Distinguish passive lookup,
input retention and active subject scanning. Identify disclosed data, coverage,
score meaning, freshness and access requirements. Select an explicit provider
and endpoint; do not turn an example into a universal requirement. RDAP
registration, provider first-seen and SafeYolo local first-seen are different
facts. A finite-window list no-match cannot establish an older domain.

Generate with [author.py](scripts/author.py), using TOMLKit to retain unrelated
controls and inline agent settings. It writes private candidate files, selected
preferences, source/service configuration and a rationale; it does not contact
providers or activate policy. Preserve material existing controls. Reconcile a
reported collision instead of deleting a control to make generation succeed.
Explain any new authority, removals, fallback and expected approval behavior.

Run `policy check` and representative `policy evaluate` cases. Check is
compile-only. Evaluate is an offline decision simulation using captured
records/feed snapshots; service/job evidence remains unavailable. Never visit,
scan, crawl or indirectly fetch the subject to improve a preview. An explicitly
authorized passive provider capture is a separate data-disclosing operation;
do not call it offline or silently add it. Deterministic adverse cases are
fixtures, not evidence that a live integration works.

Within existing operator authorization, configure sources, install the reviewed
service definition and apply the candidate through existing host controls.
Verify `policy show`, accepted source status and the actual research request.
If activation is uncertain, inspect the selected root before another write.
Keep saved, active and unknown states distinct; preserve the previous policy
and source definitions for their existing rollback mechanisms.

Use [brief.py](scripts/brief.py) for a bounded real periodic/focused example.
Run it in the research guest through ordinary proxy authority. It fetches only
CISA's public catalogue and writes a short referenced brief. It never fetches
URLs embedded in reports. Reuse existing cron/at or host scheduling; do not
build a scheduler or require repeated approvals for authorized work.
