# SafeYolo README notes

Apply these notes only to SafeYolo documentation, selecting the points relevant
to the document. Seatbelt-specific points concern `contrib/macos-seatbelt-agent`
and its integration docs. These are project owner priorities, not a template for
unrelated READMEs. Repository paths below are relative to the target checkout.

Read the applicable `AGENTS.md` and `docs/technical-writing.md`. For the macOS
contribution, use its `README.md`, `REFERENCE.md`, implementation, and
`VALIDATION.md` together. Verify behaviour against the revision being reviewed.

## Owner priorities

- **Reach the first result in two commands.** Under #237/#1053, the normal
  quick start must reach a usable coding agent in at most two commands from
  the recorded supported host/account/workspace setup. Keep required explanatory
  prose within 150 words, excluding runnable commands, the task and expected
  output. Count all required context and instructions, including any required
  reference or wizard reading. Moving setup out of view does not meet the goal.
- **Use the public entry and supported defaults.** Reuse the accepted #1050
  journey. Verify changed release resolution and omitted options against its
  underlying operations; do not require fixture names, flags or source hashes
  in public commands. Keep exact qualification identities and remaining proof
  limits in the reference and evidence. State applicable platform and account
  prerequisites before action. Show the first task and host-visible result.
  Host changes, copied authentication and access scopes belong at the software's
  actual decisions, with refusal intact. Read the whole README as a new user;
  matching commands and word counts do not establish a clear path.
- **Use one product name.** Under #1053, the product is SafeYolo. Use
  `SafeYolo`, `proxy`, `installer`, `release` and `settings` as appropriate.
  Do not describe a separate “native” edition. This owner decision takes
  precedence over the generic instruction to preserve existing terminology.
  Keep Rust, Swift and native terminology when they explain a real implementation
  distinction, an operating-system facility or historical evidence.
- **Write reusable contribution documentation.** Use the contribution's defaults
  and supported customization path. Avoid assuming the owner's particular Mac,
  account history, or personal setup.
- **Make transitions clear.** Distinguish the client agent, the Mac operator's
  terminal, and the confined Mac account when switching between them. Carry
  forward context within a continuous sequence; do not add repeated boilerplate.
- **Complete handoffs.** Explain where required keys, files, and configured SSH
  aliases come from. Use verified standard locations when available. A public-key
  handoff must clearly identify which public key moves and where the private key
  stays. Link to the approved client-transport setup or identify the missing
  integration; do not imply the Mac endpoint installer provisions that route.
- **Keep expert detail accessible.** The README should provide the normal path.
  The reference should explain entry order, policy and configuration decisions,
  checks, files changed, manual inspection, limitations, and recovery. Automation
  reduces routine decisions; it must not become the only explanation of those
  mechanics. Preserve these details when shortening the README.
- **Explain why Seatbelt is used.** Pair the `sandbox-exec` deprecation note with
  the practical rationale and continued-use examples from Apple, OpenAI, and
  Anthropic. Keep primary sources in the contribution's `REFERENCE.md` section
  “Why Seatbelt”. Distinguish use of the mechanism from support for custom profile
  interfaces and from evidence about this contribution's particular policy.

## Operational examples and evidence

Before enabling an entry, explain changes to authentication, forwarding, and
login behaviour. Document the actual scope of rollback, including changes that
remain after a helper fails. Put failure-specific prerequisites before recovery
commands. Inspect the implementation rather than assuming an installer handles
account checks, ACLs, or every setup stage.

An SSH `id` result establishes account identity, not filesystem or network
confinement. A health endpoint establishes only what it checks. Use the recorded
boundary probes for confinement claims, retaining their fixture requirements and
tested platform limits. A build or capability check does not establish a working
VM boot; keep that distinction when discussing native virtualization workloads.

Report missing setup automation or transport integration as implementation work.
Do not hide those gaps by adding warnings, inventing commands, or claiming that
existing helpers perform checks they do not implement.
For a longer unavoidable onboarding path, name the actual missing operation,
its linked owner under #237, and the smallest sufficient product repair.
Keep the actual prerequisites visible. Do not call a longer warning-filled
quick start complete or implement a new helper outside the assigned scope.
Reuse #1050's connected AMD64 first-task result; #1051/#1052 and #239 retain
their own accepted scope. Default/entry equivalence is not a new installed run
or evidence for another platform or account flow.
Use the maintained documentation, command and forbidden-phrase checks to
challenge drift, including an added mandatory command and an obsolete product
qualifier. Review required prose and decisions as well as command count.
Distinguish required reading from logs, repeated output and observer work;
displayed-word totals do not measure required reading.
Terminology changes and a warm return do not establish the cold 15-second
outcome. The recorded cold target remains unmet.
