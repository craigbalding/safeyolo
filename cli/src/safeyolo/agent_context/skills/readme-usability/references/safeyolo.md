# SafeYolo README notes

Apply these notes only to SafeYolo documentation, selecting the points relevant
to the document. Seatbelt-specific points concern `contrib/macos-seatbelt-agent`
and its integration docs. These are project owner priorities, not a template for
unrelated READMEs. Repository paths below are relative to the target checkout.

Read the applicable `AGENTS.md` and `docs/technical-writing.md`. For the macOS
contribution, use its `README.md`, `REFERENCE.md`, implementation, and
`VALIDATION.md` together. Verify behaviour against the revision being reviewed.

## Owner priorities

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
