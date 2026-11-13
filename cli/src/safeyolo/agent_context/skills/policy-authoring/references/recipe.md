# Cyber brief recipe

This walkthrough uses a host-side operator agent and a separate research
workload. The host agent uses the instance owner's existing policy authority.
The research workload receives ordinary proxy access and no Admin API token.

## Load the installed skill and select the instance

On the Linux or macOS host that owns an installed instance, use its ordinary
owner account. The examples use `$HOME/.safeyolo` and an existing research agent
named `research`. Substitute the actual selected root and agent throughout.
The root must contain the installed `bin` and `assets` trees and initialized
configuration. Install and create the research agent through the current
installation/operator guide if those inputs are absent. Host authoring needs
Python 3.12+ and TOMLKit 0.14.0. The helper's inline dependency declaration also
supports an already installed `uv`; its first launch downloads those authoring
tools through the host's configured proxy/CA. They are optional workflow tools,
not proxy-startup dependencies.

From the host terminal, expose the shipped skill to a host Codex agent. Create
the skills directory if needed. The link command creates a new entry; if the
entry already exists, inspect its destination and reuse it when appropriate.
For Claude, use `$HOME/.claude/skills` instead of `$HOME/.agents/skills`.

```sh
mkdir -p "$HOME/.agents/skills"
ln -s "$HOME/.safeyolo/assets/skills/policy-authoring" "$HOME/.agents/skills/policy-authoring"
```

Start or refresh the host agent's skill discovery. Ask it:

> Use $policy-authoring to prepare a focused cyber brief policy for the
> research agent in my `$HOME/.safeyolo` instance. Preserve my existing controls.
> Offer a threat-list exclusion and a passive registration-age check. Use the
> saved preferences when they exist; ask only about material missing choices.

The agent loads `SKILL.md` from the installed link and selects the stated root.
A link only inside a guest home does not establish this host authoring path.
The host agent should inspect the executable version, saved config/policy,
active policy, source status and adopted services/grants before changes:

```sh
"$HOME/.safeyolo/bin/safeyolo" --version
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" policy show
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" policy feeds status
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" services list
```

`policy show` reports the running source and `saved_matches_active`. If the
proxy is stopped or unreadable, active state is unknown. Read `config.toml` to
locate a nondefault policy file; do not assume it is `ROOT/policy.toml`.
`services authorized research` and the saved policy show its existing grants.
Do not copy their tokens into the research guest.

An HTTPS service check needs the selected proxy's TLS configuration. Initialization
writes `tls_ca_file`; preserve it when changing runtime settings. If the selected
instance lacks that capability, report HTTPS checks as unavailable and resolve
the intended transport before claiming working registration enforcement.

## Generate and assess a candidate

Use a private host working directory for generated files. The next commands
write only that directory. `preferences.json` is the bundled optional example:
HaGeZi threat suffixes as a hard exclusion, a 30-day RDAP condition, and
`continue` for unknown registration age. Continue leaves the existing network
guard in control; it does not declare a host safe. The Verisign example covers
exact .com registration objects. Hosted subdomains and other suffixes normally
have unknown age in this example. Select another researched endpoint or a
supported provider/check for wider coverage.

The operator-side agent copies and edits the preferences for the stated
workload; the human does not need to hand-edit TOML. Required destinations,
privacy/failure choices and the two advisory priorities are explicit fields.
For an advisory profile, select `profile: advisory` and the desired list action;
the higher-priority matching advisory decides. A hard exclusion dominates a
favorable dynamic result at every priority.

```sh
cp "$HOME/.safeyolo/assets/skills/policy-authoring/assets/preferences.json" preferences.json
"$HOME/.safeyolo/bin/safeyolo" policy feeds example hagezi > source-choice.toml
uv run --script "$HOME/.safeyolo/assets/skills/policy-authoring/scripts/author.py" --root "$HOME/.safeyolo" --choices preferences.json --sources source-choice.toml --output candidate
```

`candidate/` contains the complete policy, merged source definitions, a
credential-free service definition, saved preferences, rationale and a
representative request. Files are private. The helper preserves existing
controls, comments, inline agent identity and unrelated sources. Existing exact
destination rules remain authoritative; a preserved deny can still refuse a
requested reporting source. A conflicting recipe/service block stops generation
with its name. Resolve that specific conflict within the operator's authority.

Before the following commands, retain the current saved policy and source file
in this private working directory, using their actual selected paths. Configure
writes the merged source definitions and downloads the named sources; it does
not grant workload access. Review the chosen endpoints, refresh bounds and
terms first. No list member is visited. A failed download retains the saved
configuration and retry state; inspect status instead of treating it as empty.

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" policy feeds configure candidate/sources.toml
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" policy feeds status
"$HOME/.safeyolo/bin/safeyolo" services check candidate/cyber-rdap.yaml
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" policy check candidate/candidate.toml
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" policy evaluate candidate/candidate.toml candidate/request.json
```

Expected preview: `recorded_offline`, accepted feed version/freshness and named
rule explanations. Dynamic RDAP evidence is unavailable because offline preview
does not call it. The example's unknown fallback lets the existing guard decide.
This is a decision simulation with that limit; `policy check` alone proves only
compilation. Direct-IP requests also have unavailable hostname evidence. A
captured offline scenario may supply an IP; no DNS lookup or target visit occurs.

Review the resulting diff and rationale, including new source/provider traffic,
per-agent destination additions, rule precedence, explicit fallbacks and expected
prompts. An `approval` fallback creates a pause; the bundled example instead
uses `continue` for unknown RDAP and `unresolved` for unavailable threat data.
Keep authorization already granted for ordinary work; add no recurring ritual.

## Activate and run

On the same selected host, install the reviewed service definition under the
instance's `services` directory before applying. If that filename already exists,
compare it and reconcile a material difference before replacing it. The gateway
watches its service catalogue. Apply uses existing host policy authority to save
and activate the candidate. Only `gate:cyber-registration` gains the RDAP lookup
capability. The research agent gains no service or administrative credential.

```sh
cp candidate/cyber-rdap.yaml "$HOME/.safeyolo/services/cyber-rdap.yaml"
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" policy apply candidate/candidate.toml
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" policy show
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" services show cyber-rdap
```

Success needs `status: active`, matching saved/active source and the accepted
service definition. An unknown read is not failed activation or safe permission
to replay. Inspect that instance before retrying. To restore policy, apply the
retained prior candidate. Source rollback selects the previous accepted snapshot
without making it fresh; restore source definitions separately when needed.

In the research guest, with Python 3 and its ordinary configured proxy/CA, run
the shipped research script. The read-only skill assets are under `/safeyolo`;
if absent, the host owner can copy just this credential-free script into the
research workspace. The guest command writes the brief in its current directory.
It makes one bounded CISA catalogue request and cites entries without visiting
their embedded links. No model subscription or paid source is required.

```sh
python3 /safeyolo/skills/policy-authoring/scripts/brief.py --limit 3 --output cyber-brief.md
python3 /safeyolo/skills/policy-authoring/scripts/brief.py --focus Microsoft --limit 3 --output microsoft-brief.md
```

The first brief covers latest catalogue additions; the second is a focused run.
Each includes collection time, actual provider version, CVE references and the
meaning of the addition date. An HTTP refusal, timeout or malformed response
fails visibly and does not replace the brief with an empty successful result.
These scripts demonstrate research collection, not an exhaustive intelligence
report or proof that all referenced destinations are safe.

For a periodic brief, use the installed guest's existing cron/at instructions in
the SafeYolo scheduling reference. Capture the current run's proxy/CA and token
paths as that reference describes. Schedule the first command under its existing
workload authority; test one invocation and inspect its exit/output. A stopped
guest does not run cron; use the existing trusted-host schedule when it must
start work from a stopped guest. An expired source or provider timeout uses the
policy's explicit fallback and must remain visible in the job result. Authorized
feed refresh, passive checks and ordinary research require no new routine approval.

## Change saved preferences

A returning operator can ask:

> Keep my sources, destinations and exclusions. Change the registration threshold
> to seven days and use unresolved when registration evidence is unavailable.

The host agent reads the saved preferences and current policy, edits only those
choices, then invokes `author.py` with the previous `preferences.json` through
`--previous` and a fresh output directory. The helper replaces only recipe
blocks that still match those saved choices. It preserves unrelated later edits.
Agent/provider changes require reconciliation of the old grants. Review the
bounded diff, evaluate representative cases, apply within existing authorization
and verify active state as for the first run.
