# Maintained policy lists

SafeYolo can acquire and refresh named host lists on the trusted host. Choose a
source once, then reference its accepted snapshot in `policy.toml`. The running
proxy refreshes sources through its existing policy control loop. A stopped
proxy does not refresh sources. Restart resumes the saved retry deadlines and
accepted data.

Sources supply membership evidence. Rules in `policy.toml` assign the effect.
No source is enabled by default. In particular, ad and tracker blocking is an
optional workload choice. Absence from a list does not establish that a host is
safe. This interface supports local-list membership; it does not supply the
shared named-check result and composition interface tracked in
[#1543](https://github.com/craigbalding/safeyolo/issues/1543).

## Configure a source

Run these commands on the host, as the account that owns an initialized
instance. Replace `/path/to/instance` with that instance's root. Use a trusted
working directory and the installed `safeyolo` and `curl` commands. The acquisition
inherits the host's proxy and certificate authority settings.

The optional HaGeZi example selects threat-oriented DNS suffix data. Its
unavailable and stale behavior denies network requests governed by a policy
that references it. Review the [source choices](#source-choices) before selecting
one. The following command only writes an example to the current directory:

```sh
safeyolo policy feeds example hagezi > sources.toml
```

`configure` replaces the instance's managed source definitions and attempts the
first due downloads. Keep other required sources in the input file. Source
endpoints, including any provider keys in paths or queries, belong in this
private host file. Do not put them in guest policy, command arguments or shared
examples. The default source file is `ROOT/policy-feeds.toml`, written with mode
`0600`. If `config.toml` selects another `policy_file`, the source file and feed
data belong to that policy file's directory.

```sh
safeyolo --root /path/to/instance policy feeds configure sources.toml
safeyolo --root /path/to/instance policy feeds status
```

A usable first result has a non-null `snapshot` with a `version`, source digest,
entry count and acquisition/validation timestamps. `last_failure` is null after a
successful attempt. A saved configuration alone is not an accepted snapshot.
When a download fails, the command reports failure and preserves the saved
configuration and retry schedule. Inspect `policy feeds status` for the reason.

To use the source, copy the current policy to a candidate beside it:

```sh
cp /path/to/instance/policy.toml /path/to/instance/research-policy.toml
```

Merge the following entries into that candidate's existing tables. This example
assigns a deny rule to members. When this source has no accepted data or exceeds
its example age limit, the policy denies all governed network requests without
creating approval requests. The existing host-rule precedence still applies. Known feed members match DNS
case, trailing-root-dot and internationalized-name equivalents through the same
rule evaluator.

```toml
[lists]
threats = { feed = "hagezi" }

[hosts."$threats"]
egress = "deny"
```

With the proxy running, validate and activate the candidate:

```sh
safeyolo --root /path/to/instance policy check /path/to/instance/research-policy.toml
safeyolo --root /path/to/instance policy apply /path/to/instance/research-policy.toml
safeyolo --root /path/to/instance policy show
```

`policy show` reports the active source version under
`list_files.threats.active_snapshot`. `saved_matches_active = true` confirms that
the running policy has the saved snapshot. Subsequent accepted replacements
activate through the policy watcher. Local filename lists remain usable, for
example `registries = "lists/registries.txt"` with a `$registries` host rule.
Compilation and candidate checking never download a source or visit its members.

## Source choices

These examples were researched against the primary provider documentation on
13 November 2026. Recheck provider availability and terms when adopting a
source. The limits and failure behavior in each example are explicit SafeYolo
settings, not provider service guarantees. Print either complete configuration
with `policy feeds example hagezi` or `policy feeds example stevenblack`.

| Example | Intended use and format | Access, cadence and limits |
| --- | --- | --- |
| `hagezi` | Optional malware, phishing, scam and other threat exclusions. The TIF Mini wildcard file supplies domain suffixes. It covers each listed domain and descendants. Mini has less coverage than the larger TIF variants. Shared hosts and false positives can affect research. | Public download without a key. The current [provider documentation](https://github.com/hagezi/dns-blocklists#-threat-intelligence-feeds-a-serious-security-boost-recommended) links the formats and coverage. Its [published file](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini.txt) declares an eight-hour expiry and dataset version/time; the example polls every eight hours and permits at most two days of evidence age. The provider publishes [GPL-3.0](https://github.com/hagezi/dns-blocklists/blob/main/LICENSE) and a [disclaimer](https://github.com/hagezi/dns-blocklists#disclaimer). |
| `stevenblack` | Optional adware/tracker and malware blocking for workloads that want those exclusions. The unified hosts file supplies exact hostnames, including all aliases on valid address lines. It does not imply suffix or URL coverage. | Public download without a key. The [provider README](https://github.com/StevenBlack/hosts#list-of-all-hosts-file-variants) describes the base and optional categories. The example polls daily and permits fourteen days of evidence age; the README does not promise a fixed publication interval. The [file header](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts) supplies its dataset date. The repository has an [MIT license](https://github.com/StevenBlack/hosts/blob/master/license.txt); its [source table](https://github.com/StevenBlack/hosts#sources-of-hosts-data-unified-in-this-variant) lists separate upstream licenses, including non-commercial terms. Review those terms for your intended use and distribution. |

SafeYolo ships the configurations, not copies of the provider datasets. Both
examples cap downloads at 16 MiB and require at least 1,000 normalized entries.
HaGeZi permits up to 500,000 entries; StevenBlack permits up to 250,000. Each
rejects a membership change above 50 percent. Operators can revise these limits
in their adopted configuration after inspecting a rejected provider update.
Large lists consume policy compilation memory and time; select a smaller source
or lower limits when the host cannot accommodate the chosen list.

## Custom sources and acquisition limits

A configuration contains `[sources.NAME]` tables. The examples show all required
fields. Names use 1–80 ASCII letters, digits, underscores or hyphens.

| Field | Meaning |
| --- | --- |
| `endpoint` | Absolute HTTP or HTTPS acquisition URL without userinfo or a fragment. HTTPS uses the host's trusted certificates. HTTP is available for explicitly adopted sources, but provides no transport confidentiality or authenticity. |
| `redirect_endpoints` | Optional exact absolute URLs the source may redirect to. Other targets and redirect loops are rejected before another request. Relative redirects are rejected; adopt an explicit final endpoint instead. Credentials are never copied into another URL. |
| `format`, `scope` | `domains` with `hostname` or `domain_suffix`; `hosts` with `hostname`; or `wildcard` with `domain_suffix`. Domain suffixes include the apex and its descendants. Inputs require ASCII DNS names, or their ASCII-compatible encoding, with a dot. Underscores found in hosts feeds are preserved. IP/CIDR, full URL, adblock and response policy zone (RPZ) data are rejected instead of guessed or broadened. |
| `metadata` | `hagezi` reads its dataset time/version header; `stevenblack` reads its dataset date. Both require the selected timestamp header. The default `none` leaves provider time/version absent. |
| `cadence_seconds`, `max_age_seconds` | Delay after a successful fetch and maximum evidence age. With a provider timestamp, age uses that timestamp. Otherwise age starts at the first observation of that normalized membership. An HTTP 304, identical HTTP 200 or changed comments around unchanged membership does not renew evidence age. Retrieval alone does not prove fresh upstream intelligence. |
| `max_bytes`, `min_entries`, `max_entries` | Bound each decoded response and its normalized membership. Unexpected empty data, invalid UTF-8, malformed entries, transfer truncation and disallowed response types are rejected. |
| `max_change_percent` | Allowed additions/removals as a percentage of the union of previous and new members, from 0 to 100. A complete replacement is 100 percent. The first snapshot still requires all other validation. |
| `timeout_seconds` | Total acquisition deadline, including redirects. Response headers are capped at 64 KiB per request. One worker refreshes sources sequentially. |
| `retry_seconds`, `max_retry_seconds` | Initial and maximum exponential retry delay after failure. A retry reservation is saved before I/O so interruption and restart cannot reset the schedule. Conditional requests use accepted ETag/Last-Modified validators only at the same acquisition endpoint. |
| `on_unavailable`, `on_stale` | `on_unavailable = "deny"` blocks governed network requests until a first snapshot is available. `on_stale = "deny"` also blocks them at expiry. Explicit `on_stale = "retain"` keeps the old membership rules and ordinary non-member policy; status still reports the stale evidence. Retain never turns a missing first snapshot into an empty accepted list. |

Changing cadence, validation limits or stale behavior preserves accepted
content. Changing the endpoint, adopted redirect destinations, format, scope or
metadata interpretation requires a snapshot for that new source definition.
Until then, a referencing policy treats the source as unavailable.

## Inspect and recover

`policy feeds status` shows retained source identity, redacted endpoint, format,
scope, source digest, accepted version, timestamps, evidence age, next refresh,
last attempt/success, last failure, failure count and any pending/interrupted attempt. All timestamps are Unix
seconds in UTC. Endpoint paths and queries are omitted even when they contain no
known key. Source bytes, endpoint URLs and raw curl diagnostics are not ordinary
log output. `policy show` separately identifies the running version.

A rejected update preserves the last accepted snapshot. When the cause is fixed,
the running proxy retries automatically. To attempt one adopted source now:

```sh
safeyolo --root /path/to/instance policy feeds refresh hagezi
```

This explicit command does not change source boundaries or validation limits.
A successful acquisition can still contain expired provider evidence; the
configured stale policy continues to apply. If validation rejected a large
membership change, inspect the upstream change before deliberately revising
`max_change_percent` and configuring that file again.

To select the previous accepted snapshot for the same source definition:

```sh
safeyolo --root /path/to/instance policy feeds rollback hagezi
```

Rollback preserves the snapshot's evidence time and refresh schedule. It does
not make old data fresh or undo other policy edits. The next successful refresh
can replace it. Accepted and previous snapshots remain in `data/policy-feeds`
beside the source file, along with conditional request and retry state. Readers
load entries and provenance from one atomically replaced file. The compiled
policy retains that complete version until a replacement is activated. Its
existing dependent runtime-state comparison includes the snapshot identity.
