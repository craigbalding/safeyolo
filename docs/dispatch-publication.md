# Dispatch delivery and publication

Dispatch production is a daily operator-authored task delivered to Relay. It
is not a generic coord scheduler and it is not tied to a Relay coding-harness
session. Publication is a separate, idempotent side lane: a delayed decision,
revision, failed build, or Pages outage never holds an issue delivery claim,
occupies Forge or Lens, or blocks ordinary coordination.

## One-shot host command

Use the installed native `safeyolo` executable, as the host account that owns
the selected [native instance](native-policy.md#install-and-start). The example
uses `$HOME/.safeyolo-native`; its configuration, agent `relay`, and `backlog`
room must already exist. The operator must have send/receive access and Relay must be a
receive-authorized room member. Start that instance's Coord/NATS runtime with
`safeyolo --root "$HOME/.safeyolo-native" coord start` if it is stopped. See
[native operator communication](native-coord.md) for room setup and grants.

Deliver one operator-authored task for the explicit UTC date below. This writes
the delivery ledger and may publish one Coord message; it does not publish a
website or install a schedule:

```sh
safeyolo --root "$HOME/.safeyolo-native" coord dispatch-trigger backlog \
  --date 2026-08-29 \
  --weekly-on monday \
  --publication-mode manual
```

The command uses the same trusted local operator principal as
native `coord chat`; there is no agent-supplied sender identity. It targets
the registered Relay room member and produces one canonical `TASK` envelope.
Guest commands cannot select the host operator principal or acquire its
credentials. The command reports `delivered`, `already-delivered`, or
`reconciled`, with the date key and actual room sequence. An invalid date,
unavailable backend, denied grant or corrupt ledger produces a nonzero exit
status, rather than reporting delivery.
The explicit date is the stable key. The local coord data directory contains a
locked, atomic outbox with the SafeYolo-minted message and attention IDs. A
retry reconciles retained room history using the original prepared message
identity. The ledger is `coord/dispatch-schedule.json` under the selected
configuration's `data_dir`; that directory also retains the Coord store and
owned NATS state. Keep those inputs when restarting. The same date cannot be
rebound to another room, weekday or publication mode.

If an attempted publication has an unknown outcome, rerun the exact same
command to reconcile the original message. A matching retained message reports
`reconciled` without another publication. If history cannot confirm that
message, the command reports unknown and does not resend it automatically.
Do not delete the pending ledger entry to force a retry. A later independent
date remains usable. This protects against duplicate requests; it does not
promise that an uncertain external write occurred.

Every date requests a daily period. On the configured weekday the same task
also requests the latest fully completed Monday-through-Sunday period (a
Sunday trigger therefore selects the prior week, never the partial current
week). On the first of a month it also requests the preceding complete
calendar month. Relay may conclude that there is nothing substantive to
publish; that creates neither a placeholder artifact nor a pull request.

The host scheduler supplies the date; the command never reads the clock. If
you want scheduled requests, install the native executable at
`/usr/local/bin/safeyolo` and use the same owning host account and native root.
The daily cron entry below computes a UTC date. Cron runs at 09:17 in the
account's scheduler timezone; configure that timezone as UTC for a UTC launch:

```cron
17 9 * * * /usr/local/bin/safeyolo --root "$HOME/.safeyolo-native" coord dispatch-trigger backlog --date "$(/bin/date -u +\%F)" --weekly-on monday --publication-mode manual
```

For systemd, install these optional user units under
`~/.config/systemd/user/`, using the same owning account. The timer selects UTC
explicitly and keeps the one-shot command observable in the user journal:

```ini
# ~/.config/systemd/user/safeyolo-dispatch.service
[Unit]
Description=Deliver the daily SafeYolo Dispatch production task

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'exec /usr/local/bin/safeyolo --root "%h/.safeyolo-native" coord dispatch-trigger backlog --date "$(/bin/date -u +%%F)" --weekly-on monday --publication-mode manual'
```

```ini
# ~/.config/systemd/user/safeyolo-dispatch.timer
[Unit]
Description=Daily SafeYolo Dispatch production trigger

[Timer]
OnCalendar=*-*-* 09:17:00 UTC
Persistent=true
Unit=safeyolo-dispatch.service

[Install]
WantedBy=timers.target
```

Enable the optional timer with `systemctl --user enable --now
safeyolo-dispatch.timer` after `systemctl --user daemon-reload`. Stop future
requests with `systemctl --user disable --now safeyolo-dispatch.timer`, or remove
the cron entry. Stopping the scheduler does not retract a delivered request or
delete the ledger. The trigger is one-shot and owns no background worker. To
stop Coord for a disposable instance you own, use
`safeyolo --root "$HOME/.safeyolo-native" coord stop`; keep a shared instance
running for its other users.

No launchd example is shipped because SafeYolo does not install or validate a
launchd integration. On any host, rerun the exact one-shot command to retry;
do not add a background poller around coord.

## Default operator-approved flow

The default and initial production flow is exactly:

```text
Relay generates -> publication PR -> operator approves -> CI -> Pages
```

Relay first follows the pre-draft operator interaction and final-manifest
rules in [Dispatch generation](dispatch-generation.md). If content exists,
Relay creates `dispatch/<date>` and changes only these publication paths:

```text
site/_sources/dispatch/*.json
site/dispatch/*.md
site/snapshots/*.md
site/topics/*.md
```

Relay runs `safeyolo dispatch generate` and `safeyolo dispatch check-site`, opens one PR,
and sends the existing fixed `dispatch-publication` operator request with only
`publish`, `revise`, and `defer`. `publish` authorizes the reviewed PR to
merge; it does not give publication credentials to Forge or Lens. `revise`
returns the candidate to Relay, and `defer` leaves it parked without holding
delivery work.

The CODEOWNERS entry for `site/` identifies the repository operator. The
operator should configure the master ruleset to require that code-owner review
and the `Dispatch publication` check for `dispatch/*` PRs. The check verifies
the strict source schema and generated bytes, front matter and canonical
paths, duplicate periods or snapshots, obvious credentials and private coord
material, links, the publication path allowlist, and a complete Jekyll build.
It deliberately does not score or edit prose.

After the approved PR merges, the `Pages` workflow repeats validation, builds
the lightweight Jekyll site, uploads one Pages artifact, and deploys through
the `github-pages` environment. The workflow has only read, Pages-write, and
OIDC permissions. It is serialized, visible in Actions, and can be retried
with `workflow_dispatch`. Configure GitHub Pages to use GitHub Actions and set
the custom-domain DNS for the repository-owned `site/CNAME` value,
`safeyolo.com`; DNS and repository environment protection remain operator
settings.

## Deliberate graduation to automatic publication

There is one explicit switch, not a second publication protocol. After the
operator has inspected roughly 5–10 real Dispatches and deliberately grants a
Relay-only, site-scoped repository path, change the host invocation to:

```sh
safeyolo --root "$HOME/.safeyolo-native" coord dispatch-trigger backlog \
  --date 2026-09-15 \
  --weekly-on monday \
  --publication-mode automatic
```

That operator-authored task selects the future flow:

```text
Relay generates -> CI -> Pages
```

The same final manifest, generator, site allowlist, validation, build, and
Pages workflow remain in force; only the publication PR and operator decision
are omitted. The flag does not mint credentials or widen a grant. If the
operator has not separately provisioned Relay's narrow repository authority,
the publication attempt fails safely. Reverting the scheduler invocation to
`manual` restores the initial flow for future dates, and Relay may still use the
manual path for an exceptional publication. Existing dates retain their original
room and schedule settings.
