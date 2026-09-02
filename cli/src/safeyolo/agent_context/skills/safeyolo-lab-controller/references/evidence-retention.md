# Evidence retention

Use this reference before starting continuous logging, collecting transcripts,
copying databases, or packaging a lab.

## Start early

Create a dedicated mode-0700 evidence root before the first mutation. Keep
evidence files mode 0600 unless the operator requests otherwise. Capture:

- initial and final UTC timestamps;
- pane registry and tmux scrollback;
- commands, stdout/stderr, completion markers, and exit codes;
- tool/harness transcripts and continuation identifiers;
- process snapshots without argv or environment values that may contain
  prompts or credentials;
- product versions, configuration, health, audit, and event logs;
- domain state such as room messages, sequences, cursors, or task results;
- exact fault and recovery commands;
- local source/configuration diffs;
- a file inventory and integrity hashes.

Use `../scripts/lab-snapshot.sh EVIDENCE_ROOT` for timestamped system/tmux
snapshots. Use `../scripts/capture-evidence.sh` for selected pane scrollback and
text files. Retain the capture manifest: it maps each generated artifact to its
source path or requested pane and records whether the credential redactor ran.

## Credentials

Never copy or capture credential values, even when the laptop or evidence
directory is otherwise trusted. It is acceptable to retain:

- path and filename;
- existence;
- owner and mode;
- authentication provider and subscription/account type;
- CLI-reported logged-in state;
- absence of API-key environment variables.

Exclude authentication JSON, agent/admin tokens, HMAC secrets, NATS
credentials, private keys, private CA material, proxy environment files, and
shell output from interactive login.

The capture helper refuses common credential filenames and applies a narrow
value redactor. That is defense in depth, not permission to capture an auth
pane or credential file intentionally.

### If credential material reaches the UI or evidence

1. Stop `pipe-pane`, transcript capture, or packaging for the affected pane or
   file. Do not reproduce the value while diagnosing the incident.
2. Mark the affected pane, scrollback interval, and artifact paths as
   contaminated using metadata only. Exclude them from subsequent capture.
3. If teardown authority covers it, remove only the explicitly identified
   contaminated evidence and clear affected tmux/shell history. Otherwise stop
   and ask the operator before destructive cleanup.
4. Record where the material appeared and which surfaces could retain it, but
   never copy the value into the incident note.
5. Let the operator decide whether the exposure requires credential rotation.
   Redaction after capture does not make intentional secret collection safe.

## Raw stores

Before copying a database or binary service store, inspect its schema and
storage contract without reading credential values.

- If it can contain authorization headers, cookies, or raw request/response
  bodies, export only the metadata needed for the experiment.
- Use an online database backup, service-native snapshot, or stable API export
  rather than copying an actively mutating database/WAL pair.
- For a live message store, prefer a canonical room/history export. If raw
  storage is needed, make it quiescent or use the service's snapshot facility.
- Do not archive an entire agent home merely to retain a few transcripts.
  Select experiment-specific sessions and explicitly exclude inherited or
  unrelated history.

## Tmux history and continuous logging

Tmux scrollback is volatile and bounded. Increase a window/session history
limit only when authorized and record the previous value if it will be
restored. Continuous `pipe-pane` logging captures everything displayed, so do
not use it on panes that may show credentials or login/device codes.

Capture pane scrollback before closing panes. Preserve socket/server, pane ID,
role, and title-at-capture metadata so a transcript remains attributable after
teardown.

## Package and verify

Keep the evidence directory inspectable and optionally create a compressed
archive. Generate SHA-256 hashes after all content is final. Test archive
listing or extraction without overwriting the source evidence.

The final handoff should state:

- evidence path and archive path;
- checksum;
- included primary sources;
- excluded credential-bearing or unrelated material;
- any redaction performed;
- whether services or panes remain alive;
- any snapshot consistency limitation.
