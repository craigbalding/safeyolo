# Schedule guest shell work

Use `crontab` for recurring work and `at` for one-off work. The standard Debian
guest starts both daemons after per-run clock, environment and credential setup.
Jobs run as `agent` inside its sandbox, with its filesystem access, proxy policy
and Agent API identity. The coding harness does not have to stay active.
No manual package installation or daemon start is needed for cron or at.

Run the guest examples as `agent` in a running standard guest. Custom images
that omit the Debian scheduling integration remain usable; their scheduler
log reports that scheduling is unsupported.

## Environment, time and state

The standard guest uses UTC. Check `date '+%F %T %Z'` before setting a schedule.
`at` interprets times in the submitting process's timezone. These examples use
UTC explicitly.

Put `/usr/local/bin/safeyolo-job COMMAND [ARG...]` in scheduled entries.
The wrapper discards at's saved environment, reads the current
`/etc/environment`, and starts the command in `/workspace`. HOME is
`/home/agent`. PATH includes persistent mise shims and system command
directories. Proxy and CA settings come from the current per-run environment.
Set extra task variables inside your job script. Use absolute script and log
paths. Submit at jobs from `/home/agent`: at tries to enter its saved working
directory before the wrapper runs. At also saves the submission umask.

Read `/app/agent_token` inside the executing job. Do not export or copy tokens
into an entry, submission command or script. Do not print tokens or use shell
tracing in a script that reads them. Cron logs job command lines.

Jobs cannot run while the sandbox is stopped or the host is asleep. Cron does
not replay a backlog of all runs missed during shutdown. While cron runs,
Debian treats clock jumps under three hours specially for fixed-time jobs:
forward jumps can run skipped jobs soon afterward; backward jumps avoid
running those jobs twice. Wildcard schedules follow the new time. Larger
jumps use the corrected time immediately. Overdue at jobs normally run when
atd next processes its queue; backward correction can delay them. See
[Debian cron](https://manpages.debian.org/trixie/cron/cron.8.en.html) and
[Debian at](https://manpages.debian.org/trixie/at/at.1.en.html).
Check actual missed/repeated runs after clock correction or sleep/resume.
There is no exactly-once delivery guarantee.

Crontabs and at jobs use native files under `/var/spool/cron`. On Linux,
the host binds that directory from `agents/<name>/overlay/var/spool/cron`.
The bind retains the queues across normal stop/start. Each agent has its own
spool. The VZ guest keeps its spool in the per-agent disk overlay.
Ephemeral rootfs mode uses a fresh spool and discards it on stop. On Linux,
memory mode does not expose or change a saved default-mode queue. Selecting
default mode again exposes that saved queue. Resetting or removing an agent's
rootfs overlay also removes its saved jobs. Scripts and logs in `/home/agent`
persist independently until that home is removed. Deleting a script does not
cancel its queued entries.

Linux's `runsc --overlay2=root:dir=...` alone does not preserve rootfs files
after stop. It uses a temporary file-backed tmpfs. Scheduler persistence needs
the spool bind described above. Other rootfs files still disappear on stop
unless they are in a persistent mount.
Cron starts `@reboot` entries on a new sandbox boot.

Reusable captures precede scheduler startup. An arbitrary used-snapshot
rollback can replay, lose or interrupt work when memory, disk and mounted
files represent different times. A VM rollback cannot undo an external
effect. A restored queue does not prove delivery.

## Recurring Coord message

The operator must create `scheduled-work` and grant this agent send permission
there. Use a disposable room for a trial. Do not test a timer on pending
Factory work. The shipped example needs curl and the Agent API, with no
model, MCP adapter or NATS credential. It reads the token for each request.

In the guest, copy the example and create its payload:

```sh
mkdir -p /home/agent/jobs
cp /safeyolo/skills/safeyolo/scripts/scheduled-coord.sh /home/agent/jobs/post-coord.sh
cat > /home/agent/jobs/coord-message.json <<'JSON'
{"body":"Scheduled guest check completed.","declared_content_type":"text/plain","notify":"none"}
JSON
```

Use `crontab -e` to add the following lines to your existing crontab.
The job runs every five minutes. Mail is disabled; output and errors go to
the named log. `notify=none` retains the message without attention. Edit the
JSON deliberately when your workflow needs named recipients.

```cron
MAILTO=""
*/5 * * * * /usr/local/bin/safeyolo-job /bin/sh /home/agent/jobs/post-coord.sh >>/home/agent/jobs/coord.log 2>&1
```

Read `coord.log` and the room's canonical message. Verify `sender_kind=agent`
and `sender_agent_name`. A queued entry or HTTP request does not prove
publication. An unavailable endpoint or permission refusal fails and records
its error in the job log. Inspect history before repeating an uncertain send.

Use `crontab -l` to list entries and `crontab -e` to change them. `crontab -r`
removes the whole crontab; use it only when you intend to remove every entry.
The base provides BusyBox vi for editing. Set `VISUAL` or `EDITOR` to use a
different installed guest editor.

## One-off work, cancellation and overlap

In the guest, create an owned script and submit it from the persistent home:

```sh
mkdir -p /home/agent/jobs
cat > /home/agent/jobs/once.sh <<'SH'
#!/bin/sh
set -eu
date -u '+one-off job: %FT%TZ'
SH
cd /home/agent
printf '%s\n' '/usr/local/bin/safeyolo-job /bin/sh /home/agent/jobs/once.sh >>/home/agent/jobs/once.log 2>&1' | TZ=UTC at -M now + 5 minutes
atq
```

Submission prints a job number and time. To cancel a pending job, replace
`JOB_NUMBER` with that number, then run `atrm JOB_NUMBER` and `atq`.
Cancellation does not undo an action or stop work that already started.
`-M` disables at mail; inspect `once.log` for the actual result.

If a recurring command must not overlap, use a lock file:

```cron
*/5 * * * * /usr/bin/flock -n /home/agent/jobs/check.lock /usr/local/bin/safeyolo-job /bin/sh /home/agent/jobs/post-coord.sh >>/home/agent/jobs/coord.log 2>&1
```

An occupied lock skips that attempt. This recipe adds no retries.

## Literal input to one tmux pane

Use Coord for normal coordination when available. Queued keystrokes do not
prove that a harness accepted or acted on the text.

Run this example inside the guest on a server owned by `agent`. Tmux is an
optional guest package. If `command -v tmux` finds no command, install it with
`sudo -n apt-get update` and `sudo -n apt-get install -y tmux`.
Create this disposable server and pane, then copy the example:

```sh
mkdir -p /home/agent/.local/state/tmux /home/agent/jobs
tmux -S /home/agent/.local/state/tmux/scheduled.sock new-session -d -s scheduled -n input 'cat'
cp /safeyolo/skills/safeyolo/scripts/scheduled-tmux.sh /home/agent/jobs/tmux-input.sh
cd /home/agent
printf '%s\n' '/usr/local/bin/safeyolo-job /bin/sh /home/agent/jobs/tmux-input.sh >>/home/agent/jobs/tmux.log 2>&1' | TZ=UTC at -M now + 1 minute
```

For an existing pane, first edit the copied script's static socket, target
and expected name. The script checks the resolved session, window and pane.
It sends `Please inspect $HOME; [literal text].` to `scheduled:input.0` on the
selected socket. A missing target/server fails and records a diagnostic in
`tmux.log`. It does not fall back to the active pane. Inspect the pane:

```sh
tmux -S /home/agent/.local/state/tmux/scheduled.sock capture-pane -p -t '=scheduled:=input.0'
```

The example does not press Enter. If the intended target needs submission,
add `tmux -S "$socket" send-keys -t "$target" Enter` after the literal send in
your copy. To remove the disposable example server, run
`tmux -S /home/agent/.local/state/tmux/scheduled.sock kill-server`.

## Diagnostics and rollout

In the guest, inspect the scheduler log, processes and native job lists:

```sh
tail -n 50 /var/log/safeyolo-scheduling.log
ps -C cron,atd -o pid,user,args
crontab -l
atq
```

The log records startup, daemon exits and cron runtime errors. Use explicit
job-output redirections as shown above; no mail server is installed. A closed
per-run gate records that scheduling did not start. Inspect the boot log and
restart the sandbox after correcting a daemon/startup failure. A failed daemon
does not establish delivery. Base package maintenance entries are disabled in
the system crontab; their scripts remain available for guest administration.

Existing installations need updated host per-run scripts and a rebuilt
standard guest containing cron/at and the scheduling integration. Follow the
[guest upgrade procedure](https://github.com/craigbalding/safeyolo/blob/master/docs/guest-oci.md#upgrade-or-roll-back-the-installed-default-guest),
then stop/start affected agents. Regenerate reusable captures from those
matching inputs: an old capture contains its old startup script. A host-only
update cannot install missing rootfs packages. Custom images that omit this
integration do not acquire a scheduler automatically.
Linux also needs the host update that binds the native spool. An older host
can start the daemons but lose both queues on stop. The update cannot recover
queues already lost by an earlier stop. Before upgrading a running older
guest, save `crontab -l` and inspect `atq`; recreate needed entries after the
update. Do not copy at job files between agents.
If an agent previously installed cron itself, inspect its `/etc/crontab` and
`/etc/cron.d` before first startup. A retained VZ disk overlay can still contain
package-maintenance entries. The upgrade preserves those existing VZ files.

For a trigger that must arrive while the target sandbox is stopped, use the
separate [trusted host recipe](https://github.com/craigbalding/safeyolo/blob/master/docs/coord-operations.md#schedule-an-operator-message).
