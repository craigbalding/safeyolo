# Schedule independent hardware blackbox runs

Run Linux Kernel-based Virtual Machine (KVM) tests on devstack through Rundeck,
and physical Apple Silicon Virtualization.framework (VZ) tests on Bristol.
Each schedule selects and records its own full source commit and publishes
sanitized results to [issue #889](https://github.com/craigbalding/safeyolo/issues/889).
Use the [configuration and cron reference](INPUTS.md#host-configuration) for the
required values, their sources and the two cron recipes.

## Set up the two schedules

Craig installs each entry in the account below. The VZ cron account controls
the run; candidate execution uses Bristol's confined `sy-agent` account.

| Host | Cron account | Configuration file | Daily start |
|---|---|---|---|
| devstack | `rundeck` | `/etc/safeyolo-hardware/kvm.env` | 03:17, host local time |
| Bristol | Existing trusted operator account; record its actual name | `/etc/safeyolo-hardware/vz.env` | 03:43, host local time |

1. Install an independently reviewed, pinned script checkout at
   `/usr/local/lib/safeyolo-hardware` on each host. Protect the checkout,
   configuration and control/publication credentials from candidate writes.
   Record its full Git commit separately from the selected test commit.
2. Create the protected shell configuration files from the
   [KVM values](INPUTS.md#devstack-kvm-configuration) and
   [VZ values](INPUTS.md#bristol-vz-configuration). Obtain the Rundeck service
   URL/principal and harness from the devstack operator. Obtain the local
   `sy-agent` Secure Shell (SSH) binding, offline runtime, public certificate
   authority (CA) bundle and persistent lock from the Bristol operator. Configure the trusted accounts' GitHub
   principal for source lookup and #889 comments; keep it outside `sy-agent`.
3. Before enabling KVM, deploy the independently reviewed
   [harness helper correction](INPUTS.md#devstack-kvm-configuration).
   Before enabling VZ, supply [verified Tart inputs](INPUTS.md#prepare-selected-tart-inputs)
   for each selected full commit. Bristol uses those prepared files without
   compiling or downloading packages. Future default-branch inputs still need
   preparation; these scripts do not provide an automatic Tart feed.
4. Follow [the cron recipes](INPUTS.md#install-the-two-cron-entries) to configure
   the installed tools' PATH, private log directories, real `MAILTO` recipient
   and working `/usr/bin/mail` transport in both trusted accounts. Verify each
   host's current timezone before using its local-time schedule.
5. On each host, as its cron account, add that host's entry and read it back:

   ```sh
   crontab -e
   crontab -l
   ```

The readback must contain that host's wrapper, `overnight` argument, start time,
recipient and nonzero-exit mail command. Readback confirms installation;
actual publication and email delivery still need observation.

## Run once and find the result

With the same setup, replace `FULL_SHA` with the explicitly authorized
40-character lowercase hexadecimal commit. For VZ, its matching Tart inputs
must already be present. These commands allocate owned test resources and
publish sanitized attempt results to #889. Run from any directory in the
matching host account.

On devstack as `rundeck`:

```sh
/usr/local/lib/safeyolo-hardware/tests/blackbox/hardware/run-kvm.sh on-demand FULL_SHA
```

On Bristol as its trusted operator account:

```sh
/usr/local/lib/safeyolo-hardware/tests/blackbox/hardware/run-vz.sh on-demand FULL_SHA
```

Each command prints `Attempt: ATTEMPT_DIRECTORY`. In that private directory,
`attempt.json` records the selected commit and the GitHub index URL at
`publication.index.url`. Open that URL for the sanitized report links.
A completed successful attempt has exit 0, complete lane execution and
publication verified by readback. Missing or partial reports, unknown cleanup
and publication failure leave the attempt failed or incomplete. Raw logs stay
private. If observation is lost, use the existing
[retained-attempt recovery](INPUTS.md#inspect-or-recover-a-retained-attempt).

The two lanes run independently. Before release, both complete lanes must pass
at the exact release commit. Actual credentials, mail recipient/transport,
Bristol cron-account binding, deployed helper and future Tart inputs still need
operator provisioning and verification. The six #889 criteria remain open.
Merging the pull request remains held; see [execution and acceptance limits](INPUTS.md#execution-and-acceptance-limits).
