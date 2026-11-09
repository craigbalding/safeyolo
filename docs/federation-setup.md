# Connect instances and delegate support

Connect two existing SafeYolo instances, grant inspection of one target, and
verify that access. Use the operator accounts on the hosts that own those
instances. Each instance must already be initialized with its agents configured.
You need each owner's command-line interface (CLI) and, for different hosts,
an existing authenticated administrative channel for the file transfers below.

Replace `OWNER_ROOT` with the destination instance's directory and `SOURCE_ROOT`
with the support agent's instance directory. Multiple roots on one host are
separate instances. In the examples, `support` is your configured source agent,
`worker` is your destination target, and `primary` is the source's new route name.
Replace those names with your selections. The source support agent needs a
current run for verification.

## Set up and verify one support path

### Connect the owner and source

For different hosts, first run this on the source host. The new file contains
public instance and agent identities, with no credentials:

```sh
safeyolo --root SOURCE_ROOT configure identity source-identity.json
```

Transfer that file to the destination operator through your authenticated
administrative channel. For two accessible roots on the same host, skip the
export and select the source root directly in the next step.

On the destination owner, open connection setup:

```sh
safeyolo --root OWNER_ROOT configure connection
```

Select `broker`, then the source root or received identity file. Check both
durable identities and owning roots. Let the CLI guide the protection choice:
use `tailscale` with an existing displayed Tailscale address, `loopback` for a
source on this same host, or `tls` with generated dedicated material or your
organization's certificate, key and certificate authority (CA) files already
on this owner. Tailscale uses the resolved stable node identity and existing
tailnet policy. Loopback
requires a literal loopback address. Neither asks for certificates.

For Transport Layer Security (TLS), select the listen address and certificate
names. Generated material asks for CA and leaf lifetimes. The broker checks
certificate validity, names, key matching and separation from the interception CA.
Broker and CA private keys stay on this owner.

Review the listener, directional trust and restart effects, then save. Saving
does not activate the listener. Setup prints the completed steps and a private
handoff directory. That directory contains the scoped peer credential, public
CA when needed, and the exact source and destination identities. Keep the whole
directory private. Transfer it to the source through your authenticated
administrative channel. Do not transfer broker or CA private keys.

On the destination, return to `configure connection` and select `activate`.
Confirm the client port and distinct loopback monitor port. Activation stops
and starts this owner's proxy and Coord broker. Existing guests remain, but
requests and feeds can be interrupted. Activation grants no support authority
or reverse route.

On the source host, import the received private handoff:

```sh
safeyolo --root SOURCE_ROOT configure connection
```

Select `import`, the handoff directory and the route name `primary`. Review the
destination and before/after trust. Import refuses a handoff addressed to a
different source instance. The route applies to the next request.

### Grant inspection of the target

On the destination owner, create the named support grant `incident`:

```sh
safeyolo --root OWNER_ROOT configure support incident
```

Select the same source root or public identity file, its `support` agent, and
the local `worker` target. Names are display handles; authority binds durable
identities. For this first inspection, leave guest administration, guest log
paths, lifecycle actions, notices and factory directions unselected. Inspection
is included. You can [add those powers later](#add-support-powers-and-notices).

Choose `standing` for authority until change or revocation, or a duration such
as `8h` or an explicit future expiry. Routine authorized operations need no
further prompt. Review the before/after identities, inspection authority and
lifetime before applying. The CLI carries the complete proposal and
acknowledgment internally. A stale preview must be refreshed and reviewed
again. If a reply is lost, inspect the saved grant on its owner before another
change; the command does not retry the write automatically.

### Verify from the source

If the source support agent is stopped, start it on the source host first.
This starts its configured sandbox and coding harness:

```sh
safeyolo --root SOURCE_ROOT agent start support
```

With that agent in its current run, execute this on the source host. The
command uses that agent's authenticated listener and the owner's current grant.
It performs an inspection and records its receipt. It
runs no guest command or lifecycle action:

```sh
safeyolo --root SOURCE_ROOT support verify incident worker --agent support --home primary
```

A successful result includes these representative fields; identities and the
original operation ID differ for your instances:

```text
Authorized inspection verified: true
Model health: unverified
...
Original operation ID: inspect-...
Completion verified: true
```

Keep the original operation ID for recovery. The full result separates saved
configuration, endpoint protection, broker authentication, owning-instance Core
request/reply, notifications, applicable authority and target sandbox, control
and harness state. An authorized inspection verifies this read path. It does
not prove model progress. Observation sources show age and unavailable reasons;
old evidence or an empty page is not a current health guarantee.
A notification stream can be absent before the first notification creates it;
verification reports notification availability separately.

If verification fails, follow its named next action. On the source, use
`configure connection` → `verify` for `primary` to check the route and owner.
On the destination, use `support grants` to check `incident` and its durable
target bindings. Check the selected source agent's current run if its listener
is unavailable. If an inspection ID was printed before a lost reply, read
`support result OPERATION_ID --agent support --home primary` on this source;
use [the owner's receipt recovery](#verify-change-and-revoke) if the route or
authority is unavailable. Preserve the original ID instead of repeating the
operation. For support within one instance, omit `--home`.

## Supervise saved instances in Command Centre

Use the installed macOS Command Centre on the operator's Mac. Each selected
owner needs its running Admin API (application programming interface) and live
events enabled. For another host,
retain its existing authenticated administrative channel and explicit Admin
sharing or SSH forwards. Adding a profile does not publish a listener or grant
reverse access. These Admin connections are separate from the broker route
configured above.

For each owner below, replace `INSTANCE_ROOT` with that instance's root.
If live events are disabled, edit this owner's `config.toml` on its host.
In its `[command_centre]` table, set `enabled = true` and select an unused
`events_port`. Each root on the same host needs a distinct event port.
Then run `safeyolo --root INSTANCE_ROOT stop` and
`safeyolo --root INSTANCE_ROOT start` with that owner's root to apply the change.
This interrupts requests and feeds; existing guests remain. Export below
refuses disabled live events and identifies the selected owner to correct.

On each owning host, replace `operator-connection.json` with a new private
destination file. This export
contains the full operator Admin credential for that owner. Keep the file
private and transfer it only through your authenticated administrative channel:

```sh
safeyolo --root INSTANCE_ROOT configure command-centre operator-connection.json
```

The command authenticates the running owner and displays its durable identity,
root and Admin/events endpoints without printing the credential. It refuses a
running owner that differs from the selected root and does not overwrite an
existing file. Configured Tailnet sharing exports its published endpoints.
Local sharing exports loopback endpoints for use on this same Mac. Export
changes no listener or authority. Omit the file argument to display connection
details without exporting a credential.

In **Connection Settings**, select **Import Connection File…**, review the
owner, root, endpoints and transport, then **Connect**. Import fills the form
without connecting. Connection checks the imported durable identity. Keychain
stores credentials separately from profile metadata. Repeat for each instance.
Several roots on the same Mac use separate loopback ports and identities.
Manual URL/credential entry and existing SSH tunnels remain available. A
loopback file does not establish a remote forwarding route.

Each instance has its own menu. **Support, Notices and Receipts…** shows that
owner's pending human signals, support activity, grants, observation sources and
delivery diagnostics. Reads show their time. Failed reads retain old evidence
with a warning. Select an original receipt to compare its initiating identity,
target/run and grant at admission with current target and authority evidence.
**Read Original Receipt and Current State** submits no support effect.
**Read Guest Output** explicitly reads private, untrusted results.

The view uses the existing event stream and coalesces bursts into owner reads
while open. Reconnect refreshes current evidence; it does not replay missing
history or prove model health. If evidence is unavailable, inspect that named
owner's source and local diagnostics. The CLI recovery below remains available.
Removing a saved profile disconnects this viewer; it does not revoke authority.

## Verify, change and revoke

Return to the same named configuration command on the destination to edit
`incident`. Before adding powers, read [their effects](#add-support-powers-and-notices).
Revoke the selected grant on its owner with:

```sh
safeyolo --root OWNER_ROOT configure revoke-support incident
```

Review the exact current authority and remaining paths before confirming.
Narrowing, expiry and revocation stop newly unauthorized operations and later
result reads. Admitted work can finish; previous disclosure cannot be recalled.
Independent grants and operator permissions can remain. The existing authority
report shows coverage, reviewer control, supporting paths and unknown frontier;
partial evidence cannot establish independence.

On the destination owner, these reads remain available through operator Admin
access after support revocation. Replace `OPERATION_ID` with the original ID
from verification or the receipt list:

```sh
safeyolo --root OWNER_ROOT support receipts
safeyolo --root OWNER_ROOT support receipt OPERATION_ID
safeyolo --root OWNER_ROOT support recover OPERATION_ID
```

The list excludes guest output. `recover` reads the original receipt, then
separately observes the current durable target and current grant. It never
submits the operation again. An interrupted operation can remain
`outcome_unknown` with completion unverified. Current state cannot attribute an
uncertain earlier effect. A recreated same-name target is reported as an identity
change. If an ID has several initiators, select `--initiator` with the qualified
principal in the list. Add `--output` only when you need private, untrusted guest
results. Source-side `support result` rechecks current authority and may be
refused after narrowing or revocation.

The existing `inspect` session also offers `verify`, `notices`, `receipts`,
`receipt` and `recover`. Select the source support agent for `verify` and
`notices`, with the home route for a remote owner. Select the destination target
for its `receipts` list. Original owner and target identities stay visible.
See [support operations and receipts](peer-support.md) for exact interfaces.

## Add support powers and notices

This is optional after inspection works. On the destination, run
`configure support incident` again. Guest administration permits arbitrary
guest commands and guest sudo, reaching target data, writable mounts,
credentials, services and existing delegations. It can indirectly control
other agents or approval decisions. Exact guest log paths can follow guest
links to other target-accessible data. Select administration, log paths,
individual lifecycle actions and notices separately.

The notice menu explains each kind. `needs_operator` requires a room selection;
it discloses target-authored signal text, references and retained revisions,
without granting room history or resolving the signal. On the source, read one
retained notice page through the same support identity with:

```sh
safeyolo --root SOURCE_ROOT support notices --agent support --home primary
```

Use the printed scanned cursor with `--since` for another page. This cursor is
separate from coding-harness cursors. Unavailable feeds fail explicitly;
unresolved notices retain their unavailable reason and next action. Recovery
notices do not establish model progress. See [event meanings](operational-events.md).

Optional factory directions bind the current approved snapshot and its
operator-input recipient. Choose direction types explicitly. Setup asks before
adding that recipient as an inspection target. A changed snapshot requires new
selection and preview. This authority grants neither approval decisions nor
policy administration. See [factory directions](factories.md#delegate-direction-to-an-operator-agent).
Additional owner routes can contribute to the existing composition report;
unknown coverage remains explicit. Removing a home route, revoking peer trust,
rotating its credential and revoking a grant have different effects. Use the
[federation reference](coord-reference.md#collaborate-through-a-home-safeyolo)
for those controls and structured interfaces.

## Configure approval reviewers separately

Approval delegation is optional and separate from support. On the owner of the
pending approvals, open the named delegation:

```sh
safeyolo --root OWNER_ROOT configure approvals builds
```

Select reviewers' durable agents and instance, local beneficiaries and explicit
network, service or gateway scopes. Each eligible reviewer can decide alone.
`credential` selects a pending
beneficiary request by number and carries its observed fingerprints internally.
`request` selects the exact pending scope and its prepared bindings, including
contract values, desktop run/route or room audience/rights. The request stays
pending. Existing scopes can be retained when editing.

Delegation expiry bounds deciding authority. Issued-permission lifetime starts
at each decision and can use the current worker run. Pending requests retain
their own expiry. Existing permission-specific limits, self-benefit checks and
stale-state refusals remain. Use `approvals delegations` to list saved authority
and `configure revoke-approvals builds` to revoke it on this owner. See the
[approval reference](delegated-approvals.md) for scope envelopes and limits.

## Return after interruption or certificate changes

Setup changes the owner and source in separate steps. After interruption,
inspect the printed completed step on the named owner. Rerunning broker setup
reuses the saved peer credential unless you select rotation. Generated TLS
files remain at their printed owner path; select `import` to reuse material
created before an interrupted apply. Grants and routes remain in their
existing authoritative stores.

On the owner, use `configure connection` → `broker` → `renew` for leaf renewal
under the existing CA, or `import` for organizational renewal material. Leaf
renewal retains peer credentials and grants. For CA rotation, generate or import
a different CA, review changed trust and distribute new handoffs to affected
source routes. Activate the owner and verify each intended path. If validation
refuses expired material, renew or import before activation.

Peer credential rotation advances trust generations. Grants from the previous
generation remain invalid; use the named configuration commands to review
current identities and issue authority again. Recreated same-name agents do
not receive predecessor grants. The expert [support](peer-support.md),
[approval](delegated-approvals.md) and [federation](coord-reference.md) references
retain file interfaces, error semantics and authority limits.
