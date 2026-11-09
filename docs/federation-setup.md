# Connect instances and delegate support

Use this guide on the operator hosts that own the selected SafeYolo instances.
Initialize each instance and configure its agents first. You need access to each
owner's CLI. For different hosts, use an existing authenticated administrative
channel to transfer the explicitly selected handoffs. SafeYolo does not discover
or administer arbitrary remote hosts.

The commands below use the selected instance root. Replace `OWNER_ROOT` with
the destination instance directory, and `SOURCE_ROOT` with the support agent's
instance directory. Multiple roots on one host are separate instances. The
guides display their durable identities and canonical root paths before changes.

## Connect the source to the owner

For a source on another host, first export its public identity on that host:

```sh
safeyolo --root SOURCE_ROOT configure identity source-identity.json
```

Transfer this file to the owner's operator account through your authenticated
administrative channel. The file contains public instance and agent identities,
not credentials. If both roots are accessible on the same host, select the source
root directly instead.

On the destination owner, start connection setup:

```sh
safeyolo --root OWNER_ROOT configure connection
```

Select `broker`, then the source root or received identity file. Check the source
and destination identities and owning roots. Select one protection mode:

| Mode | Required selection |
|---|---|
| `tls` | A listen address, certificate names, and generated dedicated broker material or existing organizational certificate/key/CA files. |
| `tailscale` | Select one of this host's displayed Tailscale addresses. Setup resolves its stable node identity. No certificate questions appear. Existing tailnet policy still applies. |
| `loopback` | A literal loopback address. The source must be on the same host. No certificate questions appear. |

TLS material stays separate from the interception certificate authority (CA).
Generation asks for the CA and leaf lifetimes. Import selects files already on
the broker's owning host. The broker and CA private keys stay on that host.
The existing broker checks validate protection, certificate validity, names,
key matching and separation from the interception key before application.

Review the concrete listener, directional trust and restart effects. Saving
does not activate the new listener. Setup reports the completed owner steps and
creates a private handoff directory with a scoped peer credential, public CA
when applicable, and the exact source and destination identities. Keep the whole
directory private. Transfer it through the selected authenticated administrative
channel; do not transfer broker or CA private keys.

On this owner, return to `configure connection` and select `activate`. Confirm
the client and distinct loopback monitor ports. Activation stops and starts this
owner's proxy and Coord broker. Existing guests remain, but requests and feeds
can be interrupted. No reverse route or support authority is granted.

On the source host, run:

```sh
safeyolo --root SOURCE_ROOT configure connection
```

Select `import`, the received private handoff directory and a home route name.
Review the before/after destination and trust. Import refuses a handoff addressed
to a different source instance. The route applies to the next request.

Verification shows configuration, endpoint protection, broker authentication,
owning-instance request/reply, notification availability and operation authority
separately. A missing stream can mean no notification has created it yet.
Unavailable or unchecked evidence does not mean a healthy empty result.
Neither broker authentication nor a saved route proves support access or model
progress. Return to `configure connection` → `verify` for the owner or a named
source route.

## Select support, notices and factory directions

On the destination owner, create the named grant `incident`:

```sh
safeyolo --root OWNER_ROOT configure support incident
```

Select the support agent's instance root or authenticated identity file, its
agent, and the local targets. Names are display handles; grants bind durable
identities. Select guest administration, exact guest logs, individual lifecycle
actions and operational notices separately. Inspection is always included.
Guest administration reaches target data, writable mounts, credentials,
services and existing delegations. It can give indirect control over other
agents or approval decisions. Selected guest log paths can follow guest links
to other target-accessible data.

The notice menu explains each kind. If you select `needs_operator`, also select
the rooms whose target-authored signal summaries, references and retained
revisions may be disclosed. This does not grant room history.

For each approved factory, select only the direction types you want to delegate.
Setup resolves its current approved snapshot and operator-input recipient.
If that recipient is not already a target, setup asks whether to include its
exact identity. Factory direction grants neither approval decisions nor policy
administration. A changed snapshot needs a new explicit selection and preview.

Choose `standing`, a duration such as `8h`, or an explicit future timestamp.
Standing authority lasts until changed or revoked. Temporary authority ends at
its selected expiry. Routine authorized operations require no further prompt.

The preview shows before/after identities, powers, notices, lifetime and factory
binding. Optionally select additional configured owner routes for the existing
authority-composition report. Its coverage, reviewer control, supporting paths
and unknown frontier matter: partial evidence cannot establish independence.
The command carries the complete backend proposal and acknowledgment internally.
If application refuses a stale preview, inspect the refreshed state and decide
again. A lost transport response does not trigger a write retry.

## Configure approval reviewers separately

On the owner of the pending approvals, run:

```sh
safeyolo --root OWNER_ROOT configure approvals builds
```

Select the reviewers' instance and durable agents, then local beneficiaries.
Each eligible reviewer can decide alone. Select explicit network, service or
gateway scopes. Select `credential` to choose a pending beneficiary request by
number; its observed fingerprints are carried internally. Select `request` for
an exact pending scope, including contract values, desktop run and route, or
room audience and rights. This prepares deciding authority and leaves the
request pending. Existing scopes can be retained when editing. The expert
interfaces also support broader envelopes. The preview retains complete
prepared bindings.

Delegation expiry limits deciding authority. Issued-permission lifetime starts
at each decision and can use the current worker run. Pending requests retain
their own expiry. Permission-specific finite limits remain in force. The
backend's existing self-benefit, scope and stale-state refusals still apply.

## Verify, change and revoke

List saved authority on its owner:

```sh
safeyolo --root OWNER_ROOT support grants
safeyolo --root OWNER_ROOT approvals delegations
```

An active grant is configured authority, not proof that a model is progressing.
Use the selected support agent's existing `support_grants` and inspection-only
`support_operation` tool against the addressed owner to verify authorized access.
The [support reference](peer-support.md#investigate-and-repair) describes the exact
operation interface. Do not manufacture a repair merely to test access.

Run the same named configuration command to edit. Revoke by name on the owner:

```sh
safeyolo --root OWNER_ROOT configure revoke-support incident
safeyolo --root OWNER_ROOT configure revoke-approvals builds
```

Review the exact current authority and remaining paths before confirming.
Narrowing, expiry and revocation stop newly unauthorized operations and later
result reads. Admitted work can finish; previous disclosure cannot be recalled.
Independent grants and operator permissions can remain.

Removing a source home route, revoking destination peer trust, rotating its
credential and revoking a grant have different effects. The
[federation reference](coord-reference.md#collaborate-through-a-home-safeyolo)
retains those explicit controls and structured output.

## Return after interruption or certificate changes

Connection setup is a sequence of owner and source changes, not an atomic
cross-host transaction. Inspect the reported completed step on the named owner.
Rerunning broker setup reuses the saved peer credential unless you explicitly
select rotation. Generated TLS files remain at the printed owner path; select
`import` to reuse material created before an interrupted apply. Saved grants
and source routes remain in their existing authoritative stores.

Return to the owner's `broker` action to select `renew` under its existing CA,
or `import` organizational renewal material. Leaf renewal retains peer
credentials and grants. Generate or import a different CA for CA rotation;
review the changed trust and distribute new handoffs to affected source routes.
Activate the owner and verify each intended path. Certificate expiry is shown
when reviewing TLS material. If validation refuses expired material, select
renewal or import before activation.

Explicit peer credential rotation advances trust generations. Existing support
and approval grants from the previous generation stay invalid; use their named
configuration commands to review current identities and issue authority again.
No recreated same-name agent silently receives its predecessor's grant.

The [support](peer-support.md), [approval](delegated-approvals.md) and
[factory](factories.md#delegate-direction-to-an-operator-agent) references retain the explicit
file interfaces, error semantics and authority limits. Guided configuration is
the first delivery slice of [#1465](https://github.com/craigbalding/safeyolo/issues/1465).
Installed verification/recovery, human operation receipts and ongoing supervision
across at least three saved Command Centre instances remain separate acceptance
work in that issue. These CLI results do not establish those later outcomes.
