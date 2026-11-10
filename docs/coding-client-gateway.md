# Native coding clients through the services gateway

This opt-in integration keeps a selected provider login in the host's encrypted
credential store. The guest client sends its scoped service token. The existing
gateway replaces that token after authorization and renews the provider login
on the host. Browser and device login run on the host.

Native Codex 0.163.0 and Claude Code 2.1.306 completed real subscription
requests after host-owned renewal on Ubuntu AMD64. The recorded proof uses
SafeYolo production source `3215530dceadadd98cfe6063bf14490fd983aff7`;
[#1219](https://github.com/craigbalding/safeyolo/issues/1219) records the evidence
and source acceptance. These results cover the selected subscriptions and
client versions. This route does not substitute separately billed API access.

## Choose authentication at launch

On the operator host, use the installed SafeYolo instance and a workspace that
the selected agent may read and write. For a new agent, `agent launch` asks you
to choose client-held or host-vault authentication before any optional host
credential copying. You can select the same choice explicitly. Replace
`/path/to/workspace` with your workspace before running either example:

```sh
safeyolo agent launch /path/to/workspace --name alice --harness codex --authentication host-vault
safeyolo agent launch /path/to/workspace --name alice-claude --harness claude --authentication host-vault
```

The host guide selects a vault credential account or a file-backed host login.
For a missing host login, complete the native client's supported login on the
host, then select its file. The importer does not read a keychain. The guide
uses the existing import, inference-service authorization and client setup
operations. It configures the native client and obtains a current scoped token
at each client launch. You do not need to edit guest TOML, extract a token with
`jq`, or export a token yourself.

The guide explains host versus guest custody, the selected provider and vault
account, storage and explicit unlock, and rotating-refresh-token effects before
the relevant choice. If the guest retains authentication, choose to keep
client-held authentication or explicitly remove the displayed client inputs.
The guide does not silently copy, remove or replace retained authentication.
Unrelated settings and explicit denies remain in place. Removing a guest file
does not revoke copies the guest already read.

For an existing agent, stop the agent before changing its authentication.
Return through `safeyolo agent auth alice`, or select **h** from launch's host
controls. `agent auth alice --json` reads the current configuration, active
service binding and vault availability separately. It reports provider validity
as unknown and client use as not observed. Setup success is not a provider
request result. A normal return with `agent launch --name alice` reuses the
saved client configuration and current binding without another login import or
service grant.

## Authorize on the host

Use an existing agent, named `alice` in these examples, and the selected
instance's `safeyolo` command. Keep the provider login file outside all guest
mounts. Select a file-backed host login created by the native client's host
login flow. The importer does not read an operating-system keychain.
`/secure/codex/auth.json` and `/secure/claude/.credentials.json` below stand for
those selected files; replace each path before running its command.

Import is an explicit storage operation. It uses the selected host encrypted store.
If storage is absent, the first valid import asks you to choose local random-key
storage or passphrase protection. For a script, add `--storage local` or
`--storage passphrase`. Passphrase storage uses a hidden prompt or
`--passphrase-file FILE`; keep that host file outside guest mounts. Existing
storage keeps its type. An import with a passphrase unlocks the running proxy.
If the proxy starts later, run `credentials unlock` before service use. A proxy
restart or `credentials lock` requires another explicit unlock. See
[credential storage and unlock](credentials.md#store-a-local-credential).
Initialization and independent proxy readiness do not open or unlock the store.

An import leaves the selected file unchanged. Renewal updates the vault copy.
If another host client keeps using the original rotating refresh token, that
client may need to sign in again. Check this effect before selecting a login
that another client still uses.

For Codex:

```sh
safeyolo credentials import-client codex-account --client codex --auth-file /secure/codex/auth.json
safeyolo services authorize alice codex --capability inference --credential codex-account
```

For Claude Code:

```sh
safeyolo credentials import-client claude-account --client claude --auth-file /secure/claude/.credentials.json
safeyolo services authorize alice claude --capability inference --credential claude-account
```

Import stores the access token, refresh token and expiry. It grants no service
access. Authorization selects the agent and inference capability. Existing
[credential policy and approvals](credentials.md#authorization-binding-and-risk-approval)
still apply, including after renewal. A service grant does not override an
explicit credential deny or an approval requirement.

## Configure the guest client

The shipped setup owners preserve the selected model, unrelated settings and
explicit denies. Codex selects the SafeYolo subscription provider with
`forced_chatgpt_auth = false`, `requires_openai_auth = false`, Responses over
HTTP, and WebSockets disabled. Its scoped token is passed as
`SAFEYOLO_CODEX_GATEWAY_TOKEN`. The host supplies `ChatGPT-Account-ID` from the
selected imported login; the guest cannot replace that account selection.
Claude selects its subscription route with
`CLAUDE_CODE_OAUTH_TOKEN`. Both launchers fetch the current token through the
agent's authenticated `/gateway/services` endpoint. Tokens stay in process
memory and the launched client's environment; they are not configuration values
or displayed results. Provider credentials remain in the host vault.

For noninteractive setup, first prepare a stopped agent with its shipped host
script. In these host examples, `alice` uses Codex and `alice-claude` uses Claude.
The named vault accounts must already have been imported with the explicit
commands above:

```sh
safeyolo agent auth alice --authentication host-vault --credential codex-account --authorize --json
safeyolo agent auth alice-claude --authentication host-vault --credential claude-account --authorize --json
```

To compose an initial import in the same command, add `--auth-file HOST_FILE`
and, for a new store, `--storage local` or `--storage passphrase`. Replace
`HOST_FILE` with the selected host login file outside guest shares. Passphrase
storage accepts `--passphrase-file FILE` through the same existing import owner.
Import is storage only. Omitting `--authorize` leaves service access unchanged.
`--remove-guest-auth` explicitly removes the conflicting client inputs listed
by `agent auth --json`; omit it to retain them and refuse a conflicting change.
Host setup diagnostics go to stderr; the final structured result goes to stdout.

Explicit `credentials import-client`, `services authorize`, `credentials unlock`
and `agent create`/`configure`/`start` remain available. For direct configuration
through the installed host setup helper, replace `AGENT_HOME` with the stopped
agent's host home path and choose the client before running:

```sh
safeyolo-coord client-auth AGENT_HOME codex host-vault
safeyolo-coord client-auth AGENT_HOME claude host-vault
```

That helper configures authentication only; it imports no login and grants no
access. Use the matching installed host and Linux guest assets, then reapply the
shipped host setup. Select `client` instead of `host-vault` to return to
client-held authentication. Existing service grants are retained until you
explicitly revoke them. Returning to client-held custody does not copy a host
login into the guest.

Claude's remote managed-settings fetch uses the same authentication route.
If startup reports a failure, inspect `Managed settings (remote)` in
`claude doctor` or `/status` before changing authentication. A policy-fetch
failure alone does not establish that inference authentication failed.
For a SafeYolo refusal, inspect the request's `X-Blocked-By` header and its
approval through the host workflow below. Claude's
[server-managed settings documentation](https://code.claude.com/docs/en/server-managed-settings#platform-availability)
describes which authentication configurations fetch policy.

## Approve the first request

The first client request can stop for an existing network, credential or risky-route
approval. Service authorization does not grant those approvals. Scoped service-token
fields go through gateway validation rather than upstream credential approval.
The credential guard checks other incoming headers and the injected provider
credential before the proxy connects upstream. A credential approval can therefore
refer to a host-held provider credential even when the guest sends only a scoped token.

On the host, use `safeyolo approvals list --agent alice --json` to find the pending
request. Replace `APPROVAL_ID` below with its approval ID. Inspect the destination,
agent, credential fingerprints and offered options before approving. If the pending
request is a credential approval for a running agent, the `run` option grants the
selected fingerprints for that agent's current run. Other request kinds have their
own offered options. Use `run` only when the displayed request and lifetime match
your intent:

```sh
safeyolo approvals show APPROVAL_ID --json
safeyolo approvals approve APPROVAL_ID --option run --json
```

Expected result: the selected approval reports `approved` and `grant_active=true`.
Retry the client request. An unchanged gateway retains the scoped token. If another
approval is required, inspect that request separately. Credential approval does not
approve a risky route. Explicit denies still refuse the request. If gateway inputs
changed in the meantime, stop/relaunch the client to obtain a current scoped token,
then inspect any resulting approval.

## Return after interruption or configuration changes

Read `agent auth NAME --json` for the same selected instance and agent. The
configuration is saved in the native client settings. Authorization comes from
the running proxy's accepted binding. Vault availability comes from that
proxy's credential owner. An unavailable read is not an absent grant or proof
of an invalid provider login. Complete only the missing import, grant or explicit
unlock. Do not reimport an original login merely because a launch was interrupted;
its refresh token may have rotated. Inspect `credentials list` and the current
binding before choosing another explicit import or authorization.

After catalogue activation, gateway configuration changes, named-list input
changes or proxy restart, stop/relaunch the coding client to fetch a current
scoped token. Gateway inputs include service bindings, agent identities, host
routing and contract bindings. An ordinary credential or network approval keeps
the token when those inputs stay unchanged. A running client can be interrupted
by invalidation; continuous token replacement in that client is not provided.
Check any prior task's effects before retrying it. SafeYolo does not replay model
requests. A passphrase vault remains locked after proxy restart until an
explicit `credentials unlock` or the launch guide's explicit unlock choice.

## Renewal, refusal and limits

The existing gateway refresh owner renews an expired imported record before
delivery. Both subscription protocols use JSON. Claude retains the imported
scope list. Codex can derive a replacement expiry from its access token when
the issuer omits `expires_in`. Refresh responses stay on the host. A failed
refresh returns a categorical 503; it does not send the old provider token as
a fallback. Other policy refusals retain their existing behavior.

For a controlled renewal check, add `--expires-at 2020-01-01T00:00:00Z` to the
initial host import, before any request uses that record. This sets the refresh
deadline in the vault copy without editing the selected file. Launch the configured client and make a real request, which forces host renewal before
delivery. Make a second real client request through the same configured path.
Check the host's renewal result and the guest's files, environment and responses;
a configuration or model catalogue is insufficient proof. The selected file
stays unchanged, so reimporting it after a rotating refresh can restore a stale
refresh token.

The shipped capabilities cover Codex response/compaction POSTs on `chatgpt.com`.
On `api.anthropic.com`, Claude's inference capability covers message/token-count
POSTs, startup GETs to `/api/claude_cli/bootstrap`,
`/api/claude_code/policy_limits` and `/api/claude_code/settings`, and feature-flag
POSTs to `/api/eval/sdk-*`. Other account management, client login, plugin
downloads, custom/regional endpoints and Codex WebSockets are outside these
capabilities. Existing network policy can separately govern other client
traffic. Revoke access with `services revoke alice codex` or
`services revoke alice claude`; remove the host copy with `credentials remove`.
The older `import-codex` flow and its client-held login remain separate.
