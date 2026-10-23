# Credentials and service access

Run these commands as the operator on the host. Start a fresh installed instance with the [installation and listener instructions](installation.md#install-and-start).
The examples use `$HOME/.safeyolo`, a running proxy, and its trusted
listener for Alice. Commands below edit and activate service policy through the
private Admin API. Keep the operator token, credential files and provider
authentication on the host.

## Store a local credential

For Slack, obtain a token for the account you intend Alice to use. The example
selects the installed `slack` service's `reader` capability: POST requests to
`/api/conversations.list`, `/api/conversations.history`, and `/api/users.list`.
Authorization below maps `slack.com` and explicitly permits host-wide network
access to that host. Service authorization is scoped to Alice. The existing credential
guard also checks the host-wide network permission after credential approval;
`--allow-host-network` supplies that permission when needed. Credential policy
still applies to the injected value.

In a host terminal, inspect the running service definition, then add the token:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" services show slack
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" credentials add slack-account
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" credentials list
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" services authorize alice slack --capability reader --credential slack-account --account operator --allow-host-network
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" services authorized alice
```

`credentials add` prompts without terminal echo. It also accepts `--value-file`,
`--value-env` or piped stdin. Do not put the value in command arguments.
Add replaces an existing credential with the same name. List prints only its
name, type, expiry and external reference. Local use needs neither `op` nor
Python. The host creates `data/credentials.key` and encrypted
`data/credentials.enc`, both with mode 0600. It does not read old vault files.
Ordinary proxy stop/start retains these files and service authorization.

`services authorized` returns Alice's current `sgw_` credential, account,
credential reference name, capability and compiled routes. An agent obtains its own token from the authenticated Agent API
`GET /gateway/services`; identity comes from its trusted listener. It uses that
token in the service's declared auth header. The proxy replaces the token with
the host credential after applicable checks. Catalogue activation and proxy
restart can mint new tokens; fetch the current token again after either change.

An allowed request receives the service's response. Bob, another destination,
and a method or path outside the capability cannot use Alice's token. An upstream
service can still reject a token whose vendor permissions are insufficient.

## Unknown bearer credentials

With the default credential controls, a nonempty `Authorization: Bearer` value
that matches no known credential rule uses `unknown_secret`. Bearer detection
does not depend on entropy. Short, repetitive and placeholder bearer values
also require approval unless policy permits them. This enforces the existing
unknown-credential requirement even when a token fails the entropy heuristic.
The check also applies to bearer values in service requests before credential
injection.

Review the reported fingerprint and destination before granting an approval.
An exact-token approval applies to that token and destination. A replacement
token needs its own approval unless another applicable policy permits it.
Token shape and claimed issuer do not establish permission. This behavior
does not add automatic approval for Codex subscription OAuth tokens. The
[credential controls](settings.md#named-policy-controls) retain header
selection, exclusions, enablement and warn mode.

## Pull public images and OCI artifacts from GHCR

With default credential policy, public pulls from GitHub Container Registry
(GHCR) need no credential approval when the client obtains its anonymous bearer
token through the same running SafeYolo proxy. This applies to images and
Open Container Initiative (OCI) artifacts. Ordinary network permission must
allow the download destinations.
The client follows the registry's authentication challenge and requests its
own token. SafeYolo does not obtain or refresh tokens for the client.

SafeYolo recognises a token only after a verified HTTPS exchange at
`https://ghcr.io/token`. The final GET request sent upstream must have no body
or trailing headers. It must have no authentication headers, cookies or
injected credential. Its service must be `ghcr.io`, and each repository scope
must request only `pull`. A token with no
repository scope can cover registry discovery only. The standard `client_id`
and boolean `offline_token` parameters and an empty `account` are supported.
Other query parameters do not establish anonymous issuance. An authenticated
exchange or a token's shape alone does
not establish anonymous issuance.

The exact observed bearer can then be reused for HTTPS GET and HEAD requests
to GHCR's registry discovery endpoint and the named repositories' manifests,
blobs and tag lists. Replacement tokens from qualifying exchanges work the
same way, including concurrent requests. Redirects do not extend the token's
trusted origin or credential destination. Explicit credential permissions,
network policy and inspection of other secrets still apply. Authenticated or
private pulls, other destinations, other repositories and write operations
retain ordinary credential-policy handling.

Recognition stores only token fingerprints and repository scopes in memory,
with at most 256 tokens, 16 repository scopes per exchange, and a 15-minute
local retention window. An earlier expiry reported by GHCR shortens that
window. GHCR can omit expiry metadata; the local window is a cache limit,
not a verified token lifetime. Tokens are opaque and their internals are not
decoded. Token response capture is limited to 64 KiB and token values to
16 KiB; larger or malformed responses retain ordinary handling. Recognition
does not add token fingerprints to persistent policy or approvals.

A token cached by a client before SafeYolo observed its issuance, after cache
eviction, or across a proxy restart retains ordinary credential-policy
handling. Clear that client's cached registry token or start a fresh client
session, then repeat its anonymous token exchange through the proxy to restore
automatic recognition. Registry login credentials and personal access tokens
retain their existing approval requirements.

## Use Codex with a ChatGPT subscription

Codex supports [ChatGPT subscription authentication and OpenAI API key
authentication](https://learn.chatgpt.com/docs/auth). These are different
credentials. SafeYolo's `openai` detector recognises `sk-proj-` and
`sk-svcacct-` API keys. A grant for `openai:*` does not identify or approve a
ChatGPT subscription OAuth access token.

For the supported subscription paths, an operator can authorize an explicitly
selected login through the existing encrypted credential vault. On the operator
host, use the instance's CLI, an existing agent with a unique `agent_id`
in policy, and a trusted `auth.json` input selected before the guest can replace
its contents. In this example, `alice` is that agent and
`/secure/codex/auth.json` is the selected host input. Keep credential values out
of command arguments and output.

```sh
safeyolo credentials import-codex codex-alice --agent alice --auth-file /secure/codex/auth.json
```

The command stores the exact access and refresh pair with the agent's identity
and the supported issuer/client binding. It prints the agent and credential
name, never token values. It grants proxy authorization; provision the client's
login through the existing trusted workflow before launching the client.
An adoption marker or a guest-writable login file does not create this authority.

The default authorization is persistent until the record is removed, replaced,
or reaches an explicitly supplied `--expires-at` time. `--scope run` instead
binds the import to the agent's current independently verified sandbox run.
A stopped or replaced run cannot inherit it. To revoke an import, run
`credentials remove codex-alice` with the same instance CLI. Explicit
credential permissions, including deny and prompt, network policy, and inspection
of other secrets still apply.

The supported native Codex transport uses a JSON refresh POST to
`https://auth.openai.com/oauth/token` with the default Codex client ID. SafeYolo
checks the exact imported or observed refresh credential and complete verified
TLS exchange.
It records keyed digests of present access/refresh replacements in the same
encrypted record before releasing the response body. An omitted field retains
the existing recognition. Codex performs renewal and persists its own client
state. Malformed, duplicate, incomplete or oversized successful refresh responses
do not establish a replacement and are refused. Token response capture is bounded
to 64 KiB. An unsupported refresh request or an additional authentication header
does not establish replacement authority.

Access recognition is limited to HTTPS on `chatgpt.com:443`: account-check and
usage GET requests, Codex models/rate-limit GET requests, and Codex response POST,
compact POST and response WebSocket GET paths. It also covers the native Codex GET
paths `/backend-api/plugins/featured`, `/backend-api/ps/plugins/installed`,
`/backend-api/ps/plugins/suggested/codex`, `/backend-api/ps/plugins/list` and
`/backend-api/wham/rate-limit-reset-credits`. It does not cover custom or
regional endpoints selected by client configuration, unrelated paths, arbitrary
methods, or other OpenAI services. Only exact imported or observed credentials
receive this recognition. The issuer still decides whether a token is valid.

The encrypted imported pair, replacement digests and authorization scope survive
proxy restart. Recognition stops after revocation, expiry, an agent identity
change, or the end of a run-scoped authorization. A replacement made without a
qualifying observed exchange retains ordinary handling. SafeYolo never rescans
guest replacements to create or repair authorization.

With the [default bearer controls](#unknown-bearer-credentials), an unrecognised
`Authorization: Bearer` value uses `unknown_secret`, regardless of entropy.
Detection does not verify a JSON Web Token (JWT) signature, issuer or audience.
A claimed issuer, token shape, matching regular expression or destination alone
provides no authority. No entropy adjustment or custom classifier is needed.

When trustworthy issuance evidence is unavailable, use the manual approval
fallback. Keep `unknown_creds = "prompt"` for the intended destination.
For example, if your authorised Codex traffic uses `chatgpt.com`, merge this
field into that host's existing table in a copy of your host `policy.toml`:

```toml
[hosts."chatgpt.com"]
unknown_creds = "prompt"
```

Use the destination recorded for your client; this example does not authorise
another OpenAI service or a client-selected URL. The fragment grants no network
access. Preserve existing network permissions, credential denials and other
host fields. [Check and apply the candidate](installation.md#check-show-and-apply),
then retry the client's request. With network access permitted and blocking
credential controls active, an unapproved bearer returns HTTP 428 with a
credential fingerprint. An explicit denial returns HTTP 403.

On the host, inspect the reported agent, destination and fingerprint in the
pending credential approval or the `security.credential_guard` audit event.
Use `services approvals` to read pending records. `logs --agent WORKER --lines
50 --json` returns complete selected audit events; replace `WORKER` with your
agent's name. Match the event's `request_id`, `agent` and `host` to the client's
request, then read its `details.fingerprint`.
Do not extract or share a token or Codex authentication file to obtain the
fingerprint.

For the installed instance at `$HOME/.safeyolo`, replace `FINGERPRINT` with the
reported `hmac:` fingerprint and `HOST` with the intended destination. Approve
only the token and destination you intend to permit:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" credentials approve FINGERPRINT --destination HOST
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" policy show
```

Wait for `saved_matches_active` to be true, then let the client retry.
The exact-fingerprint grant covers that token at the chosen host. It is a
host-policy grant, not an agent-specific grant or proof of issuer or account.
It does not constrain the method or path. Existing network permissions,
explicit credential denials and inspection of other secrets still apply.

Let Codex manage login and refresh. A replacement access token needs its own
approval; approval of the preceding token does not cover it. This fallback
does not provide approval-free rotation or prove that the upstream service will
accept a token. Keep approvals when per-token provenance cannot be established.
Setting `unknown_creds = "allow"`, excluding `Authorization` from inspection,
or granting a custom token family would permit values without proving their
issuer or intended use.

## Use a 1Password reference

On the host, follow [1Password's installation and authentication instructions](https://developer.1password.com/docs/cli/get-started/)
for your chosen method. Verify the host installation with `op --version` and
check that the selected account can read the intended item.
Local setup remains independent of this optional configuration.

Replace `/absolute/path/to/op` with that host executable. Replace
`op://VAULT/ITEM/FIELD` with the item's nonsecret reference. Configure the
executable, then restart the proxy using the installation instructions
so the running process inherits the host's authentication environment:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" credentials provider --executable /absolute/path/to/op
```

After restart, register the reference and authorize Alice:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" credentials reference slack-external --provider onepassword --reference op://VAULT/ITEM/FIELD
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" credentials list
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" services authorize alice slack --capability reader --credential slack-external --account operator --allow-host-network
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" services authorized alice
```

SafeYolo stores the reference in the same encrypted store. The proxy invokes the
configured host executable with [op read --no-newline](https://developer.1password.com/docs/cli/reference/commands/read/)
only after route and approval checks. The resolved value is transient; SafeYolo does not store it
as a local credential. Keep 1Password authentication out of guest environment
variables and mounts. Provider commands, item selection and executable selection
are host choices; the guest supplies only a minted service token.

An unavailable executable, rejected read, missing item or ten-second provider
timeout returns a secret-free 503 diagnostic. The credentialed origin receives
no request. There is no substitution with a local credential. Repair host
authentication, the executable or the reference, then retry. Local credentials
continue to work independently.

## Authorization, binding and risk approval

Authorization selects an agent, capability, account and credential. A capability
with a contract can also require operator-approved binding values. Save those
values as a JSON object in a host file, then use `services bind AGENT SERVICE
CAPABILITY --bindings FILE`; `services show` supplies the contract's required
names and types. Bind derives the template and grantable operation names from the accepted
catalogue, matching the existing agent binding path. Binding does not add service
authorization. The existing watcher activates its
contract-derived routes; wait for `policy show` to report `saved_matches_active`
and fetch the current service token after that activation.

Credential policy can also prompt after identifying the injected credential.
Read `services approvals` and inspect the credential fingerprint and destination.
Use `credentials approve FINGERPRINT --destination HOST` to approve that
credential for the reported destination through the existing baseline approval
operation. Wait for `policy show` to report `saved_matches_active`, fetch the
current service token and retry. This grants no service capability or risk approval.

A risky route can require a separate approval. Use `services approvals` to read
pending requests. After checking the reported agent, service, method and path,
use `services approve AGENT SERVICE METHOD PATH --lifetime once`. Lifetimes are
`once`, `session` and `remembered`. The agent retries after approval. A grant
does not widen the capability or replace binding. Inspect and revoke grants
with `services grants` and `services revoke-grant ID`.

Credential-free services omit `--credential`. Sandbox-hosted services retain
their trusted caller headers and provider transport; an unavailable provider
does not fall back to ordinary network delivery. Use `--host` when a definition
has no default host. A host with a port retains that explicit egress constraint;
the service mapping uses its hostname.

## Catalogue changes and removals

The installer selects built-in definitions in `assets/services` and
operator definitions in `data/services`, relative to the instance root.
Standalone `safeyolo init` creates `builtin-services` and `services` instead.
The two configured catalogue paths select the directories the proxy watches.
Operator definitions replace builtins with the same service name.
`services list` and `services show` read the running process's accepted catalogue.
The existing watcher activates valid definition changes with policy. If a
definition is malformed, the previous catalogue and policy remain active.
Remove the override to select the built-in definition again.

To remove Alice's Slack access while retaining the local credential for another
use, run the first command below. To remove the credential itself, run the
second command. Both changes affect subsequent requests without a proxy restart:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" services revoke alice slack
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" credentials remove slack-account
```

Revocation stops use of that service binding. Credential removal causes remaining
bindings to fail without injecting a stale value. Other permitted nonsecret
requests remain usable. The commands replace Python `vault`, `services`
and `agent authorize/revoke`; no vault migration is provided.

For retained OAuth, `credentials add --type oauth2` accepts an expired access
token and host files for `--refresh-token-file` and `--client-secret-file`, plus
`--token-url`, `--client-id` and `--expires-at`. A service definition with
`refresh_on_401: true` uses the existing refresh owner before injection.
The name retains the existing behavior: refresh occurs on expiry before delivery.
