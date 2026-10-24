# Native coding clients through the services gateway

This opt-in integration keeps a selected provider login in the host's encrypted
credential store. The guest client sends its scoped service token. The existing
gateway replaces that token after authorization and renews the provider login
on the host. Browser and device login run on the host.

Live subscription requests and renewal remain unverified under
[#1219](https://github.com/craigbalding/safeyolo/issues/1219). The protocol checks
use standalone Codex 0.163.0 and Claude Code 2.1.306. They establish client
request formats, not provider acceptance or subscription entitlement. This
route does not substitute separately billed API access.

## Authorize on the host

Use an existing agent, named `alice` in these examples, and the selected
instance's `safeyolo` command. Keep the provider login file outside all guest
mounts. Select a file-backed host login created by the native client's host
login flow. The importer does not read an operating-system keychain.
`/secure/codex/auth.json` and `/secure/claude/.credentials.json` below stand for
those selected files; replace each path before running its command.

Import is an explicit storage operation. It uses the existing local encrypted
store and can create that store on this write. It does not change storage
selection or unlock behavior. Initialization and independent proxy readiness
do not open the store. The separate storage-choice discussion under #1050
remains unresolved.

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

Use an agent home without a provider login. Decline host authentication copying
in `agent launch`; for a directly selected Claude host script, set
`SAFEYOLO_CLAUDE_COPY_HOST_STATE=0` on the host before preparation. Do not run
browser/device login in the guest. Retained provider files require a separate
operator decision; this integration does not remove them.

The commands below run inside Alice's guest with `jq` and the documented
[`sy_api` helper](../cli/src/safeyolo/agent_context/skills/safeyolo/references/agent-api.md#calling-the-api).
Stop if token retrieval fails. Keep scoped tokens out of terminal output,
source files and logs. Fetch the current token again after catalogue activation,
policy activation or proxy restart.

For Codex, merge these settings into the guest's `.codex/config.toml`, retaining
the selected model and unrelated settings:

```toml
model_provider = "safeyolo"

[model_providers.safeyolo]
name = "SafeYolo ChatGPT subscription"
base_url = "https://chatgpt.com/backend-api/codex"
env_key = "SAFEYOLO_CODEX_GATEWAY_TOKEN"
requires_openai_auth = false
supports_websockets = false
wire_api = "responses"
```

Then retrieve the scoped token and run the client:

```sh
SAFEYOLO_CODEX_GATEWAY_TOKEN=$(sy_api /gateway/services | jq -er '.authorized.codex.token')
export SAFEYOLO_CODEX_GATEWAY_TOKEN
codex exec 'Reply READY without using tools.'
```

The host supplies the selected `ChatGPT-Account-ID` from the imported login.
The guest cannot replace that selection. OpenAI documents that
[`requires_openai_auth = true` ignores `env_key`](https://learn.chatgpt.com/docs/auth#alternative-model-providers);
this configuration uses the scoped token instead.

For Claude Code:

```sh
CLAUDE_CODE_OAUTH_TOKEN=$(sy_api /gateway/services | jq -er '.authorized.claude.token')
export CLAUDE_CODE_OAUTH_TOKEN
claude -p --tools '' 'Reply READY.'
```

Leave `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` unset for this subscription
route. In the checked client, `CLAUDE_CODE_OAUTH_TOKEN` sends a bearer token and
the OAuth capability in `anthropic-beta`. The ordinary
[gateway credential variables](https://code.claude.com/docs/en/llm-gateway)
select a different authentication path. Neither local observation establishes
that the provider accepts the substituted host subscription.

## Renewal, refusal and limits

The existing gateway refresh owner renews an expired imported record before
delivery. Both subscription protocols use JSON. Claude retains the imported
scope list. Codex can derive a replacement expiry from its access token when
the issuer omits `expires_in`. Refresh responses stay on the host. A failed
refresh returns a categorical 503; it does not send the old provider token as
a fallback. Other policy refusals retain their existing behavior.

For a controlled renewal check, add `--expires-at 2020-01-01T00:00:00Z` to the
initial host import, before any request uses that record. This sets the refresh
deadline in the vault copy without editing the selected file. Fetch the current
gateway token and make a real client request, which forces host renewal before
delivery. Make a second real client request using the current gateway token.
Check the host's renewal result and the guest's files, environment and responses;
a configuration or model catalogue is insufficient proof. The selected file
stays unchanged, so reimporting it after a rotating refresh can restore a stale
refresh token.

The shipped capabilities cover Codex response/compaction POSTs on `chatgpt.com`
and Claude message/token-count POSTs on `api.anthropic.com`. Account management,
client login, plugin downloads, custom/regional endpoints and Codex WebSockets
are outside these capabilities. Existing network policy can separately govern
other client traffic. Revoke access with `services revoke alice codex` or
`services revoke alice claude`; remove the host copy with `credentials remove`.
The older `import-codex` flow and its client-held login remain separate.
