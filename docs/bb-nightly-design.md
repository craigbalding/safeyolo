# Nightly Blackbox Test Reporting via GitHub Check Runs

## Goal

Publicly evidence blackbox test results on GitHub — tied to specific commits,
with full logs visible in the GitHub UI, badge-compatible, and with no
self-hosted runner exposure.

## Architecture

```
Mac mini (launchd)                          GitHub
├── cron: 3am daily                         ├── Check Runs (Checks tab)
├── git fetch origin main                   │   ├── status: completed
├── run-tests.sh --verbose                  │   ├── conclusion: success/failure
├── capture stdout/stderr                   │   ├── output.title: "31 passed"
└── POST /repos/.../check-runs ────────────→│   ├── output.summary: breakdown
    (GitHub App JWT auth)                   │   └── output.text: full log
                                            └── Badge reads from Checks API
```

## Why Check Runs API (not Status API)

- Full test logs visible in GitHub UI on the commit's Checks tab
- Structured output: title, summary, detailed text
- Supports annotations (could highlight failures in future)
- Shields.io reads check run conclusions for badges
- Can be a required status check for branch protection

The Check Runs API requires a **GitHub App** (PATs cannot create check runs).
A private (unlisted) GitHub App installed on the single repo is sufficient.

## GitHub App Setup

One-time manual setup by the repo owner:

1. Go to GitHub Settings → Developer Settings → GitHub Apps → New GitHub App
2. Configure:
   - **Name**: `safeyolo-bb-tests` (or similar unique name)
   - **Homepage URL**: the repo URL
   - **Webhook**: uncheck "Active" (no webhook needed)
   - **Permissions**: Repository → Checks: Read & Write
   - **Where can this app be installed?**: Only on this account
3. Create the app → note the **App ID**
4. Generate a **private key** (downloads a .pem file)
5. Install the app on `craigbalding/safeyolo` → note the **Installation ID**
6. Store on the Mac mini:
   ```
   ~/.config/safeyolo-bb/app-id          # e.g., 123456
   ~/.config/safeyolo-bb/installation-id # e.g., 789012
   ~/.config/safeyolo-bb/private-key.pem # downloaded .pem
   ```

## Nightly Runner Script

`scripts/bb-nightly.sh` — runs on the Mac mini via launchd:

```bash
#!/bin/bash
# Nightly blackbox test runner with GitHub Check Runs reporting
set -euo pipefail

REPO="craigbalding/safeyolo"
BRANCH="main"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BB_CONFIG="$HOME/.config/safeyolo-bb"

# 1. Fetch latest and get HEAD SHA
cd "$REPO_ROOT"
git fetch origin "$BRANCH"
SHA=$(git rev-parse "origin/$BRANCH")

# 2. Create check run (status: in_progress)
#    Uses GitHub App JWT auth (see auth helper below)
TOKEN=$(python3 "$SCRIPT_DIR/gh-app-token.py" \
    --app-id "$(cat $BB_CONFIG/app-id)" \
    --key "$BB_CONFIG/private-key.pem" \
    --installation-id "$(cat $BB_CONFIG/installation-id)")

CHECK_RUN_ID=$(curl -s -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$REPO/check-runs" \
    -d "{
        \"name\": \"Blackbox Tests\",
        \"head_sha\": \"$SHA\",
        \"status\": \"in_progress\",
        \"started_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
    }" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")

# 3. Run tests, capture output
git checkout "$SHA" --detach 2>/dev/null
OUTPUT=$(./tests/blackbox/run-tests.sh --verbose 2>&1) || true
EXIT_CODE=${PIPESTATUS[0]:-$?}
git checkout - 2>/dev/null

# 4. Determine conclusion
if [ "$EXIT_CODE" = "0" ]; then
    CONCLUSION="success"
    TITLE="All tests passed"
else
    CONCLUSION="failure"
    TITLE="Tests failed (exit code: $EXIT_CODE)"
fi

# 5. Parse summary from output
PROXY_LINE=$(echo "$OUTPUT" | grep "Proxy tests:" || echo "Proxy tests: not run")
ISOLATION_LINE=$(echo "$OUTPUT" | grep "Isolation tests:" || echo "Isolation tests: not run")
SUMMARY="$PROXY_LINE\n$ISOLATION_LINE"

# 6. Update check run with results
#    Truncate output to 65535 chars (GitHub limit)
TRUNCATED_OUTPUT=$(echo "$OUTPUT" | head -c 65000)

curl -s -X PATCH \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$REPO/check-runs/$CHECK_RUN_ID" \
    -d "$(python3 -c "
import json, sys
print(json.dumps({
    'status': 'completed',
    'conclusion': '$CONCLUSION',
    'completed_at': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
    'output': {
        'title': '$TITLE',
        'summary': '$SUMMARY',
        'text': '''$TRUNCATED_OUTPUT'''[:65535]
    }
}))
")"
```

## GitHub App Token Helper

`scripts/gh-app-token.py` — generates a short-lived installation token:

```python
"""Generate a GitHub App installation access token.

Uses PyJWT to create a JWT from the app's private key, then exchanges
it for an installation token scoped to the repo. Tokens expire after
1 hour. No external dependencies beyond PyJWT.
"""
import argparse
import json
import time
import urllib.request

import jwt  # PyJWT

def get_installation_token(app_id, key_path, installation_id):
    # Create JWT (expires in 10 minutes)
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 600, "iss": app_id}
    with open(key_path) as f:
        private_key = f.read()
    token = jwt.encode(payload, private_key, algorithm="RS256")

    # Exchange for installation token
    req = urllib.request.Request(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())["token"]

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--app-id", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--installation-id", required=True)
    args = p.parse_args()
    print(get_installation_token(int(args.app_id), args.key, int(args.installation_id)))
```

## launchd Plist

`~/Library/LaunchAgents/com.safeyolo.bb-nightly.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.safeyolo.bb-nightly</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/craigb/proj/safeyolo/scripts/bb-nightly.sh</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>3</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>/Users/craigb/.local/state/safeyolo/bb-nightly.log</string>
    <key>StandardErrorPath</key>
    <string>/Users/craigb/.local/state/safeyolo/bb-nightly.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/Users/craigb/proj/safeyolo/.venv/bin:/usr/local/bin:/usr/bin:/bin:/sbin</string>
    </dict>
</dict>
</plist>
```

Install: `launchctl load ~/Library/LaunchAgents/com.safeyolo.bb-nightly.plist`

## README Badge

```markdown
[![Blackbox Tests](https://img.shields.io/github/check-runs/craigbalding/safeyolo/main?nameFilter=Blackbox%20Tests&label=blackbox%20tests)](https://github.com/craigbalding/safeyolo/commits/main)
```

## Trigger Options

The launchd plist handles nightly. For on-demand:

```bash
# Manual run
~/proj/safeyolo/scripts/bb-nightly.sh

# Via hostctl (add to allowlist)
{"command": "bb-nightly", "id": "manual-bb-run"}
```

For push-to-main triggers, a lightweight GitHub Actions workflow could
use `workflow_dispatch` or `repository_dispatch` to signal the Mac mini
via the hostctl bridge. But nightly + manual covers most needs.

## Security

- **GitHub App is private** — not published, installed on one repo only
- **Private key on Mac mini only** — in `~/.config/safeyolo-bb/`, not in repo
- **Installation tokens expire in 1 hour** — short-lived, scoped to checks:write
- **No self-hosted runner** — Mac mini never executes arbitrary workflow code
- **No inbound connectivity** — Mac mini only makes outbound HTTPS to api.github.com
- **Test isolation** — runs in `~/.safeyolo-test` instance, separate from production

## Dependencies

- `PyJWT` — for GitHub App JWT generation (`pip install pyjwt[crypto]`)
- Existing: `safeyolo` CLI, guest artifacts, test certs
