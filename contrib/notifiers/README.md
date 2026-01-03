# SafeYolo Notifiers

Push notifications with one-tap approval when SafeYolo blocks credentials.

## How It Works

```
┌──────────────────┐     ┌─────────────────┐     ┌──────────────────┐
│ SafeYolo blocks  │────►│ notify.py       │────►│ Your Phone       │
│ credential       │     │ sends notif     │     │ [Approve] [Deny] │
└──────────────────┘     └─────────────────┘     └────────┬─────────┘
                                                          │ tap
                                                          ▼
┌──────────────────┐     ┌─────────────────┐     ┌──────────────────┐
│ Admin API adds   │◄────│ listener.py     │◄────│ ntfy callback    │
│ policy approval  │     │ calls API       │     │ topic            │
└──────────────────┘     └─────────────────┘     └──────────────────┘
```

1. Credential blocked → JSONL event
2. `notify.py` sends notification with action buttons
3. You tap [Approve] → button POSTs to ntfy callback topic
4. `listener.py` receives message → calls admin API
5. Credential approved, subsequent requests pass through

## Supported Backends

| Backend | Platform | Features |
|---------|----------|----------|
| [ntfy.sh](https://ntfy.sh) | Android, iOS, web | Action buttons, self-hostable |
| [Pushcut](https://pushcut.io) | iOS | Background URL actions |

Both use ntfy as the callback mechanism (Pushcut buttons POST to ntfy topic).

## Quick Start

### 1. Get Admin Token

```bash
# From SafeYolo data directory
cat ./safeyolo/data/admin_token
```

### 2. Configure Environment

```bash
# Required
export SAFEYOLO_ADMIN_TOKEN="your-admin-token"
export NTFY_TOPIC="https://ntfy.sh/my-safeyolo-alerts"

# Optional (auto-generated if not set)
export NTFY_CALLBACK_TOPIC="safeyolo-callbacks-secret123"
```

### 3. Subscribe to ntfy

- **Android**: Install ntfy app → Add subscription → Enter your topic
- **iOS**: Install ntfy app → Add subscription → Enter your topic
- **Web**: Visit `https://ntfy.sh/your-topic`

### 4. Run Both Scripts

```bash
# Terminal 1: Send notifications
python contrib/notifiers/notify.py

# Terminal 2: Handle button callbacks
python contrib/notifiers/listener.py
```

## Configuration Reference

### notify.py

| Variable | Required | Description |
|----------|----------|-------------|
| `SAFEYOLO_LOG` | No | Path to JSONL log (default: `./safeyolo/logs/safeyolo.jsonl`) |
| `NTFY_TOPIC` | Yes* | ntfy topic URL for notifications |
| `NTFY_TOKEN` | No | ntfy access token (for private topics) |
| `NTFY_SERVER` | No | ntfy server (default: `https://ntfy.sh`) |
| `NTFY_CALLBACK_TOPIC` | No | Topic for button callbacks (auto-generated) |
| `PUSHCUT_WEBHOOK` | Yes* | Pushcut webhook URL (alternative to ntfy) |

*At least one of `NTFY_TOPIC` or `PUSHCUT_WEBHOOK` required.

### listener.py

| Variable | Required | Description |
|----------|----------|-------------|
| `NTFY_CALLBACK_TOPIC` | No | Topic to subscribe to (reads from file if not set) |
| `NTFY_SERVER` | No | ntfy server (default: `https://ntfy.sh`) |
| `SAFEYOLO_ADMIN_URL` | No | Admin API URL (default: `http://localhost:9090`) |
| `SAFEYOLO_ADMIN_TOKEN` | Yes | Admin API bearer token |

## Pushcut Setup (iOS)

Pushcut provides richer iOS notifications but requires the ntfy callback mechanism.

1. Create webhook in Pushcut app:
   - Automation → Webhooks → Add Webhook
   - Name: "SafeYolo"
   - Copy webhook URL

2. Configure:
   ```bash
   export PUSHCUT_WEBHOOK="https://api.pushcut.io/xxx/notifications/SafeYolo"
   # Callback still goes through ntfy
   export NTFY_CALLBACK_TOPIC="safeyolo-callbacks-secret123"
   ```

3. When you tap [Approve], Pushcut POSTs to the ntfy callback topic.

## Running as Services

### systemd (Two Units)

```ini
# /etc/systemd/user/safeyolo-notify.service
[Unit]
Description=SafeYolo Notifications

[Service]
Type=simple
Environment=NTFY_TOPIC=https://ntfy.sh/my-topic
ExecStart=/usr/bin/python3 /path/to/contrib/notifiers/notify.py
Restart=always

[Install]
WantedBy=default.target
```

```ini
# /etc/systemd/user/safeyolo-listener.service
[Unit]
Description=SafeYolo Approval Listener

[Service]
Type=simple
Environment=SAFEYOLO_ADMIN_TOKEN=xxx
ExecStart=/usr/bin/python3 /path/to/contrib/notifiers/listener.py
Restart=always

[Install]
WantedBy=default.target
```

### Docker Compose

```yaml
services:
  safeyolo-notify:
    image: python:3.11-slim
    command: pip install httpx && python /app/notify.py
    volumes:
      - ./contrib/notifiers:/app:ro
      - ./safeyolo/logs:/logs:ro
      - ./safeyolo/data:/data
    environment:
      SAFEYOLO_LOG: /logs/safeyolo.jsonl
      NTFY_TOPIC: https://ntfy.sh/my-topic
    restart: unless-stopped

  safeyolo-listener:
    image: python:3.11-slim
    command: pip install httpx && python /app/listener.py
    volumes:
      - ./contrib/notifiers:/app:ro
      - ./safeyolo/data:/data:ro
    environment:
      SAFEYOLO_ADMIN_TOKEN: ${SAFEYOLO_ADMIN_TOKEN}
      SAFEYOLO_ADMIN_URL: http://safeyolo:9090
    restart: unless-stopped
```

## Security Notes

- **Callback topic should be secret** - anyone with the topic name can send approval messages
- Auto-generated topics use `secrets.token_urlsafe(16)` (128 bits of entropy)
- Consider self-hosting ntfy for sensitive environments
- Admin token is required for listener to modify policies

## Adding New Backends

The notify.py uses a pluggable backend pattern:

```python
class SlackBackend:
    """Slack with interactive buttons."""

    def send(self, title, message, priority, approval_payload, callback_url):
        # Slack interactive messages can POST to a webhook
        # which you'd need to bridge to ntfy callback topic
        pass
```

For full interactive flows, you'll need to bridge the button callback to ntfy
(or modify listener.py to accept callbacks directly via HTTP).

## Notification Format

```
Title: Credential Blocked: openai
Body:  openai -> api.openal.com
       Reason: destination_mismatch
       Fingerprint: hmac:a1b2c3d4...

Buttons: [Approve] [Deny]
```

Tapping Approve sends: `approve:hmac:a1b2c3d4...|api.openal.com|default`

## Troubleshooting

**Notifications not appearing:**
- Check ntfy subscription matches your topic exactly
- Verify notify.py is running: should show "Waiting for credential block events..."
- Trigger a test block via `safeyolo test`

**Approvals not working:**
- Check listener.py is running and connected
- Verify SAFEYOLO_ADMIN_TOKEN is correct
- Check admin API is reachable: `curl http://localhost:9090/health`

**Callback topic mismatch:**
- Both scripts must use the same callback topic
- Check `./safeyolo/data/ntfy_callback_topic` file
- Or set `NTFY_CALLBACK_TOPIC` explicitly for both
