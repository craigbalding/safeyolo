# SafeYolo Notifiers

Push notifications when SafeYolo blocks credentials.

## Supported Backends

| Backend | Platform | Setup |
|---------|----------|-------|
| [ntfy.sh](https://ntfy.sh) | Any (web, Android, iOS) | Free, self-hostable |
| [Pushcut](https://pushcut.io) | iOS | Requires subscription |

## Quick Start

### ntfy.sh (Recommended)

1. Pick a topic name (keep it secret - anyone with the URL can send):
   ```bash
   export NTFY_TOPIC=https://ntfy.sh/safeyolo-$(openssl rand -hex 4)
   ```

2. Subscribe on your device:
   - Android: Install ntfy app, add topic
   - iOS: Install ntfy app, add topic
   - Web: Visit your topic URL

3. Run the notifier:
   ```bash
   cd /path/to/safeyolo
   python contrib/notifiers/notify.py
   ```

### Pushcut (iOS)

1. Create a webhook in Pushcut app:
   - Automation → Webhooks → Add Webhook
   - Name it "SafeYolo"
   - Copy the webhook URL

2. Configure and run:
   ```bash
   export PUSHCUT_WEBHOOK="https://api.pushcut.io/xxx/notifications/SafeYolo"
   python contrib/notifiers/notify.py
   ```

## Configuration

All configuration via environment variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `SAFEYOLO_LOG` | No | Path to JSONL log (default: `./safeyolo/logs/safeyolo.jsonl`) |
| `NTFY_TOPIC` | One of these | ntfy topic URL |
| `NTFY_TOKEN` | No | ntfy access token (for private topics) |
| `PUSHCUT_WEBHOOK` | One of these | Pushcut webhook URL |

## Running as a Service

### With systemd

```ini
# /etc/systemd/user/safeyolo-notify.service
[Unit]
Description=SafeYolo Notifications
After=network.target

[Service]
Type=simple
Environment=NTFY_TOPIC=https://ntfy.sh/my-topic
Environment=SAFEYOLO_LOG=/home/user/project/safeyolo/logs/safeyolo.jsonl
ExecStart=/usr/bin/python3 /path/to/contrib/notifiers/notify.py
Restart=always

[Install]
WantedBy=default.target
```

### With Docker Compose

```yaml
services:
  safeyolo-notify:
    image: python:3.11-slim
    command: python /app/notify.py
    volumes:
      - ./contrib/notifiers:/app:ro
      - ./safeyolo/logs:/logs:ro
    environment:
      SAFEYOLO_LOG: /logs/safeyolo.jsonl
      NTFY_TOPIC: https://ntfy.sh/my-topic
    restart: unless-stopped
```

## Adding New Backends

The notifier uses a pluggable backend pattern. To add a new backend:

```python
class SlackBackend:
    """Slack webhook backend."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.client = httpx.Client(timeout=10.0)

    def send(self, title: str, message: str, priority: str = "default") -> bool:
        payload = {
            "text": f"*{title}*\n{message}",
        }
        try:
            resp = self.client.post(self.webhook_url, json=payload)
            resp.raise_for_status()
            return True
        except httpx.HTTPError as e:
            logging.error(f"Slack send failed: {type(e).__name__}: {e}")
            return False
```

Then add configuration and wiring in `build_backends()`.

## Notification Format

Blocks trigger notifications like:

```
Title: Credential Blocked: openai
Body:  openai credential blocked from reaching api.openal.com
       Reason: destination_mismatch
       Fingerprint: hmac:a1b2c3d4...
```

Priority is set to "high" for destination mismatches (likely typos or attacks).
