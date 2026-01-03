# SafeYolo Notifiers

Push notifications when SafeYolo blocks credentials. Optionally with one-tap approval buttons.

## Quick Start

```bash
# 1. Subscribe to an ntfy topic on your phone
#    Android/iOS: Install ntfy app, add topic

# 2. Run the notifier
export NTFY_TOPIC=https://ntfy.sh/my-safeyolo-alerts
python contrib/notifiers/notify.py
```

That's it. You'll get notifications when credentials are blocked.

## Adding Approval Buttons

To approve credentials directly from notifications:

```bash
# Terminal 1: Notifier with buttons
export NTFY_TOPIC=https://ntfy.sh/my-safeyolo-alerts
export NTFY_CALLBACK_TOPIC=my-secret-callback-topic
python contrib/notifiers/notify.py

# Terminal 2: Handle button taps
export NTFY_CALLBACK_TOPIC=my-secret-callback-topic
export SAFEYOLO_ADMIN_TOKEN=$(cat ./safeyolo/data/admin_token)
python contrib/notifiers/listener.py
```

Now notifications have [Approve] and [Deny] buttons.

## How It Works

```
Block event → notify.py → ntfy → Your phone
                                    ↓ tap [Approve]
Admin API ← listener.py ← ntfy callback topic
```

## Environment Variables

**notify.py:**
| Variable | Required | Description |
|----------|----------|-------------|
| `NTFY_TOPIC` | Yes | ntfy topic URL |
| `NTFY_CALLBACK_TOPIC` | No | Enable approval buttons |
| `SAFEYOLO_LOG` | No | Log path (default: `./safeyolo/logs/safeyolo.jsonl`) |

**listener.py:**
| Variable | Required | Description |
|----------|----------|-------------|
| `NTFY_CALLBACK_TOPIC` | Yes | Same as notify.py |
| `SAFEYOLO_ADMIN_TOKEN` | Yes | Admin API token |
| `SAFEYOLO_ADMIN_URL` | No | Admin URL (default: `http://localhost:9090`) |

## Pushcut (iOS)

For Pushcut instead of ntfy notifications, modify `send_notification()` to POST to your Pushcut webhook. The button callbacks still go through ntfy.

## Adapting This Example

These scripts are intentionally simple. Fork and modify:

- Add Slack/Discord webhooks
- Filter by credential type
- Add rate limiting
- Log to a database

See the main [contrib README](../README.md) for the integration pattern.
