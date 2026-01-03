# SafeYolo Monitors

Log monitoring and visualization tools.

## logtail.py

Live tail of SafeYolo JSONL logs with periodic traffic summaries.

**Features:**
- Shows blocks and warnings immediately
- Periodic summaries: requests/sec, status codes, latency stats, top domains
- Handles docker log prefixes (extracts JSON from mixed output)
- Optional Rich-based visual dashboard

**Usage:**

```bash
# Pipe from docker logs
docker logs -f safeyolo 2>&1 | python contrib/monitors/logtail.py

# Tail a log file
tail -f ./safeyolo/logs/safeyolo.jsonl | python contrib/monitors/logtail.py

# Read from file directly
python contrib/monitors/logtail.py ./safeyolo/logs/safeyolo.jsonl

# Visual dashboard mode (requires: pip install rich)
python contrib/monitors/logtail.py --visual ./safeyolo/logs/safeyolo.jsonl

# Custom summary interval
python contrib/monitors/logtail.py --interval 10

# Events only, no summaries
python contrib/monitors/logtail.py --no-summary
```

**Sample output (text mode):**

```
[BLOCK] 14:32:15 credential-guard blocked api.example.com/v1/chat
        reason: destination_mismatch
        fingerprint: hmac:a1b2c3d4e5f6...

[RATE] 14:32:18 api.openai.com warn (wait 1200ms)

[14:32:20] 47 req (9.4/s) 42/3/2 lat=89ms (p95 234) api.openai.com:35 httpbin.org:12
```

**Requirements:**
- Python 3.10+
- `rich` (optional, for `--visual` mode)
