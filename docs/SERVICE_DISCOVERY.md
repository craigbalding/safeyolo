# Service Discovery

SafeYolo automatically identifies which agent is making each request using
Docker's embedded DNS — no configuration needed.

## How It Works

1. Agent container starts and joins the `safeyolo_internal` Docker network
2. Docker assigns an IP and registers the container name in its DNS
3. When the proxy sees a request from an unknown IP, it does a reverse DNS lookup
4. Docker's DNS resolves the IP back to the container name (e.g., `claude`)
5. The result is cached (5 minute TTL) — subsequent requests skip the DNS lookup

```
Agent "claude" (172.20.0.3)
    │
    │  HTTP request
    ▼
SafeYolo proxy
    │
    ├─ Source IP: 172.20.0.3
    ├─ DNS cache miss → gethostbyaddr("172.20.0.3")
    ├─ Docker DNS returns: "claude.safeyolo_internal"
    ├─ Strip suffix → "claude"
    ├─ Cache: 172.20.0.3 → claude (5min TTL)
    │
    ▼
credential_guard evaluates policy for principal "project:claude"
```

## Container Naming

Agent containers use `container_name: <instance_name>` in their
docker-compose template. This ensures:

- Reverse DNS returns the clean instance name (not a compose-generated hash)
- Only one instance of each agent can run at a time (prevents shared-volume conflicts)

## Troubleshooting

### All requests show "unknown" principal

1. Verify the agent container is on the `safeyolo_internal` network: `docker network inspect safeyolo_internal`
2. Test reverse DNS from the proxy: `docker exec safeyolo python3 -c "import socket; print(socket.gethostbyaddr('<agent-ip>'))"`
3. Check the proxy logs for "DNS discovery" or "Unknown source IP" messages

### Agent not being identified

The proxy caches failed DNS lookups for 60 seconds. If you started the proxy
before the agent, wait a minute for the negative cache to expire, or restart
the proxy.
