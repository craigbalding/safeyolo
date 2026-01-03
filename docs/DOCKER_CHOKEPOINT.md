# Docker Chokepoint Deployment

This guide explains how to deploy SafeYolo as a network chokepoint where **bypass is impossible** - traffic either goes through the proxy or fails.

## How It Works

SafeYolo creates two Docker networks:

1. **safeyolo-internal** (`172.30.0.0/24`) - marked `internal: true`
   - No default gateway to internet
   - All project containers live here
   - Direct connections get "no route to host"

2. **default** - normal bridge with internet access
   - Only SafeYolo container connects here
   - SafeYolo bridges traffic from internal to internet

```
┌─────────────────────────────────────────────────────────────┐
│  safeyolo-internal (no internet)                            │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Agent       │  │  App         │  │  Worker      │      │
│  │  Container   │  │  Container   │  │  Container   │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                 │                 │               │
│         └────────────────►│◄────────────────┘               │
│                           │                                 │
│                           ▼                                 │
│                  ┌────────────────┐                         │
│                  │   SafeYolo     │                         │
│                  │  172.30.0.10   │                         │
│                  │    :8080       │                         │
│                  └────────┬───────┘                         │
│                           │                                 │
└───────────────────────────┼─────────────────────────────────┘
                            │
                            ▼
                    ┌───────────────┐
                    │   Internet    │
                    └───────────────┘
```

## Setup

### 1. Start SafeYolo First

```bash
cd safeyolo
docker compose up -d
```

This creates the `safeyolo-internal` network.

### 2. Configure Project Containers

In your project's `docker-compose.yml`:

```yaml
services:
  myapp:
    # ... your config ...
    networks:
      - safeyolo-internal
    environment:
      - HTTP_PROXY=http://172.30.0.10:8080
      - HTTPS_PROXY=http://172.30.0.10:8080
      - NO_PROXY=localhost,127.0.0.1,172.30.0.0/24

networks:
  safeyolo-internal:
    external: true
```

### 3. Mount CA Certificate

For HTTPS inspection, containers must trust SafeYolo's CA:

```yaml
services:
  myapp:
    volumes:
      - safeyolo-certs:/certs:ro
    # In your entrypoint or Dockerfile:
    # cp /certs/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/safeyolo.crt
    # update-ca-certificates

volumes:
  safeyolo-certs:
    external: true
```

## Verification

Test that bypass is impossible:

```bash
# From inside a project container:

# This works (goes through proxy):
curl -x http://172.30.0.10:8080 https://httpbin.org/ip

# This fails (no route):
curl --noproxy '*' https://httpbin.org/ip
# Error: Could not resolve host / No route to host
```

## Security Properties

| Scenario | Result |
|----------|--------|
| Code respects `HTTP_PROXY` | Inspected by SafeYolo |
| Code ignores proxy vars | Connection fails (no route) |
| Code uses hardcoded IPs | Connection fails (no route) |
| Code tries DNS exfil | DNS fails (no resolver outside network) |
| Container-to-container | Works (same internal network) |

## When to Use This

**Use chokepoint mode when:**
- Running untrusted or AI-generated code
- You need audit logs of all egress
- Credential protection must be enforced, not optional

**Host proxy mode is fine when:**
- You control all code running on the machine
- Best-effort logging is sufficient
- You have other egress controls (firewall, VPN)

## Troubleshooting

**"No route to host" for legitimate requests:**
- Verify `HTTP_PROXY` is set correctly
- Check SafeYolo container is running: `docker ps | grep safeyolo`
- Verify network connectivity: `ping 172.30.0.10`

**SSL errors:**
- CA cert not installed - see mount instructions above
- Some tools need explicit cert path: `--cacert /certs/mitmproxy-ca-cert.pem`

**Container can't resolve DNS:**
- Internal network has no DNS by default
- Either use IP addresses or configure DNS to resolve through proxy
