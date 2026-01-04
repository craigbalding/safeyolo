# Service Discovery

SafeYolo uses service discovery to identify which project is making each request,
enabling per-project credential policies.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                       HOST (your machine)                     │
│                                                               │
│  ┌─────────────────────┐        ┌─────────────────────────┐  │
│  │     safeyolo CLI    │        │    services.yaml        │  │
│  │                     │───────▶│                         │  │
│  │  - agent add        │ writes │  claude-code:           │  │
│  │  - agent run        │        │    ip: 172.31.0.20      │  │
│  └─────────────────────┘        │  openai-codex:          │  │
│                                 │    ip: 172.31.0.21      │  │
│                                 └─────────────────────────┘  │
│                                           │                   │
│                                           │ mounted           │
│                                           ▼                   │
│  ┌────────────────────────────────────────────────────────┐  │
│  │               safeyolo container                        │  │
│  │                                                         │  │
│  │  service_discovery.py reads services.yaml               │  │
│  │  Maps IP → project for credential isolation             │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

## How It Works

**Managed Users (CLI):**
1. `safeyolo agent add claude-code` assigns static IP (172.31.0.20)
2. Writes entry to `~/.safeyolo/data/services.yaml`
3. Agent container gets static IP via docker-compose
4. SafeYolo reads services.yaml to map IP → project

**Integrated Users (Pro Teams):**
1. Provide your own `services.yaml` with IP ranges
2. Mount to `/app/data/services.yaml` in container
3. No CLI dependency

## Configuration

### services.yaml

Located at `~/.safeyolo/data/services.yaml` (managed by CLI) or mounted to `/app/data/services.yaml`.

```yaml
services:
  # Exact IP mapping (managed users)
  claude-code:
    ip: "172.31.0.20"
    project: claude-code

  # IP range mapping (pro teams)
  backend-services:
    ip_range: "10.0.1.0/24"
    project: backend-team

  ml-cluster:
    ip_range: "10.0.2.0/24"
    project: ml-team
```

### Static IP Allocation

The CLI assigns static IPs from the `172.31.0.0/24` subnet:

| Agent | IP |
|-------|-----|
| safeyolo proxy | 172.31.0.10 |
| claude-code | 172.31.0.20 |
| openai-codex | 172.31.0.21 |
| (custom agents) | 172.31.0.22+ |

## Lookup Priority

1. **Exact IP match** - Check if IP is in services.yaml
2. **IP range match** - Check if IP falls within any `ip_range`
3. **Default** - Return "default" project

## Pro Team Integration

For teams with existing infrastructure, you can bypass the CLI entirely:

```yaml
# Custom services.yaml
services:
  # Kubernetes pods
  k8s-agents:
    ip_range: "10.244.0.0/16"
    project: k8s-cluster

  # EC2 instances
  aws-workers:
    ip_range: "172.16.0.0/12"
    project: aws-team

  # Development machines
  dev-team:
    ip_range: "192.168.1.0/24"
    project: developers
```

Mount this file to `/app/data/services.yaml` when running the safeyolo container.

## Docker Access Requirements

The CLI requires Docker access to manage agent containers:

```bash
# Check if you have Docker access
safeyolo setup check

# If needed, add yourself to docker group
sudo usermod -aG docker $USER
newgrp docker  # or log out and back in
```

The SafeYolo container itself does NOT need Docker socket access. It only reads
the static `services.yaml` configuration.

## Troubleshooting

### All requests show "default" project

1. Check services.yaml exists: `cat ~/.safeyolo/data/services.yaml`
2. Verify IP mapping matches your container's IP
3. Restart safeyolo to reload config

### Agent container can't reach SafeYolo

1. Verify both are on the `safeyolo-internal` network
2. Check agent has correct static IP assigned
3. Verify proxy environment variables are set

### Custom agent not discovered

1. Run `safeyolo agent add <name>` to register it
2. Or manually add to services.yaml with correct IP
