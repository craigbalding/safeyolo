# SafeYolo CLI

Command-line interface for managing the SafeYolo security proxy.

## Installation

```bash
# Recommended: pipx (isolated environment)
pipx install safeyolo

# Alternative: pip
pip install safeyolo
```

## Quick Start

```bash
# Initialize configuration in current directory
safeyolo init

# Start the proxy
safeyolo start

# View logs
safeyolo logs -f

# Check status
safeyolo status

# Stop the proxy
safeyolo stop
```

## Commands

### Setup

- `safeyolo init` - Initialize configuration in current directory
- `safeyolo start` - Start the proxy container
- `safeyolo stop` - Stop the proxy container
- `safeyolo status` - Show proxy status and statistics

### Logs

- `safeyolo logs` - View logs
- `safeyolo logs -f` - Follow logs in real-time
- `safeyolo logs --security` - Show only security events
- `safeyolo logs --raw` - Output raw JSONL

## Configuration

Configuration is stored in `./safeyolo/` (project-specific) or `~/.safeyolo/` (global).

```
safeyolo/
├── config.yaml          # Main configuration
├── rules.json           # Credential patterns
├── docker-compose.yml   # Generated compose file
├── logs/                # Audit logs
├── certs/               # mitmproxy CA certificate
├── policies/            # Approved credentials
└── data/                # Runtime data
```

## Requirements

- Python 3.10+
- Docker

## License

MIT
