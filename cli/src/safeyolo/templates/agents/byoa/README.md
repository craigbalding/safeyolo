# BYOA - Bring Your Own Agent

Boots into a bash shell inside the SafeYolo sandbox. No agent is pre-installed —
use mise to install your preferred coding agent or tools.

## Quick Start

1. Ensure SafeYolo is running: `safeyolo status`
2. Add agent: `safeyolo agent add myagent byoa`
3. Start: `safeyolo agent start myagent`
4. Inside the VM, install your agent via mise

## Why BYOA?

Use this template when:
- Your agent isn't covered by the built-in templates
- You want to test a new agent inside the sandbox
- You need a generic sandboxed development environment
