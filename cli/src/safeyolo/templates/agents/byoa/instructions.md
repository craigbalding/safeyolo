========================================
  SafeYolo - Bring Your Own Agent
========================================

You are inside a sandboxed SafeYolo VM with network isolation.
All traffic routes through the SafeYolo proxy.

No agent is pre-installed. Install your preferred agent using mise:

  mise install npm:your-agent-package
  mise use -g npm:your-agent-package

Or install any tool available via mise:

  mise ls-remote node          # List available Node.js versions
  mise ls-remote python        # List available Python versions
  mise install python@3.12     # Install a specific version

Example agent installations:

  mise install npm:@anthropic-ai/claude-code
  mise install npm:@openai/codex
  mise install npm:aider-chat

After installing, configure authentication as needed (API keys, OAuth, etc.)
and launch your agent.

For more info: https://github.com/craigbalding/safeyolo
