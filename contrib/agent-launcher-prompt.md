# Configure a host launcher with a coding agent

Use this prompt with an agent that can read your SafeYolo checkout. If it runs
inside SafeYolo, have it prepare the file for you to copy to the host; a launcher
must not remain in any guest-writable share.

> Help configure my SafeYolo agent launcher. Read docs/agent-launchers.md and
> contrib/agent-launcher-template.sh from this checkout. Ask which host terminal
> manager/session I use, whether I prefer windows or panes, and whether this
> should be the shared ordinary-agent default or a per-agent override. Ask about
> pre-launch, post-launch and actual-exit actions only if I want custom actions.
> First consider the built-in tmux presets: I may not need a script. Keep local
> foreground use in my current terminal and remote/background runs persistent
> on the SafeYolo host. Tailscale is the default remote route; support my SSH
> configuration or existing tunnels without making the agent depend on them.
> Preserve explicit manager/supervisor selection. Do not invent extra approvals,
> limits, restart policies or hook restrictions. Produce the smallest script and
> exact configuration commands needed for my choices. Prove new-launch, reuse,
> attach/disconnect and stop with a disposable agent before changing my defaults.
