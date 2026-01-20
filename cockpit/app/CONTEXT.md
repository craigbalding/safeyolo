# Context Loading Order
1. ../agents.md - Critical context for the 'Cockpit' scope which includes the current 'app' 
2. ./agents.md - Specific context governing the Wails3 'app' (a module of the scope)
3. Other context files according to the instructions of discovery defined by the above ones.
4. ./agents.memory.md - persistant memory collected during the previous sessions
5. /agents.md - the root context explaining the superscope, not critical for most tasks unless otherwise instructed

Ignore /CLAUDE.md if present