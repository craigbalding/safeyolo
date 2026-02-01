# Agent Extended Context aka Technical Patterns Documented

> Implementation details and session memories for AI agents continuing development.

This document should be used as a persistent memory for agents and models, so that discoveries made during development are recorded and used as context when visiting same issues or processing tasks where we can learn from previous iterations.
---

### USAGE:
- Create ## level entries for major topics, categorize materials in a reasonable hierarchy
- Update previous statements if there are more current discoveries or context regarding a previous discovery or memory
- Always stop before making a change in this text and let the human user decide regarding whether the proposed new knowledge or change worth recording

# Memories

## Session: Extension Development (Lit 3 + Chrome Extension MV3)

---

## Pattern 1: Lit 3+ Decorator Syntax

### Issue

Decorators without `accessor` keyword fail with modern Lit 3 and Web Component
specs.

### Solution

Always use `accessor` keyword with reactive property decorators:

```typescript
// ❌ WRONG (old syntax)
@state() private currentView: ViewType = 'archive'

// ✅ CORRECT (Lit 3+ syntax)
@state() accessor private currentView: ViewType = 'archive'
```

### Applies To

- `@state()` - Internal reactive state
- `@property()` - Public reactive properties
- Any class field decorator in Lit components

---

## Pattern 10: Efficient Investigation Workflow

### Issue

Launching agents and running multiple diagnostic commands causes massive context
growth (e.g., 33K → 67K tokens) during simple investigations.

### Solution

Always start with **direct file inspection** before launching agents:

```bash
# ✅ EFFICIENT - Direct inspection
view file_path  # Read the file directly
# Then check documentation if needed

# ❌ INEFFICIENT - Agent + many diagnostics
agent "find all deno config files"  # Launches separate process
# + 10+ bash commands
# + Test file creation/deletion
# + All outputs included in context
```

### Investigation Priority Order

1. **Direct `view`** - Read the actual file
2. **Direct `grep`/`glob`** - Search codebase efficiently
3. **External docs** - Check official documentation
4. **Agent tool** - Only for complex, multi-step searches requiring autonomous
   decisions

### Applies To

- Simple configuration investigations
- Finding specific files or patterns
- Checking tool options or formats
- Any diagnostic work before coding

---

## Summary Checklist

For future extension development:

- [ ] Use `accessor` keyword with all Lit 3 decorators
- [ ] Use agent tool only for complex multi-step searches

---

END OF PATTERNS DOCUMENT
