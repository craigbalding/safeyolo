## Agents' logs / Agentic session tasks and plans summaries archive

> Recording details of tasks done and session plans aka `agents' logs`

## Main conventions

### Forbidden/unwanted behavior
The details stored in the `agent's logs` folder and files should not be used as context of agentic coding tasks or any other context performed by agents/models/tools, it's purely for processing by humans.
See the related section of ./unwanted-behavior.md .

### Location
On user's request summaries of tasks done and session plans should be placed in `_@dev/archive.agentic-plans-sessions` subfolder of the top directory of the relevant `module of this scope`.

### File Naming Pattern
Use the following format for task documentation files:

```
YYMMDD[a-z].<humanly telling name about task completed or planned>.[plan|done].md
```

**Components:**
- `YYMMDD`: Year, month, day (e.g., `260118` for 2026-01-18)
- `[a-z]`: Single lowercase letter identifier (use sequential letters if multiple tasks on same day)
- `[plan|done]`: Either `plan` (intended work) or `done` (completed work)
- `.<name>`: Short, humanly descriptive name (kebab-case, lowercase)

**Examples:**
- `260118a.bun-not-npm_and_vite-upgrade-to-7.done.md`
- `260118b.add-auth-flow.plan.md`
- `260120a.fix-bug-in-main.done.md`

### When to Use Each Type

Task documentation should not be created automatically. Only when the user (or a ci/cd or similar entitled external facility) prompted to create one or update it.

#### `.plan` Files
Plan files are created **before** starting implementation, when the user asked for creating one and:
- Task is complex and requires planning
- Multiple approaches need evaluation
- Changes span multiple files/modules
- Breaking changes are involved
- Future reference needed for intended approach

**Plan file contents should include:**
- Summary of intended work
- Proposed approach/implementation strategy
- Files expected to be modified
- Potential risks or edge cases
- Dependencies on other work

#### `.done` Files
Done files are created **after** completing work when the user asked for creating one and:
- Task is completed and verified
- Changes are tested and working
- Documentation should capture what was actually done
- Future reference needed for implementation details

**Done file contents should include:**
- Agent & Model Information (coding agent, model name, thinking effort level)
- Summary of what was accomplished
- Changes made (with file paths)
- Compatibility verification performed
- Tests completed
- Any notes, caveats, or decisions made

### Documentation Templates

#### `.done` Template:
```markdown
# <Task Title>

**Date**: YYYY-MM-DD
**Status**: ✅ Done

## Agent & Model Information

- **Agent**: Crush (Coding agent)
- **Model**: <Model Name>
- **Thinking Effort Level**: <Low|Medium|High>

## Summary

<Brief description of what was accomplished>

## Changes Made

### 1. <Category>
- **<file path>**:
  - Description of changes

### 2. <Category>
- **<file path>**:
  - Description of changes

## Verification

- ✅ <Test performed>
- ✅ <Test performed>

## Files Modified
- `<path>` (X lines changed)

## Notes
- Any important decisions, caveats, or observations
```

#### `.plan` Template:
```markdown
# <Task Title>

**Date**: YYYY-MM-DD
**Status**: 📋 Plan

## Summary

<Brief description of intended work>

## Proposed Approach

<High-level strategy for implementation>

## Implementation Steps

1. <Step description>
2. <Step description>
3. ...

## Files to Modify

- `<path>`: Reason for change
- `<path>`: Reason for change

## Potential Risks

- <Risk 1>
- <Risk 2>

## Dependencies

- <Any work or changes this depends on>
```

### Best Practices
- Always date documents (YYYY-MM-DD)
- Use descriptive task names in the filename
- Include agent/model info for context on how work was performed
- Document thinking effort level to indicate depth of analysis
- List all files modified for easy reference
- Capture verification steps performed
- Note any breaking changes or compatibility concerns
