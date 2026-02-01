# Persistent agentic memory aka Critical learnings

With the term `agentic memory file` we refer to any `agents.memory.md` named file of a given module within the relevant `modules of this scope`:
    - This term is automatically applicable to the agentic memory file that resides at the top folder of the package, submodule, module or shared library which is the main subject of the current session as defined by the user/human.
    - In course of operation we might encounter other modules, shared libraries, etc of `this scope` which belong to the context of the current task and have an agentic memory file, and so those are subjects to the given rules as well if there's relevant to the current task knowledge in them.
    - Similarly named files in other scopes are not to be modified.

## Rationale 

Sometimes we learn important context by trial and error. When the agent/model driven session discovers particular ways of proper implementation in the context of the given API behaviors, correct parameter formats, or other implementation details or methods through testing, that might belong to and be recorded in the relevant `agents.memory.md` as a **persistent context**. This might be essential for future sessions to avoid repetitive mistakes or spending tokens on resolving complicated questions already answered.

## What knowledge belongs here

Duh, critical learnings means substantial or very important for subsequent agentic sessions information or methods, so it's not about taking notes and the blahblah llm-based tools tend to generate along valuable information. Knowledge we want to persist is like:
    * Undocumented details that we learnt by testing and trial/errors.
    * Details that we construed from processing multiple sources (expensive queries and thinking).
    * Details deemed worth memorizing by the user.

## Exclusions

* We do not want to bloat the agentic memory file with information that can be easily gathered as texts from other sources in the repo or texts from external sources obviously belonging to the subject of the task.
* We do not bloat persistent memory with stuff (derivative knowledge) that we anytime can reconstruct from primary pieces of knowledge we had to record.

## Approach to recording

* Record knowledge in minimalist form
* Do not make obvious comments
* Do not take notes here, only valuable details and hints

## Rules

### Collecting/marking/recording/updating

1. In the context of the current session we constantly generate valuable information:
    * Let's try marking parts of the context as candidates for memorization.
    * Try not to compress the parts of context marked as memorization candidates.

2. The main rule regarding recording and updating marked context as persistent memory is that modification of the `agents.memory.md` files can only be done when the user/human instructs to doing so.


### Retrieval and usage

* The main rule regarding using the contents of an `agents.memory.md` file is to pick stuff relevant in the context of the current task knowledge (and ignore the rest).

