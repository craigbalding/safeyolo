# Rules of discovery

1. Context files other than the standard `agents.md` files in the hierarchy of `this scope` (that is the scope's top agents.md and the ones belonging to the relevant `modules of this scope`) should never be discovered or searched for automatically, instead follow the rule that all relevant context files are explicitly (and conditionally) referenced in this agents.md files hierarchy.

1. Instead of a self-contained conventional agents.md hierarchy and special folders with agentic rules (like /specs, /docs) we utilize the conventional hierarchy of agents.md-s extended by specialized context/conventions/instructions/guideline files (hereinafter: `specialized context files`/file) explicitly referenced in the relevant agents.md files. Which `specialized context files` are to be used/discovered conditionally according to the instructions given in the referring agents.md.

1. Unconditionally parse (read) the `specialized context files` identified by the `follow!` instruction.
    * The instruction format is `follow! [symbolic-path/to/file.md](relative/path/to/file.md)` or just `follow! [relative/path/to/file.md]`.
    * Treat the content of these referenced `specialized context files` as if they were directly embedded in the given agents file document.
        * The `follow!` instruction might narrow the context embedding with detailed instructions which parts or aspects of the referenced `specialized context file` to incorporate in the actual context of the session.
    * Treat the whole or explicitly narrowed down content of that external file as if it was inherent part of the content of the given agents.md file (or the inherited intermediary file and so of the agents.md file).

1. Also expect conventional references or instructions to include external context/conventions/guideline sources and process those adequately. 

1. As a general rule, a more specific specialized context overrides the instructions/conventions given by an upstream (agents) file when conflicting. But explicit rules guiding the evaluation in question might take precedence.
    * Behaviors forbidden on a higher level can not be unlocked by a downstream instruction/convention. For example our top level agents.md file always incorporates a `forbidden-behavior.md` instructions set, which means the latter is part of the high agent.md and no instruction in the downstream agents.md-s or `specialized context files` or any other source of context/instructions/conventions can overrule those prohibitions provided in the forbidden-behavior.md.

1. Never use files in `[dev]/planslog/` as context.

1. Shared guidelines should be referenced, not duplicated.
    * See the relevant section below
