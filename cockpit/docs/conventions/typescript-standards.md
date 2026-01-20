# TypeScript Standards

The following conventions apply to all typescript code (and to javascript code if relevant). 
Ignore when working on non-typescript or non-javascript code.

## Basics
- Load the relevant tsconfig.json and all upstream (extends) ts configs
  - take into account specifics of the given package manager or the runner regarding hoisting
- Normally use latest TypeScript syntax from 'latest'
- ESNext modules only (except explicitly marked exceptions)
- Resolution: 
  - Bundler for apps
  - NodeNext for libraries unless specified otherwise


## Coding style & imports
- When defining a function, class or similar where its name is proceeded by round parentheses, do add a space between the name and the parentheses
- Use template literals where appropriate
- Do not use semicolons when they are not necessary
- Prefer single quotes over double where technically possible
- When importing modules, first import external (node_modules or CND or located in the /vendor folder) modules (the standard ones and more specific ones then), then separate local imports with an empty line (the utility or other common ones and the ones specific to the given code file), then styles, then configs 
- Within external modules, list majors first (React, Tanstack, Stytch, Douyinfe, Lynxjs)
- Within local imports, list code and types imports first, followed by styles, then configs

### Commenting Rules
- If a comment explains line(s) above: prepend comment text with `^ ` (caret and space)
- If a comment explains line(s) below: start its text with a capital letter, end with a colon
- If a comment explains the given line: don't start its text with a capital letter
- Do not remove comments except when part of the removed code block
- Do not remove commented out code except when part of the removed code block
- Never remove commented out code from configuration files

## Syntax Requirements
- Enable strict mode
- No unused locals/parameters
- Use verbatim module syntax
- Use ESNext modules with bundler resolution

## Code Quality
- Strict type checking must be enabled
- All variables and parameters must be used
- Prefer explicit type annotations for public APIs
- Use const assertions where appropriate
