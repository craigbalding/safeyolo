# Basic rules of coding the ts frontend

## Source files topology
- The main source code of the frontend app is in `./frontend/src`
- Additional sources are in:
    - `./frontend/bindings`
    - tbd
- Common parts of the ts app are in `./frontend/src/pieces`

## Organizing code
- Lets break code into smaller (30-400 loc) files, pieces
- Every code file we prefer to hold one main class or function with other blocks being satelites of that main piece
- Files comprising one package or complex component should be separated in a subfolder, or named in a manner like 'what-shouldve-been-the-subfolder-name.specific-name.ts'.
- Types can acompany the class or function, or may occupy a separate file.

## Coding conventions 
- Make sure to include 'TypeScript Standards' (typescript-standards.md) conventions
- Use 'nanonanostores' for state management and as a runtime js cross-component shared store

## HTML design
- Use Lit
- Do not use React or other framework unless explicitly instructed in case of a the given component or that imports are already present in the component
- Use '@patternfly/elements' as a component library with Lit