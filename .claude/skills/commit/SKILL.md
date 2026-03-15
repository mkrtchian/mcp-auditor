---
name: commit
description: Stage all changes and create a conventional commit
disable-model-invocation: false
allowed-tools: Bash, Read, Grep, Glob
---

Create a git commit following the Conventional Commits specification.

- Format: `type(scope): description`
- Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, `style`
- Scope is optional but recommended (e.g., `docs(adr)`, `feat(graph)`, `fix(cli)`)
- Description in imperative mood, lowercase, no period at the end
- Add a body if the change is non-trivial
- If $ARGUMENTS is provided, use it as guidance for the commit message but still review the actual changes
