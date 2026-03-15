---
name: standards
description: Review uncommitted changes against CLAUDE.md coding and testing standards, then fix violations via refactoring only
disable-model-invocation: false
allowed-tools: Bash, Read, Edit, Grep, Glob
---

Review all uncommitted changes (staged + unstaged + untracked) against the coding and testing standards defined in CLAUDE.md, then fix any violations.

## Steps

1. **Read CLAUDE.md** to load the current standards. CLAUDE.md is the single source of truth — do not hardcode rules here.
2. **Identify changed files**: run `git diff --name-only` (unstaged), `git diff --cached --name-only` (staged), and `git ls-files --others --exclude-standard` (untracked). Merge into a single list. Include all file types — code snippets in plans or ADRs should also respect coding standards.
3. **Read each changed file** and check it against every applicable standard from CLAUDE.md.
4. **Fix every violation** by editing the files. Only refactor — no behavior changes. If a fix would change behavior, report it to the user instead of applying it.
5. **Run `uv run pyright` and `uv run pytest tests/unit`** only if fixes were applied, to verify nothing broke.
6. **Report** a summary of what was found and fixed. If nothing needed fixing, say so.

## Constraints

- Never change test assertions or production logic — refactoring only.
- If a file is too large to split, suggest the split to the user rather than doing it autonomously.
