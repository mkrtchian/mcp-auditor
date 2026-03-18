---
name: patrol
description: >-
  Launch 5 parallel subagents that each pick 3 random project files and review
  them against every coding and testing standard from CLAUDE.md, fixing
  violations via refactoring only.
user-invocable: true
disable-model-invocation: true
allowed-tools: Agent, Read, Bash, Glob
---

# Patrol — random standards sweep

Launch 5 subagents in parallel. Each one picks 3 different random files from the
project and audits them sequentially, rule-by-rule against the coding and
testing standards defined in CLAUDE.md.

## Steps

1. **Collect candidate files.** Use Glob to list all `src/**/*.py` and `tests/**/*.py` files. **Exclude `__init__.py` files** — they are package markers with no meaningful logic to review.
2. **Pick 15 random files.** Use a Bash one-liner (`shuf -n15`) to select 15 files at random from the list. If there are fewer than 15 files, use all of them.
3. **Launch 5 subagents in parallel** using the Agent tool with `subagent_type: "spec-driven-dev:sdd-standards-enforcer"`. Assign 3 files to each agent (files 1-3 to agent 1, files 4-6 to agent 2, etc.). Each agent receives the following prompt:

   > Read CLAUDE.md to load the current coding and testing standards.
   >
   > You have 3 files to review, one after the other:
   > 1. `{file_path_1}`
   > 2. `{file_path_2}`
   > 3. `{file_path_3}`
   >
   > For each file, read it in its entirety, then go through **every**
   > applicable standard from CLAUDE.md, one by one, and check whether the
   > file respects it. For each standard:
   > - State the standard name/rule.
   > - State whether the file complies or not.
   > - If it does not comply, fix the violation by editing the file.
   >
   > Finish each file completely before moving to the next.
   >
   > Constraints:
   > - **Refactoring only** — no behavior changes. If a fix would change behavior,
   >   report it instead of applying it.
   > - Never change test assertions or production logic.
   > - If a file is too large to split, report it to the user rather than doing it.
   > - After all fixes on all three files, run `uv run pyright` and
   >   `uv run pytest tests/unit -x` to verify nothing broke.
   > - Do NOT commit anything.

4. **Summarize results.** After all 5 agents complete, output a concise summary:
   which files were reviewed, what was fixed, and what was flagged but not auto-fixed.
