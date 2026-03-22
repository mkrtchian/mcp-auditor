---
name: design-patrol
description: >-
  Launch 5 parallel review agents that each analyse 2 random project files in
  the spirit of Kent Beck and Eric Evans, then apply the clear-win
  refactorings.
user-invocable: true
disable-model-invocation: true
allowed-tools: Agent, Read, Edit, Bash, Glob
---

# Design Patrol — random design review

Two phases: 5 parallel agents **read and analyse** (no edits), then you (the
main agent) **apply** the clear-win refactorings. This avoids conflicting edits
on shared files.

## Phase 1 — Parallel review (read-only)

1. **Collect candidate files.** Use Glob to list all `src/**/*.py` and `tests/**/*.py` files. **Exclude `__init__.py` files** — they are package markers with no meaningful logic to review.
2. **Pick 10 random files.** Use a Bash one-liner (`shuf -n10`) to select 10 files at random from the list. If there are fewer than 10 files, use all of them.
3. **Launch 5 subagents in parallel** using the Agent tool. Assign 2 files to each agent (files 1-2 to agent 1, files 3-4 to agent 2, etc.). Each agent receives the following prompt:

   > Read CLAUDE.md to understand the project's architecture (hexagonal,
   > domain/graph inside, adapters outside) and coding philosophy.
   >
   > You are doing a **design review**, not a standards audit. Put yourself in the
   > mindset of **Kent Beck** and **Eric Evans**:
   >
   > - Beck asks: "Is this code as simple as it could be? Does it communicate its
   >   intent? Is there duplication that reveals a missing abstraction? Would I
   >   feel confident changing this code tomorrow?"
   > - Evans asks: "Does this code speak the language of the domain? Is there an
   >   implicit concept here that deserves a name? Is domain logic in the right
   >   place — inside the hexagon, not leaked into adapters or CLI?"
   >
   > You have 2 files to review, one after the other:
   > 1. `{file_path_1}`
   > 2. `{file_path_2}`
   >
   > For each file:
   > 1. Read it in its entirety.
   > 2. Read the **direct project imports** that are essential to understand the
   >    file's role (e.g. the domain models it uses, the port it implements).
   >    Don't chase the full import tree — just enough for context.
   > 3. Sit with the code. Ask yourself the Beck and Evans questions above.
   >    Don't scan for rule violations — **feel where the friction is**.
   >
   > **Do NOT edit any file.** Your output is a review report only.
   >
   > For each file, produce a short report:
   > - **File**: path
   > - **Verdict**: "well-designed" | "has improvement opportunities"
   > - **Insights** (only if verdict is not "well-designed"): For each insight,
   >   describe what you noticed, why it matters, and a concrete refactoring
   >   proposal. Classify each as:
   >   - **clear-win**: better name, concept extraction, logic moved to the right
   >     layer, duplication removed — safe to apply as-is.
   >   - **needs-discussion**: significant but ambiguous, trade-offs involved,
   >     risk of behavior change — flag for the user.
   >
   > Prefer **one well-chosen insight** over many small nitpicks. Quality over
   > quantity. If a file is well-designed, say so and move on.

## Phase 2 — Apply refactorings (you, the main agent)

4. **Collect the 5 review reports.** Separate **clear-win** insights from
   **needs-discussion** insights. Set the needs-discussion ones aside for the
   summary — do not act on them.
5. **Apply only the clear-win refactorings yourself**, one by one. For each:
   - Read the file(s) involved.
   - Apply the refactoring.
   - Verify it's purely structural — no behavior change.
   - If two insights conflict (e.g. both want to rename the same thing
     differently), pick the better one and note the conflict.
6. After all refactorings, run `uv run pyright` and
   `uv run pytest tests/unit -x` to verify nothing broke.
7. Do NOT commit anything.

## Phase 3 — Summary

8. **Summarize results.** Output a concise summary:
   - Which files were reviewed.
   - What clear-win refactorings were applied.
   - What needs-discussion items are flagged for the user's consideration.
