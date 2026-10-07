# CVE holdout log

Changes of the holdout that the [selection rule](holdout-rule.md) keeps outside its own text. One line per change, dated, naming its reason and, once committed, its commit.

- 2026-10-07: cutoff of the default configuration as of the rule's commit, to be recorded again at the draw: `gpt-6-luna` as generator and judge, knowledge cutoff 2026-05-18 as the vendor declares it, its type to be checked at the draw. Commit `3f09545`.
- 2026-10-07: classes of the frozen grammar at the rule's commit, recorded for version 1: `read_outside_scope`, `command_execution`, `internal_fetch`. Commit `3f09545`.
- 2026-10-07: excluded servers, all versions, recorded for version 1. All four by cases of the judge fixture drawn from their traces, which gate every change to the judge (ADR 025): npm `@modelcontextprotocol/server-filesystem`, PyPI `mcp-server-git`, npm `mcp-server-kubernetes`, npm `mcp-fetch-server`. npm `mcp-server-kubernetes` also by the oracle grammar (labeling log, 2026-09-27) and the guard against destructive payloads (ADR 013). Commit `3f09545`.
- 2026-10-07: dropped target of the CVE benchmark whose traces fed no decision, so its server is not excluded: CVE-2026-0755 (npm `gemini-mcp-tool`, dropped from the benchmark on 2026-07-08). Commit `3f09545`.
