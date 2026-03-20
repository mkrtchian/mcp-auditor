# ADR 007: End-to-End Eval Case Export

**Date:** 2026-03-20
**Status:** Accepted

## Context

ADR 006 introduced a judge isolation eval with a dataset sourced from "observed false positives — extracted from eval runs." But the end-to-end eval report only stores aggregated verdicts per tool/category. There is no mechanism to extract individual cases.

In practice, judge eval cases are hand-crafted from what we imagine the generator produces. After several iterations, the judge eval reaches F1 = 1.00 on 28 curated cases — but end-to-end precision remains at 0.61 (threshold: 0.85). The curated cases do not represent what happens in the real pipeline.

ADR 006 rejected "Inline in the end-to-end eval" for two reasons: slow feedback loop and confounded signal. These reasons hold for *iterating on the judge prompt via the e2e eval*. They do not hold for *extracting cases from the e2e eval to feed the judge eval dataset*. The iteration loop stays in the judge isolation eval; the e2e eval becomes the data source.

## Decision

The end-to-end eval exports every judged case with full context to `evals/judged_cases.jsonl` alongside the existing `eval_report.json`. Each line contains everything the judge received and produced:

```json
{
  "run_index": 0,
  "tool_name": "execute_query",
  "tool_description": "Execute a SQL query against the database.",
  "category": "input_validation",
  "description": "Verify the tool rejects DROP TABLE statements",
  "arguments": {"query": "'; DROP TABLE users;--"},
  "response": "[db: /opt/mcp-server/config/database.yml] Executed: ...",
  "error": null,
  "verdict": "fail",
  "justification": "The tool accepted a destructive SQL statement without...",
  "expected_verdict": "pass",
  "correct": false
}
```

After an e2e run, misclassified cases (`"correct": false`) are reviewed and selectively promoted into `judge_cases.json`. Not every false positive is a judge problem — some are generator problems (misleading description, irrelevant payload). The human decides which cases are judge-attributable.

## Alternatives considered

### LangSmith tracing

ADR 006 mentions LangSmith for "observing graph runs, inspecting intermediate state." Tracing does capture the data, but it lives in an external service, requires manual inspection through a UI, and is not structured for programmatic extraction. Tracing is for ad-hoc debugging; case export is a recurring data pipeline.

### Separate capture script

A standalone script that runs a single e2e eval and dumps detailed cases, separate from `run_evals.py`. Rejected because it duplicates the pipeline — the e2e eval already runs the graph and has access to all the data. The export is a few lines on top of what exists.

## Consequences

- The e2e eval produces a second output file. This closes the feedback loop that ADR 006 assumed but did not implement: e2e run → case export → human review → judge eval dataset → prompt iteration → e2e run.
- The judge eval dataset evolves from hand-crafted to empirically grounded.
- The export also reveals generator problems. When a case is misclassified because the generator wrote a misleading description, that is visible — it just doesn't become a judge eval case.
- The `EvalResult` model must carry test case context (description, arguments, response/error) which is currently discarded after judging. This is the main implementation cost.
