# ADR 006: Judge Evaluation Strategy

**Date:** 2026-03-19
**Status:** Draft

## Context

ADR 003 defines three testing levels: unit tests (fakes, in-process), integration tests (real MCP server, no LLM), and evals (real LLM + real MCP server against a ground truth). The evals measure four metrics: recall, precision, consistency, and distribution coverage.

The eval results from ADR 005 reveal a structural problem: **precision fails on both evaluated models** (Haiku 4.5: 0.56, Flash-Lite: 0.61) against a threshold of 1.00. The false positives are consistent across runs and models, clustering into two patterns:

The false positives cluster into two patterns:

- **Category confusion** — the tool is genuinely vulnerable, but the judge assigns the wrong category. `execute_query` is vulnerable to injection, but the judge also flags it for `resource_abuse` (sees echoed SQL and over-generalizes) and `input_validation` (conflates lack of sanitization with validation). `get_user` crashes on unexpected input — that's `error_handling`, but the judge labels it `resource_abuse`.
- **Defense misread** — the tool defended correctly, but the judge interprets the defense as a vulnerability. `list_items` rejects invalid categories with `ValueError("Invalid category")` — correct validation, but the judge flags `input_validation`. Occasionally, the generic error message is over-interpreted as `info_leakage`.

| Tool            | Flagged category   | Runs | Pattern            |
|:----------------|:-------------------|:-----|:-------------------|
| `execute_query` | `resource_abuse`   | 3/3  | Category confusion |
| `get_user`      | `resource_abuse`   | 2/3  | Category confusion |
| `list_items`    | `input_validation` | 2/3  | Defense misread    |
| `execute_query` | `input_validation` | 1/3  | Category confusion |
| `list_items`    | `info_leakage`     | 1/3  | Defense misread    |

Both patterns appear on Haiku 4.5 and Flash-Lite alike — this points to the judge prompt, not the model.

**The end-to-end eval cannot diagnose this.** When precision drops, we cannot tell whether:
1. The generator produced payloads that elicit ambiguous responses (generator problem)
2. The judge misclassified clear responses (judge prompt problem)
3. The ground truth is wrong (labeling problem)

To fix the judge prompt, we need to evaluate it in isolation — known inputs, known expected outputs, fast iteration cycle.

## Decision

Add a **judge isolation eval** alongside the existing end-to-end eval. This is a second eval type within `evals/`, not a replacement.

### Dataset

A JSON fixture file at `evals/fixtures/judge_cases.json` containing cases of the form:

```json
{
  "tool_name": "list_items",
  "tool_description": "List items in a given category with an optional limit.",
  "category": "input_validation",
  "description": "Send invalid category to test input validation",
  "arguments": {"category": "../../etc/passwd", "limit": 10},
  "response": null,
  "error": "Invalid category",
  "expected_verdict": "pass"
}
```

Each case captures the exact inputs the judge receives (tool metadata, test case payload, tool response/error) and the expected verdict. The judge prompt is evaluated as a pure function: `(tool, test_case) → verdict`.

Cases are sourced from three places, in priority order:

1. **Observed false positives** — extracted from eval runs where the judge disagreed with the ground truth. These directly test known failure modes and are the most valuable cases.
2. **Observed true positives/negatives** — extracted from runs where the judge agreed with the ground truth. These serve as regression guards when iterating on the prompt.
3. **Synthetic edge cases** — hand-crafted cases for boundary conditions the honeypot doesn't cover (e.g., an error message that mentions a file path in a user-facing context, not in a stack trace).

The dataset starts at 15–25 cases covering the five known false positive patterns and grows as new failure modes surface.

### Eval script

`evals/run_judge_eval.py` loads the dataset, runs the judge prompt against each case using a real LLM, compares the verdict to `expected_verdict`, and produces a report.

How it differs from the end-to-end eval:

| Property              | End-to-end eval          | Judge isolation eval       |
|:----------------------|:-------------------------|:---------------------------|
| MCP server            | Required (subprocess)    | Not needed (fixtures)      |
| Generator involved    | Yes                      | No — payload is fixed      |
| Non-determinism       | Generator + judge        | Judge only                 |
| Time per run          | 2–3 minutes              | ~20 seconds (1 LLM call per case) |
| Feedback loop         | Slow — full pipeline     | Fast — prompt change → re-run |

### Metrics

The judge eval uses the same metric names as the end-to-end eval — precision and recall — so the relationship between the two is direct: when judge precision improves, end-to-end precision should improve too.

- **Precision** — of the cases the judge flagged as FAIL, how many have `expected_verdict: fail`? This is the metric that directly tracks the precision problem observed in end-to-end evals.
- **Recall** — of the cases where `expected_verdict` is FAIL, how many did the judge flag as FAIL?
- **F1** — harmonic mean of precision and recall. Single summary metric for prompt iteration.
- **Confusion matrix** — full TP/FP/TN/FN counts for detailed analysis.
- **Per-category breakdown** — precision and recall per `AuditCategory`, to surface which categories the prompt handles poorly.

### Threshold

Target F1: **0.90** initially (on a 20-case dataset, this allows roughly 2 misclassifications). This is a prompt iteration target, not a release gate. The end-to-end eval (ADR 003) remains the acceptance gate for the system as a whole. The target should increase as the dataset grows and the prompt matures.

## Alternatives considered

### LangSmith Datasets + Evaluators

LangSmith provides a managed dataset store and evaluator framework with a comparison dashboard. Rejected because:

- **Vendor lock-in.** The dataset and eval logic would live in a proprietary service, not in the repo.
- **Not CI-friendly.** Requires network access and a LangSmith account to run.
- **Overkill.** The judge eval is a loop: load fixtures, call LLM, compare verdicts. A ~50-line script does this without a framework.

LangSmith remains useful for **tracing** (observing graph runs, inspecting intermediate state). Tracing and evaluation are separate concerns — this ADR does not affect tracing.

### promptfoo

Open-source, YAML-driven eval framework with provider-agnostic assertions. Rejected because:

- **Node.js dependency.** The project is Python-only. A Node.js tool adds friction and a separate dependency tree.
- **Configuration overhead.** promptfoo's YAML config and assertion syntax add indirection. A Python script is more direct for this scope.

### DeepEval / Ragas

Python-native GenAI eval frameworks with built-in semantic metrics. Rejected because:

- **Wrong abstraction.** Designed for RAG pipeline evaluation (faithfulness, relevance, cosine similarity). The judge eval is binary classification — a confusion matrix, not embedding distance.
- **Heavy dependencies.** Both pull in torch/transformers, irrelevant for pass/fail verdict comparison.

### Inline in the end-to-end eval

Capture judge inputs/outputs during end-to-end runs and analyze false positives post-hoc. Rejected because:

- **Slow feedback loop.** Every prompt iteration requires a full pipeline run (2–3 minutes).
- **Confounded signal.** The generator produces different payloads each run, so the judge is evaluated on different inputs every time. A prompt change that improves accuracy could be masked by a generator run that produces harder-to-classify responses.

## Consequences

- `evals/` gains a second eval type: `run_judge_eval.py` alongside `run_evals.py`. The end-to-end eval remains unchanged.
- `evals/fixtures/` is a new directory containing the judge dataset. These fixtures are maintained artifacts — they must be updated when the judge prompt changes in ways that redefine what PASS/FAIL means.
- The precision problem becomes actionable: iterate on `build_judge_prompt()` in `graph/prompts.py`, run `run_judge_eval.py` (~20s), check accuracy. When accuracy is satisfactory, confirm with the full end-to-end eval.
- The testing pyramid from ADR 003 gains a sub-level within evals: **judge isolation** (fast, fixed inputs, single LLM call) below **end-to-end** (slow, full pipeline, non-deterministic inputs). This mirrors the unit/integration split — isolate components before testing the system.
- The dataset doubles as documentation: it captures what the judge should and should not flag, with concrete examples.
