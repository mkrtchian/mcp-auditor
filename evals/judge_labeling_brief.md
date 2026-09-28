# Judge isolation fixture: labeling brief

The drawn judge cases (`evals/fixtures/judge_cases_drawn.json`) are labeled one by one by a human, with an assistant under this brief. The label says whether the tool's response or error shows a failure, planted or not, in the category tested, and it cites the rubric clause that decided it (the rubric entry of `docs/labeling-log.md`). The label must not depend on what the judge said or on what the source cell expects ([ADR 025](../docs/adr/025-judge-eval-drawn-fixture.md)). This brief is committed before the draw, and the assistant is given it at the start of the labeling session.

## What the assistant may show and explain

- The case's judge inputs: tool name and description, category, payload description, arguments, response and error.
- The code of the server that answered, with its comments removed. The honeypots' comments name the planted flaws, and so name the source cell's label.
- The published mechanism of a CVE, for a case drawn from a CVE target.
- The definition of the category tested, as the rubric gives it.
- The rubric and its clauses.

It may explain what the response shows, what the code does with the arguments, and what a clause means.

## What it never shows or infers

- The judge's verdict or justification, from any export, report or trace.
- The source cell's label in the ground truth (`evals/ground_truth.py`), or whether the cell is planted.
- The `correct` field and the run index.
- Anything read from the judge prompt (`src/mcp_auditor/graph/prompts.py`) or the category guidance (`src/mcp_auditor/domain/category_guidance.py`).

If the labeler asks for one of these, the assistant declines and says which rule of this brief applies.

## It never proposes a label

The assistant never proposes, ranks or hints at a label or a clause, including by saying which way a case "looks". The labeler decides, and writes the label and the clause in the drawn file. A case the rubric cannot decide is labeled `unspecified`, and the assistant does not argue it into `pass` or `fail`.

## What the labeling log records

The labeling log entry of the swap commit records about the assisted labeling:

- That the labeler was assisted, by which model, under this brief.
- What the labeler already knew of the verdicts and of the cells before labeling (the honeypot flaws, the cases of the legacy fixture, the judge traces already read).
- The questions asked of the assistant, or a faithful summary of them, and any request it declined.
