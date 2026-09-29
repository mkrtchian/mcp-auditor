# Judge isolation fixture: labeling brief

The drawn judge cases (`evals/fixtures/judge_cases_drawn.json`) are labeled one by one by a human, with an assistant under this brief. The label says whether the tool's response or error shows a failure, planted or not, in the category tested, and it cites the rubric clause that decided it (section "Judge cases" of the rubric in `docs/labeling-log.md`). The label must not depend on what the judge said or on what the source cell expects ([ADR 025](../docs/adr/025-judge-eval-drawn-fixture.md)). This brief is committed before the draw, and the assistant is given it at the start of the labeling session.

## What the assistant may show and explain

- The case's judge inputs: tool name and description, category, payload description, arguments, response and error.
- The code of the server that answered, with its comments removed. The honeypots' comments name the planted flaws, and so name the source cell's label.
- The published mechanism of a CVE, for a case drawn from a CVE target, read from its NVD entry and its GitHub advisory only (rubric clause J10).
- The definition of the category tested, as the rubric gives it.
- The rubric and its clauses.

It may explain what the response shows, what the code does with the arguments, and what a clause means. It presents every case in the same order (tool name and description, category, payload description, arguments, response, error), and says which of the response and the error holds text, for instance "the response is empty, the text is in the error field".

## What it never shows or infers

- The judge's verdict or justification, from any export, report or trace.
- The source cell's label in the ground truth (`evals/ground_truth.py`), or whether the cell is planted.
- The `correct` field and the run index.
- Anything read from the judge prompt (`src/mcp_auditor/graph/prompts.py`) or the category guidance (`src/mcp_auditor/domain/category_guidance.py`).

If the labeler asks for one of these, the assistant declines and says which rule of this brief applies.

## It never proposes a label

The assistant never proposes, ranks or hints at a label or a clause, including by saying which way a case "looks". The labeler decides, and writes the label and the clause in the drawn file. A case the rubric cannot decide is labeled `unspecified`, and the assistant does not argue it into `pass` or `fail`.

## Independent labelers

Once the maintainer has labeled every case, two agents label every case again, each on its own: one on Claude Opus 5.5 and one on Claude Fable 5.1, at their highest reasoning effort. Each starts in a fresh session, with every drawn case, its label and clause fields empty, the rubric, and the material this brief lets the assistant show. Neither sees the maintainer's labels, the other agent's labels, or anything this brief forbids. Each returns, for every case, a label, the clause that decided it, and its reason in a few sentences. They are labelers, not the assistant, so the rule that the assistant never proposes a label does not bind them.

Every case where one agent or both disagree with the maintainer is examined again from the judge inputs and the rubric. The maintainer sees the labels, clauses and reasons of both agents, given in the same form, and keeps or changes the label. Each disagreement is filed under one cause: the maintainer's label was wrong and changes, the agent's label was wrong and the maintainer's stays, the clause allows two answers, or the clause decides the case unambiguously but wrongly. A clause that allows two answers is revised and applied again to every case. A case a clause decides wrongly keeps the label the clause gives and is listed as a known disagreement, as the rubric says.

## What the labeling log records

The labeling log entry of the swap commit records about the labeling:

- That the labeler was assisted, by which model, under this brief.
- What the labeler already knew of the verdicts and of the cells before labeling (the honeypot flaws, the cases of the legacy fixture, the judge traces already read).
- The agreement before review between each pair of labelers (the maintainer and each agent, and the two agents), which measures how far the labels depend on the labeler.
- How many labels the maintainer changed in review, and toward which agent's label, if any.
- How many disagreements fall under each cause: the maintainer's label wrong, the agent's label wrong, a clause that allows two answers, a clause that decides wrongly.
- The agreement after review, as the final state of the labels and not as a measure of their reliability.
