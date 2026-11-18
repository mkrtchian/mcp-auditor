# Bounded tool responses in prompts, and per-run status in the nuisance run

## Context

An MCP tool can return an arbitrarily large response: a database query that returns a whole table, a file read in full, a log dump. The auditor copies the raw text of a tool response or error into five prompts with no bound: the judgment of a test case, the context extraction (every response of the tool in one prompt), the chain judgment, the chain step observation and the chain step planning. The chain planning prompt cuts a response to 200 characters, but copies each error whole.

Two defects follow from it.

1. **A prompt longer than the model's context window ends the whole audit.** The provider rejects the request (HTTP 400, a `ContextOverflowError` in the LangChain integrations of Anthropic, OpenAI, Google and Fireworks; Alibaba's overflow message, "Range of input length should be [1, xxx]", matches none of `langchain_openai`'s patterns and stays an `OpenAIInvalidRequestError`). `LLM._call_once` re-raises it, `call_model` does not catch it, and the exception leaves the graph: one tool with a large response costs the audit of every tool. The CVE benchmark suites classify it as a transient provider error and audit the server again, three times, then leave it out of N. The nuisance run of 2026-11-18 lost the ArcadeDB server that way (`AnthropicContextOverflowError` at its three audit attempts of one run) and met the same error on desktop-commander, token-optimizer and dbt-mcp. The holdout run of 2026-11-17 met it twice on one target, whose next audit attempts passed.
2. **A response just under the window passes and costs a great deal.** A prompt of close to a million tokens costs about 0.50 $ on Claude Haiku 5.5, whose input price rises above 100 000 tokens, against about 0.0005 $ for an ordinary call. The judge does not need megabytes to decide: what it has to see (an error, a leak, a value) holds in a few lines, and a huge response drowns it.

The fix bounds every tool response and error at 20 000 characters before it enters a prompt, keeping its start and its end around a marker that says how much was cut. The bound comes from the largest prompt the auditor builds: the context extraction copies up to 10 responses (the default test budget), so 200 000 characters at most, about 80 000 tokens at the 2.5 characters per token Anthropic gives for the tokenizer of Claude Haiku 5.5 (1M tokens for about 2.5M characters). That stays inside the base price tier of Claude Haiku 5.5 (100 000 tokens) and inside the smallest context windows in current use (128 000 tokens). The responses the instruments record are far below it (the longest response of the judge cases is 435 characters, and `tests/honeypot_server.py` caps its rendered rows at `MAX_RESPONSE = 2_000`), so no gated prompt changes.

A prompt the provider still rejects for its length (a huge tool description, a small window) becomes a missed model call with a new cause, `prompt_too_long`, as a refusal or an unreadable answer already does: the audit goes on, the report names the call, `--ci` exits 3.

The same change gives the nuisance run what the holdout run already prints after each run of a target: one line per run of a server with its status, here flagged or not flagged, and how many runs are done out of the total. Today the nuisance run prints nothing on an audit that succeeds, so a run of fifteen hours shows no result until its end, and a run stopped early leaves none. The nuisance suite rule (Reading) says the status per run spends nothing.

The help text of `run_nuisance run --runs` still says "default 3" while `NUISANCE_RUNS` is 2: it is corrected in passing.

### Where the change lands, and why (ADR 016)

The bound and the new missed-call cause are a change to the system under test. They were found through provider errors in the harness log of a nuisance run, not through a score, and no number was read to choose them. Their justification holds once every mention of a measurement is deleted: an MCP server can return a response of any size, a prompt larger than the model's window makes the whole audit fail for every tool, and a prompt of a million tokens costs a thousand times an ordinary call for no gain in what the model can judge. The commit message of that change answers the four questions of ADR 016.

The suites' handling of `prompt_too_long` and the nuisance run's per-run line are instrument changes. The first changes which runs count as incomplete, so it gets an entry in `docs/labeling-log.md`, in `docs/detection-suite-log.md` and in `docs/nuisance-suite-log.md`. The second changes what a run prints, never what it grades.

No rule version is opened and the rules' text is not touched. Both rules, under Run conditions and statistic, speak of a model call the model provider refused (the nuisance suite rule adds one that came back unreadable), and send an audit that ends on any other error to its retries. The suites already read an unreadable answer as the detection suite rule's refused model call. A prompt the model provider rejects for its length no longer ends the audit on an error: the audit ends with a report that holds a missed model call, and both suites read it as they read an unreadable answer. Each suite log entry states this reading of its rule.

## Approach

1. A pure domain function bounds a text shown to a model, and a second one counts the responses and errors of a report that exceed the bound.
2. The six prompt builders that show a tool response or error (the five above, plus the errors of the chain planning prompt) render every one through that function. The three copies of "JSON-dump a dict response, else `str()`" (two in `graph/prompts.py`, one in `graph/chain_prompts.py`) become one domain function, so the rendering of a response under the bound stays byte-for-byte what it is today.
3. The LLM adapter turns `langchain_core.exceptions.ContextOverflowError` into a new domain exception, `PromptTooLong`, and `call_model` turns that into a missed model call of cause `prompt_too_long`.
4. The product report names the cut responses per tool; the JSON report carries their count per tool; the suites count them per run in their server health, which stays report-only.
5. The suites treat `prompt_too_long` as they treat an unreadable answer.
6. The nuisance run prints one status line per run of a server, with its progress.

## Files to modify

### Domain

**New `src/mcp_auditor/domain/shown_response.py`**

```python
MAX_SHOWN_LENGTH = 20_000  # characters of one tool response or error a prompt shows

def rendered_response(response: dict[str, Any] | str) -> str: ...
def shown_to_model(text: str) -> str: ...
def is_cut(text: str) -> bool: ...
def cut_responses(tool_report: ToolReport) -> int: ...
```

- `rendered_response` is the rendering the prompts use today: `json.dumps(response)` for a dict, `str(response)` otherwise. It replaces the three inline copies (`_format_cases_for_extraction` and `_format_outcome` in `graph/prompts.py`, `_format_single_step_summary` in `graph/chain_prompts.py`). Its parameter is `str | dict[str, Any]`, the non-`None` part of `TestCase.response` (`str | dict[str, Any] | None`). `ChainStep.response` is `str | None`, so a chain step's response needs no rendering: `_format_chain_history` and `_format_latest_outcome` pass it to `shown_to_model` as is.
- `shown_to_model(text)` returns `text` unchanged when `len(text) <= MAX_SHOWN_LENGTH`. Otherwise it returns the first `MAX_SHOWN_LENGTH // 2` characters, then `\n[{cut} characters cut by mcp-auditor]\n` (`[1 character cut by mcp-auditor]` when `cut == 1`), then the last `MAX_SHOWN_LENGTH - MAX_SHOWN_LENGTH // 2` characters, where `cut = len(text) - MAX_SHOWN_LENGTH`, written as a plain integer. The marker follows the wording of the redaction marker (`[value of NAME, redacted by mcp-auditor]`) so a reader of a prompt recognizes it as the auditor's.
- `is_cut(text)` is `len(text) > MAX_SHOWN_LENGTH`.
- `cut_responses(tool_report)` counts, across the tool's test cases and the steps of its chains, every response (through `rendered_response`) and every error for which `is_cut` holds. A blocked test case has no response and counts nothing.

`shown_response.py` imports `ToolReport` from `domain/models.py` at module level. `models.py` reaches it the way `JudgeResult.owasp` reaches `domain/owasp.py`: a local import inside the computed property, so no import cycle forms.

**`src/mcp_auditor/domain/models.py`**

- `MissCause` gains `PROMPT_TOO_LONG = "prompt_too_long"`.
- `ToolReport` gains a pydantic `@computed_field` `cut_responses: int` that returns `shown_response.cut_responses(self)` (local import, as `JudgeResult.owasp` does), so the JSON report carries it per tool. Pydantic ignores unknown fields on validation by default, and no model of `domain/models.py` sets `extra="forbid"` (checked), so a JSON report dumped with the field still loads (an export read back by `evals/draw_judge_cases.py`, `AuditReport.model_validate_json` in `test_models.py`). The LangGraph checkpoint of a resumed audit rebuilds a pydantic model with `cls(**model_dump())` (`langgraph/checkpoint/serde/jsonplus.py`), which ignores the extra key the same way, as it already does for `JudgeResult.owasp`.

**`src/mcp_auditor/domain/ports.py`**

```python
class PromptTooLong(Exception):
    """The provider rejected the prompt as longer than the model's context window."""

    def __init__(self, usage: ProviderUsage): ...
```

It carries the usage of the call so far (the throttled requests counted before the rejection), as `ProviderRefusal` does. It carries no provider message: the message of a context overflow quotes token counts, and nothing in the report needs it. Its `__init__` calls `super().__init__("the model provider rejected the prompt as longer than the model's context window")`, worded as `ProviderThrottled`'s "the model provider throttled the request past every retry": without it `str()` of the exception is the repr of its usage, which is what a judge eval crash and the model probe's error text would print.

**`src/mcp_auditor/domain/rendering.py`**

- `MISS_CAUSE_LABELS` gains `MissCause.PROMPT_TOO_LONG: "Prompt longer than the model's context window"`.
- The tool section adds, after the coverage gap and the missed calls of the tool, `**Responses shown cut**: {n} response(s) or error(s) over 20,000 characters, shown to the model with their middle cut` when `tool_report.cut_responses > 0`. The number in the text is `f"{MAX_SHOWN_LENGTH:,}"`: `rendering.py` formats no number with a separator today, and the repository's English text and `console.py` (`{usage.input_tokens:,}`) use the comma.

**`src/mcp_auditor/progress.py`**

- `UNJUDGED_LINES` gains `MissCause.PROMPT_TOO_LONG: "  ? not judged, the prompt was longer than the model's context window"`.

### Graph

**`src/mcp_auditor/graph/prompts.py`**

- `_format_cases_for_extraction`: `Response:` shows `shown_to_model(rendered_response(case.response))`, `Error:` shows `shown_to_model(case.error)`.
- `_format_outcome` (judgment of a test case): same for `Tool response:` and `Tool error:`.

**`src/mcp_auditor/graph/chain_prompts.py`**

- `_format_chain_history` (observation history, step planning history, chain judgment): `Response:` and `Error:` through `shown_to_model`.
- `_format_latest_outcome` (latest step of the observation): same.
- `_format_single_step_summary` (chain planning) keeps its 200-character response snippet, built on `rendered_response`, and shows `Error:` through `shown_to_model`: today it copies each error whole, the one unbounded text of the chain planning prompt.

**`src/mcp_auditor/graph/missed_model_calls.py`**

- `call_model` catches `PromptTooLong` and returns `_missed(call, MissCause.PROMPT_TOO_LONG, str(too_long), too_long.usage)`, as it does for `ProviderThrottled`: the detail is the exception's own fixed message, "the model provider rejected the prompt as longer than the model's context window".

No node changes: every node already handles a `Missed` answer.

### Adapters

**`src/mcp_auditor/adapters/llm.py`**

- `_call_once`: in the `except Exception as error` branch, before the throttle check, `if isinstance(error, ContextOverflowError): raise PromptTooLong(usage_so_far.add(ProviderUsage(throttled_requests=tally.requests))) from error`. `ContextOverflowError` is `langchain_core.exceptions.ContextOverflowError`, the base of `AnthropicContextOverflowError`, `OpenAIContextOverflowError` and `OpenAIAPIContextOverflowError` (OpenAI, Alibaba and OpenRouter through `ChatOpenAI`), `GoogleContextOverflowError` and `FireworksContextOverflowError` in the installed integrations (confirmed in `.venv`: `langchain-core` 1.7.0, `langchain-anthropic` 1.7.6, `langchain-openai` 1.7.2, `langchain-google-genai` 4.4.2, `langchain-fireworks` 1.7.1). Each integration raises its subclass only when the provider's error text matches its patterns (`_handle_openai_bad_request`, `_handle_anthropic_bad_request`, `_handle_client_error`); Alibaba's overflow text matches none, so an Alibaba overflow still leaves the graph as today.
- `generate_structured` lets `PromptTooLong` out without a retry: the same prompt would be rejected again. This needs no code of its own: `_call_once` raises it from inside `_attempt`, outside the parse-attempt loop's handling, as `ProviderRefusal` from `refusal_from_error` already leaves. The test below pins it.
- `pyproject.toml`: the `langchain-core` floor rises from `>=1.6.6` to `>=1.7.0`, the locked version where `ContextOverflowError` was verified, and `uv lock` records it (no installed version changes).
- `llm.py` is at 306 lines and gains about three (the import and the two lines of the branch): it is not split in this plan.

### CVE benchmark suites

**`evals/cve/audit_attempts.py`**

- `_CAUSE_WORDING` gains `MissCause.PROMPT_TOO_LONG: "prompt longer than the model's context window"`.
- The comment above `INCOMPLETE_ATTEMPTS` ("a policy refusal or an unreadable answer") names the new cause.
- No other change: `graded_or_incomplete` already makes any missed model call of a run that did not detect an `IncompleteAttempt`, and `evals/cve/detection/audit.py` sets apart only `PROVIDER_THROTTLED`, so the detection gate and the holdout run read a `prompt_too_long` run as they read an unreadable one with no code change there.

**`evals/cve/nuisance/audit.py`**

- `_INCOMPLETE_CAUSES` gains `MissCause.PROMPT_TOO_LONG`, so a nuisance run and the nuisance gate count such a run incomplete (`is_incomplete`, `incomplete_causes`), as they count an unreadable answer.
- The module docstring ("a refused or unreadable step is kept") names the new cause.

**`evals/cve/detection/holdout_markdown.py`**, **`evals/cve/nuisance/markdown.py`** and **`evals/cve/nuisance/results.py`**

- The wording "a model call refused or unreadable" (the `_INCOMPLETE_RUNS` label of both markdown modules, the `incomplete` field's comment) becomes "a model call missed: refused, unreadable or too long". The tests that pin the label change with it: `tests/unit/nuisance/test_nuisance_report.py` (two expected strings) and `tests/unit/detection/test_detection_holdout_report.py` (three). Grep `evals/` and `tests/` for the phrase and update every living copy.

**`evals/cve/server_health.py`**

- `ServerHealth` gains `cut_responses: int = 0`, summed by `__add__`, and `health_of` fills it with the sum of `tool_report.cut_responses` over the report. Like the other counts it is report-only: no statistic, grading, retry, gate or baseline reads it. The module docstring names it.

**`evals/cve/detection/holdout_assembly.py`**, **`evals/cve/detection/holdout_results.py`**, **`evals/cve/detection/holdout_target_line.py`**, **`evals/cve/detection/holdout_markdown.py`**, and the nuisance counterparts (**`evals/cve/nuisance/assembly.py`**, **`evals/cve/nuisance/results.py`**, **`evals/cve/nuisance/report.py`** (`ServerRunLine`, `ServerLine` and the function that builds them), **`evals/cve/nuisance/markdown.py`**)

- Carry `cut_responses` from `ServerHealth` to the per-run status, the per-target or per-server line and the markdown health line, exactly as `relaunches` and `unsent_calls` are carried: the health line adds `{n} response(s) shown cut` when it is not zero. Follow the path `relaunches` takes in each file, field by field (`holdout_assembly.py` and `holdout_target_line.py` each build two of them). These are the only modules that read `ServerHealth` past `launch_audit.py` (grep `relaunches` and `lost_connection_responses` under `evals/` to confirm).

**`evals/cve/nuisance/run.py`**

- `NuisanceDeps` gains `announce_run: Callable[[str], None]`, which prints one finished line; `default_deps` sets it to `print_run_status` of `run_status.py` below, which prints through `evals.eval_display.console` (the console of the command's live bar) with `rich.markup.escape` applied, as `audit.py` prints its lines. The total cannot ride on `announce_audits`: `evals/run_nuisance.py` (`_tracked`) replaces `announce_audits` with the live bar's `AuditProgress.announce`, so a done count fed by it would never see the total.
- `_run_all`, which already computes `len(surviving) * ctx.runs` for `announce_audits`, wraps `deps.audit` in an announcing audit before handing it to `_run_server`, the way `AuditProgress.tracked` wraps it: `announcing(deps.audit, deps.announce_run, total) -> Audit`, from `run_status.py` below, returns a closure that awaits `audit(server)`, counts it done, calls `announce(run_status_line(server, outcome, RunCount(done, total)))` and returns the outcome. It lives in `run_status.py`, not in `run.py`, which is already at 301 lines (`CLAUDE.md`: files rarely exceed 300 lines, when they do, split); the `Audit` type alias and the default printer live there too, and `run.py` imports them from there, since `run_status.py` cannot import `run.py` without a cycle. What is left in `run.py` is the field, its default, the import and the wrapping in `_run_all`, less the alias: about three lines net, so `run.py` ends near 304 lines. It is not split further in this plan. `_run_server` keeps its signature and calls the wrapped audit, so a server played alone (magento2) and a server among its siblings (`sibling_runs`) are both announced as each run finishes, not once the server's runs are gathered. The count is safe without a lock: every run's coroutine resumes on the one event loop.
- A new `evals/cve/nuisance/run_status.py` holds `Audit`, `announcing`, `print_run_status(line: str) -> None`, the pure `run_status_line(server: AdmittedServer, outcome: NuisanceAudit | DroppedRun, count: RunCount) -> str` and the frozen dataclass `RunCount(done: int, total: int)`. The line reads:
  - for a report: `{package}: flagged [{done}/{total} runs]` or `{package}: not flagged [{done}/{total} runs]`, with `, incomplete` after the status when `is_incomplete(report)` (`evals/cve/nuisance/audit.py`, which reads `_INCOMPLETE_CAUSES`) holds;
  - for a dropped run: `{package}: run dropped ({reason}) [{done}/{total} runs]`, with the reason from `DROPPED_RUN_REASONS[outcome.cause]`.
  The run is flagged when `flagged_tools(report, counted_tools(server))` (`evals/cve/nuisance/counter.py`, `evals/cve/nuisance/counting.py`) is not empty. The line prints no count of alarms: the nuisance suite rule (Reading) lists what a run prints, the status per server and per run among it, and a per-run count of alarms is not on that list, so the counts stay in the run report.
- The done count counts runs, not audit attempts: `deps.audit` is `nuisance_audit`, one run with its up to `NUISANCE_INFRA_ATTEMPTS` audit attempts, so one call of the wrapped audit is one run done, as for `AuditProgress.tracked`.
- The test givens build `NuisanceDeps` in two places that gain the field: `tests/unit/nuisance/support/test_nuisance_run_given.py` (the keyword constructor, which collects the lines in a list, and `deps_reaching_nothing`, positional, whose `announce_run` raises `AssertionError`).

The line prints no proof text, no judge input and no per-case verdict: a status per run and a count, which the nuisance suite rule (Reading) says spend nothing.

**`evals/run_nuisance.py`**

- `run.add_argument("--runs", ..., help="default 3, lowerable to 1")` says `default 2`, read from `NUISANCE_RUNS` (already imported there) so it cannot drift again: `help=f"default {NUISANCE_RUNS}, lowerable to 1"`. No other help drifts: `vet` and `fix-check` take no `--runs`, the gate's (`gate/gate_command.py`) has no help text, and `run_detection_holdout run`'s "default 3" matches `HOLDOUT_RUNS = 3`.

### Living docs

- `docs/glossary.md`: **missed model call** names its fourth cause, "or a prompt the model provider rejected as longer than the model's context window" (the glossary's **provider** sense is written qualified, "Words with several senses"); a new entry **cut response**, in "The auditor": "a tool response or error longer than 20,000 characters, shown to a model with its middle replaced by a marker naming how many characters were cut. The report counts them per tool. Code: `cut_responses`, `[N characters cut by mcp-auditor]`." No rename, so no line in `docs/glossary-log.md`.
- `README.md`: the list of missed-call causes appears twice, in phase 2 of the audit ("A model call (a generation, a judgment, a chain step) that the model provider refuses...", line 43) and in the `--ci` paragraph ("refused by the model provider, answered in no expected format, or throttled by the provider past every retry", line 299): both name the new cause. Phase 4 ("Judge each response", line 45) says that a response or error over 20,000 characters is shown to the model with its middle cut, and that the report counts them per tool (`cut_responses` in the JSON report). The `--ci` row of the options table (line 253) says only "a missed model call" and stays.
- `README.md`, the detection gate paragraph (line 209, "in which a model call was missed (refused by the model provider, or an unreadable model answer) is not graded"), names the new cause too.
- `CONTRIBUTING.md`: the honeypot suite paragraph ("A refused or unreadable step leaves the pass completed", line 102) names the new cause: `evals/metrics.py` fails a pass only on `PROVIDER_THROTTLED`, so a `prompt_too_long` call leaves the pass completed, as an unreadable answer does, with no code change. The detection gate paragraph (line 50, "a model call was missed (refused by the model provider, or an unreadable model answer)") and the nuisance gate paragraph (line 58, "a model call was refused or came back unreadable is attempted again") name it as well, and the nuisance run paragraph (line 56, the `uv run python -m evals.run_nuisance run` description) says that it prints one status line per run of a server (flagged, not flagged, or dropped) and how many runs are done. Grep `README.md` and `CONTRIBUTING.md` for "unreadable" to catch every living copy.
- `CHANGELOG.md`, `[Unreleased]`: under Fixed, "Every tool response and error shown to a model is bounded at 20,000 characters, its middle cut and marked, so a huge response no longer ends the audit or costs a prompt of a million tokens, and a prompt the model provider still rejects for its length is a missed model call of cause `prompt_too_long`, where it used to end the audit" (steps 1 and 2 each write their half); under Added, "The report counts, per tool, the responses shown cut to the model" and "The nuisance run prints one status line per run of a server, with its progress"; under Fixed, the `--runs` help.
- `CLAUDE.md`: the `run_nuisance run` line of the Commands list gains "prints one status line per run of a server (flagged, not flagged, or dropped) and how many runs are done".
- `docs/labeling-log.md`, `docs/detection-suite-log.md`, `docs/nuisance-suite-log.md`: one entry each, dated, saying that a model call the model provider rejects for its length is now a missed model call of cause `prompt_too_long`, counted as an incomplete run as an unreadable answer is, where it used to end the audit as a provider error, retried and then left out of N; and, in the nuisance suite log, that the run prints a status line per run. Each suite log entry ends on its reading of the rule and on "no rule version opens", as the latest entries of the detection suite log do: the rule (Run conditions and statistic) counts an audit with a refused model call and no detection as not detected (the nuisance suite rule: one with a refused or unreadable model call and no counted FAIL as not flagged) and retries an audit that ends on any other error, and an audit whose prompt the model provider rejects for its length no longer ends on an error, so it is read as the audit with an unreadable answer already is. The labeling log entry takes the form of its latest entries (a dated heading, What changes, Fingerprint, The four questions of ADR 016), with the grammar and counter fingerprints unchanged. No entry changes a recorded decision.

## What stays unchanged

- Every prompt whose tool responses and errors are all at most 20 000 characters is byte-for-byte what it is today. `tests/unit/auditor/support/model_inputs_golden.json` is not regenerated: `test_model_inputs_golden.py` must pass unchanged.
- The responses the report and the oracle read: `TestCase.response`, `ChainStep.response` and the errors are stored whole. Only what a model is shown is bounded. A nonce in the cut middle of a response stays visible to the oracle; the judge, which no longer sees it, may then rule PASS, and the target reads `reached_but_judged_pass`.
- The chain planning snippet of 200 characters.
- The payload arguments and the tool descriptions in prompts: the auditor writes the first, and a huge description is left to the `prompt_too_long` missed call.
- The attack context and its bounds (ADR 035).
- The grammar, the counter and every fixture fingerprint: no file of `GRAMMAR_PATHS`, `ENVIRONMENT_PATHS` (`evals/cve/detection/baseline.py`), `_COUNTER_PATHS` (`evals/cve/nuisance/counter.py`), `_PUBLIC_NAME_SOURCES` or `CONFINEMENT_SOURCE` (`evals/cve/nuisance/fingerprint.py`) is touched. `counter.py` is read, never edited.
- The detection suite rule and the nuisance suite rule.
- The retry policy of the suites for a provider error that is not a context overflow.
- The judge eval and the model probe, which call `generate_structured` directly, not through `call_model`. `judge_one_case` (`evals/run_judge_eval.py`) catches only `UnparseableOutput` and `ProviderRefusal`, so a `PromptTooLong` propagates and crashes the run (exit 4), as a context overflow does today; its judge cases (435 characters at most) never reach it. `observe` (`evals/run_probe.py`) records it as `CallOutcome.ERROR` through its catch-all `except Exception`.
- The holdout run's per-run line (`evals/cve/detection/audit.py`).
- `evals/declared_flips.json`: no gated cell or judge case is expected to flip, since no instrument's recorded response approaches the bound.

## Edge cases

- **A response of exactly 20 000 characters** is shown whole; 20 001 characters cut 1 character.
- **A dict response** is measured and cut on its JSON rendering. The cut text is no longer valid JSON; the marker says why.
- **A response cut in the middle of a redaction marker** (`[value of NAME, redacted by mcp-auditor]`, only under `--env`): the half marker reveals nothing, since the value was replaced before the cut. Accepted as is.
- **A response cut in the middle of a multi-byte character**: Python slices code points, so no invalid character is produced.
- **A prompt still too long after the bound** (a tool description of megabytes, a context window smaller than the largest prompt, about 80 000 tokens at the default test budget): a `prompt_too_long` missed call; the judgment, extraction, observation or planning is skipped as for a refusal; a chain whose step call is missed ends as it does today on a missed call.
- **`ContextOverflowError` raised by a provider the auditor does not list**: any subclass of `ContextOverflowError` is caught, whatever the provider.
- **A nuisance server played alone (magento2)**: its runs are announced one by one, as they finish.
- **A nuisance run with zero surviving servers**: no line is printed; `announce_audits(0)` and no `announce_run` call.
- **A nuisance run stopped by an exception**: the lines already printed stay in the log; the partial result is written as today.

### Accepted limits

- **An Alibaba overflow still ends the audit.** Its error text matches none of `langchain_openai`'s patterns, so it is no `ContextOverflowError` and leaves the graph as today. The adapter matches no provider error text of its own.
- **A large `--budget` can overflow a small context window.** The bound is on each response and error, not on their sum: the context extraction prompt copies every response of the tool, so `--budget 50` can reach a million characters. The prompt then becomes a `prompt_too_long` missed call and the audit is incomplete. There is no bound on the sum and no second call with fewer responses.

## Test scenarios

Unit tests, given/then per the testing standards, in the directory of each area.

**Domain (`tests/unit/auditor/`)**

- `shown_to_model` on a text of 20,000 characters returns it unchanged; on 20,001 characters it returns the first 10,000, the marker `[1 character cut by mcp-auditor]` on its own line, and the last 10,000. On 50,000 characters the marker is `[30000 characters cut by mcp-auditor]`.
- `rendered_response` on a dict equals `json.dumps` of it, on a string equals the string.
- `cut_responses` on a tool report counts a test case whose dict response renders over the bound, a test case whose error is over the bound, a chain step whose response is over the bound, and nothing for short ones or a blocked test case.
- The JSON dump of a `ToolReport` carries `cut_responses`, and `ToolReport.model_validate` of that dump succeeds.
- The markdown report shows the "Responses shown cut" line for a tool with one cut response and no such line otherwise; the missed-call cause label for `prompt_too_long`.

**Graph (`tests/unit/auditor/test_prompts.py`, `test_chain_prompts.py`, `test_missed_model_calls.py`, `test_graph.py`)**

- The judge prompt of a test case with a 50 000-character response contains its first and last 10 000 characters and the marker, and not a character from the cut middle (plant a distinctive string in the middle and assert it is absent).
- The extraction prompt bounds each test case's response and error separately.
- The chain judgment, observation and step planning prompts bound each step's response and error.
- The chain planning prompt bounds each test case's error, and keeps its 200-character response snippet.
- `call_model` with a `FakeLLM` whose script holds `PromptTooLong(usage)` returns a `Missed` with cause `prompt_too_long` and that usage. Extend `ModelFailure` in `tests/fakes/llm.py` with `PromptTooLong`.
- A whole graph run where the judgment of one test case raises `PromptTooLong` ends normally: the other test cases are judged, the report lists one missed model call of cause `prompt_too_long`, and the tool's other reports are present.

**Adapter (`tests/unit/auditor/test_llm_adapter.py`)**

- A fake chat model whose `ainvoke` raises `AnthropicContextOverflowError` (and, parametrized, each other `ContextOverflowError` subclass the implementer confirmed) makes `generate_structured` raise `PromptTooLong` after one call, with no parse retry.
- A plain `BadRequestError` that is not an overflow still propagates as today.

**Suites (`tests/unit/cve/`, `tests/unit/nuisance/`, `tests/unit/detection/`)**

- A nuisance audit report with a `prompt_too_long` missed call and no alarm counts as an incomplete run in the nuisance run and is attempted again by the nuisance gate, as one with an unreadable answer is.
- A detection report with a `prompt_too_long` missed call and no detection is an incomplete audit attempt (`IncompleteAttempt`), and `describe_missed_call_causes` names the cause.
- `health_of` counts the cut responses of a report; the holdout and nuisance markdown health lines show `{n} response(s) shown cut` when it is not zero.
- `run_status_line` for a flagged run with 2 alarms, a not-flagged run, an incomplete not-flagged run and a dropped run, each with its `[done/total runs]` (`tests/unit/nuisance/test_nuisance_run_status.py`, its given and then in `tests/unit/nuisance/support/`).
- `run_nuisance` with fake deps announces one line per run of each surviving server, a server played alone included, each line naming that run's outcome, the done count rising from 1 to the total of `len(surviving) * runs`.
- `run_nuisance.py run --help` shows `default 2`.

## Verification

- The short loop while writing, then the full checks that close a step: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .`, `uv run pyright`.
- `uv run pytest tests/unit/auditor/test_model_inputs_golden.py -n 0` passes with the golden unchanged (`git diff --stat tests/unit/auditor/support/model_inputs_golden.json` is empty).
- `git diff --stat` on the fingerprinted files listed under "What stays unchanged" is empty.
- Honeypot gate under the reference settings: `uv run python -m evals.run_honeypot_suite`, green. Judge gate: `uv run python -m evals.run_judge_eval`, green. Both are expected unchanged, since no recorded response reaches the bound; a flip on either reverts the change, as `CLAUDE.md` requires.
- No Docker command: no image, detection or nuisance fixture, or calibration changes.

## Due diligence record

What the due-diligence pass concluded, on 2026-11-18, about the external facts this plan cites or defers. Later passes, the implementation-phase fact check included, read it. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: Claude Haiku 5.5 (`claude-haiku-5-5`) has a 1M-token context window (verified against platform.claude.com/docs/en/models/haiku-5-5/overview)
- SETTLED: Claude Haiku 5.5 input costs $0.10 / MTok for prompts up to 100,000 tokens and $0.50 / MTok for prompts over 100,000 tokens, the whole prompt at the higher rate, so a prompt of close to 1M tokens costs about 0.50 $ (verified against platform.claude.com/docs/en/models/haiku-5-5/overview)
- SETTLED: the tokenizer of Claude Haiku 5.5 counts about 2.5 characters per token (1M tokens for about 2.5M Unicode characters), so 200,000 characters is about 80,000 tokens (verified against platform.claude.com/docs/en/models/haiku-5-5/overview, corrected from "three characters per token")
- SETTLED: `langchain_core.exceptions.ContextOverflowError` is the base of `AnthropicContextOverflowError`, `OpenAIContextOverflowError`, `OpenAIAPIContextOverflowError`, `GoogleContextOverflowError` and `FireworksContextOverflowError` (verified against the installed sources: langchain-core 1.7.0, langchain-anthropic 1.7.6, langchain-openai 1.7.2, langchain-google-genai 4.4.2, langchain-fireworks 1.7.1)
- SETTLED: each integration raises its overflow subclass only on a matching error text, and Alibaba's overflow text, `Range of input length should be [1, xxx]（InternalError.Algo.InvalidParameter）`, matches none of `langchain_openai`'s patterns (verified against the installed `_handle_openai_bad_request` and alibabacloud.com/help/en/model-studio/error-code, corrected from "every LangChain integration the auditor uses")
- SETTLED: the LangGraph checkpoint rebuilds a pydantic model with `cls(**model_dump())`, falling back to `model_construct` (verified against the installed langgraph-checkpoint 4.3.0, `langgraph/checkpoint/serde/jsonplus.py`)
- OPEN (unverified): the smallest context window in current use is 128,000 tokens. No source settles it: the default model of every provider the auditor supports was found at 200K or more (`claude-haiku-4-5`, the `anthropic` default, at 200K, `gpt-6-luna` at 1.05M, `z-ai/glm-5.3` at about 1M on OpenRouter with one endpoint at 262,144, `glm-5p3-flash` at 1040K on Fireworks, `qwen3.8-flash` at 1M), `gemini-3.5-flash-lite`'s window was not found, and a user-chosen model can be smaller
- OPEN (unverified): an OpenRouter or Fireworks overflow reaches `ContextOverflowError`. It depends on the upstream error text containing `context_length_exceeded` or `prompt is too long`, which OpenRouter documents as an error code but whose body varies with the upstream provider

## Implementation steps

Every step follows the Workflow of `CLAUDE.md`: tests first and seen red, the short loop (`uv run pytest <test files> -n 0` while red, then `uv run pytest tests/unit -n auto --maxprocesses 6`, `--lf` on a failure, then the full short loop again), `uv run pyright <changed files>` in the loop. Each step closes with `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .` and `uv run pyright` with no file argument, all green. Every step also checks that `git diff --stat` on the fingerprinted files of "What stays unchanged" is empty, and runs no Docker command.

### Step 1: Bound every tool response and error shown to a model

A change to the system under test: its commit message answers the four questions of ADR 016 (see "Where the change lands, and why").

- **Files**:
  - Tests: new `tests/unit/auditor/test_shown_response.py` (with `tests/unit/auditor/support/test_shown_response_given.py` only for builders that abstract something, such as a tool report with a long dict response, a long error, a long chain step and a blocked case), `tests/unit/auditor/test_prompts.py` (+ `support/test_prompts_given.py`), `tests/unit/auditor/test_chain_prompts.py`, `tests/unit/auditor/test_models.py`, `tests/unit/auditor/test_rendering.py` (+ `support/test_rendering_given.py`, `support/test_rendering_then.py`)
  - Production: new `src/mcp_auditor/domain/shown_response.py`, `src/mcp_auditor/domain/models.py`, `src/mcp_auditor/domain/rendering.py`, `src/mcp_auditor/graph/prompts.py`, `src/mcp_auditor/graph/chain_prompts.py`
  - Living docs: `README.md` (phase 4, "Judge each response"), `docs/glossary.md` (new entry **cut response**), `CHANGELOG.md` (`[Unreleased]`)
- **Do**:
  1. Write the tests below first and see them fail.
  2. `domain/shown_response.py`, as specified under "Domain": `MAX_SHOWN_LENGTH = 20_000`, `rendered_response(response: dict[str, Any] | str) -> str` (`json.dumps` for a dict, `str()` otherwise, exactly the rendering the three inline copies do today), `shown_to_model(text: str) -> str` (unchanged at or under the bound, else first `MAX_SHOWN_LENGTH // 2` characters, `\n[{cut} characters cut by mcp-auditor]\n` with the singular `[1 character cut by mcp-auditor]`, last `MAX_SHOWN_LENGTH - MAX_SHOWN_LENGTH // 2` characters, `cut = len(text) - MAX_SHOWN_LENGTH`), `is_cut(text: str) -> bool`, `cut_responses(tool_report: ToolReport) -> int` (test case responses through `rendered_response`, test case errors, chain step responses and errors, a blocked test case counts nothing). It imports `ToolReport` at module level.
  3. `domain/models.py`: `ToolReport` gains `@computed_field` `cut_responses: int`, returning `shown_response.cut_responses(self)` through a local import, as `JudgeResult.owasp` does. Do not touch `MissCause` here (step 2).
  4. `graph/prompts.py`: `_format_cases_for_extraction` and `_format_outcome` show `shown_to_model(rendered_response(case.response))` and `shown_to_model(case.error)`, dropping their inline rendering. `graph/chain_prompts.py`: `_format_chain_history` and `_format_latest_outcome` show each step's `response` and `error` through `shown_to_model` (a `ChainStep.response` is `str | None`, no rendering), and `_format_single_step_summary` builds its 200-character snippet on `rendered_response` and shows its `Error:` through `shown_to_model`. Keep every `None` branch as it is today.
  5. `domain/rendering.py`: the tool section adds, after the coverage gap and the missed calls of the tool, `**Responses shown cut**: {n} response(s) or error(s) over {MAX_SHOWN_LENGTH:,} characters, shown to the model with their middle cut` when `tool_report.cut_responses > 0`. Keep `rendering.py` under 300 lines (it is at 287): if the line pushes it over, move the tool section's helpers, not the line, into a sibling module.
  6. Living docs: README phase 4 says that a response or error over 20,000 characters is shown to the model with its middle cut, and that the report counts them per tool (`cut_responses` in the JSON report). Glossary: the **cut response** entry worded in "Living docs" above. CHANGELOG `[Unreleased]`: under Fixed, "Every tool response and error shown to a model is bounded at 20,000 characters, its middle cut and marked, so a huge response no longer ends the audit or costs a prompt of a million tokens" (step 2 extends this entry with `prompt_too_long`), under Added, "The report counts, per tool, the responses shown cut to the model".
- **Test**:
  - `shown_to_model`: 20,000 characters unchanged, 20,001 characters give the first 10,000, `\n[1 character cut by mcp-auditor]\n` and the last 10,000, 50,000 characters give the marker `[30000 characters cut by mcp-auditor]`.
  - `rendered_response`: a dict equals `json.dumps` of it, a string equals itself.
  - `cut_responses`: counts a test case whose dict response renders over the bound, a test case whose error is over the bound, a chain step whose response is over the bound, a chain step whose error is over the bound, and nothing for short ones or a blocked test case.
  - `ToolReport`: its `model_dump(mode="json")` carries `cut_responses`, and `ToolReport.model_validate` of that dump succeeds.
  - Judge prompt of a test case with a 50,000-character response holding a distinctive string in its middle: it contains the first and last 10,000 characters and the marker, and not the distinctive string. Extraction prompt: each test case's response and error bounded separately. Chain judgment, observation and step planning prompts: each step's response and error bounded. Chain planning prompt: each test case's error bounded, the 200-character response snippet kept.
  - Markdown report: the "Responses shown cut" line for a tool with one cut response, no such line for a tool with none.
- **Verify**: the step's closing checks, plus `uv run pytest tests/unit/auditor/test_model_inputs_golden.py -n 0` passing with `git diff --stat tests/unit/auditor/support/model_inputs_golden.json` empty (the golden is never regenerated).

### Step 2: A prompt the provider rejects for its length becomes a missed model call

A change to the system under test: its commit message answers the four questions of ADR 016.

- **Files**:
  - Tests: `tests/fakes/llm.py`, `tests/unit/auditor/test_missed_model_calls.py`, `tests/unit/auditor/test_graph.py` (+ `support/test_graph_given.py`, `support/test_graph_then.py`), `tests/unit/auditor/test_llm_adapter.py` (+ `support/test_llm_adapter_given.py`, `support/test_llm_adapter_then.py`), `tests/unit/auditor/test_rendering.py`, `tests/unit/auditor/test_progress.py`
  - Production: `src/mcp_auditor/domain/ports.py`, `src/mcp_auditor/domain/models.py`, `src/mcp_auditor/domain/rendering.py`, `src/mcp_auditor/progress.py`, `src/mcp_auditor/graph/missed_model_calls.py`, `src/mcp_auditor/adapters/llm.py`, `pyproject.toml` (`langchain-core>=1.7.0`) with `uv.lock`
  - Living docs: `README.md` (phase 2, line 43, and the `--ci` paragraph, line 299), `CONTRIBUTING.md` (honeypot suite paragraph, line 102), `docs/glossary.md` (**missed model call**), `CHANGELOG.md`
- **Do**:
  1. `tests/fakes/llm.py`: `ModelFailure` and the `isinstance` check of `FakeLLM.generate_structured` include `PromptTooLong`. `support/test_graph_given.py`: `MODEL_FAILURES` gains the new cause with a `PromptTooLong` builder, so the two graph tests parametrized over it (a missed judgment, a missed chain observation) cover it. Write the tests below and see them fail.
  2. `domain/ports.py`: `class PromptTooLong(Exception)` with `__init__(self, usage: ProviderUsage)` calling `super().__init__("the model provider rejected the prompt as longer than the model's context window")` and storing `usage`, docstring as in "Domain", no provider message.
  3. `domain/models.py`: `MissCause.PROMPT_TOO_LONG = "prompt_too_long"`. `domain/rendering.py`: `MISS_CAUSE_LABELS[MissCause.PROMPT_TOO_LONG] = "Prompt longer than the model's context window"`. `progress.py`: `UNJUDGED_LINES[MissCause.PROMPT_TOO_LONG] = "  ? not judged, the prompt was longer than the model's context window"`.
  4. `graph/missed_model_calls.py`: `call_model` catches `PromptTooLong as too_long` and returns `_missed(call, MissCause.PROMPT_TOO_LONG, str(too_long), too_long.usage)`, as the `ProviderThrottled` branch does.
  5. `adapters/llm.py`, `_call_once`: in the `except Exception as error` branch, before the throttle check, `if isinstance(error, ContextOverflowError): raise PromptTooLong(usage_so_far.add(ProviderUsage(throttled_requests=tally.requests))) from error`, with `from langchain_core.exceptions import ContextOverflowError` (match the names `_call_once` actually uses for the usage so far and the throttle tally). Confirm in `.venv` which `ContextOverflowError` subclasses the installed integrations define, for the parametrized test. No retry code: the raise leaves `_attempt` outside the parse-attempt loop, as `ProviderRefusal` does.
  6. Living docs: README phase 2 and `--ci` paragraph name the fourth cause ("or a prompt the model provider rejected as longer than the model's context window"). CONTRIBUTING honeypot paragraph: a `prompt_too_long` call leaves the pass completed, as an unreadable answer does (`evals/metrics.py` fails a pass only on `PROVIDER_THROTTLED`, no code change). Glossary **missed model call** names the fourth cause. CHANGELOG: the Fixed entry of step 1 gains "and a prompt the model provider still rejects for its length is a missed model call of cause `prompt_too_long`, where it used to end the audit".
- **Test**:
  - `call_model` with a `FakeLLM` scripted with `PromptTooLong(usage)` returns a `Missed` of cause `prompt_too_long`, the exception's message as its detail and that usage.
  - A whole graph run where the judgment of one test case raises `PromptTooLong` ends normally: the other test cases are judged, the report lists one missed model call of cause `prompt_too_long`, the tool's report is present.
  - Adapter: a fake chat model whose `ainvoke` raises `AnthropicContextOverflowError`, parametrized over every installed `ContextOverflowError` subclass, makes `generate_structured` raise `PromptTooLong` after one call (the fake counts its calls), no parse retry. A plain `BadRequestError` (or the error type the existing adapter tests use for a non-overflow provider error) still propagates as today.
  - Rendering: the missed-call label for `prompt_too_long`. Progress: the unjudged line for `prompt_too_long`.
- **Verify**: the step's closing checks, the model inputs golden unchanged as in step 1. Then, as the last check of the system under test change, the honeypot gate (`uv run python -m evals.run_honeypot_suite`) and the judge gate (`uv run python -m evals.run_judge_eval`), both green: they need an LLM key and spend money, so state their volume and cost before launching them, and if they cannot be run, say so in the report so they are run by hand before the commit. A flip on either reverts the change (`CLAUDE.md`, "When an eval number comes back red").

### Step 3: The CVE benchmark suites count a `prompt_too_long` run as incomplete

An instrument change: it has its entry in `docs/labeling-log.md`, `docs/detection-suite-log.md` and `docs/nuisance-suite-log.md`, and opens no rule version. No detection or nuisance run is launched between step 2 and this step: until it lands, the nuisance suite counts a `prompt_too_long` run as complete and the suites' console names no cause for it.

- **Files**:
  - Tests: `tests/unit/detection/test_detection_audit.py` (+ `support/test_detection_audit_given.py`), `tests/unit/nuisance/test_nuisance_retry_policy.py` (+ `support/test_nuisance_retry_policy_given.py`), which holds both the nuisance run's policy and the gate's (`gate_run`), `tests/unit/nuisance/test_nuisance_report.py`, `tests/unit/detection/test_detection_holdout_report.py`
  - Production: `evals/cve/audit_attempts.py`, `evals/cve/nuisance/audit.py`, `evals/cve/detection/holdout_markdown.py`, `evals/cve/nuisance/markdown.py`, `evals/cve/nuisance/results.py`
  - Living docs: `README.md` (detection gate paragraph, line 209), `CONTRIBUTING.md` (detection gate paragraph, line 50, nuisance gate paragraph, line 58), `docs/labeling-log.md`, `docs/detection-suite-log.md`, `docs/nuisance-suite-log.md`
- **Do**:
  1. Write the tests below and see them fail.
  2. `evals/cve/audit_attempts.py`: `_CAUSE_WORDING[MissCause.PROMPT_TOO_LONG] = "prompt longer than the model's context window"`, and the comment above `INCOMPLETE_ATTEMPTS` names the new cause. No other change there or in `evals/cve/detection/audit.py`.
  3. `evals/cve/nuisance/audit.py`: `_INCOMPLETE_CAUSES` gains `MissCause.PROMPT_TOO_LONG`, the module docstring names the new cause.
  4. The label "a model call refused or unreadable" becomes "a model call missed: refused, unreadable or too long" in `_INCOMPLETE_RUNS` of `holdout_markdown.py` and `nuisance/markdown.py` and in the `incomplete` field's comment of `nuisance/results.py`. Update the five pinned strings (two in `test_nuisance_report.py`, three in `test_detection_holdout_report.py`), then grep `evals/` and `tests/` for "refused or unreadable" and update every living copy.
  5. Living docs: README detection gate paragraph and CONTRIBUTING detection and nuisance gate paragraphs name the new cause (grep both files for "unreadable" to catch every living copy, the honeypot paragraph already done in step 2). One dated entry (2026-11-18) in each of the three logs, as worded in "Living docs" above, each suite log entry ending on its reading of the rule and on "no rule version opens", the labeling log entry in the form of its latest entries: a model call the model provider rejects for its length is now a missed model call of cause `prompt_too_long`, counted as an incomplete run as an unreadable answer is, where it used to end the audit as a provider error, retried and then left out of N. No entry changes a recorded decision.
- **Test**:
  - A detection report with a `prompt_too_long` missed call and no detection is an `IncompleteAttempt` (already covered since step 2 by the tests of `test_detection_audit.py` parametrized over `list(MissCause)`, so not seen red here), and `describe_missed_call_causes` names "prompt longer than the model's context window" (the red test of this half).
  - A nuisance audit report with a `prompt_too_long` missed call and no alarm counts as an incomplete run (`is_incomplete`, `incomplete_causes`), stands without a retry in the nuisance run and is attempted again by the nuisance gate (`gate_run`), as one with an unreadable answer is: extend the parametrized cases of `test_nuisance_retry_policy.py`.
  - The holdout and nuisance markdown reports show the new incomplete-runs label.
- **Verify**: the step's closing checks.

### Step 4: Carry the cut responses into the suites' server health

An instrument change of what a report prints, never what it grades: `cut_responses` is report-only, like `relaunches`.

- **Files**:
  - Tests: `tests/unit/cve/test_cve_server_health.py` (+ `support/test_cve_server_health_given.py`), `tests/unit/detection/test_detection_holdout_report.py`, `tests/unit/nuisance/test_nuisance_report.py` (+ `support/test_nuisance_report_given.py`), and every test that builds a run status or a line (grep `HoldoutRunStatus(`, `NuisanceRunStatus(`, `TargetRunLine(` and `ServerRunLine(` under `tests/unit`: today `test_cve_holdout_statistic.py`, `test_detection_holdout_report.py`, `support/test_nuisance_statistic_given.py`, `support/test_nuisance_report_given.py`, and `test_nuisance_assembly.py`, whose three `NuisanceRunStatus` are positional), which gain `cut_responses=0` or its positional equivalent. A `ServerHealth(...)` built in a test needs no edit, the field has a default.
  - Production: `evals/cve/server_health.py`, `evals/cve/detection/holdout_assembly.py`, `evals/cve/detection/holdout_results.py`, `evals/cve/detection/holdout_target_line.py`, `evals/cve/detection/holdout_markdown.py`, `evals/cve/nuisance/assembly.py`, `evals/cve/nuisance/results.py`, `evals/cve/nuisance/report.py`, `evals/cve/nuisance/markdown.py`
- **Do**: every production edit is mechanical, one field following the path `relaunches` takes in each file (grep `relaunches` under `evals/`).
  1. Write the tests below and see them fail.
  2. `server_health.py`: `ServerHealth` gains `cut_responses: int = 0` (after `unsent_calls`), summed by `__add__`, `NO_INCIDENTS` gains a fifth `0`, `health_of` fills it with `sum(tool.cut_responses for tool in report.tool_reports)`, the module docstring names it among the report-only counts.
  3. Detection side: `HoldoutRunStatus` gains `cut_responses: int` after `unsent_calls` (no default, the dataclass has non-default fields after it), filled in both builders of `holdout_assembly.py`, `HoldoutTargetResult` (or whatever in `holdout_results.py` sums `relaunches` over `statuses`) gains the matching sum, `TargetRunLine` and `TargetLine` in `holdout_target_line.py` gain it in their fields and their two builders, and the health line of `holdout_markdown.py` adds `{n} response(s) shown cut` when it is not zero, after `{n} call(s) not sent`.
  4. Nuisance side: the same on `NuisanceRunStatus` and its server-level sum (`nuisance/results.py`), `nuisance/assembly.py`, `ServerRunLine`, `ServerLine` and their builder (`nuisance/report.py`), and the health line of `nuisance/markdown.py`.
  5. Update every test constructor found by the grep with `cut_responses=0` (or the positional equivalent) so the suite stays green.
- **Test**:
  - `health_of` counts the cut responses of a report (a report with two tools, one cut response each, gives 2), and `ServerHealth.__add__` sums them.
  - Each run status carries the cut responses of its server: give one health a nonzero count in the existing tests of `test_nuisance_assembly.py` and `test_detection_holdout_run.py` that pin the relaunches and the calls not sent per run status.
  - The holdout markdown and the nuisance markdown health lines show `1 response(s) shown cut` for a run or server with one, and no such fact when it is zero.
- **Verify**: the step's closing checks, plus `git diff --stat` on `evals/cve/nuisance/counter.py`, `evals/cve/nuisance/counting.py` and the `GRAMMAR_PATHS` files empty.

### Step 5: The nuisance run prints one status line per run of a server

An instrument change of what a run prints, never what it grades: the nuisance suite rule (Reading) says a status per run spends nothing.

- **Files**:
  - Tests: new `tests/unit/nuisance/test_nuisance_run_status.py` (+ `support/test_nuisance_run_status_given.py`, `support/test_nuisance_run_status_then.py` where they abstract something), `tests/unit/nuisance/test_nuisance_run.py` (+ `support/test_nuisance_run_given.py`), `tests/unit/nuisance/test_run_nuisance_run.py` (+ its given if needed)
  - Production: new `evals/cve/nuisance/run_status.py`, `evals/cve/nuisance/run.py`, `evals/run_nuisance.py`
  - Living docs: `CLAUDE.md` (the `run_nuisance run` line), `CONTRIBUTING.md` (nuisance run paragraph, line 56), `CHANGELOG.md`, `docs/nuisance-suite-log.md` (the entry of step 3)
- **Do**:
  1. Write the tests below and see them fail. `support/test_nuisance_run_given.py`: the keyword `NuisanceDeps` constructor gains an `announce_run` that appends each line to a list the test can read, and `deps_reaching_nothing` (positional) gains, at the field's position, an `announce_run` that raises `AssertionError`.
  2. New `evals/cve/nuisance/run_status.py`: the `Audit` type alias (moved from `run.py`, which imports it from here), the frozen dataclass `RunCount(done: int, total: int)`, the pure `run_status_line(server: AdmittedServer, outcome: NuisanceAudit | DroppedRun, count: RunCount) -> str`, `announcing(audit: Audit, announce: Callable[[str], None], total: int) -> Audit` and `print_run_status(line: str) -> None`, which prints `rich.markup.escape(line)` through `evals.eval_display.console` (as `evals/cve/nuisance/audit.py` prints its lines). The line reads `{package}: flagged [{done}/{total} runs]` or `{package}: not flagged [{done}/{total} runs]`, with `, incomplete` after the status when `is_incomplete(report)` holds, and `{package}: run dropped ({DROPPED_RUN_REASONS[outcome.cause]}) [{done}/{total} runs]` for a dropped run, flagged when `flagged_tools(report, counted_tools(server))` is not empty (read `evals/cve/nuisance/counter.py` and `counting.py` for the exact names, edit neither). `announcing` returns a closure that awaits `audit(server)`, increments a done count (no lock, one event loop), announces `run_status_line(server, outcome, RunCount(done, total))` and returns the outcome. Check how `DroppedRun` and `NuisanceAudit` expose the server's package and report before writing the line.
  3. `evals/cve/nuisance/run.py`: `NuisanceDeps` gains `announce_run: Callable[[str], None]`, `default_deps` sets it to `print_run_status`, and `_run_all` wraps `deps.audit` with `announcing(deps.audit, deps.announce_run, len(surviving) * ctx.runs)` before handing it to `_run_server`, which keeps its signature. `run.py` is at 301 lines and ends near 304: keep what it gains to the field, its default, the import and the wrapping, and do not split it further here.
  4. `evals/run_nuisance.py`: `--runs` help becomes `f"default {NUISANCE_RUNS}, lowerable to 1"`. `_tracked` keeps replacing `announce_audits` and `audit` only, so the audit `_run_all` wraps is the bar's tracked one: on each finished run the bar advances, then the line prints.
  5. Living docs: the `CLAUDE.md` `run_nuisance run` line and the CONTRIBUTING nuisance run paragraph say that it prints one status line per run of a server (flagged, not flagged, or dropped) and how many runs are done. CHANGELOG `[Unreleased]`: under Added, "The nuisance run prints one status line per run of a server, with its progress", under Fixed, "`run_nuisance run --help` gives the default number of runs, 2, read from the code". The step-3 entry of `docs/nuisance-suite-log.md` gains the sentence that the run prints a status line per run, which spends nothing under the nuisance suite rule (Reading).
- **Test**:
  - `run_status_line`: a flagged run (`pkg: flagged [1/4 runs]`), a not-flagged run, an incomplete not-flagged run (`, incomplete` after the status), and a dropped run with its reason, each with its `[done/total runs]`.
  - `run_nuisance` with fake deps announces one line per run of each surviving server, a server played alone (magento2) included, each line naming that run's outcome, the done counts running from 1 to `len(surviving) * runs`. A run with zero surviving servers announces no line.
  - `run_nuisance.py run --help` shows `default 2`.
- **Verify**: the step's closing checks.
