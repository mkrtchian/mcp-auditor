# Test suite review: fix the tests that need it

## Context

A review of the whole test suite (132 test files, 1,770 test functions) against the testing standards of `CLAUDE.md` (Given/When/Then, behavior over implementation, usefulness) raised 173 findings. Each finding was then checked against the code: 133 hold, 35 hold in part, 5 do not. This plan covers the findings recommended for application. The rest is listed under "Out of scope" with the reason.

The findings fall into five kinds, in decreasing order of harm:

1. **Tests that cannot fail.** A substring that the static text of a prompt or the ANSI codes of a console always contain (`"10"`, `"integer"`, `"0"`), a fake built and never used, a test with no assertion, a test identical to its neighbour under a name that promises another case. These give a green the code has not earned.
2. **Tests whose name promises more than they check.** "Before any check" through fakes that let every check pass, "is logged" with nothing reading the log, "round trips" with nothing read back, "columnar" and "inline" with the same assertion.
3. **Tests coupled to data or wiring that changes for good reasons.** Targets taken by position in `CVE_TARGETS`, counts derived by hand from the live ground truth, candidate order in the probe roster, module path constants and `subprocess.run` patched in the eval session, private functions called under `pyright: ignore`, logger internals.
4. **Tests of the library or of a constant.** Pydantic construction and serialization, a lookup table restated, a constant compared to itself, argparse help.
5. **Given/When/Then structure.** Setup builders left in the spec file where a companion is due, one-line `then` wrappers that abstract nothing, duplicated fakes and fixtures across files, `@pytest.mark.asyncio` markers that `asyncio_mode = "auto"` makes redundant.

Every change keeps or strengthens what the suite guards. Where a test is deleted, the behavior it named is either covered elsewhere (named in the item) or was never observable through it.

## Approach

Five areas, each one commit (the breakdown may split an area further), plus one sweep commit for the asyncio markers at the end. Each area is test-only except two small production refactorings, flagged below. Each production refactoring is its own commit, carrying only the test edits its new signature forces, ahead of the rest of its area: a revert then undoes the refactoring alone, and the area's test rewrites land on a green, already-refactored base. No production behavior changes anywhere.

Two production changes, both no-behavior refactorings of the eval harness, outside the hexagon:

- `evals/cve_replay.py`: three pure functions made public so their unit tests stop reaching private names (area D).
- `evals/eval_session.py`: a `WorkingTree` value object, everything the session reads from the repository (baseline and declaration files, parent commit, dirty state, tree), injected into `open_session` and `declarations_of_head`, so the tests stop patching module paths and `subprocess.run` (area C). Same move as `JudgeHarness`, which already injects the baseline path and the declarations read into the judge session.

Neither touches scoring code, labels, fixtures, a golden master or a fingerprinted module: `evals/cve_replay.py` is in neither `GRAMMAR_PATHS` nor `_ENVIRONMENT_PATHS` of `evals/cve_baseline.py`. No baseline reset, no labeling log entry, no declared flip. Each of the two commit messages states this.

Both go test-first, as any change here: rewrite the tests against the new signature or the public name, see them fail (import or type error is the expected red for a pure rename or signature change), then change production.

Shared decisions across areas:

- `RaisingLLM` moves to `tests/fakes/llm.py` (exported from `tests/fakes/__init__.py`), used by `test_judge_session.py`, `test_run_judge_eval.py` and `test_run_probe.py`, which drops its private `_RaisingLLM` copy.
- `support/test_holdout_census_given.py::_provenance` becomes public `a_provenance()`, reused by the census draw and holdout draw givens instead of their two copies.
- The `ProviderThrottled` wording is pinned once, in `tests/unit/test_missed_steps.py`.
- Companions live under `tests/<level>/support/`, as everywhere in the suite.

## Area A: prompts, rendering, console, graph nodes, config

### Tests that cannot fail

`tests/unit/test_prompts.py`
- `test_includes_budget`: budget `37`, assert `"37" in prompt` (the template always holds "10 digits").
- `test_includes_schema`: schema with a property `account_number` of type integer, assert `"account_number" in prompt` (the template always holds "integer").
- `test_includes_all_categories` becomes `test_lists_only_the_requested_categories`: request `[INJECTION, RESOURCE_ABUSE]`, then for every `AuditCategory`, `assert (f"- {category.value}\n" in prompt) == (category in requested)`. List lines render as `- <value>\n`, guidance lines as `- <value>: ...`.
- The two tests at about lines 83 and 93 that assert the absence of the attack context header: take the header from production, `format_attack_context(AttackContext(db_engine="sqlite")).splitlines()[0]`, and assert it is absent, so the check follows the real wording.

`tests/unit/test_chain_prompts.py`
- `test_omits_attack_context_when_empty`: same fix as above (header from `format_attack_context`).
- `test_omits_most_significant_step_instruction`: delete (guards a removed phrase; the lasting contract, deterministic payload stamping, is `TestMakeJudgeChain.test_stamps_identity_and_deterministic_payload`).
- `test_asks_for_verdict`: delete ("FAIL"/"PASS" come from `JUDGING_RULES`, asserted present by `test_states_the_same_rules_as_the_single_call_judge`).
- `test_includes_chain_budget`: `chain_budget=17`, assert `"17" in prompt`.

`tests/unit/test_rendering.py` and `support/test_rendering_then.py`
- Add to the then module, below its first caller: `summary_of(markdown)` (text between `## Summary\n` and the next `\n## `, or the end of the document: the empty report has no section after its summary).
- `markdown_summary_has_counts` asserts `f"**Tools audited**: {tools}\n"`, `f"**Findings**: {findings}\n"` and each `f"{count} {severity}"` inside `summary_of(markdown)` (today `str(2) in markdown` matches any digit).
- `test_markdown_empty_report`: `then.markdown_summary_has_counts(result, tools=0, findings=0, per_severity_dict={})` instead of `"0" in result`.
- `markdown_contains_finding`: assert the heading `f"### FAIL -- {category} ({severity})"` (the heading renders `category_with_owasp_label(category)`, so `category` is the rendered label: plain `input_validation` for the one caller, which has no OWASP mapping) and `f"**Justification**: {justification}"` within that finding's block (text after the heading up to the next `###`).
- `test_json_round_trip` becomes `test_json_carries_the_whole_report`: `assert AuditReport.model_validate_json(render_json(report)) == report` on `given.a_two_tool_report()` (verified to hold today). Delete `test_json_enum_values`, and `json_has_expected_structure` and `json_has_enum_strings` from the then module.

`tests/unit/test_console_findings.py`, `support/test_console_given.py`, new `support/test_console_findings_then.py`
- Add `a_plain_display()` to the console given: `Console(file=buffer, force_terminal=False, no_color=True, width=100)`. Not `a_ci_display()`: CI mode routes `print_summary` through `render_summary` and would stop testing `_format_fail_cell`.
- Then module: `summary_row_reads(output, tool_name, expected_cells)` (splits the one row naming the tool on `│` and compares the stripped non-empty cells, the outer panel border giving empty ones) and `findings_recap_reads(output, expected_lines)` (the non-empty inner lines of the recap panel, stripped of `│ `).
- `test_summary_fail_column_zero_shows_no_breakdown`: plain display, `then.summary_row_reads(..., "get_user", ["get_user", "1", "1", "0"])` (today `"0" in output` matches the ANSI codes).
- `test_discovery_columnar_for_many_tools`: plain display, first line is exactly `"Discovered 8 tools:"`, and `" ".join(columns).split() == names`. `test_discovery_inline_for_few_tools`: plain display, output lines are exactly `["Discovered 4 tools: alpha, beta, gamma, delta"]`. Today both only check that names appear, so swapping the layout branch passes.
- `test_findings_recap_groups_by_severity`: input with the LOW tool first so sorting is observable, plain display, `then.findings_recap_reads(output, ["MEDIUM", "get_user > injection / MCP-05 — SQL injection possible", "LOW", "list_items > input_validation — No length check"])` (the dash is the rendered output, verbatim).

`tests/unit/test_console_display.py`
- `test_discovery_shows_count_and_names`: tool names `read_file`, `write_file`, `list_dir`, output read through `Text.from_ansi(buffer.getvalue()).plain`, assert `"3 tools"` and each name. `test_ci_mode_shows_discovery`: `"2 tools"` instead of `"2"`, and also assert `"write_file"`.
- `test_header_states_the_execution_regime`: parametrize over the three regimes (`CONFINED` "confined", `UNCONFINED` "unconfined", `DECLARED_CONTAINER` "declared container") and assert `f"execution: {shown}"` (today `"confined"` matches "unconfined"). The bar glyph assertions of the score test stay.

`tests/unit/test_cli.py`
- `test_chains_option_is_parsed` (only reads `--help`, so nothing is parsed) becomes `test_a_negative_chain_count_is_refused`: `run --chains -1 -- python x.py` exits 2 and names `--chains` (verified: refused before any config, launch or LLM step).
- Delete `test_relay_options_are_documented` (`--env` and `--env-plain` are driven by real invocations elsewhere). `test_confinement_options_are_documented` stays as is: `--image` and `--mount` are exercised by no other CLI test, and a real invocation would reach the container runtime.

### Library tests and duplicates

`tests/unit/test_chain_models.py`: delete `TestAttackChain`, `TestStepObservation`, `TestChainPlanBatch` (Pydantic construction) and `TestToolReportWithChains` (no code reads a report back from JSON; checkpoints go through LangGraph's serializer). Keep `TestAuditReportChainFindings`. Clean the imports.

`tests/unit/test_models.py`: delete `TestToolDefinition`, `TestTestCase`, `TestToolResponse` (Pydantic defaults, constructors and a round trip now covered by `test_json_carries_the_whole_report`). Clean the imports.

`tests/unit/test_config.py`: the env-var tests `test_default_settings` and `test_anthropic_provider_defaults` keep only what only they check, renamed `test_the_provider_defaults_to_openai` (`MCP_AUDITOR_PROVIDER` unset gives `"openai"`) and `test_the_provider_is_read_from_the_environment` (`anthropic` set gives `"anthropic"`). `test_the_provider_defaults_to_openai` also keeps that a bare `Settings()` resolves the default model, with no literal: `settings.resolve_model() == _settings("openai").resolve_model()` and the same for `resolve_reasoning`. It is the only test of the `model` and `reasoning` field defaults, since every `_settings(...)` test passes them explicitly. The default model and reasoning per provider stay owned by the `_settings(...)` tests.

`tests/unit/test_chat_model_factory.py`: in the default-model tests (google, anthropic, openai, fireworks, alibaba), resolve `model = settings.resolve_model()` once, build with it, and assert the built model against `model` and, where the built model carries the reasoning string, `settings.resolve_reasoning(model)` instead of literals (google `thinking_level`, openai, fireworks and anthropic `reasoning_effort`; anthropic's default is `None`). Anthropic's `thinking is None` stays: it is the only test of how the factory encodes no reasoning (`_anthropic_thinking(None)` gives `{}`), not a restated default. Alibaba's `extra_body == {"enable_thinking": False}` is the provider's encoding, not a restated default, and stays; rename them without the model name (e.g. `test_openai_builds_its_default_model_at_its_default_reasoning`). Keep the literals that are not defaults (explicit overrides, timeouts, `max_tokens`, endpoints, the OpenRouter `z-ai/glm-5.3` tied to `_glm_efforts()`), and the transport assertion of the Google test (landmine).

`tests/unit/test_cli_config_file.py` into `tests/unit/test_config_file.py`: move the three `merge_defaults` tests verbatim, rewrite the `env` refusal through `given.a_config_file_containing(tmp_path, env=["GITHUB_TOKEN"])` as `test_rejects_the_relayed_environment_as_a_file_key`, delete `test_cli_config_file.py`. In `test_config_file.py`, delete `test_converts_tools_list_to_comma_string` (covered by `test_loads_all_supported_keys`) and `test_chains_is_accepted_key`, and add `chains=3` to the input and `"chains": 3` to the expected dict of `test_loads_all_supported_keys`.

`tests/unit/test_generate_test_cases.py`: move `assert result["judged_cases"] == []` into `test_a_complete_batch_is_kept_without_retry` and delete `test_produces_pending_cases`.

### Graph nodes and checkpointing

`tests/unit/test_nodes.py` and `support/test_nodes_then.py`
- Delete the one-line wrappers `discovered_tools_count`, `current_tool_is`, `pending_cases_count`, `current_case_has_response`, `judged_cases_count`, `tool_report_has_cases`, `attack_context_has_db_engine` and inline them. Keep `current_case_has_error`, `discovered_tools_are`, `judged_case_identity_from`, `judged_case_uses_judgment`, `refused_step_recorded`. Where inlining, prefer the stronger form: `result["attack_context"] == AttackContext(db_engine="sqlite")`, `result["tool_reports"][0].cases == judged`, `[blocked] = result["judged_cases"]`; drop the count line in `test_filters_tools_by_name` (pinned by `discovered_tools_are`).
- Merge `test_dispatches_on_current_tool` and `test_success` into `test_records_the_response_of_the_current_tool` (tool `read_file` answering `"read_file was called"`; assert the response, `blocked_reason is None`, `pending_cases == []`).
- `test_accumulates_provider_usage` becomes `test_records_the_usage_of_the_extraction`: `result["provider_usage"] == [FAKE_USAGE]` (from `tests.fakes.llm`).

`tests/unit/test_chain_nodes.py`, `support/test_chain_nodes_given.py`, `support/test_chain_nodes_then.py`
- Delete the one-line wrappers `pending_chains_count`, `current_chain_goal_is`, `completed_chains_count`, `chain_has_steps`; inline them, using `[chain] = result["completed_chains"]` where a count is followed by taking the chain. Keep `chain_eval_result_is`.
- `refused_step_recorded` and `unreadable_step_recorded` stop comparing the production `detail` wording (owned by `test_missed_steps.py`): both go through a private `_one_missed_step(result, step, cause)` asserting `(tool_name, step, cause)`, with the tool name from a new `DEFAULT_TOOL_NAME = "file_manager"` in the given, used as `a_tool`'s default.
- `test_mid_chain_block_judges_the_executed_prefix`: replace the step count and the `payload not in` line with `assert chain.steps == [executed]`.

`tests/unit/test_graph.py` and `support/test_graph_then.py`
- `test_destructive_payload_is_blocked_and_never_sent`: the inline comprehensions become `then.one_case_blocked_unjudged_and_unsent(report, fake_mcp_client)` (one blocked case, unjudged, one judged case, one call sent). `then.report_has_cases(report, 2)` stays before it: it is what rules out a third case neither blocked nor judged.
- `test_attack_context_populated_after_audit`: delete the `attack_context_is_non_empty` line and the function (implied by `db_engine == "sqlite"`).
- `test_chain_budget_one_produces_chain` and `test_chain_budget_two_produces_two_chains` become one parametrized `test_the_chain_budget_sets_the_number_of_judged_chains` over `(1, a_fake_llm_for_single_tool_with_chain)` and `(2, a_fake_llm_for_single_tool_with_two_chains)`, asserting `then.report_has_judged_chains(report, chain_budget)` (count, and every chain has an `eval_result`). The two other tests pairing `report_has_chains` with `chain_has_eval_result` (about lines 345 and 361) use it too; delete the two old helpers once no caller is left. Delete `provider_usage_is_positive` (no caller left). `test_chain_budget_zero_skips_chains` stays.
- `test_checkpointer_round_trips_nested_subgraph_state` (never reads the checkpointer) becomes `test_the_checkpointer_round_trips_the_chain_state`: run with a `MemorySaver` and a thread id, read `(await graph.aget_state(config)).values`, assert `then.report_has_judged_chains(stored["audit_report"].tool_reports[0], 1)` (verified: the chain comes back as an `AttackChain` with its `eval_result`).

`tests/unit/test_checkpointing.py`: move `ServerDyingOnCall`, `given_a_crashed_audit` and `given_the_latest_checkpoint_holds` to a new `support/test_checkpointing_given.py` (as `ServerDyingOnCall`, `a_crashed_audit`, `a_latest_checkpoint_holding`), and `then_each_tool_audited_once` to a new `support/test_checkpointing_then.py` (as `each_tool_audited_once`). The graph helpers keep coming from `test_graph_given`, imported as `graph_given`.

## Area B: LLM adapter, judge, probe, redaction, throttling

`tests/unit/test_llm_adapter.py`, `tests/unit/test_llm_refusals.py`, new `support/test_llm_adapter_given.py` and `support/test_llm_refusals_given.py`, `support/test_llm_patience_given.py`
- Adapter given (the shared base): `Output`, `PYDANTIC_SCHEMA`, `DICT_SCHEMA`, `A_FULL_USAGE` (the `CompletionUsage` both files define today as `_CUT_USAGE` and `_FILTERED_USAGE`), `an_llm(responses, schema=DICT_SCHEMA, max_parse_attempts=3)`, `token_details(cache_read, reasoning)`, `a_completion(finish_reason, message, usage)` and `a_cut_completion(usage)`.
- Refusals given: imports the base and holds `OPENAI_POLICY_MESSAGE`, `a_bad_request(message, code)`, `a_permission_denied(body)`, `a_content_filtered(refusal, usage=None)`, `wrapped(cause)`, `with_raw(response, **raw_fields)` (today's private helpers, made public).
- Patience given: `Output` imported from the adapter given; `a_refusal` returns `a_bad_request("Invalid prompt", code="invalid_prompt")`. It keeps its own `an_llm(chat_model, patience)` (its tests read `chat_model.calls`).
- Spec files: `LLM(FakeChatModel(...), schema, max_parse_attempts=n)` becomes `given.an_llm(...)`, private helpers and constants go. Completion `id`/`model` become `"scripted"`; no assertion reads them (check with grep).
- Delete `test_a_response_cut_at_the_length_limit_on_every_attempt_raises` (a subset of `test_the_raised_error_counts_the_truncated_attempts_and_their_usage`). Delete `test_dicts_failing_validation_on_every_attempt_raise` and move its `match="unparseable output after 3 attempts"` into `test_the_raised_error_carries_the_usage_of_every_attempt`, renamed `test_dicts_failing_validation_on_every_attempt_raise_with_the_usage_of_each`.

`tests/unit/test_llm_throttling.py`: delete `test_no_breaker_outside_an_audit` and `test_an_audit_opens_a_closed_breaker_and_removes_it_on_exit` (ContextVar plumbing; the behavior is covered through the LLM by `test_llm_patience.py::TestBreaker`). Rename `TestOneAudit` to `TestThrottleBreaker`. The covering test trips the breaker inside an audit before its outside call, so a breaker shared by default outside any audit would pass it: add to `test_llm_patience.py::TestBreaker` `test_outside_any_audit_an_exhausted_call_does_not_block_the_next` (no `one_audit()`, a first call exhausted raises `ProviderThrottled`, a second call on the same LLM returns `Output(value="ok")`). `evals/run_probe.py` calls the LLM outside any audit.

`tests/fakes/llm.py`, `tests/unit/test_judge_session.py`, `tests/unit/test_run_judge_eval.py`, new `support/test_run_judge_eval_given.py`, `tests/unit/test_run_probe.py`
- `RaisingLLM` moves to `tests/fakes/llm.py` and is exported from `tests/fakes/__init__.py`. `test_run_probe.py` uses it and deletes `_RaisingLLM`.
- The three `judge_one_case` tests (and `THROTTLED`) move from `test_judge_session.py` to `test_run_judge_eval.py`. `AnsweringLLM` moves from the session given to the new run_judge_eval given, which also holds `a_judge_case()` (the first case of `a_judge_fixture()`). `test_run_judge_eval.py` imports that given.

`tests/unit/test_judge_gate.py`, `support/test_judge_gate_given.py`: add `a_floors_only_input(runs, baseline=None)` and use it in the three tests that build `JudgeGateInput(mode=FLOORS_ONLY, ...)` inline.

`ProviderThrottled` wording
- Delete `tests/unit/test_ports.py`: the two "fake satisfies port" tests assert `is not None` (strict pyright already checks conformance at every injection site), and `test_provider_throttled_names_the_wait_and_the_provider_message` reads its arguments back.
- `tests/unit/test_missed_steps.py`: the throttled case builds `ProviderThrottled(..., 312.4, usage)` instead of `312.0`; the expected `"(312 s waited by the auditor)"` is unchanged and now also covers the rounding.
- `tests/unit/test_run_probe.py::test_a_throttled_call_is_an_error_carrying_its_usage_and_the_provider_message`: `assert observation.error == str(throttled)` instead of the restated wording.

`tests/unit/test_redaction.py`: delete `test_stream_flush_returns_the_held_carry` (pins the carry length; flushing is covered by `test_stream_redacts_a_value_split_over_two_chunks`).

`tests/unit/test_log_redaction.py`, new `support/test_log_redaction_given.py`
- Given: `VALUE`, `SDK_LOGGERS = ("", "client", "mcp.client.stdio")`, a context manager `sdk_output()` attaching a `StreamHandler` on a `StringIO` per logger and removing it on exit, and `server_data_logged()` logging `"server sent %s", VALUE` at ERROR on each. The level matters: a record below the logger's effective level would be dropped by level, and the stdio silencing test would pass for the wrong reason.
- Replace the two tests reading `root.filters` and `stdio.level` with three output-based tests: `test_an_active_redaction_masks_the_value_and_silences_the_stdio_logger` (the `client` output carries `marker("TOKEN")`, the `mcp.client.stdio` output is empty, `VALUE` appears in no output), `test_an_active_redaction_is_undone_on_exit` (logged after the context, every output carries `VALUE`), `test_an_inactive_redaction_leaves_every_record_as_logged` (under `Redaction.none()`, every output carries `VALUE`). Verified: the active test fails if `""` or `"client"` is dropped from the redacted loggers. Keep `test_a_record_and_its_exception_are_formatted_with_the_marker`. The integration guard `tests/integration/test_relayed_environment.py` named by the landmine is unchanged.

`tests/unit/test_throttling.py`: `test_a_429_outside_any_count_is_ignored` has no assertion: it fails only if the handler raises outside a count (an exception in `emit` propagates through `logging.Handler.handle` to the logging call), and never checks that the 429 is left out. It becomes `test_a_429_outside_any_count_is_left_out_of_the_next_count`: one call answered 429 outside any count, then inside `counting_throttles()` one call answered 200, `tally.requests == 0`.

`tests/unit/test_probe_subset.py`: derive names from the roster. `first, second = CANDIDATES[:2]`, `select_candidates([second.name, first.name, second.name]) == [second, first]`; the unknown-name test passes `CANDIDATES[0].name` and asserts `"nope"`, `REFERENCE.name` and `CANDIDATES[1].name` in the message.

## Area C: honeypot eval harness

### Production: `WorkingTree` in `evals/eval_session.py`

The name: "checkout" already means `/srv/app` in the CVE benchmark (`cve_environments.py`, `cve_route.py`, the holdout kit), and "repository" reads as the persistence pattern. The object is everything the honeypot session reads from the git working tree, so it carries all of it, not only what today's tests need.

```python
@dataclass(frozen=True)
class WorkingTree:
    """What the eval session reads from the repository it runs in."""

    baseline_path: Path
    declared_flips_path: Path
    parent_commit: Callable[[], str | None]
    is_dirty: Callable[[], bool]
    read_tree: Callable[[], TreeState]


def open_session(options: EvalOptions, working_tree: WorkingTree) -> EvalSession: ...
def declarations_of_head(suite: Suite, working_tree: WorkingTree) -> tuple[list[DeclaredFlip], bool]: ...
```

- `open_session` loads the baseline from `working_tree.baseline_path` (`_load_committed_baseline` takes the path instead of reading `BASELINE_PATH`), reads the declarations through `declarations_of_head(Suite.HONEYPOT, working_tree)`, and records `working_tree.read_tree()` when recording a baseline, where it calls `read_tree()` today.
- `declarations_of_head` reads `working_tree.declared_flips_path` (in the refusal reason too), and calls `working_tree.parent_commit()` and `working_tree.is_dirty()` where it calls `_parent_commit()` and `_tree_is_dirty()` today. Its logic is unchanged.
- `REPOSITORY_TREE = WorkingTree(BASELINE_PATH, DECLARED_FLIPS_PATH, _parent_commit, _tree_is_dirty, read_tree)` at the bottom of the module, after the functions it names. `read_tree` stays a public function (`run_judge_eval` imports it for `JudgeHarness`).
- `tests/unit/test_eval_session.py` gains `test_the_repository_tree_reads_the_committed_files_and_this_repository`: `REPOSITORY_TREE == WorkingTree(BASELINE_PATH, DECLARED_FLIPS_PATH, eval_session._parent_commit, eval_session._tree_is_dirty, read_tree)`, comparing the functions by identity, with no git call. No other test builds the real tree, and a field swapped in it would only show on the next eval run, as a spurious refusal or a baseline silently not loaded (the gate then falls back to the legacy thresholds). The two private functions are read through the module, under `pyright: ignore[reportPrivateUsage]`: the test pins the composition, which is the one thing it is for.
- `evals/run_evals.py`: `open_session(options, REPOSITORY_TREE)`. `evals/run_judge_eval.py`: `declarations=lambda: declarations_of_head(Suite.JUDGE, REPOSITORY_TREE)`. `JudgeHarness` is otherwise unchanged.

Tests, `support/test_eval_session_given.py`: replace `a_git_whose_parent_is_declared` with `a_working_tree(declared_flips_path, dirty=False)` (parent is `PARENT`, baseline path `declared_flips_path.parent / "no_baseline.json"`, `read_tree` is `a_git_that_must_not_run` since no unit test records) and `a_working_tree_that_must_not_read_git(declared_flips_path)` (every git read is `a_git_that_must_not_run`). `tests/unit/test_eval_session.py`: drop every `monkeypatch` of `DECLARED_FLIPS_PATH`, `BASELINE_PATH` and `subprocess.run`, and the `eval_session` module import. `open_session` gets `given.a_working_tree(...)`; the invalid-declaration and empty-declaration tests call `declarations_of_head(Suite.HONEYPOT, given.a_working_tree_that_must_not_read_git(path))` directly (the empty one then asserts `== ([], False)`). The invalid-reasoning test passes `given.a_working_tree_that_must_not_read_git(given.a_declaration_file(tmp_path))`. This also removes two hidden reads of committed files: `test_an_invalid_declaration_file_is_refused_before_any_git_read` loaded `evals/baselines/honeypot_e2e.json`, and `test_an_invalid_reasoning_setting_is_refused_before_any_llm_call` read the real baseline and `evals/declared_flips.json`.

### Tests

`tests/unit/test_eval_metrics.py`
- `test_a_blocked_case_leaves_verdict_metrics_untouched`: keep only `assert aggregate_verdicts(with_a_block) == aggregate_verdicts(judged)`; the three recomputations on equal inputs cannot differ.
- `test_distribution_coverage_drops_when_the_only_case_of_a_category_is_blocked`: delete the second report and the `<` comparison, implied by `== 4/5`.

`tests/unit/test_eval_judging.py`, `support/test_eval_judging_given.py`
- `test_without_baseline_the_legacy_thresholds_judge_and_nothing_replays`: delete the `verdict` assertion, keep the `distribution_coverage` reason and its comment. `test_eval_gate_verdict.py` only calls `judge_gate` with hand-built inputs, and the reason is the one check that the no-baseline path of `judge_runs` hands the real metrics to the gate. Keep mode, thresholds, empty cells and deltas, no replay.
- Add `PLANTED_FLAWS = sum(verdict == EvalVerdict.FAIL for verdict in MERGED_GROUND_TRUTH.values())` to the given and express `(7, 8)` as `(PLANTED_FLAWS - 1, PLANTED_FLAWS)` and `(7 * 3, 3, 8)` as `((PLANTED_FLAWS - 1) * 3, 3, PLANTED_FLAWS)`. A label revision under ADR 020 then needs no test edit.

`tests/unit/test_export.py`, new `support/test_export_then.py`
- Then: `SINGLE_STEP_FIELDS` (the eleven keys), `exported_records(path)` (reads the JSONL), `every_record_is_a_single_step_with(records, fields)`.
- Split `test_writes_correct_fields_and_correct_values` into `test_a_judged_case_is_written_with_the_single_step_fields_and_its_label` (fields `SINGLE_STEP_FIELDS | {"expected_verdict", "correct"}`), `test_each_record_compares_its_verdict_to_the_label_of_its_cell` (three cases: `("fail", "fail", True)`, `("pass", "fail", False)`, `("pass", None, None)`), `test_each_record_carries_the_index_of_its_run` (`[0, 1]`).
- Delete `TestExportHandlesMissingGroundTruth` (its case is the third tuple). Turn the remaining one-test classes into plain functions; the chain and CVE tests use `then.exported_records`, the CVE one `then.every_record_is_a_single_step_with(records, then.SINGLE_STEP_FIELDS | {"cve_id"})`. `_read_jsonl` and `import json` leave the test file.

`tests/unit/test_fixture_contamination.py`, `support/test_fixture_contamination_given.py`: the five-word and four-word run tests use an inline corpus `{"Adds file contents to the staging area"}` with constants `"qqq contents to the staging area qqq"` (leaks) and `"qqq to the staging area qqq"` (does not), instead of runs cut from the live corpus. Delete `a_run_of`. Rename the four-word test `test_a_four_word_run_of_server_text_does_not_leak`.

## Area D: CVE benchmark

### Production: `evals/cve_replay.py`

Rename `_arguments_agree`, `_replayed_units` and `_lost_connection` to `arguments_agree`, `replayed_units` and `lost_connection` (definitions and call sites in `replay_credit`, `_struck`, `_run_patched`). `_sent_a_call` and `_next_output` stay private. Do not move them into `cve_report_units`, `cve_units`, `cve_proofs` or a new module beside them: those are fingerprinted grammar paths, and moving code there resets every CVE baseline. `tests/unit/test_cve_replay.py` imports the three names and drops the `pyright: ignore` suppressions; `_agree` stays as a local helper.

### Unit tests

`tests/unit/test_cve_audit.py`, `support/test_cve_audit_given.py` (one commit; replaces every private call except the two `_checked_grade` tests, whose `replay` keyword is the deliberate seam and has no public path)
- Given: `a_target_launching(launch=Launch("x", []))` replaces `a_target_launching_nothing()`. One fake replaces `an_audit_reporting`, `a_grading_that_must_not_run`, `captured_graph_input`, `breakers_seen_by_the_graph`, `tools_filters_seen_by_the_graph`, `_a_graph_running` and `captured_connect_timeout`:

```python
@dataclass
class AuditWiringSeen:
    graph_inputs: list[dict[str, object]] = field(default_factory=list)
    tools_filters: list[frozenset[str] | None] = field(default_factory=list)
    breakers: list[ThrottleBreaker | None] = field(default_factory=list)
    timeouts: list[int] = field(default_factory=list)


def an_audit_reporting(monkeypatch: pytest.MonkeyPatch, report: AuditReport | None = None) -> AuditWiringSeen:
    """Fakes the two imported collaborators, build_graph and connect, and records what they were given."""
```

  It patches `cve_audit.build_graph` (the fake graph records `graph_input` and `current_breaker()`, returns `{"audit_report": report or grammar.a_report()}`; the builder records `kwargs["tools_filter"]`) and `cve_audit.connect` (records `tool_call_timeout`, yields `FakeMCPClient([])`). `a_report_throttled(times)` builds on `grammar.a_report()` so it grades cleanly.
- Tests drive the public `attempt_once(target, auditor, SessionThrottles(), {}, overrides)`: the two throttle-message tests, the breaker-per-attempt test (two attempts, two distinct breakers), and the throttled-step test without `a_grading_that_must_not_run` (a `ThrottledAttempt` outcome already proves grading did not run).
- The seven override tests and the two tools-filter tests become two parametrized tables. `test_a_forced_setting_wins_and_an_unset_one_keeps_the_launch_own` over a launch with `chain_budget=3, max_chain_steps=5`: `(None, 3, 5, TOOL_CALL_TIMEOUT)`, `(RunOverrides(None, None, None), 3, 5, TOOL_CALL_TIMEOUT)`, `(RunOverrides(7, 9, 11), 7, 9, 11)`, `(RunOverrides(None, 9, None), 3, 9, TOOL_CALL_TIMEOUT)`, `(RunOverrides(7, None, None), 7, 5, TOOL_CALL_TIMEOUT)`, asserting the graph input's chain settings and `seen.timeouts`. `test_the_graph_audits_the_target_tools_filter_unless_every_tool_is_audited`: `None` and `RunOverrides(None, None, None)` give `TARGET.tools_filter`, `audit_every_tool=True` gives `None`.

`tests/unit/test_cve_oracle.py`: delete `test_the_report_json_carries_the_throttled_requests` and `test_the_report_json_carries_the_provider_usage_and_the_tree` (set a plain field, read it back from `model_dump`). The old-JSON compatibility test stays.

`tests/unit/test_cve_targets.py`: delete `test_the_kubernetes_note_is_broadened_beyond_the_env_nonce` and `test_the_git_init_note_no_longer_stages_the_dot_path` (prose of `note`; the git_init staging landmine is guarded by `test_the_git_init_exploit_stages_exact_relative_paths_outside_the_checkout`, untouched). Delete `test_the_environment_picks_the_normal_launch_in_the_normal_launch_mode` (redundant with the recording-builder test of the default SSRF target and with the parametrized launch-mode test).

`tests/unit/test_cve_planting.py`, `support/test_cve_planting_given.py`
- Delete `test_the_spec_holds_no_host_path_container_or_network_name_nor_argv` (asserts an unused fake is empty).
- `test_a_teardown_failure_is_logged_and_does_not_raise` becomes `test_a_teardown_failure_is_logged_and_the_rest_of_the_teardown_still_runs`: with `remove_sentinel` failing, `docker.holders == {}` and `"planting teardown failed" in caplog.text` (verified on the fake).
- `test_a_host_user_launch_resolves_the_uid_only_at_planted`: delete `host.user.value == "host"` (asserts the given).
- Delete `spec.account.name not in spec.account.home` and `name not in "/tmp"` (cannot fail once home is `/tmp`), the `startswith("/")` line after the exact path list, and `len(first) <= 32` after the `{0,31}` regex. Replace `"-e" in args.env` and the `NAME=value` membership with `args.env == ("-e", f"FICTIONAL_TOKEN={spec.nonces['env-1']}")`.
- In `test_a_sentinel_that_does_not_serve_raises_and_leaves_nothing_alive` and `test_a_setup_failure_after_the_holder_undoes_everything_and_raises_planting_failed`, the three inline asserts become `then.nothing_left_alive(docker)` (verified to pass, it also checks `host_files`).

`tests/unit/test_cve_planting_layout.py`, `support/test_cve_planting_given.py`: delete `test_the_git_remote_url_nonce_is_url_safe_for_a_userinfo` (checks `FakeNonces` against the regex). Delete `_NonUrlSafeNonces` and `test_the_non_url_safe_regex_rejects_a_userinfo_delimiter`; add `FixedTokenNonces(token)` to the given beside `FakeNonces`, and parametrize the refusal test over `"needs@encoding"`, `"needs:encoding"`, `"needs/encoding"` through `planting_spec`, asserting the id `bare-remote-url-fic` is named and the token is not.

`tests/unit/test_cve_places.py`: delete `test_the_real_places_file_validates_under_its_schema` and `_assert_coordinate_is_well_formed` (content pinned by the hash test, uniqueness enforced by `load_places`, coordinates covered by the rejection tests, and three other tests load the real file). Delete the stale comment above `test_every_target_reaches_only_the_closed_vocabulary` (targets do keep places now).

`tests/unit/test_cve_strike.py`: delete `test_a_nonce_under_fail_is_detected` and `test_an_echoed_nonce_never_counts` (duplicates of `test_cve_grammar.py`, no strike involved). `test_a_nonce_in_a_judged_unit_is_reported_unchecked_under_an_unchecked_check` duplicates another test; rewrite it as `test_a_nonce_in_a_pass_judged_unit_is_still_reported_unchecked` with `verdict=grammar.PASS`, the only test of that branch of `_unchecked_places`.

`tests/unit/test_cve_route.py`: `test_the_route_procedure_issues_at_least_one_call_for_the_git_filter` becomes `test_a_required_array_argument_is_called_with_an_empty_list`, with the single tool `git_add` (with files) and `assert dict(calls)["git_add"]["files"] == []`.

`tests/unit/test_cve_session.py`, `support/test_cve_session_given.py`, new `support/test_cve_session_then.py`: `the_one_target_ends(result, outcome, verdict=None) -> TargetComparison` (asserts the gate exists, a single target, its outcome, and the verdict when given; returns the comparison for the tests that then check `replays`) replaces the repeated block. Delete `ScriptedCheck.checked` (never read).

`tests/unit/test_cve_survey.py`: delete `support/test_cve_survey_given.py` and use `test_cve_planting_given` (its builders and `FakeNonces` cover the survey; verified 13/13 with the planting fake). Mapping: `a_file_place(id, path)` to `file_place(id, path=...)`, `an_endpoint_place(id, host, path)` to `endpoint_place(id, host=..., path=...)`, the other place builders lose their article, `NO_NETWORK`/`WITH_NETWORK`/`HOST_USER` become `unprivileged_host()`, `unprivileged_host(has_network=True)`, `host_user_host()`. The reach test builds its two non-default reaches with `dataclasses.replace(..., reachable_by=...)`. The expected survey lines read `(fictional-family)`.

`tests/unit/test_run_cve_benchmark.py`, new `support/test_run_cve_benchmark_given.py`
- Given: `BILLED_CVE`, `PRICED_MODEL`, `exit_code_of(monkeypatch, *flags)` (sets argv, runs `main`, returns the exit code), `a_session_under_priced_models(monkeypatch, audit_target=None, dirty=False)` (provider and model env vars, `preflight_ok`, `read_tree`, `audit_target`, `run_gated` stubs), `a_billing_audit_target` (the per-target one; it serves all callers, since `count(report, target_id)` also adds to the total), `an_audit_target_recording(forced)`, `a_session_auditing_nothing`, `a_session_that_crashes_if_started`.
- The unpriced-model refusal stands in `a_session_that_crashes_if_started` instead of recording sessions: `main` turns any exception into exit 4, so exit 3 proves the session never ran.
- The measurement-run test keeps its recording of the overrides handed to `audit_target`: the report's `measurement` is computed from the arguments separately, so the recording is the only check of that wiring.
- Split the measurement-flag refusal: `test_a_measurement_flag_outside_an_ungated_run_is_refused` over `--chains 3`, `--chain-steps 3`, `--tool-call-timeout 30`, `--no-tools-filter`, `--record-baseline --tool-call-timeout 30`, asserting exit 3 and `MEASUREMENT_UNGATED` in the output; `test_chain_steps_without_chains_are_refused` over `--ungated --chain-steps 3` and `--ungated --chains 0 --chain-steps 3`, asserting `STEPS_WITHOUT_CHAINS`. The `--calibrate --chains 3` and `--survey --no-tools-filter` cases go (covered with their reason by the "runs no audit" test). The reason constants are imported from `evals/cve_measurement.py`.

`tests/unit/test_target_execution.py`: delete `test_the_launcher_table_is_closed` (restates `IMAGE_BY_LAUNCHER`). Parametrize `test_an_unknown_launcher_stops_before_any_runtime_call` over `python`, `node`, `uv`, `bun`, and add `test_a_known_launcher_runs_confined_in_its_own_image` over `("npx", "node:24-bookworm-slim")` and `("uvx", "ghcr.io/astral-sh/uv:python3.14-trixie-slim")` (regime `CONFINED`, `runtime.pulled == [expected_image]`). The images are literals: reading them back from `IMAGE_BY_LAUNCHER` would let a swapped or wrong image pass.

### Integration tests

`tests/integration/test_cve_replay.py`, `tests/integration/test_cve_calibration.py`, their givens, new `tests/integration/conftest.py`, new `tests/integration/support/cve_stub_target.py`, new `tests/integration/support/test_cve_replay_then.py`
- `conftest.py` holds the `docker_on_the_host` fixture, today duplicated verbatim in both files. `test_cve_replay.py` uses it module-wide with `pytestmark = pytest.mark.usefixtures("docker_on_the_host")`; `test_cve_calibration.py` keeps its per-test decorators (its git reference-arm test must not use the fake docker).
- `cve_stub_target.py` (a shared builder module like its `cve_stub_server.py` neighbours) holds `a_docker_that_runs_its_command_on_the_host`, `a_file_place`, `reading`, and `a_stub_target(cve_id, builder, benign, *, aim=OUTSIDE_AIM, kept_places)`, the body of today's calibration `_a_target` with the exploit `reading("/outside/flag")`. Both givens build on it; the replay given keeps only its builder closure. `FLAW_PATH` stays `"/outside/flag"` to match the shared exploit (say so in one comment).
- Then: `the_credit_is_kept(check)`, `the_flaw_credit_is_struck(check)`, `the_credit_is_left_unchecked(check)`, replacing the repeated inline pairs; the `grade_run(...).status` lines stay inline. `test_a_fresh_nonce_of_another_location_strikes_nothing` keeps its own weaker assertion.

`tests/integration/test_holdout_kit.py`: in `test_list_tools_and_a_benign_call_over_a_real_launch`, move the tools assertion after the When, as `"list_directory" in {tool.name for tool in tools}`, and replace `response.content is not None` (a `str`, cannot fail) with `".git" in response.content` (proves the `/srv` layout is mounted; observed `'[DIR] .git'`).

`tests/integration/test_confined_launch.py`, new `support/test_confined_launch_given.py` and `_then.py`
- Given: `a_confined_context(options)` (the `LaunchContext` with `DockerRuntime`, the host's uid, gid, home, Docker env and environ, and a fresh container name) and `a_mount_hostile_directory(root, name, leaf)`.
- Then: `the_read_only_mount_refused_the_write(refused, reference)` asserting `refused.is_error`, `"read-only file system" in refused.content` (observed: `EROFS: read-only file system, open '...'`) and the file absent on the host (today a lenient `or` passes on any error); `the_record_lists_the_mounts(record, writable, read_only)` (record present, `oom_killed is False`, both paths listed); `no_container_is_left(name)`.
- Both tests build their context through the given. Every assertion of the first test is kept: the `oom_killed` check guards the `--memory-swap` landmine.

## Area E: holdout and census

`tests/unit/test_census_draw.py`, new `support/test_census_draw_given.py`, `support/test_holdout_census_given.py`
- Move the builders at the bottom of the spec file to the new given, public: `A_DRAWN_FLAW`, `A_TWICE_GIVEN_UP_FLAW`, `a_draw()`, `a_card(flaw)`, `a_census_with_draw(draw)`, and `a_census_drawing(identifiers)` (merges `_census_of(identifiers, _a_draw_of(identifiers))`, always called together). `_a_draw_of` and `_flaw` stay private in the given; `_provenance` is replaced by the census given's `a_provenance()`.
- `test_thirty_drawn_flaws_disclosed_after_one_date_raise_no_problem` becomes `test_thirty_drawn_flaws_disclosed_after_one_date_load`: `load_census(census.written(tmp_path, given.a_census_drawing(identifiers)))` and `loaded.draw == census_of_thirty.draw` (verified to load cleanly), instead of a five-argument `draw_problems(...)` assembled inline.

`tests/unit/test_holdout_draw.py`, new `support/test_holdout_draw_given.py`: move `_flaw`, `_agreed_classifications`, `_census` and the two constants to the given as `a_flaw`, `agreed_classifications`, `a_census`, `AN_EXCLUDED_SERVER`, `A_BENCHMARK_FLAW`, with `sources=a_provenance()`.

`tests/unit/test_holdout_audit.py`: delete `test_a_detection_with_a_refused_step_passes_through` (identical to `test_a_graded_audit_passes_through`, no refused step set up; the rule it names is `test_cve_audit.py::test_a_detection_is_kept_whatever_step_was_missed`).

`tests/unit/test_holdout_run.py`, new `support/test_holdout_run_given.py`
- Move the builders (`_conditions`, `_target`, `_report`, `_graded`, `_deps`, `_scripted`, `_raising_deps`, `_three_detections`, `_run`) to the given as `a_target`, `a_report`, `graded`, `scripted`, `deps_auditing`, `deps_reaching_nothing`, `three_detections`, `run`, plus `LUNA_PRICE`, `SETTINGS` and `_conditions`.
- `a_target(cve_id=FILESYSTEM, **changes)` looks the target up by `cve_id` (`FILESYSTEM = "CVE-2025-53109"`, `KUBERNETES = "CVE-2025-53355"`) instead of an index into `CVE_TARGETS`. Real targets are needed: `run_holdout` plants the kept places and fingerprints the fixture.
- `run(targets, deps, *, dates=None, runs=3)` (`dates=None` gives every target `date(2026, 1, 1)`, an explicit `{}` is kept for the census test). The three tests calling `run_holdout` in full go through it.
- An autouse fixture in `test_holdout_run.py` deletes `LANGSMITH_TRACING` and `LANGCHAIN_TRACING_V2` with `monkeypatch.delenv(..., raising=False)`, so the file stops failing on a machine whose shell has tracing on (`tests/conftest.py` only neutralises `.env`). The tracing test sets its variable in its own body, after the fixture ran. Not inside `run`: `run` has no monkeypatch, and clearing there would also erase the tracing test's variable.
- `test_a_drawn_target_with_a_tools_filter_refuses_before_any_check` and `test_tracing_refuses_before_any_container` run on `deps_reaching_nothing()`, so a refusal moved after a check or a rebuild goes red (today every dep succeeds).
- `test_target_services_dedups_images_and_patched_twins` uses two targets with synthetic images sharing one (`("app",)` / `"app-patched"` and `("app", "sentinel")` / `"other-patched"`), expecting `["app", "app-patched", "sentinel", "other-patched"]`. Today the two real targets share no service, so the dedup is never exercised.

`tests/unit/test_holdout_conditions.py`: in `test_the_committed_file_is_ready_for_the_logged_models`, delete the two single-model `require_ready` calls (implied by the two-model one). The value pins stay: they are the holdout run conditions logged in `docs/holdout-log.md`, and the test forces a second file to move with them.

`tests/unit/test_holdout_targets.py`: delete `test_the_empty_holdout_target_tuple_loads` (a change detector that the transplant of a drawn target turns red; the loop over an empty tuple cannot fail; the empty-draw behavior is `test_run_holdout.py::test_run_without_a_drawn_target_exits_zero_and_says_so`). Drop the `CVETarget` import if unused.

`tests/unit/test_holdout_kit_isolation.py`, `support/holdout_kit_isolation.py`
- `import_closure_offenders(modules, root)` takes the directory it imports from (passed as `cwd` to the fresh interpreter). Add `kit_modules(out)`: every module of the written kit's `evals` package, by dotted name.
- Delete `_KIT_MODULES`, `_COPIED_CLEAN_MODULES` and `test_no_copied_clean_module_imports_mcp_auditor` (hand copies of the dossier's lists; the written-tree scan in `test_run_holdout.py::test_calibration_dossier_writes_an_isolated_kit` covers every copied file). Replace `test_kit_import_closure_holds_no_mcp_auditor_module` with `test_the_written_kit_imports_from_its_own_tree_with_no_mcp_auditor_module`: `write_kit(census_given.a_census(), census_given.FLAW_WITH_A_CVE, out)`, then `iso.import_closure_offenders(iso.kit_modules(out), root=out) == []`. This checks the kit's real promise (it runs with no repository on the path), which no test checks today; verified by prototype (16 modules import, no `mcp_auditor` module loads). Keep `test_no_kit_file_imports_mcp_auditor` and the negative control.
- The spec file's module docstring drops "and the clean modules the dossier copies" and names the written kit's import closure instead.
- The support module's docstring drops "(Step 5)": "Isolation checks for the holdout calibration kit, static and at runtime. Reused by test_holdout_kit_isolation.py and test_run_holdout.py on the written `--out` tree: the one place that knows what "free of mcp_auditor" means for the kit."

`tests/unit/test_holdout_report.py`: `test_render_markdown_shows_the_number_ladder_split_controls_and_cost` becomes `test_render_markdown_shows_the_number_ladder_controls_and_cost` and pins rendered lines instead of section names: `"Capability: 0.667 (95% Wilson "`, `"## Ladder\n- 3 detecting run(s): 1 target(s)\n- 1 detecting run(s): 1 target(s)\n"`, `"## Controls\n- clopper_pearson: "`, `"- unchecked_as_misses_wilson: "`, `"- CVE-C: dead condition on the patched version"`, `"Incomplete runs (a step refused or unreadable): 1 (CVE-B)"`, and `markdown.endswith("Total cost: $0.06")` (checked against the actual output).

`tests/unit/test_holdout_hierarchical.py`: delete `test_contrast_clamps_to_minus_one_one` (its input sits at the positive end, where the upper bound cannot pass 1; on the most extreme inputs the holdout allows, the unclamped low stays above -0.995). Replace `test_interval_clamps_to_zero_one` (its input `[3]*5` reaches neither clamp) with `test_an_all_missed_interval_clamps_its_low_bound_to_zero`: `hierarchical_interval([0] * 20, RUNS, GammaPrior(1.0, 1.0)).low == 0.0`. The low clamp is reachable: when every target is missed, `_quantile` extrapolates below 0 (about -0.001 for 20 targets), and a run that detects nothing depends on that clamp, which no test covers today. Only the upper clamp is unreachable by construction.

`tests/unit/test_run_census.py`: delete `test_the_help_lists_the_four_subcommands` (each subcommand runs end to end in the file). Drop the imports ruff then flags.

## Sweep: `@pytest.mark.asyncio`

Last commit, after the areas: delete every `@pytest.mark.asyncio` line (104 in `test_llm_adapter.py`, `test_llm_refusals.py`, `test_llm_patience.py`, `test_graph.py`, `test_checkpointing.py`, `test_chain_nodes.py`, `test_graph_throttling.py`, `test_run_probe.py`): `pyproject.toml` sets `asyncio_mode = "auto"`. Let ruff flag any `import pytest` left unused, and check the async tests still collect and run.

## What stays unchanged

- Every honeypot server, golden master (`cve_layout_check_golden.json`, `cve_route_golden.json`, the CVE grammar golden), baseline, fixture and declared flips file. No test refactoring here regenerates a golden file.
- The landmine guards: `tests/integration/test_relayed_environment.py`, the git_init staged-paths test, the `/srv` read-write and read-only mount assertions, the hardened argv golden test, `test_wire_models_mirror_their_domain_models`, the `oom_killed` assertion, the Google transport assertion.
- Deliberate pins confirmed by the review: `HOLDOUT_INFRA_ATTEMPTS == 3` (the published holdout rule), the value pins of `test_holdout_conditions.py`, the byte-for-byte Markdown rows of `test_cve_oracle.py`, the direct test of `observe_case`, the recording of overrides in the measurement-run test.
- No production behavior. No living doc changes: no command, flag, prerequisite or user-facing behavior moves, so `README.md`, `CLAUDE.md`, `CONTRIBUTING.md` and `CHANGELOG.md` stay as they are.

## Out of scope

- Findings judged optional (cosmetic or low value): about sixty, among them the shared Docker-image prerequisite helper, the console-module injection in the holdout audit, the allowlist of report text fields, parametrizing near-identical test pairs, moving `TestFilterTools` and `tracing_enabled` tests, renames in `test_judge_metrics.py`, the `RecordingBuilder` fake, the route and preflight givens, the stream handler given.
- Findings refuted or kept on purpose: `observe_case` direct test, the cve_session given (it monkeypatches nothing), the Markdown rows of the CVE report, the holdout infra-attempt pin, the overrides recording, the private probe budget constant (a production knob for test speed costs more than it saves), the wire model parity guard.
- Injecting the graph builder and the MCP connection into `attempt_once`: area D keeps patching the two imported collaborators `cve_audit.build_graph` and `cve_audit.connect` (better than today's private functions), where area C removes the module patching of the eval session. A third production change, left for its own plan.
- Production observations from the review, each its own change if wanted: the unreachable clamps in `evals/holdout_hierarchical.py`, `ProviderThrottled.waited_seconds` read nowhere, the `dict` arm of `TestCase.response` that no caller writes.

## Verification

After each area, the short loop on the touched files: `uv run pytest tests/unit -n auto --maxprocesses 4`, the touched integration files, `uv run pyright <touched files>`, `uv run ruff check .`. Each area closes with the full check: `uv run pytest -n auto`, `uv run ruff check .`, `uv run pyright`.

Checks specific to this plan:
- For each rewritten false green, break the production behavior locally once and confirm the new test goes red, then restore it. A test that was never red may pass for the wrong reason. The list: prompts and chain prompts (budget, schema, categories, attack context header), rendering (summary counts, finding block, JSON carries the whole report), console (fail cell, discovery layouts, recap order, regime label, discovery count), the negative `--chains` refusal, the 429 left out of the next count, log redaction (each of `""`, `"client"`, `mcp.client.stdio` dropped in turn), the checkpointer round trip, the planting teardown that goes on after a failure, the PASS-judged unchecked nonce, the empty-list required array, the confined read-only mount refusal, the holdout kit `.git` content, the holdout run refusals before any check, the service dedup, the written kit import closure, and the throttled `ProviderThrottled` rounding.
- `git status` shows no change to any golden JSON, baseline or fixture under `evals/`.
- The test count moves by the deletions, merges and parametrized cases listed and nothing else: before each area, write down the expected delta (a parametrized table counts one item per case), then compare `uv run pytest --collect-only -q | tail -1` before and after, so a test lost by a bad move is noticed.
- Area C: `uv run python -m evals.run_evals --help` and `uv run python -m evals.run_judge_eval --help` still start (the composition roots build the real `WorkingTree`).

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites, read by the later passes. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, not what is true now. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- SETTLED: `asyncio_mode = "auto"` makes every `@pytest.mark.asyncio` redundant, 104 bare markers, none with arguments (verified against `pyproject.toml` and the locked pytest-asyncio 1.4.0)
- SETTLED: an exception raised in a `logging.Handler.emit` propagates to the logging call, it is not swallowed (verified on the project's CPython 3.13; the plan's earlier wording was corrected)
- SETTLED: `Console(file=buffer, force_terminal=False, no_color=True, width=100)` and `Text.from_ansi` exist (verified against the locked rich 15.0.0)
- SETTLED: `MemorySaver` and `graph.aget_state(config)` exist (verified against the locked langgraph 1.2.12)
- SETTLED: `AuditReport.model_validate_json` is the Pydantic v2 API (verified against the locked pydantic 2.12.5)

## Implementation steps

Each step is one commit. The items of each step are specified in full in the plan sections it names: read that section before starting, the step lists the files, the order and the checks. Every step is test-only unless marked production.

Common to every step:
- Before touching anything, run `uv run pytest --collect-only -q | tail -1` and write down the expected test count delta from the step's items (a parametrized table counts one per case). Compare after.
- For each rewritten false green in the step (the list under "Verification" in the plan), break the production behavior locally once, see the new test go red, restore.
- Short loop while working: `uv run pytest tests/unit -n auto --maxprocesses 4`, the touched integration files, `uv run pyright <touched files>`, `uv run ruff check .`.
- Close the step with the full check: `uv run pytest -n auto`, `uv run ruff check .`, `uv run pyright`, all green. `git status` shows no change to any golden JSON, baseline or fixture under `evals/` or `tests/unit/support/*.json`.
- Keep the `@pytest.mark.asyncio` markers as they are until Step 18.

### Step 1: Area A, prompts, rendering, console, CLI false greens

- **Files**: `tests/unit/test_prompts.py`, `tests/unit/test_chain_prompts.py`, `tests/unit/test_rendering.py`, `tests/unit/support/test_rendering_then.py`, `tests/unit/test_console_findings.py`, `tests/unit/support/test_console_given.py`, new `tests/unit/support/test_console_findings_then.py`, `tests/unit/test_console_display.py`, `tests/unit/test_cli.py`.
- **Do**: apply plan Area A, "Tests that cannot fail", every bullet, in file order. Then helpers first (`summary_of` below its first caller in the rendering then, `a_plain_display()` in the console given, `summary_row_reads` and `findings_recap_reads` in the new console findings then), then the spec rewrites. Header of the attack context taken from `format_attack_context(AttackContext(db_engine="sqlite")).splitlines()[0]`. Deletions: `test_omits_most_significant_step_instruction`, `test_asks_for_verdict`, `test_json_enum_values`, `json_has_expected_structure`, `json_has_enum_strings`, `test_relay_options_are_documented`.
- **Test**: budget `37` / chain budget `17` appear, `account_number` appears, only the requested categories are listed (`- <value>\n` lines), summary counts read exactly inside `summary_of`, finding heading and justification within its block, `AuditReport.model_validate_json(render_json(report)) == report`, summary row cells `["get_user", "1", "1", "0"]`, exact columnar and inline discovery layouts, recap lines in severity order with the LOW tool given first, `"3 tools"` / `"2 tools"` read through `Text.from_ansi(...).plain`, regime label parametrized over the three regimes, `run --chains -1 -- python x.py` exits 2 naming `--chains`.
- **Verify**: common checks. Break each rewritten behavior once (budget, schema, category filter, attack context header, summary counts, finding block, a dropped report field in JSON, fail cell, layout branch, recap sort, regime label, discovery count, the negative `--chains` validation) and see red.

### Step 2: Area A, library tests, duplicates and config

- **Files**: `tests/unit/test_chain_models.py`, `tests/unit/test_models.py`, `tests/unit/test_config.py`, `tests/unit/test_chat_model_factory.py`, `tests/unit/test_cli_config_file.py` (deleted), `tests/unit/test_config_file.py`, `tests/unit/test_generate_test_cases.py`.
- **Do**: apply plan Area A, "Library tests and duplicates". Delete `TestAttackChain`, `TestStepObservation`, `TestChainPlanBatch`, `TestToolReportWithChains`, `TestToolDefinition`, `TestTestCase`, `TestToolResponse`, clean imports. Rename and reduce the two config env-var tests, `test_the_provider_defaults_to_openai` keeping the bare `Settings()` resolution against `_settings("openai")`. In the factory default-model tests resolve `settings.resolve_model()` and `settings.resolve_reasoning(model)` instead of literals, keep the listed non-default literals, Anthropic's `thinking is None` and the Google transport assertion (landmine). Move the three `merge_defaults` tests into `test_config_file.py`, rewrite the `env` refusal through `given.a_config_file_containing(tmp_path, env=["GITHUB_TOKEN"])`, delete `test_cli_config_file.py`, `test_converts_tools_list_to_comma_string`, `test_chains_is_accepted_key`, add `chains=3` to `test_loads_all_supported_keys`. Move the `judged_cases == []` assertion and delete `test_produces_pending_cases`.
- **Test**: `test_the_provider_defaults_to_openai`, `test_the_provider_is_read_from_the_environment`, the renamed factory default tests, `test_rejects_the_relayed_environment_as_a_file_key`, `test_loads_all_supported_keys` with `chains`.
- **Verify**: common checks. The collected count drops by exactly the deleted tests and classes.

### Step 3: Area A, graph nodes and checkpointing

- **Files**: `tests/unit/test_nodes.py`, `tests/unit/support/test_nodes_then.py`, `tests/unit/test_chain_nodes.py`, `tests/unit/support/test_chain_nodes_given.py`, `tests/unit/support/test_chain_nodes_then.py`, `tests/unit/test_graph.py`, `tests/unit/support/test_graph_then.py`, `tests/unit/test_checkpointing.py`, new `tests/unit/support/test_checkpointing_given.py`, new `tests/unit/support/test_checkpointing_then.py`.
- **Do**: apply plan Area A, "Graph nodes and checkpointing". Create the two checkpointing companions first and move `ServerDyingOnCall`, `a_crashed_audit`, `a_latest_checkpoint_holding`, `each_tool_audited_once` into them. Add `then.one_case_blocked_unjudged_and_unsent` and `then.report_has_judged_chains(report, count)` to the graph then, `DEFAULT_TOOL_NAME = "file_manager"` and `_one_missed_step(result, step, cause)` to the chain nodes given/then. Inline and delete the listed one-line wrappers in the nodes and chain nodes thens, delete `attack_context_is_non_empty`, `provider_usage_is_positive`, `report_has_chains`, `chain_has_eval_result` once callers are gone.
- **Test**: `test_records_the_response_of_the_current_tool` (merge), `test_records_the_usage_of_the_extraction` (`== [FAKE_USAGE]`), `test_mid_chain_block_judges_the_executed_prefix` (`chain.steps == [executed]`), parametrized `test_the_chain_budget_sets_the_number_of_judged_chains` over budgets 1 and 2, `test_the_checkpointer_round_trips_the_chain_state` reading `(await graph.aget_state(config)).values` from a `MemorySaver`.
- **Verify**: common checks. Break the chain state persistence (for example, drop `eval_result` before it is stored) once and see the checkpointer test go red.

### Step 4: Area B, LLM adapter and refusals givens, throttle breaker

- **Files**: `tests/unit/test_llm_adapter.py`, `tests/unit/test_llm_refusals.py`, new `tests/unit/support/test_llm_adapter_given.py`, new `tests/unit/support/test_llm_refusals_given.py`, `tests/unit/support/test_llm_patience_given.py`, `tests/unit/test_llm_patience.py`, `tests/unit/test_llm_throttling.py`, `tests/unit/test_redaction.py`.
- **Do**: apply plan Area B, first two bullets groups and the `test_redaction.py` item. Write the adapter given (shared base: `Output`, `PYDANTIC_SCHEMA`, `DICT_SCHEMA`, `A_FULL_USAGE`, `an_llm`, `token_details`, `a_completion`, `a_cut_completion`), the refusals given on top of it (public helpers listed in the plan), point the patience given at them (`a_refusal` via `a_bad_request("Invalid prompt", code="invalid_prompt")`, its own `an_llm(chat_model, patience)` stays). Rewrite both spec files on the givens, completion `id`/`model` become `"scripted"` after a grep confirms no assertion reads them. Delete the two adapter tests named in the plan and move the `match=` into the renamed test. Delete the two ContextVar tests in `test_llm_throttling.py`, rename `TestOneAudit` to `TestThrottleBreaker`, and add `test_outside_any_audit_an_exhausted_call_does_not_block_the_next` to `TestBreaker` (written first; make `_current_breaker` default to a shared breaker once to see it go red). Delete `test_stream_flush_returns_the_held_carry`.
- **Test**: `test_outside_any_audit_an_exhausted_call_does_not_block_the_next`, `test_dicts_failing_validation_on_every_attempt_raise_with_the_usage_of_each` (match `"unparseable output after 3 attempts"` and the usage of each attempt). All other adapter, refusals and patience tests unchanged in behavior.
- **Verify**: common checks. `test_llm_patience.py` stays green on the moved helpers.

### Step 5: Area B, `RaisingLLM`, judge and probe tests, `ProviderThrottled` wording

- **Files**: `tests/fakes/llm.py`, `tests/fakes/__init__.py`, `tests/unit/test_judge_session.py`, `tests/unit/support/test_judge_session_given.py`, `tests/unit/test_run_judge_eval.py`, new `tests/unit/support/test_run_judge_eval_given.py`, `tests/unit/test_run_probe.py`, `tests/unit/test_ports.py` (deleted), `tests/unit/test_missed_steps.py`.
- **Do**: apply plan Area B, the `RaisingLLM` group and the `ProviderThrottled` wording group. Move `RaisingLLM` to `tests/fakes/llm.py`, export it, use it in `test_run_probe.py` and drop `_RaisingLLM`. Move the three `judge_one_case` tests and `THROTTLED` to `test_run_judge_eval.py`, `AnsweringLLM` to the new run_judge_eval given beside `a_judge_case()` (first case of `a_judge_fixture()`). Delete `test_ports.py`. Build the throttled case of `test_missed_steps.py` with `312.4`. In the probe throttled test assert `observation.error == str(throttled)`.
- **Test**: the moved `judge_one_case` tests pass in their new file, the missed-step throttled detail still reads `"(312 s waited by the auditor)"`.
- **Verify**: common checks. Collected count drops by the three `test_ports.py` tests only. Break the rounding of the waited seconds once and see `test_missed_steps.py` go red.

### Step 6: Area B, log redaction, throttling count, judge gate, probe subset

- **Files**: `tests/unit/test_log_redaction.py`, new `tests/unit/support/test_log_redaction_given.py`, `tests/unit/test_throttling.py`, `tests/unit/test_judge_gate.py`, `tests/unit/support/test_judge_gate_given.py`, `tests/unit/test_probe_subset.py`.
- **Do**: apply plan Area B, the `test_log_redaction.py`, `test_throttling.py`, `test_judge_gate.py` and `test_probe_subset.py` items. The log redaction given holds `VALUE`, `SDK_LOGGERS`, the `sdk_output()` context manager and `server_data_logged()`. Add `a_floors_only_input(runs, baseline=None)` to the judge gate given. Derive probe subset names from `CANDIDATES` and `REFERENCE`.
- **Test**: `test_an_active_redaction_masks_the_value_and_silences_the_stdio_logger`, `test_an_active_redaction_is_undone_on_exit`, `test_an_inactive_redaction_leaves_every_record_as_logged` (replacing the two internals tests, keep the marker formatting test), `test_a_429_outside_any_count_is_left_out_of_the_next_count` (`tally.requests == 0`), the probe subset order `[second, first]`.
- **Verify**: common checks. Drop each of `""`, `"client"`, `mcp.client.stdio` from the redacted loggers in turn and see the active test go red. Make the handler count outside a count and see the 429 test go red. `tests/integration/test_relayed_environment.py` untouched and green.

### Step 7: Area C, production: `WorkingTree` in the eval session

- **Files**: `evals/eval_session.py`, `evals/run_evals.py`, `evals/run_judge_eval.py`, `tests/unit/test_eval_session.py`, `tests/unit/support/test_eval_session_given.py`.
- **Do**: plan Area C, "Production: `WorkingTree`". Test-first: rewrite the given (`a_working_tree(declared_flips_path, dirty=False)`, `a_working_tree_that_must_not_read_git(declared_flips_path)`, replacing `a_git_whose_parent_is_declared`) and the spec file (no monkeypatch of `DECLARED_FLIPS_PATH`, `BASELINE_PATH`, `subprocess.run`, no `eval_session` module import, `declarations_of_head(Suite.HONEYPOT, ...)` called directly in the invalid and empty declaration tests). Run them, see the import or type error. Then add the frozen `WorkingTree` dataclass, the new `open_session(options, working_tree)` and `declarations_of_head(suite, working_tree)` signatures, `_load_committed_baseline` taking the path, `REPOSITORY_TREE` at the bottom of the module, and the two composition-root call sites. Logic unchanged.
- **Test**: every existing eval session test passes against the injected tree. The empty declaration test asserts `== ([], False)`. Add `test_the_repository_tree_reads_the_committed_files_and_this_repository` (plan Area C), written before `REPOSITORY_TREE` exists so it starts red.
- **Verify**: common checks, plus `uv run python -m evals.run_evals --help` and `uv run python -m evals.run_judge_eval --help` start. The collected count grows by one. Commit message: a no-behavior refactoring of the eval harness, no scoring code, label, fixture, golden master or fingerprinted module touched, no baseline reset, no labeling log entry, no declared flip.

### Step 8: Area C, honeypot eval harness tests

- **Files**: `tests/unit/test_eval_metrics.py`, `tests/unit/test_eval_judging.py`, `tests/unit/support/test_eval_judging_given.py`, `tests/unit/test_export.py`, new `tests/unit/support/test_export_then.py`, `tests/unit/test_fixture_contamination.py`, `tests/unit/support/test_fixture_contamination_given.py`.
- **Do**: plan Area C, "Tests". Reduce the two eval metrics tests. In eval judging, drop the verdict assertion of the legacy-threshold test (keep the `distribution_coverage` reason and its comment), add `PLANTED_FLAWS` to the given and express the counts from it. Write the export then (`SINGLE_STEP_FIELDS`, `exported_records`, `every_record_is_a_single_step_with`), split the export test in three, delete `TestExportHandlesMissingGroundTruth`, turn the one-test classes into functions, remove `_read_jsonl` and `import json`. Replace the contamination run tests with the inline corpus and constants, delete `a_run_of`, rename the four-word test.
- **Test**: `test_a_judged_case_is_written_with_the_single_step_fields_and_its_label`, `test_each_record_compares_its_verdict_to_the_label_of_its_cell` (three cases), `test_each_record_carries_the_index_of_its_run` (`[0, 1]`), `test_a_four_word_run_of_server_text_does_not_leak`.
- **Verify**: common checks.

### Step 9: Area D, production: public replay functions in `evals/cve_replay.py`

- **Files**: `evals/cve_replay.py`, `tests/unit/test_cve_replay.py`.
- **Do**: plan Area D, "Production: `evals/cve_replay.py`". Test-first: import `arguments_agree`, `replayed_units`, `lost_connection` in the test and drop the `pyright: ignore` suppressions (`_agree` stays local), see the import error. Then rename the three functions and their call sites in `replay_credit`, `_struck`, `_run_patched`. `_sent_a_call` and `_next_output` stay private. Move nothing into a fingerprinted grammar module.
- **Test**: the existing replay tests, unchanged in behavior.
- **Verify**: common checks. `grep -rn "_arguments_agree\|_replayed_units\|_lost_connection" evals tests` is empty. Collected count unchanged. Commit message as in Step 7 (`evals/cve_replay.py` is in neither `GRAMMAR_PATHS` nor `_ENVIRONMENT_PATHS`).

### Step 10: Area D, CVE audit wiring, benchmark CLI, target execution

- **Files**: `tests/unit/test_cve_audit.py`, `tests/unit/support/test_cve_audit_given.py`, `tests/unit/test_run_cve_benchmark.py`, new `tests/unit/support/test_run_cve_benchmark_given.py`, `tests/unit/test_target_execution.py`.
- **Do**: plan Area D, the `test_cve_audit.py`, `test_run_cve_benchmark.py` and `test_target_execution.py` items. In the CVE audit given, `a_target_launching(launch=Launch("x", []))`, the `AuditWiringSeen` dataclass and `an_audit_reporting(monkeypatch, report=None)` patching `cve_audit.build_graph` and `cve_audit.connect`, replacing the seven helpers named in the plan, `a_report_throttled(times)` built on `grammar.a_report()`. Drive the public `attempt_once(...)` everywhere except the two `_checked_grade` tests. Benchmark given: `BILLED_CVE`, `PRICED_MODEL`, `exit_code_of`, `a_session_under_priced_models`, `a_billing_audit_target`, `an_audit_target_recording`, `a_session_auditing_nothing`, `a_session_that_crashes_if_started`, the measurement-run recording kept. Delete `test_the_launcher_table_is_closed`.
- **Test**: parametrized `test_a_forced_setting_wins_and_an_unset_one_keeps_the_launch_own` (five rows from the plan), `test_the_graph_audits_the_target_tools_filter_unless_every_tool_is_audited` (three cases), the breaker-per-attempt test (two distinct breakers), `test_a_measurement_flag_outside_an_ungated_run_is_refused` (five flag sets, exit 3, `MEASUREMENT_UNGATED`), `test_chain_steps_without_chains_are_refused` (two, `STEPS_WITHOUT_CHAINS`), unpriced-model refusal exits 3 under `a_session_that_crashes_if_started`, `test_an_unknown_launcher_stops_before_any_runtime_call` over `python`, `node`, `uv`, `bun`, `test_a_known_launcher_runs_confined_in_its_own_image` over `("npx", "node:24-bookworm-slim")` and `("uvx", "ghcr.io/astral-sh/uv:python3.14-trixie-slim")`, literal images.
- **Verify**: common checks. No `cve_audit._` private name remains in the test file except `_checked_grade`.

### Step 11: Area D, CVE oracle, targets, places, strike, route, session tests

- **Files**: `tests/unit/test_cve_oracle.py`, `tests/unit/test_cve_targets.py`, `tests/unit/test_cve_places.py`, `tests/unit/test_cve_strike.py`, `tests/unit/test_cve_route.py`, `tests/unit/test_cve_session.py`, `tests/unit/support/test_cve_session_given.py`, new `tests/unit/support/test_cve_session_then.py`.
- **Do**: plan Area D, the items for these files. Deletions in oracle (two report JSON tests), targets (three tests, the git_init staged-paths test untouched), places (the real-file schema test, `_assert_coordinate_is_well_formed`, the stale comment), strike (two duplicates). Rewrite the strike unchecked test with `verdict=grammar.PASS`, the route test with the single `git_add` tool. Add `the_one_target_ends(result, outcome, verdict=None) -> TargetComparison` to the new then and use it, delete `ScriptedCheck.checked`.
- **Test**: `test_a_nonce_in_a_pass_judged_unit_is_still_reported_unchecked`, `test_a_required_array_argument_is_called_with_an_empty_list` (`dict(calls)["git_add"]["files"] == []`).
- **Verify**: common checks. Break the PASS branch of `_unchecked_places` and the empty-list argument of the route once each and see red. `cve_route_golden.json` unchanged.

### Step 12: Area D, CVE planting, planting layout and survey tests

- **Files**: `tests/unit/test_cve_planting.py`, `tests/unit/support/test_cve_planting_given.py`, `tests/unit/test_cve_planting_layout.py`, `tests/unit/test_cve_survey.py`, `tests/unit/support/test_cve_survey_given.py` (deleted).
- **Do**: plan Area D, the planting, planting layout and survey items. Planting: the deletion, the teardown test rewrite, the redundant assertions removed, the exact `args.env` tuple, `then.nothing_left_alive(docker)` in the two failure tests. Layout: delete the URL-safe nonce test, `_NonUrlSafeNonces` and its regex test, add `FixedTokenNonces(token)` to the planting given and parametrize the refusal over the three tokens. Survey: switch to the planting given with the mapping in the plan, `dataclasses.replace(..., reachable_by=...)` for the two reaches, expected lines `(fictional-family)`, delete the survey given.
- **Test**: `test_a_teardown_failure_is_logged_and_the_rest_of_the_teardown_still_runs` (`docker.holders == {}`, `"planting teardown failed"` in `caplog.text`), the refusal naming `bare-remote-url-fic` and not the token for `"needs@encoding"`, `"needs:encoding"`, `"needs/encoding"`, the 13 survey tests on the planting fake.
- **Verify**: common checks. Make the teardown stop at the first failure once and see red.

### Step 13: Area D, CVE replay and calibration integration tests

- **Files**: new `tests/integration/conftest.py`, new `tests/integration/support/cve_stub_target.py`, new `tests/integration/support/test_cve_replay_then.py`, `tests/integration/test_cve_replay.py`, `tests/integration/support/test_cve_replay_given.py`, `tests/integration/test_cve_calibration.py`, `tests/integration/support/test_cve_calibration_given.py`.
- **Do**: plan Area D, "Integration tests", first group. Move `docker_on_the_host` to the conftest, `pytestmark = pytest.mark.usefixtures("docker_on_the_host")` in the replay file, per-test decorators kept in calibration. Shared builders in `cve_stub_target.py` (`a_docker_that_runs_its_command_on_the_host`, `a_file_place`, `reading`, `a_stub_target(...)`), both givens build on it, the replay given keeps only its builder closure, `FLAW_PATH = "/outside/flag"` with a one-line comment. Then: `the_credit_is_kept`, `the_flaw_credit_is_struck`, `the_credit_is_left_unchecked`.
- **Test**: every replay and calibration integration test unchanged in behavior. `test_a_fresh_nonce_of_another_location_strikes_nothing` keeps its own assertion.
- **Verify**: common checks, plus `uv run pytest tests/integration/test_cve_replay.py tests/integration/test_cve_calibration.py -n auto`. Same collected count for both files.

### Step 14: Area D, holdout kit and confined launch integration tests

- **Files**: `tests/integration/test_holdout_kit.py`, `tests/integration/test_confined_launch.py`, new `tests/integration/support/test_confined_launch_given.py`, new `tests/integration/support/test_confined_launch_then.py`.
- **Do**: plan Area D, the `test_holdout_kit.py` and `test_confined_launch.py` items. Given: `a_confined_context(options)`, `a_mount_hostile_directory(root, name, leaf)`. Then: `the_read_only_mount_refused_the_write`, `the_record_lists_the_mounts` (keeps `oom_killed is False`, the `--memory-swap` landmine guard), `no_container_is_left`.
- **Test**: the holdout kit lists `list_directory` after the When and the benign call content carries `".git"`. The read-only refusal requires `"read-only file system"` and the file absent on the host.
- **Verify**: common checks, plus `uv run pytest tests/integration/test_holdout_kit.py tests/integration/test_confined_launch.py` with Docker available (they skip without it, say so if they did). Break the read-only mount and the `/srv` mount once each where Docker is available.

### Step 15: Area E, holdout run, audit, conditions and targets tests

- **Files**: `tests/unit/test_holdout_run.py`, new `tests/unit/support/test_holdout_run_given.py`, `tests/unit/test_holdout_audit.py`, `tests/unit/test_holdout_conditions.py`, `tests/unit/test_holdout_targets.py`.
- **Do**: plan Area E, the items for these files. Move the builders to the given under the public names, `a_target(cve_id=FILESYSTEM, **changes)` looking up by id (`FILESYSTEM`, `KUBERNETES`), `run(targets, deps, *, dates=None, runs=3)`, `deps_reaching_nothing()` for the two refusal tests. Autouse fixture deleting `LANGSMITH_TRACING` and `LANGCHAIN_TRACING_V2`. Delete `test_a_detection_with_a_refused_step_passes_through`, the two single-model `require_ready` calls, `test_the_empty_holdout_target_tuple_loads` and its unused import.
- **Test**: `test_target_services_dedups_images_and_patched_twins` with the two synthetic targets expecting `["app", "app-patched", "sentinel", "other-patched"]`, the two refusals on `deps_reaching_nothing()`.
- **Verify**: common checks, once with `LANGSMITH_TRACING=true` exported in the shell for `uv run pytest tests/unit/test_holdout_run.py`. Move the tools-filter refusal after a check once and see red, break the dedup once and see red.

### Step 16: Area E, census draw and holdout draw givens

- **Files**: `tests/unit/test_census_draw.py`, new `tests/unit/support/test_census_draw_given.py`, `tests/unit/support/test_holdout_census_given.py`, `tests/unit/test_holdout_draw.py`, new `tests/unit/support/test_holdout_draw_given.py`.
- **Do**: plan Area E, the census draw and holdout draw items. Make `_provenance` public as `a_provenance()` in the census given and use it in both new givens. Move the census draw builders (`A_DRAWN_FLAW`, `A_TWICE_GIVEN_UP_FLAW`, `a_draw`, `a_card`, `a_census_with_draw`, `a_census_drawing`) and the holdout draw ones (`a_flaw`, `agreed_classifications`, `a_census`, `AN_EXCLUDED_SERVER`, `A_BENCHMARK_FLAW`).
- **Test**: `test_thirty_drawn_flaws_disclosed_after_one_date_load` through `load_census(census.written(tmp_path, ...))`, `loaded.draw == census_of_thirty.draw`.
- **Verify**: common checks. Collected count unchanged.

### Step 17: Area E, kit isolation, holdout report, hierarchical, run census

- **Files**: `tests/unit/test_holdout_kit_isolation.py`, `tests/unit/support/holdout_kit_isolation.py`, `tests/unit/test_holdout_report.py`, `tests/unit/test_holdout_hierarchical.py`, `tests/unit/test_run_census.py`.
- **Do**: plan Area E, the items for these files. `import_closure_offenders(modules, root)` passing `root` as `cwd`, add `kit_modules(out)`, delete `_KIT_MODULES`, `_COPIED_CLEAN_MODULES` and `test_no_copied_clean_module_imports_mcp_auditor`, the two docstrings rewritten as specified (check `test_run_holdout.py`'s caller still type-checks against the new signature). Pin the rendered report lines. Delete the contrast clamp test and the help test, replace the interval clamp test with `test_an_all_missed_interval_clamps_its_low_bound_to_zero` (remove `max(0.0, low)` once locally to see it go red), drop the imports ruff flags.
- **Test**: `test_the_written_kit_imports_from_its_own_tree_with_no_mcp_auditor_module` (`== []`), `test_an_all_missed_interval_clamps_its_low_bound_to_zero`, `test_render_markdown_shows_the_number_ladder_controls_and_cost` with the lines listed in the plan and `markdown.endswith("Total cost: $0.06")`.
- **Verify**: common checks. Add an `import mcp_auditor` to one written kit module once and see the closure test go red.

### Step 18: Sweep, `@pytest.mark.asyncio` markers

- **Files**: `tests/unit/test_llm_adapter.py`, `tests/unit/test_llm_refusals.py`, `tests/unit/test_llm_patience.py`, `tests/unit/test_graph.py`, `tests/unit/test_checkpointing.py`, `tests/unit/test_chain_nodes.py`, `tests/unit/test_graph_throttling.py`, `tests/unit/test_run_probe.py`.
- **Do**: plan "Sweep". Delete every `@pytest.mark.asyncio` line (`grep -rn "pytest.mark.asyncio" tests` empty afterwards), remove any `import pytest` ruff flags as unused.
- **Test**: no new test. Every async test still collects and runs (none skipped or reported "not natively supported").
- **Verify**: common checks. The collected count is unchanged and no `PytestUnhandledCoroutineWarning` appears.
