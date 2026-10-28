# Run plumbing robustness before the first holdout and nuisance runs

## Context

The first CVE holdout run (`run_holdout run`, 30 targets) and the first nuisance run (`run_nuisance run`) are close. A holdout run's traces are never read, only its aggregate report, so a pipeline defect that only shows during such a run can be neither diagnosed nor fixed from it. Every path that can silently degrade a number has to be closed now, in code, and checked on the acceptance layer or with no-LLM tests.

One such defect was just found and fixed for the replay alone (`ce2b698`, `afca3ac`): `mcp-server-kubernetes` arms a 5 s timer in `port_forward` that it never clears, so Node outlives the 2 s the MCP SDK grants after closing stdin, the SDK sends SIGTERM, the server's handler logs `Received SIGTERM, shutting down...` to stdout, and the SDK's `stdout_reader` (`mcp/client/stdio/__init__.py`, around lines 139-215 in mcp 1.30.0) fails to parse it and raises `anyio.BrokenResourceError` from `read_stream_writer.send(exc)`, since it only catches `ClosedResourceError` and the session's receive loop has already closed the receiving end. Leaving the client then raises an exception group. The replay discarded every complete attempt, so every detection on that server was unchecked. A review of the harness found that the same teardown error reaches every other caller (`StdioMCPClient.connect` in the CLI, which today exits 1 with no report on such a server, the vulnerable-side audit in `evals/cve_audit.py`, the layout check, the nuisance audit and benign call), and a wider robustness review found further paths that turn infrastructure noise into a plausible verdict. This plan closes the ones that bear on the first holdout and nuisance numbers.

It does not change what a run measures: no rung, proof, aim, grammar module, fixture, label, run condition or statistic moves. It changes how infrastructure failures are classified, retried and reported, and it stops the run from printing server text.

## Scope

1. Tolerant transport teardown, at the root.
2. No server text in the log: silence the SDK's stdio logger on bench runs, print exception types only on the holdout and nuisance paths, and count the non-protocol lines a server writes instead.
3. Fatal provider errors stop the run, transient ones get their own not-run cause instead of `launch_failure`.
4. Per-audit server health counts in the holdout and nuisance reports (on the console only for acceptance, whose traces are readable): non-protocol stdout lines and lost-connection responses.
5. Why a replay stays unchecked and the cause of each failed attempt, in the holdout report and on the console.
6. Missed-step causes separated in the holdout and nuisance reports.
7. Timeouts on `initialize` and `list_tools`.
8. A run's result is written before its report is built, and a run never overwrites an existing report.
9. Containers left running by a run: refuse to start over leftovers of the run's images, sweep the run's own leftovers at its end.
10. Retry, in the pre-run check, the layout check and the nuisance benign call, only a failed launch or connection, never an observation of a launch that ran (an exploit's dead condition, a layout observation, an erroring benign answer).
11. The misleading comment at `evals/cve_audit.py:146`, living docs and log entries.

Out of scope, decided with the maintainer: pinning base-image digests (a separate plan), the nuisance suite's compose services and missing Dockerfiles (part of the admission work in progress), and the minor findings (the replay's tool-call timeout following the run conditions, Doris state between runs, the served model snapshot, `recorded_at` at the start of the run). Calibration-time replay checks were considered and dropped: calibration never calls `port_forward` and exits cleanly, so it could not have caught this defect, and adding a calibration condition would open a holdout rule version.

## 1. Tolerant transport teardown

`src/mcp_auditor/adapters/mcp_client.py`, `StdioMCPClient.connect`: tolerate only the teardown error described above. Two facts of the SDK shape it (both checked against mcp 1.30.0 and anyio 4.15.1 with `tests/integration/support/cve_replay_stub_server.py`): every exception that crosses `connect` comes out wrapped in nested `ExceptionGroup`s by the task groups of `stdio_client` and `ClientSession`, a body's `ValueError` included; and when the body raises on a server that is noisy at shutdown, the body's exception is dropped and the group holds only the `BrokenResourceError`. So the shim keeps the body's exception and raises it in that case, instead of letting the teardown error stand for it. Shape:

```python
body_error: BaseException | None = None
try:
    async with AsyncExitStack() as stack:
        ...
        try:
            yield client
        except BaseException as error:
            body_error = error
            raise
except BaseExceptionGroup as group:
    if not _only_broken_streams(group):
        raise
    if body_error is not None:
        raise body_error


def _only_broken_streams(group: BaseExceptionGroup) -> bool:
    _, rest = group.split(anyio.BrokenResourceError)
    return rest is None
```

A body that completed and a teardown group of broken streams only: the client exits cleanly. A body that raised and a teardown group of broken streams only: the body's exception propagates (a `CancelledError` included). Everything else propagates as today: an `OSError`, a termination failure, and a group with any leaf that is not `BrokenResourceError` (a body's exception the SDK wrapped together with the teardown error included). `anyio` is imported as the transitive dependency of `mcp` it already is, not added to `pyproject.toml`, since `uv.lock` stays unchanged. A comment states the why in one or two lines (a server that logs its shutdown to stdout after the session stopped reading makes the SDK's reader raise, `mcp` 1.30.0). The same change goes into `evals/holdout_kit/kit_client.py`, `KitMCPClient.connect`, written out again since the kit imports nothing from `mcp_auditor` (its closure test pins that). `ce2b698` stays: it now covers only a raising exit of `target.launched`.

This is a change to the system under test. The commit message answers the four questions of ADR 016. It changes no verdict, only whether a finished audit's report is delivered, so no declared flip and no baseline reset.

Diligence point: check whether an `mcp` release after 1.30.0 (still `<2`) catches `BrokenResourceError` in `stdout_reader`. If one does, the plan may prefer the upgrade, but `uv.lock` is about to be frozen and the shim is narrow, so the shim is the default.

## 2. No server text in the log, a counter instead

- `src/mcp_auditor/adapters/log_redaction.py`: extract the silencing of `mcp.client.stdio` already done inside `redacted_sdk_logging` into a public context manager `silenced_stdio_logging()`, used by `redacted_sdk_logging` and by the bench runners. The SDK's `logger.exception("Failed to parse JSONRPC message from server")` quotes the raw line in `input_value=`, truncated by pydantic only past about 50 characters, so a short line holding a nonce would reach the log whole.
- The runners enter it for the whole run: `evals/run_holdout.py` (`run`, `calibrate`), `evals/run_nuisance.py` (`run`, `gate`, `calibrate`), `evals/run_cve_benchmark.py` (all modes, for uniformity). The CLI keeps today's behaviour (silenced only while a value is relayed).
- Exception texts on the holdout and nuisance paths: `attempt_once` (`evals/cve_audit.py`, the `run skipped`/`teardown failed` line), `nuisance_audit` (`run failed to launch (...)`, `LaunchFailed.reason`) and `_print_incidents` (`evals/cve_audit.py` and `evals/nuisance_audit.py`, which print `missed.detail`, the provider's refusal message, model text) print the exception type and the missed-step cause only when called from a holdout or nuisance run. The acceptance path keeps the message, since its traces are readable. The type is the real one: `_audit` wraps everything into `LaunchError(str(exc)) from exc` and `audit_once` into `LaunchFailed(str(exc))`, whose own type says nothing and whose message is already "unhandled errors in a TaskGroup (1 sub-exception)", so the description follows `__cause__` and then the leaves of an exception group down to the original errors and names their types. Pass this as one value object, defined once in step 2 with its final shape (section 2's "report detail": two module-level instances, full and types-only, exposing `describe(error) -> str` and the server lines a check may print), carried on the existing `Auditor` and reused unchanged by the pre-run and layout checks in step 3, not a boolean flag threaded through calls.

- The pre-run check and the layout check print no server text inside a holdout or nuisance run either (decided by the maintainer): `cve_calibration.check_target` (`_report_dead`, `_dump_exchanges`, up to 500 characters of each response, nonces included, and `_print_tail`) and `cve_layout_check._report_launch_error` (the exception text and the stderr tail) take the same failure-description value as section 2, so on the holdout and nuisance paths they print the target, the dead conditions and the exception type only, never an exchange, a stderr line or a message. Calibration (`--calibrate`, `run_holdout calibrate`, `run_nuisance calibrate`) and the acceptance pre-run check keep the full detail, which repairing a fixture needs.

## 3. Provider errors

Today an exception escaping `graph.ainvoke` (a billing limit raised as 429 is excluded from throttling by `llm_throttling._is_billing_limit`, a 401, a 403 that is not a host block, a 404, a 5xx after the SDK's retries, Anthropic's 529, a connection error) is wrapped into `LaunchError` by `_audit` (`evals/cve_audit.py`, the `except Exception` around the whole client block) and by `nuisance_audit.audit_once`, retried three times, then the target leaves N as `launch_failure`. A spending cap hit mid-run would empty N of every remaining target behind a report that reads complete.

- Classify at `graph.ainvoke` itself, inside the client block: in `_audit` (CVE, `evals/cve_audit.py`) and `_audit` (nuisance, whose catch-all is the `try` of `audit_once` around `entered_in_thread`, `_audit` has none). An exception the classifier recognizes as a provider's becomes `AuditFailed(cause)`, everything else stays `LaunchError` / `LaunchFailed`. It cannot be done outside the client block: every exception crossing `connect` arrives wrapped in nested `ExceptionGroup`s (section 1), while a body's exception on a server noisy at shutdown comes out bare (the shim of section 1 raises it unwrapped). So the handler must be `except* AuditFailed`, placed before the `except Exception` that builds `LaunchError`: `except*` matches the bare exception and the grouped one alike, where `isinstance` misses the grouped case and `group.split` misses the bare one. The unit tests' fake `connect` (`tests/unit/support/test_cve_audit_given.py`, the nuisance audit test's) wraps a body exception in nested `ExceptionGroup`s as the SDK does, so a test cannot pass on an implementation that only handles the bare shape.
- Not every exception out of `graph.ainvoke` is the provider's: the graph's first node calls `list_tools` (`graph/nodes.py`), so a `TimeoutError` (section 7) or an `McpError` of a server that died, and a bug in the graph, also leave `ainvoke`. Those stay `LaunchError` / `LaunchFailed` as today.
- A pure classifier in a new small module `evals/provider_errors.py`, importing no provider SDK. A provider error is a `langchain_core.exceptions.ModelError` (the three integrations map their HTTP errors onto its subclasses, for example `OpenAIAuthenticationError(openai.AuthenticationError, ModelAuthenticationError)` in `langchain_openai`, the same in `langchain_anthropic` and `langchain_google_genai`), or failing that an exception carrying an integer `status_code` (an error a path raises unmapped; Google's errors carry `code`, not `status_code`, which is why the `ModelError` taxonomy comes first). Verify in the step, at the locked versions, that the structured-output path of each provider raises a `ModelError` subclass for a 401 and a 5xx. Fatal: `ModelAuthenticationError`, `ModelPermissionDeniedError`, `ModelNotFoundError`, status 401, 402, 403, 404 read from `status_code`, or from `code` on the exception or on its `__cause__` (decided by the maintainer: `langchain_google_genai` raises an unmapped client status, 402 included, as a plain `ChatGoogleGenerativeAIError` whose `code` sits on its `__cause__`), and billing limits, read with `llm_throttling`'s billing test made public (`_is_billing_limit` renamed `is_billing_limit`: pyright strict rejects importing a private name, and duplicating the codes would let them drift). `is_billing_limit` knows only OpenAI's codes today, while `langchain_anthropic` turns every Anthropic 400 into `AnthropicInvalidRequestError`, and an exhausted Anthropic credit balance is believed to arrive as such a 400 ("credit balance is too low", unverified in this repo): the step verifies the real error body Anthropic sends (its API docs and the `anthropic` SDK's error types at the locked version), then extends `is_billing_limit` with what it finds (the `billing_error` error type, status 402, and the message), so that under the holdout's provider a spending cap stops the run instead of emptying N target by target. Transient: every other provider error (5xx, 529, `ModelConnectionError`, `ModelTimeoutError`, a 400 that is not a refusal, which is deterministic per audit but not run-wide). Host-block 403s and refusals never reach it: the LLM adapter turns them into `ProviderRefusal` inside the graph.
- Fatal: `attempt_once` and `audit_once` raise `ProviderFatal`. No retry. The acceptance runner and the nuisance gate already turn an escaping exception into exit 4 (`run_cve_benchmark.main`, `nuisance_gate_command.gate`). `run_holdout.main` and `run_nuisance.main` catch only `Refused` and `ValueError` today, so they gain a `ProviderFatal` branch that prints the cause's type and status (no message text) and returns 4 (`CRASHED_EXIT`, already defined in `run_holdout.py` and in `nuisance_commands.py`). Decided by the maintainer: the targets or servers already finished are kept. A first failure stops the run: `_run_all` runs one task per target (server) and waits with `asyncio.wait(..., return_when=FIRST_EXCEPTION)`, cancels the pending ones, and when any task raised, assembles the finished targets into a partial result and raises `RunInterrupted(partial, cause)`. `_run_target` / `_run_server` run their sibling runs in an `asyncio.TaskGroup`, so one run's exception cancels its siblings instead of leaving them orphaned. This holds for any exception, not only `ProviderFatal`: the CLI writes the partial result to `<report>.result.json` with `partial: true` (no report is built from it), then exits 4 with the type and status of a `ProviderFatal` cause, or re-raises any other cause as the crash it is.
- Transient: `attempt_once` returns a new outcome `ProviderErrorAttempt` beside `ThrottledAttempt`, and `audit_once` a `ProviderError` beside `LaunchFailed`. `holdout_audit` and `nuisance_audit` retry it within the existing infra attempts, and a run dropped for it carries a new `NotRunCause.PROVIDER_ERROR` (holdout `evals/holdout_results.py`, nuisance `evals/nuisance_results.py`, with a reason in each `DROPPED_RUN_REASONS`), so the report's not-run section names it apart from `launch_failure`. Precedence when a run's attempts or a target's runs mix causes: throttled, then provider error, then launch failure, in `holdout_audit` / `nuisance_audit` and in `_run_target` (`evals/holdout_run.py`) / `_run_server` (`evals/nuisance_run.py`).
- Acceptance (`run_cve_benchmark`): a fatal error crashes the run too. `graded_despite_missed_steps` returns None at once on a `ProviderErrorAttempt`, as on a `ThrottledAttempt`, so a transient one is skipped as today but printed as a provider error.

## 4. Server health counts

A value object `ServerHealth(non_protocol_lines: int, lost_connection_responses: int)` with `+`, in a new module `evals/server_health.py`, which also becomes the home of `lost_connection` and `LOST_CONNECTION_RESPONSES` (moved from `evals/cve_replay.py`, which imports them back).

- Non-protocol lines: `StdioMCPClient` passes a `message_handler` to `ClientSession` that counts every incoming `Exception` (the SDK forwards a line it cannot parse to the session as an exception, `mcp/client/session.py` `_handle_incoming`) and exposes the count as a read-only property, `non_protocol_lines`. Lines written after the session stopped reading are not counted, and need not be. The source of mcp 1.30.0 confirms the path (`shared/session.py` `_receive_loop` hands an `Exception` read from the stream to `_handle_incoming`, which calls the message handler). The integration test pins it, and if an upgrade breaks it, the fallback is a logging handler on `mcp.client.stdio` that keeps the count and drops the record.
- Lost connections: the responses of the audit's recorded calls for which `lost_connection` is true. `evals/cve_audit.py` already records every call. `evals/nuisance_audit.py` wraps its client in `RecordingClient` too.
- `evals/cve_environments.py` is not touched, its return annotation included: it is fingerprinted by AST into every acceptance and holdout fixture (`cve_baseline._ENVIRONMENT_PATHS`), and an annotation is part of the AST, so narrowing it would move every fixture fingerprint and reset the acceptance baseline. `connect` keeps yielding an `MCPClientPort`. `evals/server_health.py` defines a `runtime_checkable` Protocol carrying `non_protocol_lines`, and the CVE and nuisance audits read the count through an `isinstance` check against it after the audit. The unit tests' fake `connect` (`tests/unit/support/test_cve_audit_given.py`, `tests/unit/test_nuisance_audit.py`) yields a fake client that gains the property.
- Carried per run: `GradedAudit` and `IncompleteAttempt` (CVE), `IncompleteRun` (holdout), the nuisance audit outcome (today a bare `AuditReport`, so it becomes a value carrying the report and its health, and `gate_run` and the nuisance gate session that consume it follow). Per the convention of `holdout_results.py` and `nuisance_results.py` (the per-run facts live in the run statuses, the aggregates are computed from them), the counts go on `HoldoutRunStatus` and `NuisanceRunStatus`, filled by `evals/holdout_assembly.py` and `evals/nuisance_assembly.py`, and `HoldoutTargetResult` and `NuisanceServerResult` sum them as properties. They reach `TargetLine` / `TargetRunLine` (`evals/holdout_report.py`), `ServerLine` / `ServerRunLine` (`evals/nuisance_report.py`). The CVE acceptance report (`CVEResult`) gains no field: its traces are readable and the console lines suffice. Report-only: no statistic, gate, baseline or comparison reads them. The markdown of each report gets one line per target or server with a non-zero count, and the console prints a one-line warning when an audit ends with a lost connection.

## 5. Replay attempt causes

`evals/cve_replay.py`: two levels, kept apart. Per attempt, an enum `ReplayAttemptFailure` with `LAUNCH_FAILED` (an exception entering the launch or its client, or leaving it before every call was answered) and `LOST_CONNECTION` (at a call the vulnerable run answered). Per run, an enum `UncheckedReason` with `ARGUMENTS_DISAGREE` (no attempt launched) and `NO_ATTEMPT_DECIDED` (failed attempts, or truncated and failed ones with no complete one). An unchecked run carries its reason and the failure causes of its attempts, a decided run neither (its failed attempts, if any, still show as attempt causes). `replay_credit` keeps returning a `CreditCheck` (in `evals/cve_grammar.py`, fingerprinted, untouched) and a new function or return shape outside the grammar carries the reason and the attempt causes, for example `replay_with_causes(run) -> ReplayOutcome(check, unchecked_reason, attempt_failures)`, with `replay_credit` kept as the thin caller `_checked_grade` injects, or `_checked_grade` switched to the new shape, whichever keeps the injection seam simplest. The values ride on `GradedAudit` and reach the holdout report (per run, and per target as counts by cause). The console prints them on an unchecked run, acceptance included: `CVE-x: replay unchecked, no_attempt_decided (launch_failed x3)`.

## 6. Missed-step causes in the reports

`HoldoutRunStatus` and `NuisanceRunStatus` gain the missed-step causes of an incomplete run, from the run's report, as a sorted list of `MissCause` values as strings (`list[str]`, the convention of `holdout_results.py`), not a `frozenset`, which `json.dumps(default=str)` would write as `frozenset({...})` in the `.result.json`. The reports gain counts by cause next to `incomplete_run_count` (holdout) and the incomplete line (nuisance), and `TargetRunLine` / `ServerRunLine` carry the causes per run. The holdout rule names only refusals as counted not detected, so the report must let a reader tell an unreadable answer from a refusal.

## 7. Timeouts on initialize and list_tools

`StdioMCPClient.connect`: `session.initialize()` under `asyncio.timeout(_INITIALIZE_TIMEOUT)`, 120 s, generous for JVM and .NET servers that start slowly. `list_tools()` under the same 120 s, not the 30 s `tool_call_timeout`: the layout check reads a failed `tools/list` as a break, so a slow `tools/list` under a short timeout would turn into a break that does not exist today. An `initialize` timeout leaves `connect` as an `ExceptionGroup` holding the `TimeoutError` (it is raised inside the SDK's task groups, section 1), and a `list_tools` timeout as a bare `TimeoutError`. Every caller already catches `Exception` and reads both as a failed launch, the audit included: the graph's `list_tools` runs inside `graph.ainvoke`, and section 3 leaves a `TimeoutError` there a `LaunchError`. Same change in `KitMCPClient`. A system-under-test change, covered by the same ADR 016 commit message as section 1 if done in the same step, otherwise its own.

## 8. Results kept, reports never overwritten

- `evals/run_holdout.py` `_run` and `evals/run_nuisance.py` `_run` (the CLI, where `build_report` and the writing live, not the orchestrators `holdout_run.py` / `nuisance_run.py`): refuse to start, raising `Refused` (exit 3), when the report path, its `.md` sibling or its `.result.json` sibling already exists, with a message naming `--report`. The `.result.json` is included so that relaunching after a crash in `build_report` cannot overwrite the one result it kept. Checked before any image is built.
- Write the run result (`HoldoutRunResult`, `NuisanceRunResult`, statuses and counts only, no proof field exists on them) to `report.with_suffix(".result.json")` before `build_report`, so an exception in building or rendering the report loses no paid run. Serialized with `dataclasses.asdict` and `json.dumps(default=str)`. A test asserts the written file has no proof field, as the report test does.

## 9. Containers left running

The holdout and nuisance runs know their images: `target_services` returns compose service names, so the holdout's tags are `cve_targets.image_tag(service)` over them (`mcp-auditor-cve-<service>:local`), and the nuisance's `nuisance_images.image_tag(server.service)`. `docker ps --filter ancestor=<tag>` lists containers of an image. Backend images stay out of both checks: the persistent Doris cluster is left running between runs on purpose (`evals/doris_backend.py`), so including `_backend_images` would refuse every run after the first and remove the cluster at the end. The labelled helpers (holders, sentinels, `mcp-auditor-cve`) are not the run's images and keep their own teardown.

- At start, both before and after the rebuild (decided by the maintainer: `docker ps --filter ancestor=<tag>` matches the image a tag resolves to, so a container of an image the rebuild replaced is only seen before it): refuse when any container of the run's images is running, listing them, since it is either a leftover of an earlier run or a concurrent run (two eval processes collide on the Doris sentinel's fixed address anyway). The maintainer removes them by hand.
- At the end, in a `finally`: remove, with `docker rm -f`, the containers of the run's images that are still running, and print how many. A desktop-commander container ignores both stdin close and SIGTERM and outlives the SIGKILL of its `docker` CLI, about 20 per holdout run.
- The docker calls live in the composition root of each run (`default_deps`), behind two injected callables, so the orchestrators stay testable with fakes. `evals/cve_environments.py` and the planting modules, which are fingerprinted, are not touched (`--name`/`--init`/`--cidfile` there would move every fixture fingerprint and reset the acceptance baseline).

## 10. Retry of a failed launch in the pre-run check and the benign call

- `evals/cve_calibration.check_target`: `_exercise` returning `None` (the version did not launch) is retried up to `PRE_RUN_LAUNCH_ATTEMPTS = 3` launches of that version before `the ... version did not launch` is recorded. A dead condition read from a launch that ran is never retried.
- `evals/cve_layout_check._observe`: only entering the launch and its client (`target.launched` and `connect`, the `initialize` handshake included) is retried, up to the same number of launches, before `_failed_observation()` is returned. `route_observations`, which runs `tools/list` and the calls on a launched server, is outside the retry: a `tools/list` that raises on a server that launched is the break signal itself and is decided at once. The golden master of the layout check's decisions does not see `_observe`, so it proves nothing here: the absence of a rule version rests on the reading below, logged.
- Reading, decided by the maintainer and logged in `docs/holdout-log.md`: one observation of a version is obtained in up to `PRE_RUN_LAUNCH_ATTEMPTS` launches, so "launches each version once" (holdout-rule.md, fallback paragraph) still holds, and no rule version opens. Only a launch or connection error is retried: a launch that runs and whose `tools/list` or call errors with the layout and not without it is an observation, decided at once, never retried.
- `evals/nuisance_run.benign_call`: only a failed launch or connection is retried, up to the same number of launches, keeping the last reason (decided by the maintainer). A benign call that answered with an error is an observation of a launch that ran, decided at once and never retried, as on the holdout side, where a patched benign call that errors is a dead condition: `nuisance-rule.md` says the benign call "must return without error", and retrying it until it succeeds would keep the best of several tries.
- Calibration shares `check_target`, so it gains the same retry, which only turns a transient dead reading into a live one.

## 11. Comment, docs, logs

- `evals/cve_audit.py:146`: the comment says the run is "captured before __exit__", which covers only the exit of `target.launched`. Reword to what it covers.
- Each step writes the log entries for what it changes, in its own commit, as `ce2b698` did (the step list says which). The entries together cover:
- `docs/labeling-log.md`: the CVE instrument changes (provider-error classification, server health counts, replay causes, launch retries in the pre-run check and the layout check), with the four questions of ADR 016, the state of the baselines and the fingerprints (unchanged).
- `docs/holdout-log.md`: the holdout-side changes (not-run cause `provider_error`, missed-step causes, the result file and report refusal, the container checks, the pre-run launch retry, no proof text printed), stating no rule version opens and why, and the reading of holdout-rule.md ("an audit that ends on any other error is retried at most twice", then the target leaves N) for a run stopped on a first failure: it publishes no number, its partial result is never reported, and it is relaunched whole at the same commit.
- `docs/nuisance-log.md`: the same for the nuisance side, the connection-only benign-call retry and the stopped-run reading (`nuisance-rule.md`, the audit error clause) included.
- `CHANGELOG.md` `[Unreleased]`: the CLI no longer loses a finished audit when the server logs its shutdown to stdout, the initialize timeout, the report refusal and result file, the new report fields and not-run cause.
- `CLAUDE.md` Commands: the `run_holdout run` and `run_nuisance run` lines mention the report refusal. `README.md` only if it documents the affected behaviour.

## What stays unchanged

The grammar modules and their fingerprint, `CreditCheck`, the fixture fingerprint's modules (`cve_environments.py`, `cve_layout.py`, `cve_places.py`, the planting modules, `cve_endpoint_address.py`), every fixture and Dockerfile, the honeypot and judge evals, the statistic, the gates and baselines, the holdout and nuisance rules, `holdout_conditions.json`, `uv.lock`.

## Edge cases

- Body raises and teardown raises only broken streams: the SDK drops the body's exception from the group, and the shim raises the body's exception it kept (section 1).
- Teardown group mixing `BrokenResourceError` and another error, the body's own included: propagates as a group.
- A fatal provider error while sibling audits are in flight: the pending target tasks are cancelled and a target's sibling runs are cancelled by their task group, the partial result holds only the targets that finished, and the run's `finally` sweep (section 9) runs after. Accepted by the maintainer: the sweep may remove containers started by hand from the run's images, since a holdout run runs alone on the host.
- A server that dies mid-audit: the audit continues as today against error responses, and the run's `lost_connection_responses` count is non-zero. No retry, which would need a rule version.
- A fatal provider error on the first audit of a run: the run stops, the pending audits are cancelled, and only what was already in flight has been spent. A fatal error after some targets finished: their outcomes are written as a partial `.result.json`, then the run exits 4 (section 3). Any other exception in a run is handled the same way, then re-raised. A stopped run publishes no number: its partial result is never reported, and the run is relaunched whole at the same commit (logged, section 11). A deterministic provider error read as transient (a context overflow) spends the three infra attempts and drops the target as `provider_error`, accepted by the maintainer.
- A transient provider error on every attempt of one run of a target: the target leaves N with `provider_error`.
- The report path exists: refused before any rebuild or container.
- A container of the run's images running at start: refused. None at the end: the sweep prints nothing.
- Pre-run launch retry on a target whose patched launch fails deterministically: three launches, then dead as before.

## Test scenarios

Integration (`tests/integration/`, no Docker, through the `docker` shim of `cve_stub_target.a_docker_that_runs_its_command_on_the_host`):

- A stub server that writes a non-JSON line to stdout after stdin closes (the `noisy_shutdown` flag of `tests/integration/support/cve_replay_stub_server.py`, already under `support/`, reused or moved to a server whose name is not the replay's): `StdioMCPClient.connect` exits cleanly after a call. Same for `KitMCPClient` (its own test file, since the kit's tests already run its client). These need no `docker` shim: `ServerLaunch.unconfined` runs the stub directly.
- The body raises inside `connect` with the same stub: the body's own exception propagates, not the group of broken streams.
- A stub writing a non-JSON line mid-session: `non_protocol_lines` counts it and the call still answers.
- A stub that never answers `initialize`: `connect` raises, within the timeout, an exception group holding a `TimeoutError` (inject a short timeout for the test).
- The CLI audit (`Audit.run` with a fake LLM, the pattern of the existing CLI tests) against the noisy-shutdown stub produces a report.

Unit (`tests/unit/`, fakes, given/then modules):

- `provider_errors` classification: billing type and codes, the authentication, permission and not-found `ModelError` subclasses and an unmapped 401/402/403/404 fatal, 500/529/400 and `ModelConnectionError`/`ModelTimeoutError` transient, and a plain `TimeoutError`, an `McpError` or a `KeyError` not a provider error at all.
- `cve_audit.attempt_once` and `nuisance_audit.audit_once` (through their public entry points, as `tests/unit/test_cve_audit.py` already does, not `_audit`): a `list_tools` failure inside `graph.ainvoke` stays a launch failure, a fatal provider error raises `ProviderFatal`, a transient one returns `ProviderErrorAttempt` / `ProviderError`.
- `holdout_audit` and `nuisance_audit`: a fatal outcome raises, a transient one retries and drops with `PROVIDER_ERROR`, precedence throttled over provider error over launch failure.
- `run_holdout` and `run_nuisance` (`tests/unit/test_run_holdout.py`, `tests/unit/test_run_nuisance.py`): refuse an existing report, `.md` or `.result.json` path before any dep is reached, write the result file before the report, and exit 4 on `ProviderFatal`.
- The orchestrators: a `ProviderFatal` (or any other exception) from one target's run while another target finished cancels the pending targets and raises `RunInterrupted` with a partial result holding the finished target with `partial: true`. The leftover-container check is consulted before and after the rebuild.
- `provider_errors`: an error whose `__cause__` carries `code=402` reads fatal, as does one with `code=401` on itself.
- No server text on the holdout path: a dead target in `vet_all` prints its conditions and no exchange or stderr line (assert on the captured console), while `--calibrate` keeps them.
- `holdout_run` and `nuisance_run`: refuse on leftover containers, sweep at the end even when the run raises.
- Reports: health counts, replay failure causes and missed-step causes appear in the JSON and markdown, and the no-proof-field tests extend to the new models.
- `check_target`, `_observe` and `benign_call` retries: a launch that fails twice then succeeds reads live, three failures read as before, a dead condition is not retried.
- `cve_replay`: an unchecked run reports its `UncheckedReason`, each failed attempt its `ReplayAttemptFailure`, and a decided run no reason (the existing integration scenarios gain assertions on them).

## Verification

```bash
uv run pytest -n auto
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run python -m evals.run_cve_benchmark --calibrate
uv run python -m evals.run_holdout calibrate
```

The grammar fingerprint and every fixture fingerprint must be unchanged (compare `grammar_fingerprint()` and `fixture_fingerprint` of the acceptance and holdout targets before and after). Then one exploratory acceptance run of CVE-2025-53355 under the holdout's conditions (Haiku 5.5 `low`, `--ungated --runs 1 --chains 3 --chain-steps 3 --tool-call-timeout 30 --no-tools-filter`, about $0.30) shows the detection decided, the health counts and no SDK traceback in the log. Its number is exploratory. The honeypot and judge gates run on the final commit because `src/` changes.

## Due diligence record

What the plan-diligence pass concluded about the plan's external facts, on 2026-10-28, kept here so it survives into implementation, where the fact check reads it. No pass may treat a line here as a reason to skip a verification: the record says what was concluded once, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: `mcp==1.30.0` and `anyio==4.15.1` are the locked versions (verified against `uv.lock`).
- SETTLED: `stdout_reader` in `mcp/client/stdio/__init__.py` catches only `anyio.ClosedResourceError` around its loop, so `read_stream_writer.send(exc)` can raise `anyio.BrokenResourceError` (verified against the installed mcp 1.30.0 source and the `v1.x` branch on GitHub).
- SETTLED: no `mcp` release after 1.30.0 and below 2 exists, the 1.x line ends at 1.30.0 (2026-09-07) and the 2.x line is at 2.3.0, so the shim is the only option under `mcp>=1.0.0,<2` (verified against PyPI release history and the python-sdk GitHub releases).
- SETTLED: a line that fails to parse reaches the client's `message_handler` as an `Exception` (`shared/session.py` `_receive_loop` to `client/session.py` `_handle_incoming`, verified against the installed mcp 1.30.0 source).
- SETTLED: pydantic's `input_value=` quotes a short unparsable line whole and truncates a long one to its head and tail (verified by running `JSONRPCMessage.model_validate_json` at the locked versions).
- SETTLED: `langchain_core.exceptions.ModelError` with `ModelAuthenticationError`, `ModelPermissionDeniedError`, `ModelNotFoundError`, `ModelInvalidRequestError`, `ModelRateLimitError`, `ModelAPIError`, `ModelConnectionError`, `ModelTimeoutError`, and `ContextOverflowError(ModelError)` (verified against installed langchain-core 1.7.0).
- SETTLED: `langchain_openai` 1.7.2 and `langchain_anthropic` 1.7.6 map 401, 403, 404, 400, 429, 5xx, connection and timeout errors onto those subclasses, Anthropic's 529 as `AnthropicOverloadedError(ModelAPIError)` (verified against installed source).
- SETTLED: `langchain_google_genai` 4.4.2 maps only 400, 401, 403, 404, 429 and server errors onto `ModelError` subclasses, any other client status (402 included) is raised as a plain `ChatGoogleGenerativeAIError` with no `status_code` (verified against installed source).
- OPEN (deferred): that the structured-output path of each provider raises those subclasses at runtime for a 401 and a 5xx, left by the plan to its step.
- SETTLED: `docker ps --filter ancestor=<image:tag>` matches containers of that image or a descendant (verified against docs.docker.com), and a container of an earlier build of a tag is not matched once the tag is rebuilt to a new image ID (verified locally with a throwaway image).
- SETTLED: `asyncio.timeout` and `BaseExceptionGroup.split` are stdlib on the project's `requires-python = ">=3.13"`.

## Implementation steps

Every step closes with the same checks, and every step that touches `evals/` also checks the fingerprints. Before the first edit of a step, save the fingerprints of the parent commit, then compare after the step:

```bash
uv run python -c "from evals.cve_baseline import grammar_fingerprint, fixture_fingerprint; from evals.cve_places import load_places, HOLDOUT_PLACES; from evals.cve_targets import CVE_TARGETS; from evals.holdout_targets import HOLDOUT_TARGETS; p = load_places(HOLDOUT_PLACES); print('grammar', grammar_fingerprint()); [print(t.cve_id, fixture_fingerprint(t, p)) for t in (*CVE_TARGETS, *HOLDOUT_TARGETS)]" > "$TMPDIR"/fingerprints-before.txt
```

The same command also prints `counter_fingerprint()` (`evals/nuisance_counter.py`) and `nuisance_fixture_fingerprint(server)` (`evals/nuisance_images.py`) for every admitted server, loaded as `nuisance_run` loads the admission: extend it with those lines in step 1, before the first edit.

Closing checks (named "the closing checks" below): `uv run pytest -n auto` green, `uv run ruff check .` clean, `uv run ruff format --check .` clean, `uv run pyright` with no error, and the fingerprint command rerun into `fingerprints-after.txt` with `diff` empty. None of `evals/cve_environments.py`, `cve_layout.py`, `cve_places.py`, the planting modules, `cve_endpoint_address.py`, `cve_grammar.py`, `cve_proofs.py`, `cve_units.py`, `cve_report_units.py`, any fixture, Dockerfile or `uv.lock` is edited by any step.

### Step 1: Tolerant teardown, initialize and list_tools timeouts, non-protocol line count in the clients

- **Files**: `tests/integration/test_mcp_client_transport.py` (new) with its `tests/integration/support/test_mcp_client_transport_given.py`, `tests/integration/support/cve_replay_stub_server.py` (or a renamed copy, see Do), the kit's client test (a new `tests/integration/test_holdout_kit_client.py`, or a case in `tests/integration/test_holdout_kit.py` if it already runs `KitMCPClient` without Docker), `src/mcp_auditor/adapters/mcp_client.py`, `evals/holdout_kit/kit_client.py`, `evals/cve_audit.py` (comment only), `CHANGELOG.md`.
- **Do**:
  - Tests first. Reuse the `noisy_shutdown` flag of `cve_replay_stub_server.py`, and add two flags: `noisy_mid_session` (writes one non-JSON line straight to fd 1 before answering the first `read`) and `silent_initialize` (never answers `initialize`: for example sleep forever before `app.run()`, reading nothing). If the stub is moved to a neutral name (for example `tests/integration/support/stdio_stub_server.py`), update `tests/integration/support/test_cve_replay_given.py` and every other importer of the old path. Launch it with `ServerLaunch.unconfined` (no `docker` shim needed).
  - `StdioMCPClient.connect` (section 1): the shim of section 1, verbatim shape, with `_only_broken_streams` right below it and a one or two line comment giving the why (a server that logs its shutdown to stdout after the session stopped reading makes the SDK's reader raise, `mcp` 1.30.0). `import anyio` (transitive, `pyproject.toml` and `uv.lock` unchanged).
  - Section 7: `session.initialize()` under `asyncio.timeout(initialize_timeout)`, with a module constant `_INITIALIZE_TIMEOUT = 120` and a keyword parameter `initialize_timeout: float = _INITIALIZE_TIMEOUT` on `connect` so the test injects a short one. `list_tools()` under `asyncio.timeout(initialize_timeout)` (the same 120 s, section 7), letting the `TimeoutError` propagate.
  - Section 4, client half: a `message_handler` passed to `ClientSession` that increments a counter on every incoming `Exception` (and does nothing else), exposed as a read-only property `non_protocol_lines: int`. Keep the method under 20 lines: the handler can be a bound method of the client.
  - `KitMCPClient.connect`: the same shim and the same two timeouts, written out again (no import from `mcp_auditor`, the kit closure test pins it). No line counter needed in the kit.
  - `evals/cve_audit.py`, the comment above `run = RunToCheck(...)` (around line 146): it covers only a raising exit of `target.launched` (the client's own teardown is now tolerated in `connect`). Reword to that.
  - `CHANGELOG.md` `[Unreleased]`: the CLI no longer loses a finished audit when the server logs its shutdown to stdout, and the server's `initialize` now times out after 120 s.
- **Test** (integration, `tests/integration/test_mcp_client_transport.py`):
  - Noisy-shutdown stub: `connect`, one `call_tool`, leave: no exception.
  - Noisy-shutdown stub, body raises `ValueError("body")` inside `connect`: a bare `ValueError` with that message propagates, not an `ExceptionGroup`.
  - Mid-session non-JSON line: the call still answers and `client.non_protocol_lines == 1`.
  - Silent `initialize` with `initialize_timeout=0.5`: `connect` raises within a few seconds an `ExceptionGroup` whose `split(TimeoutError)` match is not None.
  - `KitMCPClient` against the noisy-shutdown stub: exits cleanly after a call.
  - CLI audit: `Audit.run` with a fake LLM against the noisy-shutdown stub (follow `tests/integration/support/test_resume_earlier_checkpoint_given.py` for building an `Audit`) returns a report (not None, no exception).
- **Verify**: run the new integration files and `uv run pytest tests/unit -n auto --maxprocesses 4` in the loop, then the closing checks. The commit is a change to the system under test: its message answers the four questions of ADR 016 (no verdict changes, only whether a finished audit's report is delivered, so no declared flip and no baseline reset).

### Step 2: No server text in the log of the bench runs

- **Files**: `tests/unit/test_log_redaction.py` (and `tests/unit/support/test_log_redaction_given.py` if a helper is needed), `tests/unit/test_cve_audit.py` with `tests/unit/support/test_cve_audit_given.py`, `tests/unit/test_nuisance_audit.py`, `src/mcp_auditor/adapters/log_redaction.py`, a new `evals/failure_text.py`, `evals/cve_audit.py`, `evals/nuisance_audit.py`, `evals/holdout_run.py` and `evals/nuisance_run.py` (`default_deps` wiring only), `evals/run_holdout.py`, `evals/run_nuisance.py`, `evals/run_cve_benchmark.py` (one `with` each).
- **Do**:
  - Tests first (see Test).
  - `log_redaction.py`: extract `silenced_stdio_logging()` (a public `@contextmanager` raising `mcp.client.stdio` to `CRITICAL` and restoring its previous level), used by `redacted_sdk_logging` in place of its inline code. CLI behaviour unchanged.
  - Enter `silenced_stdio_logging()` around the whole command in `run_holdout.main` (covers `run` and `calibrate`), `run_nuisance.main` (covers `run`, `gate`, `calibrate`) and `run_cve_benchmark.main` (every mode).
  - `evals/failure_text.py`: the report-detail value of section 2, in its final shape now so step 3 reuses it unchanged: a small frozen value with two module-level instances, `FULL_DETAIL` (the acceptance and calibration default) and `TYPES_ONLY` (the holdout and nuisance runs), exposing `describe(error: BaseException) -> str`, `missed_detail(missed: MissedStep) -> str` and a way for a check to get the server lines it may print (exchanges, stderr tail), empty in `TYPES_ONLY`. `FULL_DETAIL.describe` gives today's text. `TYPES_ONLY.describe` follows `__cause__` and then the leaves of an exception group down to the original errors and names their types, never a message, so a `LaunchError` from an `ExceptionGroup([TimeoutError()])` reads `TimeoutError`, not `LaunchError`. `TYPES_ONLY.missed_detail` gives the missed-step cause without `missed.detail`.
  - `Auditor` gains `report_detail` with `FULL_DETAIL` as default. `attempt_once` prints its `run skipped` / `teardown failed` line through `auditor.report_detail.describe(exc)`, and `_print_incidents` (`evals/cve_audit.py`, `evals/nuisance_audit.py`) prints each missed step through `report_detail.missed_detail`. `audit_once` builds `LaunchFailed(auditor.auditor.report_detail.describe(exc))`, so `nuisance_audit`'s `run failed to launch (...)` line carries the type only on a nuisance run.
  - Logs, in this step's commit: `docs/holdout-log.md` and `docs/nuisance-log.md`, an entry each that the runs print no server or model text (the SDK's stdio logger silenced, exception types and missed-step causes only).
  - `holdout_run.default_deps` and `nuisance_run.default_deps` build their auditor with `TYPES_ONLY` (`dataclasses.replace(build_auditor(HOLDOUT_BUDGET), report_detail=TYPES_ONLY)` or a parameter of `build_auditor`, whichever reads simpler). The acceptance runner and the nuisance gate keep the default.
- **Test**:
  - `silenced_stdio_logging`: a record logged on `mcp.client.stdio` at `ERROR` inside the context reaches no handler, the level is restored after, and `redacted_sdk_logging` still silences it while a value is relayed (the existing tests keep passing).
  - The two instances: `FULL_DETAIL.describe` gives type and message, `TYPES_ONLY.describe` gives no message text (a `ValueError("secret-nonce")` yields a string without `secret-nonce`), a nested `ExceptionGroup` yields its leaves' type names, and `LaunchError(...)` raised `from ExceptionGroup([TimeoutError()])` yields `TimeoutError`. `TYPES_ONLY.missed_detail` of a refusal holds the cause and not the provider's message.
  - `attempt_once` with an auditor carrying `TYPES_ONLY` and a launch that raises `LaunchError("secret-nonce")` (existing given helpers): the captured console holds `run skipped` and no `secret-nonce`. With the default auditor the message is printed as today.
  - `audit_once` with a `TYPES_ONLY` auditor and a launch raising with a message: `LaunchFailed.reason` holds no message text.
- **Verify**: `uv run pytest tests/unit -n auto --maxprocesses 4`, then the closing checks.

### Step 3: Pre-run check and layout check: no server text on the holdout and nuisance paths, launch retries

- **Files**: `tests/integration/test_cve_calibration.py` with `tests/integration/support/test_cve_calibration_given.py` (and a stub flag or a stub target that fails its first N launches, through a counter file in `tmp_path`), `tests/unit/test_nuisance_run.py` with `tests/unit/support/test_nuisance_run_given.py`, `evals/cve_calibration.py`, `evals/cve_layout_check.py`, `evals/holdout_vetting.py`, `evals/holdout_run.py` (`default_deps` wiring), `evals/nuisance_run.py` (`benign_call`).
- **Do**:
  - Tests first (see Test). The retry tests need a target whose launch fails a set number of times then serves: extend the stub target of `tests/integration/support/cve_stub_target.py` / `test_cve_calibration_given.py` with a server that exits at startup while a counter file holds fewer than N marks (it appends one per launch).
  - `check_target(target, places, *, report_detail=FULL_DETAIL)` (the value of step 2, unchanged). With `FULL_DETAIL` it prints as today. With `TYPES_ONLY` it prints the target and its dead conditions only: `_exercise`'s `calibration error` line gives the exception type only and skips `_print_tail`, and `_report_dead` skips `_dump_exchanges`.
  - `cve_layout_check._observe` / `_report_launch_error`: the same value, threaded from `observe_versions` (and from `observe_layout` in `holdout_vetting.py`, which takes it as a keyword). On the type-only value, the exception type only and no stderr tail. `confirm_admission` (calibration) keeps the full detail.
  - Retries (section 10): `PRE_RUN_LAUNCH_ATTEMPTS = 3` in `evals/cve_calibration.py`. `check_target` calls `_exercise` for a version up to that many times while it returns `None`, then records `the ... version did not launch`. A launch that ran is never retried, whatever it read. `_observe` retries only entering `target.launched` and `connect` (a launch or handshake that fails), up to the same count, before `_failed_observation()`: `route_observations` runs outside the retry, and its failure on a launched server is decided at once. Keep each function under 20 lines: a small `_first_launch(attempt)` helper used by both is fine since it has two callers.
  - `holdout_run.default_deps`: `check` and `layout` pass the type-only value. `run_cve_benchmark`'s pre-run check, `--calibrate`, `run_holdout calibrate`, `run_nuisance calibrate` keep the default.
  - `nuisance_run.benign_call`: only a failed launch or connection (the `except Exception` branch) is retried, up to `PRE_RUN_LAUNCH_ATTEMPTS` launches, keeping the last reason. A non-None `benign_call_failure` (a benign call that answered with an error) is returned at once, never retried. Its connection-failure text uses the type only (it is printed into the nuisance report's not-run row).
  - Logs, in this step's commit: `docs/labeling-log.md` (the launch retries of the pre-run check and the layout check, CVE instrument, four questions of ADR 016), `docs/holdout-log.md` (the same, with the reading that one observation of a version is obtained in up to `PRE_RUN_LAUNCH_ATTEMPTS` launches, so no rule version opens), `docs/nuisance-log.md` (the connection-only retry of the benign call and why an erroring answer is not retried).
  - The golden master of the layout check (`tests/unit/test_cve_layout_check.py`, `test_layout_check_verdicts_match_the_golden_master`) must pass unchanged: its JSON is not regenerated.
- **Test**:
  - Integration, `check_target`: a target whose vulnerable launch fails twice then serves reads live, three failures read `the vulnerable version did not launch`. A target dead on a condition (an existing given, for example `a_target_whose_exploit_misses`) launches once per version (assert on the counter file).
  - Integration, `_observe` through `observe_versions`: a launch failing twice then serving gives a successful observation, three failures give the failed observation, and a server that launches but whose `tools/list` fails is observed once (counter file), not retried.
  - Integration, no server text: a dead target checked with the type-only value prints its dead conditions and no `tool exchanges` line, no stderr line and no exception message (assert on `capsys`), while the default value keeps them (the existing `CVE-DEAD calibration error ... no tools registered` assertion keeps passing).
  - Unit, `benign_call` (monkeypatch the launch or the connect it uses, following `test_nuisance_run_given.py`): a connection failing twice then answering returns None, three failures return the last reason, and an erroring benign answer returns its reason after one launch, not retried.
- **Verify**: the touched integration files in the loop, then the closing checks, then, with Docker, `uv run python -m evals.run_cve_benchmark --calibrate` and `uv run python -m evals.run_holdout calibrate` green as before.

### Step 4: Provider error classification at the audit level

- **Files**: `tests/unit/test_provider_errors.py` (new, with a given module if fixtures need building), `tests/unit/test_cve_audit.py` with its given, `tests/unit/test_nuisance_audit.py`, `tests/unit/test_holdout_audit.py`, `evals/provider_errors.py` (new), `src/mcp_auditor/adapters/llm_throttling.py`, `evals/cve_audit.py`, `evals/nuisance_audit.py`, `evals/holdout_audit.py`, `evals/holdout_results.py`, `evals/nuisance_results.py`, `CHANGELOG.md`.
- **Do**:
  - First settle the OPEN diligence point: at the locked versions, check that the structured-output path of each provider (`langchain_openai`, `langchain_anthropic`, `langchain_google_genai`, the way `adapters/llm.py` binds them) raises a `ModelError` subclass for a 401 and a 5xx. Use an `httpx.MockTransport` or the SDK's own test hooks, no network. Write the result in the step's report. If one path raises unmapped, the `status_code` / `code` fallback must cover it; add a test case built from the exception that path raises.
  - Tests first (see Test).
  - `llm_throttling.py`: rename `_is_billing_limit` to `is_billing_limit` (and its callers). Then verify the error an exhausted Anthropic credit balance raises at the locked versions (Anthropic's API error documentation and the `anthropic` SDK's error classes, then what `langchain_anthropic` turns it into, `AnthropicInvalidRequestError` for a 400), and extend `is_billing_limit` to recognize it (the `billing_error` type, status 402, and the message it carries), with a test built on that exception. Write what was verified in the step's report.
  - `evals/provider_errors.py`: `ProviderFatal(Exception)` carrying the cause, a pure `classify(error: BaseException) -> ProviderErrorKind | None` (an enum `FATAL` / `TRANSIENT`, or two predicates, whichever reads better) per section 3: `ModelError` taxonomy first, then an integer `status_code` on the error, then `code` on the error or on its `__cause__`; fatal on `ModelAuthenticationError`, `ModelPermissionDeniedError`, `ModelNotFoundError`, 401/402/403/404 and `is_billing_limit`; every other provider error transient; anything else None. Imports no provider SDK. A `describe_provider_error(error) -> str` giving the type and the status, never the message, for the CLI branch of step 5.
  - `cve_audit._audit`: wrap only `graph.ainvoke` (inside the client block) so a provider error becomes `AuditFailed(error)` (a fatal or transient tag on it), everything else keeps today's path. The outer handler is `except* AuditFailed`, placed before the `except Exception` that builds `LaunchError` (section 3: the exception arrives bare on a server noisy at shutdown and wrapped in nested groups otherwise, and `except*` reads both). `attempt_once` raises `ProviderFatal` on a fatal one and returns a new `ProviderErrorAttempt` (frozen dataclass beside `ThrottledAttempt`) on a transient one, printing the type and status, never the message. `graded_despite_missed_steps` returns None at once on a `ProviderErrorAttempt`, as on a `ThrottledAttempt`, printing it as a provider error.
  - `nuisance_audit`: the same classification around `graph.ainvoke` in `_audit`, read in `audit_once`'s `try` around `entered_in_thread`: fatal raises `ProviderFatal`, transient returns a new `ProviderError(reason)` beside `LaunchFailed`. `nuisance_audit` retries it within `NUISANCE_INFRA_ATTEMPTS`.
  - `holdout_audit`: retries a `ProviderErrorAttempt` within `HOLDOUT_INFRA_ATTEMPTS`. A run that drops picks its cause by the precedence throttled, then provider error, then launch failure, over all its attempts. Same precedence in `nuisance_audit`.
  - `NotRunCause.PROVIDER_ERROR = "provider_error"` in `holdout_results.py` and `nuisance_results.py`, with its reason in each `DROPPED_RUN_REASONS` (for example "a run hit a provider error past every retry").
  - The fake `connect` of `tests/unit/support/test_cve_audit_given.py` and of the nuisance audit test wraps an exception raised by the body in nested `ExceptionGroup`s, as the SDK does (section 3), and a case keeps the bare shape, so both reach the classification.
  - Logs, in this step's commit: `docs/labeling-log.md` (the provider-error classification, CVE instrument, four questions of ADR 016), `docs/holdout-log.md` and `docs/nuisance-log.md` (the `provider_error` not-run cause).
  - `CHANGELOG.md` `[Unreleased]`: the new not-run cause, and that a fatal provider error (authentication, permission, not found, billing) stops the run.
- **Test**:
  - `classify`: a billing-limit error (type and codes `llm_throttling` already recognizes) fatal, `ModelAuthenticationError` / `ModelPermissionDeniedError` / `ModelNotFoundError` fatal, a plain exception with `status_code` 401/402/403/404 fatal, an error whose `__cause__` carries `code=402` fatal, one with `code=401` on itself fatal, 500 / 529 / 400 and `ModelConnectionError` / `ModelTimeoutError` transient, a plain `TimeoutError`, an `McpError` and a `KeyError` None.
  - `attempt_once` through its public entry point (the fake `connect` of `test_cve_audit_given.py`, a `FakeLLM` that raises), with the body's exception both wrapped in nested groups and bare: a `list_tools` failure inside `graph.ainvoke` still returns None (launch failure), a fatal provider error raises `ProviderFatal`, a transient one returns `ProviderErrorAttempt`, and its printed line holds no message text.
  - `is_billing_limit` on the Anthropic credit-exhausted error the step verified: true, and `classify` reads it fatal.
  - `audit_once`: same three cases, with `LaunchFailed` / `ProviderFatal` / `ProviderError`.
  - `holdout_audit` and `nuisance_audit`: a `ProviderFatal` from the attempt propagates, a transient outcome at every attempt drops with `PROVIDER_ERROR`, a transient then a graded attempt returns the grade, and attempts mixing throttled, provider error and launch failure drop as throttled, provider error and launch mixed drop as provider error.
- **Verify**: `uv run pytest tests/unit -n auto --maxprocesses 4`, then the closing checks.

### Step 5: Run orchestrators and CLIs: precedence per target, partial result on a fatal error, result file, report refusal

- **Files**: `tests/unit/test_holdout_run.py` with `tests/unit/support/test_holdout_run_given.py`, `tests/unit/test_nuisance_run.py` with its given, `tests/unit/test_run_holdout.py`, `tests/unit/test_run_nuisance.py`, `evals/holdout_run.py`, `evals/nuisance_run.py`, `evals/run_holdout.py`, `evals/run_nuisance.py`, `evals/holdout_results.py` / `evals/nuisance_results.py` (a `partial` field), `CLAUDE.md`, `CHANGELOG.md`.
- **Do**:
  - Tests first (see Test).
  - `_run_target` (`holdout_run.py`) and `_run_server` (`nuisance_run.py`): drop with the precedence throttled, then provider error, then launch failure.
  - `_run_all` in both: one task per target (server), `asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)`, then cancel and await the pending tasks. When a task raised, assemble the finished targets (servers) into a partial `HoldoutRunResult` (`NuisanceRunResult`) with `partial=True` and raise `RunInterrupted(partial, cause)` (a small exception in `holdout_results.py` / `nuisance_results.py`, or one shared module), whatever the cause. `_run_target` / `_run_server` run their sibling runs in an `asyncio.TaskGroup`, so a run's exception cancels its siblings, and unwrap the group's single cause so `RunInterrupted` carries the original exception. `HoldoutRunResult` and `NuisanceRunResult` gain `partial: bool = False` (last field). If `holdout_run.py` grows past about 300 lines, move `rebuild_images`, `_tail` and `target_services` into a new `evals/run_images.py` imported by both orchestrators (step 6 adds the container helpers there).
  - `run_holdout._run` and `run_nuisance._run`: before any dep is built (first thing after the tracing refusal), raise `Refused` naming `--report` when the report path, `report.with_suffix(".md")` or `report.with_suffix(".result.json")` exists. After the run, write the result to `report.with_suffix(".result.json")` with `json.dumps(dataclasses.asdict(run), default=str, indent=2)`, then build, render and write the report. On `RunInterrupted`, the CLI writes its partial result to the same `.result.json` path, then lets a `ProviderFatal` cause reach `main` and re-raises any other cause.
  - `run_holdout.main` restricts its `except ValueError` (read today as a malformed census, exit 3) to the census load: a `ValueError` raised during the run is a crash, not a census error. Check `run_nuisance.main` for the same pattern and apply the same restriction if it has it.
  - `run_holdout.main` and `run_nuisance.main` gain a `ProviderFatal` branch printing `describe_provider_error` of its cause (type and status, no message) and returning `CRASHED_EXIT` (already defined in `run_holdout.py` and in `nuisance_commands.py`, import it in `run_nuisance.py`).
  - `CLAUDE.md` Commands: the `run_holdout run` and `run_nuisance run` lines say the run refuses an existing report, `.md` or `.result.json` path and writes the run result beside the report. `CHANGELOG.md`: the same, and exit 4 on a fatal provider error with the finished targets kept. `README.md` only if it documents these commands' outputs.
  - Logs, in this step's commit: `docs/holdout-log.md` and `docs/nuisance-log.md`, the result file and report refusal, and the reading of the audit-error clause for a run stopped on a first failure (it publishes no number, its partial result is never reported, it is relaunched whole at the same commit).
- **Test**:
  - `run_holdout` / `run_nuisance` CLI: an existing report, `.md` or `.result.json` path is refused (exit 3) before any dep is reached (a deps factory that fails the test if called, or the existing pattern of these test files); a run writes the `.result.json` before the report (a `build_report` that raises still leaves the result file), the result file holds no proof field (extend the existing no-proof assertion); a `ProviderFatal` returns 4 and prints no message text.
  - Orchestrators: one target's run raising `ProviderFatal` while another target finished raises `RunInterrupted` carrying a partial result with `partial=True` that holds the finished target and the `ProviderFatal` cause; a still-pending target is cancelled (its fake audit sees `CancelledError` and is never awaited to completion); a run raising another exception is interrupted the same way; a target whose runs drop as provider error and launch failure is not run as `provider_error`.
  - CLI: a `ValueError` raised by the run (not by the census load) is not read as exit 3.
- **Verify**: `uv run pytest tests/unit -n auto --maxprocesses 4`, then the closing checks.

### Step 6: Containers left running by a run

- **Files**: `tests/unit/test_holdout_run.py` with its given, `tests/unit/test_nuisance_run.py` with its given, a new `evals/run_containers.py` (the two docker callables; or in `evals/run_images.py` if step 5 created it), `evals/holdout_run.py`, `evals/nuisance_run.py`.
- **Do**:
  - Tests first (see Test). The fakes in both given modules gain the two new deps.
  - `running_containers(tags: Sequence[str]) -> list[str]` (`docker ps --filter ancestor=<tag> --format ...` per tag, returning the container ids and names) and `remove_containers(ids: Sequence[str]) -> None` (`docker rm -f`), plain functions used only by the two `default_deps`.
  - `HoldoutDeps` and `NuisanceDeps` gain `running_containers` and `remove_containers` callables. The run's tags: `cve_targets.image_tag(service)` over `target_services(targets)` for the holdout, `nuisance_images.image_tag(server.service)` for the nuisance. Never the backend images.
  - In `run_holdout` / `run_nuisance` (orchestrators): refuse with `Refused`, listing the containers, when any is running before the rebuild and again after it. Wrap everything from the rebuild on in `try` / `finally`: the `finally` lists the running containers of the run's images, removes them and prints how many when there were any. Keep the top-level function readable: one helper for the refusal (called twice) and one for the sweep.
  - Logs, in this step's commit: `docs/holdout-log.md` and `docs/nuisance-log.md`, the container checks.
- **Test**:
  - A container listed before the rebuild refuses the run before any audit; one appearing only after the rebuild refuses too (the fake returns it on its second call).
  - The sweep removes the containers listed at the end and runs when the run raises (an audit raising `ProviderFatal`, or a `Refused` from "no target survived"); no container at the end removes nothing and prints nothing.
  - The tags passed are the run's image tags, no backend image.
- **Verify**: `uv run pytest tests/unit -n auto --maxprocesses 4`, then the closing checks.

### Step 7: Server health and replay causes captured on the CVE path

- **Files**: `tests/unit/test_server_health.py` (new, small), `tests/unit/test_cve_replay.py`, `tests/integration/test_cve_replay.py` with its given and then modules, `tests/unit/test_cve_audit.py` with its given (the fake client gains `non_protocol_lines`), `tests/unit/test_holdout_audit.py`, `evals/server_health.py` (new), `evals/cve_replay.py`, `evals/cve_audit.py`, `evals/cve_session_model.py` (`GradedAudit` only), `evals/holdout_audit.py`.
- **Do**:
  - Tests first (see Test).
  - `evals/server_health.py`: `ServerHealth(non_protocol_lines: int, lost_connection_responses: int)` frozen with `__add__` and a zero value, `lost_connection` and `LOST_CONNECTION_RESPONSES` moved from `cve_replay.py` (which imports them back), a `runtime_checkable` Protocol carrying `non_protocol_lines`, and a pure `health_of(client: object, calls: Sequence[Exchange]) -> ServerHealth` reading the count through the Protocol (0 when the client does not carry it) and the lost connections from the recorded responses.
  - `cve_replay.py`: the two enums of section 5, `ReplayAttemptFailure` (`LAUNCH_FAILED`, `LOST_CONNECTION`) per attempt and `UncheckedReason` (`ARGUMENTS_DISAGREE`, `NO_ATTEMPT_DECIDED`) per run, and a `replay_with_causes(run) -> ReplayOutcome(check, unchecked_reason, attempt_failures)` returning the `CreditCheck` as today plus the reason (None on a decided run) and the causes of the attempts that did not complete. `_run_patched` returns the failure cause instead of `None` so each attempt's cause is known. Choose whichever of the two shapes of section 5 keeps `_checked_grade`'s injection seam simplest. `CreditCheck` and `cve_grammar.py` untouched. Update the module docstring where it lists the outcomes.
  - `cve_audit.py`: `_audit` returns the health with the report (read inside the client block, after `graph.ainvoke`, through `health_of(mcp_client, recorder.exchanges)`). `GradedAudit` gains `health: ServerHealth`, `unchecked_reason: UncheckedReason | None` and `replay_attempt_failures: tuple[ReplayAttemptFailure, ...]`, `IncompleteAttempt` gains `health`, `IncompleteRun` (holdout_audit) carries it on. Give the new fields defaults only if that avoids touching many unrelated givens; otherwise pass them explicitly. Console: one warning line when an audit ends with `lost_connection_responses > 0`, and on an unchecked replay `CVE-x: replay unchecked, no_attempt_decided (launch_failed x3)` (the reason, then the attempt counts by cause). The acceptance report (`CVEResult`) gains no field: these console lines are its view.
  - Logs, in this step's commit: `docs/labeling-log.md`, the server health counts and the replay causes (CVE instrument, four questions of ADR 016).
- **Test**:
  - `ServerHealth` addition and `health_of` with a client with and without the property.
  - Integration `test_cve_replay.py`: each existing scenario asserts what it produces (a patched launch dying at a call the vulnerable run answered: attempt causes `LOST_CONNECTION` and, unchecked, `NO_ATTEMPT_DECIDED`; a launch that does not start: `LAUNCH_FAILED` x3 and `NO_ATTEMPT_DECIDED`; mixed truncated and failed: `NO_ATTEMPT_DECIDED`; a complete attempt: no reason, no cause). Unit `test_cve_replay.py`: arguments that disagree read `ARGUMENTS_DISAGREE` with no attempt cause.
  - `attempt_once` with a fake client reporting 2 non-protocol lines and one lost-connection response: the `GradedAudit` (or `IncompleteAttempt`) carries `ServerHealth(2, 1)`, and the console shows the lost-connection warning.
- **Verify**: the touched integration file and the unit suite in the loop, then the closing checks.

### Step 8: Nuisance audit outcome with its health and missed-step causes, carried to the run statuses

- **Files**: `tests/unit/test_nuisance_audit.py`, `tests/unit/test_nuisance_run.py` with its given, `tests/unit/test_nuisance_gate_session.py` with its given (and `tests/unit/support/test_nuisance_gate_report_given.py`, which builds gate runs), `evals/nuisance_audit.py`, `evals/nuisance_run.py`, `evals/nuisance_gate_session.py` (types only), `evals/nuisance_results.py`, `evals/nuisance_assembly.py`.
- **Do**:
  - Tests first (see Test).
  - `nuisance_audit._audit` wraps its client in `RecordingClient` and returns a `NuisanceAudit(report, health)` frozen value (`health_of` from step 7). `audit_once`, `nuisance_audit`, `gate_run` and the `Audit` type alias of `nuisance_run.py` move from `AuditReport` to `NuisanceAudit`. `GateRun` keeps its `report`. The nuisance gate session follows the types, nothing else. Console: the lost-connection warning line, as on the CVE path.
  - `NuisanceRunStatus` gains `non_protocol_lines: int`, `lost_connection_responses: int` and `miss_causes: list[str]` (the sorted `MissCause` values of a refusal or an unreadable answer, as `is_incomplete` reads them, empty on a complete run). `NuisanceServerResult` sums the counts as properties (`non_protocol_lines`, `lost_connection_responses`) and counts incomplete runs by cause (`incomplete_runs_by_cause` or one property per cause). `NuisanceRunResult` keeps `incomplete_run_count` and gains nothing it can compute from its servers.
  - `assemble_server` takes the `NuisanceAudit` values and fills the new status fields.
  - Logs, in this step's commit: `docs/nuisance-log.md`, the server health counts and missed-step causes carried to the run statuses.
- **Test**:
  - `audit_once` with a fake client reporting non-protocol lines and a lost-connection response: the outcome carries the health.
  - `assemble_server`: statuses carry health and causes; the server result sums them.
  - A gate run still decides as before on the new outcome type (existing gate tests keep passing with the givens adapted).
- **Verify**: `uv run pytest tests/unit -n auto --maxprocesses 4`, then the closing checks.

### Step 9: Health, replay causes and missed-step causes in the holdout and nuisance reports

- **Files**: `tests/unit/test_holdout_report.py` with its given, `tests/unit/test_nuisance_report.py` with its given, the holdout assembly test (in `tests/unit/test_holdout_run.py` or a dedicated file if assembly is tested there), `evals/holdout_results.py`, `evals/holdout_assembly.py`, `evals/holdout_report.py`, `evals/holdout_markdown.py`, `evals/nuisance_report.py`, `evals/nuisance_markdown.py`, `CHANGELOG.md`.
- **Do**:
  - Tests first (see Test).
  - `HoldoutRunStatus` gains `non_protocol_lines`, `lost_connection_responses`, `unchecked_reason: str | None` and `replay_attempt_failures: list[str]` (from a graded run's replay, None and empty otherwise) and `miss_causes: list[str]` (the sorted `MissCause` values of an `IncompleteRun`'s report). `assemble_target` fills them from `GradedAudit` / `IncompleteRun` (step 7). `HoldoutTargetResult` sums the counts and counts unchecked reasons and attempt failures by cause as properties.
  - `holdout_report.py`: `TargetRunLine` carries the per-run counts, replay failures and miss causes, `TargetLine` the sums and replay counts by cause, and `HoldoutReport` incomplete-run counts by cause next to `incomplete_run_count`. `nuisance_report.py`: `ServerRunLine` and `ServerLine` likewise from step 8's statuses, and incomplete counts by cause next to the incomplete line.
  - Markdown of both: one line per target or server with a non-zero health count or replay failure, and the incomplete runs split by cause (refused by the provider, unreadable answer).
  - Report-only: the statistic modules (`holdout_statistic.py`, `nuisance_statistic.py`) are not touched.
  - `CHANGELOG.md` `[Unreleased]`: the new report fields of the holdout and nuisance reports, and the acceptance console lines (step 6).
  - Logs, in this step's commit: `docs/holdout-log.md` and `docs/nuisance-log.md`, the new report-only fields and the missed-step causes split by cause.
- **Test**:
  - Holdout and nuisance reports: health counts, replay failure causes (holdout) and missed-step causes appear in the JSON and the markdown; the no-proof-field tests extend to the new models (the new fields hold counts and cause names only).
  - Holdout assembly: a graded run with replay failures and an incomplete run with a refusal produce the matching statuses.
- **Verify**: `uv run pytest tests/unit -n auto --maxprocesses 4`, then the closing checks.

### Step 10: Final verification and log read-through

- **Files**: `docs/labeling-log.md`, `docs/holdout-log.md`, `docs/nuisance-log.md`, `CHANGELOG.md` and `README.md`, only to fix what the read-through finds.
- **Do**:
  - Read the entries steps 2 to 9 wrote against section 11: every change listed there has its entry, each entry follows its log's existing format, carries the four questions of ADR 016 where the log asks for them, and states the decisions only, with no public trace of hesitations or questions.
  - Read the `[Unreleased]` section of `CHANGELOG.md` against section 11 and complete it.
- **Test**: none new.
- **Verify**: the closing checks, then with Docker `uv run python -m evals.run_cve_benchmark --calibrate` and `uv run python -m evals.run_holdout calibrate` green. The exploratory acceptance run of CVE-2025-53355 and the honeypot and judge gates on the final commit (Verification) are run by the maintainer, not in this step, since they spend LLM credits.
