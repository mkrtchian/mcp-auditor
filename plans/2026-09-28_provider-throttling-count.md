# Count the requests the model provider throttled

## Context

When a provider answers HTTP 429 (rate limited), its client library retries the request by itself (`max_retries=3` in `adapters/llm.py`) and the auditor only sees an answer that came later. A throttled audit is slower, and one whose retries run out fails a step, with nothing that names the cause. The CVE benchmark and the honeypot evals now run six audits at once by default (`--concurrency`), which makes throttling likelier, and a user with a small quota meets it too. The count has to be visible, per audit, to decide the concurrency and to explain a slow or incomplete audit.

Where a 429 is visible depends on who retries, read in the installed libraries:

| Provider | Who retries | Where a 429 shows |
|---|---|---|
| `openai`, `alibaba` (`ChatOpenAI`) | the `openai` SDK, over `httpx2` | the `httpx2` logger logs every response with its status (`'HTTP Request: %s %s "%s %d %s"'`, status in `record.args[3]`) |
| `anthropic` | the `anthropic` SDK, over `httpx` | the `httpx` logger, same format |
| `fireworks` | LangChain itself (`langchain_fireworks` builds its SDK client with `max_retries=0` and retries with tenacity through `create_base_retry_decorator`), each retry a new HTTP request | the `httpx` logger, same format: the `fireworks` SDK's default async client is `httpx_aiohttp.HttpxAiohttpClient`, a subclass of `httpx.AsyncClient` whose `send` logs every response whatever the transport (checked: `type(AsyncFireworks()._client).__mro__`) |
| `google` | the `google-genai` SDK, with tenacity | nowhere today: its async requests go through `aiohttp` whenever `aiohttp` is installed, which logs no response |

Taking the retries away from the libraries would make every 429 visible but would change how the auditor behaves under throttling (delays, `Retry-After`), so the retries stay theirs. So one channel, the `httpx`/`httpx2` log, covers every provider, and no LangChain callback is needed (one on Fireworks would count each 429 twice). For Google, the auditor passes `client_args={"transport": httpx.AsyncHTTPTransport()}` to `ChatGoogleGenerativeAI`, which makes `google-genai` use its `httpx` client instead of `aiohttp` (`BaseApiClient._use_aiohttp` is false once `async_client_args` holds a `transport`): its responses are then logged like Anthropic's, and its retries stay its own (decided in discussion). Checked on the installed versions: a `ChatGoogleGenerativeAI` built this way with an `httpx.MockTransport` answering 429 then 200 logs both responses on `httpx` and its `ainvoke` succeeds after the SDK's own retry. Passing a prebuilt `genai.Client` through `client=` does not work: `ChatGoogleGenerativeAI.validate_environment` overwrites `self.client` unconditionally.

## Approach

- **All of it lives in `adapters/`.** A new module `src/mcp_auditor/adapters/throttling.py` counts the 429 responses of the current LLM call. The domain sees one number per call, beside the tokens, and knows nothing of HTTP, status codes or SDKs.
- **Per-call attribution through a `ContextVar`.** `LLM._invoke` opens a tally for the call, the log handler adds to the tally of the call in progress. A `ContextVar` set in a task is seen by everything that task awaits, and not by other tasks, so concurrent audits (and concurrent calls, should they come) never mix their counts.
- **`TokenUsage` becomes `ProviderUsage`** (decided in discussion), with a new field `throttled_requests: int = 0`. It already travels from each LLM call to the report (graph state reducer, `AuditReport`, CLI, rendering, eval merge), so the count follows the same path.
- **Shown where the tokens are, and live.** The CLI warns at the first throttled request of an audit and prints the total in the summary. The evals and the CVE benchmark print a line per audit that was throttled, as it completes, and the session total in their report.

## `src/mcp_auditor/adapters/throttling.py` (new)

```python
@dataclass
class ThrottleTally:
    requests: int = 0


@contextmanager
def counting_throttles() -> Iterator[ThrottleTally]:
    """Counts the HTTP 429 responses received while the block runs, in this task only."""


def install_throttle_log_handler() -> None:
    """Idempotent: attaches the counting handler to the `httpx` and `httpx2` loggers."""
```

- `_current_tally: ContextVar[ThrottleTally | None]`, default `None`. `counting_throttles` sets it and resets it with the token in a `finally`.
- The log handler's `emit` reads the status as `record.args[3]` when `record.args` is a tuple of at least four items and the message is the `HTTP Request:` format, and adds one to the current tally when it is `429`. Anything else, including no tally open, is ignored. `emit` never raises.
- `install_throttle_log_handler` adds the handler once (a module-level flag or a check on `logger.handlers`), and lowers each logger to `INFO` only when its effective level is above `INFO`, so it never raises a level someone set lower. No handler is added to the root logger: the CLI configures no logging, so with a handler found on the `httpx` loggers Python's last-resort handler stays silent and no `HTTP Request` line is printed. The implementer checks it by running an audit.
- The module docstring states the table above in three sentences: which providers log on which logger, and why Google's model is given an `httpx` transport. It is the one place that couples the count to the libraries' log format, so it also says a library change of that format silently stops the count, which the tests pin.

## `src/mcp_auditor/adapters/llm.py`

- `LLM.__init__` is unchanged: no callback is passed, every provider is counted by the log handler.
- `_create_for_provider` calls `install_throttle_log_handler()` once per LLM built (idempotent), so the CLI, the evals and the probe all count without their own setup.
- `_invoke(structured, prompt, usage_so_far)` becomes, in substance:

```python
with counting_throttles() as tally:
    try:
        raw = await structured.ainvoke(prompt)
    except Exception as error:
        # a ProviderRefusal carries usage_so_far plus the throttles of this call
    ...
return raw, tally.requests
```

  `_Attempt` gains the count, and `_unpack_raw_response` puts it into the attempt's `ProviderUsage.throttled_requests`, so `accumulated_usage.add` sums it across parse attempts like the tokens. The shape (a tuple, or passing the tally in) is the implementer's, within three arguments. An exception other than a refusal still propagates as today: a request whose retries all ended in 429 fails the step, and its count is lost with it, which is acceptable since the failure itself is reported.
- `_make_google_model(model, reasoning)` gives the model an `httpx` transport, everything else as today:

```python
ChatGoogleGenerativeAI(
    model=model,
    max_retries=3,
    client_args={"transport": httpx.AsyncHTTPTransport()},
    ...,  # thinking_level when reasoning is set, as today
)
```

  `ChatGoogleGenerativeAI` still builds the `genai.Client` itself (API key from `GOOGLE_API_KEY` or `GEMINI_API_KEY`, base URL, user agent), and the SDK builds its own `AsyncHttpxClient` (a `httpx.AsyncClient`) over that transport, so only the transport changes. The timeout needs nothing: the SDK passes `http_request.timeout` per request on both paths. `client_args` also reaches the sync `httpx.Client`, which then holds an async transport and would fail a sync call: the auditor makes none (`LLM` only calls `ainvoke`), a sentence in a comment says so. Do not pass `client=`: `validate_environment` overwrites it.
- `_to_token_usage` becomes `_to_provider_usage`.

## The rename `TokenUsage` → `ProviderUsage`

- `src/mcp_auditor/domain/models.py`: `class ProviderUsage(BaseModel)`, docstring: "What the model provider billed and how often it throttled. Cost is computed at report time, not here.", fields as today plus `throttled_requests: int = 0`, `add` sums it.
- Every reference in `src/`, `evals/` and `tests/` follows (`domain/__init__.py`, `ports.py`, `graph/nodes.py`, `graph/chain_nodes.py`, `graph/refusals.py`, `graph/state.py`, `console.py`, `domain/rendering.py`, `adapters/llm.py`, `checkpointing.py` (docstring), `evals/honeypots.py`, `evals/fault_injection.py`, `evals/probe.py`, `evals/probe_corpus.py`, `evals/run_probe.py`, `evals/metrics.py` (reads `audit_report.token_usage` to fill `RunDetail`), and 30 test modules, `tests/fakes/` included). No alias is kept.
- **The field and the state channel are renamed too** (decided in discussion): `AuditReport.token_usage` → `provider_usage`, the three `token_usage` channels of `graph/state.py` → `provider_usage`, `_sum_token_usage` → `_sum_provider_usage`, and the `checkpointing.resume_or_reset` docstring. Keeping `token_usage` as the name of a `ProviderUsage` would leave the two names disagreeing everywhere they meet.
- **Consequence for `--resume`**, measured before writing this plan: a checkpoint stores each usage with its class path, and one written under the old name deserializes as a plain dict. With the channel renamed, a resumed audit that was interrupted under the old version finds no `provider_usage` for the steps done before the interruption, and its report under-counts those steps' tokens: no crash. Keeping the channel name would instead feed those dicts to `ProviderUsage.add` and crash the report. The implementer confirms it with a unit test if the existing resume tests make it cheap (a state whose old channel holds dicts, resumed, builds a report), otherwise by reasoning written in the commit message. `CHANGELOG.md` states it.
- The JSON report's `token_usage` key becomes `provider_usage`, a user-facing change of the report format, listed under `### Changed` in the changelog.
- `evals/metrics.py`'s `RunDetail.token_usage` (a dict of token counts in the eval report) keeps its name: it holds tokens only. Only its source changes, `audit_report.provider_usage`.

## Display

### CLI

- `src/mcp_auditor/stream_handler.py`: `AuditProgressReporter` watches the `provider_usage` lists in the stream updates, and at the first usage with `throttled_requests > 0` of the audit calls `display.print_warning("the model provider is throttling requests (HTTP 429): they are retried, the audit slows down")`, once per audit.
- `src/mcp_auditor/console.py`: `_format_token_usage` becomes `_format_provider_usage`, and appends `  |  Throttled: N` when `N > 0`. In CI mode, `render_summary` carries it (next point).
- `src/mcp_auditor/domain/rendering.py`: after the token line, `**Throttled by the model provider**: N requests, retried` when `N > 0`. Nothing when 0, like the refused steps.

### Honeypot evals (`evals/run_evals.py`)

- After each audit, in the `audit` closure of `_announced_audit` (the one place that sees runs and replays alike), when its report's `provider_usage.throttled_requests > 0`: `{honeypot} was throttled {N} time(s) by the model provider (HTTP 429)`, in yellow. The closure knows no run number (the announcement is a preformatted string, and a replay has none), so the line carries none.
- The session total is summed in that same closure, into a small mutable tally that `run_evals` creates and passes to `_announced_audit`: the merged run reports of `audit_honeypots` cannot give it, since `_replay_audit` keeps only the verdicts of a replay's report. It goes into `EvalReport.config["throttled_requests"]`, next to `"concurrency"`, and `eval_display.print_summary` prints `Throttled by the model provider: N requests at concurrency C` in yellow when `N > 0`.

### CVE benchmark

- `evals/cve_audit.py`: `_print_incidents` gains a line `CVE-x: throttled N time(s) by the model provider (HTTP 429)` when `N > 0`. The session total: `run_cve_benchmark._run_graded` creates a small mutable tally and passes it through `_harness(budget, concurrency, tally)` to `audit_target(budget, concurrency, tally)`, whose `audit` closure adds each completed report's count. `audit_target` keeps returning the `bounded` callable (which exposes no attribute of what it wraps), and `_run_graded` reads the tally once `run_gated` returns. The same tally type serves the honeypot evals.
- `evals/cve_oracle.CVEBenchmarkReport` gains `throttled_requests: int` next to `concurrency`, same comment (an execution observation, never compared nor recorded). `render_markdown` shows it on the conditions line when `> 0`. `run_cve_benchmark._print_session` prints the yellow total line as the evals do (it takes the session only today, so it gains the total or the report).

## Dependencies (decided in discussion)

`pyproject.toml` declares `httpx>=0.28.1` and `httpx2>=2.13.1` as direct dependencies, the versions already in `uv.lock`: `adapters/throttling.py` and `adapters/llm.py` import them, and a module that imports a package declares it. `uv lock` is re-run and must not move any version.

## What stays unchanged

- The retries: their number, their delays, `Retry-After`, owned by the libraries for every provider.
- The graph, the prompts, the guard, the gates, the baselines, `CVERunConditions`, `BaselineConditions`: throttling is observed, never a condition.
- The transports of `openai`, `alibaba`, `anthropic` and `fireworks`.
- The probe's statistics: the probe keeps counting a throttled call's latency as before (`evals/probe_method.md`). Its code follows the rename only.

## Edge cases

- No 429: nothing printed anywhere, `throttled_requests` is 0 in the JSON.
- Two audits at once, one throttled: only its report counts it (the `ContextVar`).
- A request whose retries all end in 429: the step fails as today, and the throttles of that call are not in any report.
- A log record from `httpx` outside any LLM call (the MCP SDK uses `httpx` for HTTP transports, not for stdio, and the auditor has no HTTP transport): no tally open, ignored.
- A library changes its log format: the count stays at 0. The tests on real `httpx` and `httpx2` clients catch it on the next dependency upgrade.

## Test scenarios

The tests that go through a real retry (Fireworks, Google, any 429-then-200 scenario) shorten the retry waits to about zero (decided in discussion): through a public setting when the library has one (Google's retry options, for example `initial_delay`), otherwise by replacing tenacity's sleep inside the test only. The unit suite gains no multi-second wait.

`tests/unit/test_throttling.py` (new, Given/When/Then where it abstracts, the helpers in `tests/unit/support/test_throttling_given.py` and `test_throttling_then.py` like the other test modules):

- A real `httpx.AsyncClient` on an `httpx.MockTransport` answering 429 then 200, called twice inside `counting_throttles()` with the handler installed: the tally reads 1. Same with `httpx2`. These pin the library log format.
- Outside `counting_throttles()`, a 429 is ignored and nothing raises.
- Two tasks gathered, each in its own `counting_throttles()`, one receiving two 429s and the other none: 2 and 0.
- A `ChatFireworks` whose `async_client` is `AsyncFireworks(api_key=..., max_retries=0, http_client=httpx.AsyncClient(transport=MockTransport)).chat.completions` answering 429 then 200, invoked inside `counting_throttles()`: the tally reads 1, not 2 (LangChain's retry is not counted on top of the logged response).
- A `ChatGoogleGenerativeAI` built with `client_args={"transport": MockTransport}` answering 429 then 200, invoked inside `counting_throttles()`: the tally reads 1 (pins that `google-genai` retries a 429 itself and logs through `httpx` once it has a transport).
- `install_throttle_log_handler()` called twice, then one 429 inside `counting_throttles()`: the tally reads 1, not 2.

`tests/unit/test_llm_adapter.py` (where `LLM` is tested with a fake chat model): a fake chat model that emits a `429` log record on the `httpx2` logger during `ainvoke`, then answers: the returned `ProviderUsage.throttled_requests` is 1, and it sums across parse attempts.

`tests/unit/test_llm_adapter.py`, class `TestMakeChatModel`: the Google model built by `make_chat_model` carries an `httpx.AsyncHTTPTransport` in its public `client_args` field, read like `model` and `thinking_level` in the neighboring tests. No assertion on the SDK's private `_use_aiohttp()`: the MockTransport test above covers the behavior that field produces.

`tests/unit/test_stream_handler.py`: two updates carrying throttled usages print one warning.

`tests/unit/test_rendering.py` and the console tests (`test_console_display.py`): the throttled line appears with `N > 0`, and not with 0.

`tests/unit/test_cve_audit.py`, `test_cve_oracle.py`, `test_run_cve_benchmark.py` and the eval tests: a scripted audit reporting throttles yields the per-audit line and the session total in the report, a replay's throttles included for the honeypot evals. The CVE report JSON carries `throttled_requests`.

## Verification

```bash
uv run pytest -n auto
uv run ruff check . && uv run ruff format --check . && uv run pyright
uv run mcp-auditor run -- uv run python tests/honeypot_server.py   # the real CLI: no HTTP Request line printed, the summary shows tokens, no throttled line when none occurred
MCP_AUDITOR_PROVIDER=google uv run mcp-auditor run -- uv run python tests/honeypot_server.py   # Google through httpx still audits (needs GOOGLE_API_KEY)
uv run python -m evals.run_cve_benchmark --ungated --cve CVE-2025-53355 --runs 1 --concurrency 1   # the report carries throttled_requests
```

The implementer adapts the CLI invocation to the real command syntax in `README.md`.

## Commits

1. The rename `TokenUsage` → `ProviderUsage`, field and channel included, with no new behavior.
2. `httpx` and `httpx2` declared in `pyproject.toml`, `adapters/throttling.py` and its wiring in `adapters/llm.py` for `openai`, `alibaba`, `anthropic`, `fireworks`: the count reaches the report.
3. The Google model given an `httpx` transport.
4. The CLI display (live warning, summary, Markdown report).
5. The evals and the CVE benchmark display (per audit, session total, reports).

## Living docs

- `README.md`: the report section names the throttled count and what it means, and one sentence on the `google` provider's transport if the README describes providers' clients.
- `CHANGELOG.md` `[Unreleased]`: `### Added`, the audit counts the requests the model provider throttled (HTTP 429), warns at the first, and reports the total. The evals and the CVE benchmark print it per audit and per session. `### Changed`, the JSON report's `token_usage` becomes `provider_usage` and gains `throttled_requests`, the `google` provider talks to the API over `httpx` instead of `aiohttp`, and an audit interrupted under a previous version resumes with the tokens of its earlier steps missing from the report.
- `CLAUDE.md` and `CONTRIBUTING.md`: no command changes. `CLAUDE.md` Landmines gains one line: the throttle count reads the `httpx`/`httpx2` log format, and Google's model is given an `httpx` transport for it, so do not drop `client_args={"transport": ...}` from `_make_google_model` (without it `google-genai` switches to `aiohttp` and Google's 429s silently stop counting).

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites, checked on 2026-09-28 against the versions installed from `uv.lock` (source read and behavior run locally). Later passes read it. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: `'HTTP Request: %s %s "%s %d %s"'` is the response log format of both `httpx` 0.28.1 (`httpx/_client.py`) and `httpx2` 2.13.1 (`httpx2/_client.py`), status as the fourth argument (verified against the installed source)
- SETTLED: `logging.getLogger("httpx2")` is the `httpx2` logger name, and `httpx2.MockTransport` exists (verified against the installed source)
- SETTLED: `openai` 3.19.2 defaults its async client to a `httpx2.AsyncClient` subclass, `anthropic` 0.84.0 to a `httpx.AsyncClient` subclass (verified by printing each client's MRO)
- SETTLED: `fireworks-ai` 1.2.15 defaults its async client to `httpx_aiohttp.HttpxAiohttpClient`, a `httpx.AsyncClient` subclass that overrides only transport construction, so `send` logs (verified by MRO and source)
- SETTLED: `langchain-fireworks` 1.6.2 builds `AsyncFireworks(..., max_retries=0)` and retries through `create_base_retry_decorator` (verified against `langchain_fireworks/chat_models.py`)
- SETTLED: `ChatFireworks.async_client` is the SDK's `.chat.completions` resource, not the `AsyncFireworks` client (verified: `llm.async_client.create(**kwargs)` in `langchain_fireworks/chat_models.py`), the test scenario was corrected accordingly
- SETTLED: `client_args={"transport": httpx.AsyncHTTPTransport()}` on `ChatGoogleGenerativeAI` (langchain-google-genai 4.2.1) reaches both `client_args` and `async_client_args` of `google-genai` 1.68.0, and `BaseApiClient._use_aiohttp()` returns false once a transport is set (verified in source and by running it)
- SETTLED: a `ChatGoogleGenerativeAI` on a `httpx.MockTransport` answering 429 then 200 logs both responses on `httpx` and `ainvoke` succeeds after the SDK's own retry (verified by running it)
- SETTLED: `ChatGoogleGenerativeAI.validate_environment` assigns `self.client = Client(...)` unconditionally (verified against the installed source)
- OPEN (unverified): the CLI printing no `HTTP Request` line once `httpx`/`httpx2` are lowered to `INFO`, reasoned from the stdlib's last-resort handler and the absence of any `basicConfig` in `src/` and `evals/`, left to the plan's own run of the CLI

## Implementation steps

Verification commands for every step (from `CLAUDE.md`): `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`. Each step ends with all four green. The steps follow the five commits of the plan, one commit per step.

### Step 1: Rename `TokenUsage` to `ProviderUsage`, field and channel included

- **Files**: `src/mcp_auditor/domain/models.py`, `domain/__init__.py`, `domain/ports.py`, `domain/rendering.py`, `graph/nodes.py`, `graph/chain_nodes.py`, `graph/refusals.py`, `graph/state.py`, `adapters/llm.py`, `checkpointing.py`, `console.py`; `evals/honeypots.py`, `evals/fault_injection.py`, `evals/probe.py`, `evals/probe_corpus.py`, `evals/run_probe.py`, `evals/metrics.py`; every test module and fake that `grep -rl "TokenUsage\|token_usage" src evals tests` lists (about 30, `tests/fakes/` and `tests/unit/support/` included); `CHANGELOG.md`.
- **Do**:
  - Mechanical rename, no new behavior: `TokenUsage` → `ProviderUsage` (class, imports, `__all__`), `AuditReport.token_usage` → `provider_usage`, the three `token_usage` channels of `graph/state.py` → `provider_usage`, `_sum_token_usage` → `_sum_provider_usage`, `_to_token_usage` → `_to_provider_usage` in `adapters/llm.py`, `_format_token_usage` → `_format_provider_usage` in `console.py`, the `checkpointing.resume_or_reset` docstring. Every node that writes `{"token_usage": [...]}` writes `{"provider_usage": [...]}`. Test helper names that say `token_usage` follow when they name this object. No alias kept.
  - `ProviderUsage` docstring: "What the model provider billed and how often it throttled. Cost is computed at report time, not here." Do NOT add `throttled_requests` yet (step 2).
  - `evals/metrics.py`: `RunDetail.token_usage` keeps its name (tokens only), only its source becomes `audit_report.provider_usage`.
  - Leave `plans/`, `docs/adr/` and `evals/baselines/` untouched. Check that no stored fixture (`evals/fixtures/*.json`, recorded baselines) carries a `token_usage` key read back into `AuditReport`: `grep -rn token_usage evals/fixtures evals/baselines`. If one does, stop and report rather than rewriting a fixture.
  - Resume consequence: if `tests/unit/test_checkpointing.py` makes it cheap (a checkpointed state whose old `token_usage` channel holds dicts, resumed, still builds a report with no crash), add that test; otherwise write the reasoning of the plan's "Consequence for `--resume`" into the commit message (the implementer hands it to the committer).
  - `CHANGELOG.md` `[Unreleased]` `### Changed`: the JSON report's `token_usage` key becomes `provider_usage`, and an audit interrupted under a previous version resumes with the tokens of its earlier steps missing from the report.
- **Test**: existing suite green after the rename (it is the regression net). Optional resume test above.
- **Verify**: `grep -rn "TokenUsage\|_sum_token_usage\|_to_token_usage\|_format_token_usage" src evals tests` returns nothing; `grep -rn "token_usage" src tests` returns nothing; in `evals/` only `RunDetail.token_usage` and its use remain. Then the four commands, all green.

### Step 2: Count the throttled requests in the adapters (`openai`, `alibaba`, `anthropic`, `fireworks`)

- **Files**: `tests/unit/test_throttling.py` (new), `tests/unit/support/test_throttling_given.py` (new), `tests/unit/support/test_throttling_then.py` (new, only if it abstracts something), `tests/unit/test_llm_adapter.py`, `src/mcp_auditor/adapters/throttling.py` (new), `src/mcp_auditor/adapters/llm.py`, `src/mcp_auditor/domain/models.py`, `pyproject.toml`, `uv.lock`, `CHANGELOG.md`.
- **Do** (tests first):
  - `tests/unit/test_throttling.py` with the scenarios below. Given helpers build a real `httpx.AsyncClient` / `httpx2.AsyncClient` over a `MockTransport` scripted with a list of statuses (429 then 200), and the `ChatFireworks` of the plan: `ChatFireworks(api_key="test", ...)` with `async_client = AsyncFireworks(api_key=..., max_retries=0, http_client=httpx.AsyncClient(transport=MockTransport)).chat.completions` (the resource, not the client), answering a minimal chat-completion JSON on 200. For the LangChain tenacity retry, shorten the wait inside the test only (monkeypatch tenacity's sleep, for example `tenacity.nap.sleep` / the `asyncio.sleep` tenacity's async retrying uses, to a no-op coroutine), no multi-second wait.
  - `pyproject.toml`: add `httpx>=0.28.1` and `httpx2>=2.13.1` to `dependencies`, then `uv lock`: `git diff uv.lock` must show no version moved (only the direct-dependency declaration lines of the project package).
  - `adapters/throttling.py` per the plan: module docstring (which provider logs on which logger, why Google gets an `httpx` transport, a library log format change silently stops the count and the tests pin it), `ThrottleTally` dataclass, `_current_tally: ContextVar[ThrottleTally | None]`, `counting_throttles()` context manager (set, yield, reset with the token in `finally`), a private `logging.Handler` subclass whose `emit` adds one when `record.msg` starts with `"HTTP Request:"`, `record.args` is a tuple of at least four items and `record.args[3] == 429`, and a tally is open, never raising; `install_throttle_log_handler()` idempotent on the `httpx` and `httpx2` loggers, lowering a logger to `INFO` only when `getEffectiveLevel() > INFO`, no handler on the root logger.
  - `domain/models.py`: `ProviderUsage.throttled_requests: int = 0`, summed by `add`.
  - `adapters/llm.py`: `_create_for_provider` calls `install_throttle_log_handler()`. `_invoke` opens `counting_throttles()` around `ainvoke` and returns the raw response with `tally.requests`; a refusal raised there carries `usage_so_far.add(ProviderUsage(throttled_requests=tally.requests))`. `_Attempt` / `_unpack_raw_response` put the count into the attempt's `ProviderUsage.throttled_requests` so `generate_structured` sums it across parse attempts. At most three arguments per function. Other exceptions propagate as today.
  - `CHANGELOG.md` `[Unreleased]` `### Changed`: extend the step 1 line, the JSON report's `provider_usage` gains `throttled_requests`.
- **Test**:
  - `httpx` client, 429 then 200, two calls inside `counting_throttles()` with the handler installed: tally 1. Same with `httpx2`.
  - A 429 outside `counting_throttles()`: ignored, nothing raises.
  - Two tasks gathered, each in its own `counting_throttles()`, one receiving two 429s, the other none: 2 and 0.
  - `ChatFireworks` on the mock transport, 429 then 200, `ainvoke` inside `counting_throttles()`: tally 1, not 2.
  - `install_throttle_log_handler()` called twice, then one 429: tally 1.
  - `test_llm_adapter.py`: a fake chat model that logs a 429 record on the `httpx2` logger (`logging.getLogger("httpx2").info('HTTP Request: %s %s "%s %d %s"', "POST", url, "HTTP/1.1", 429, "Too Many Requests")`) during `ainvoke`, then answers: `ProviderUsage.throttled_requests` is 1; with a first malformed attempt that also logs a 429, the total across attempts is 2. Make sure the handler is installed in this test (call `install_throttle_log_handler()` in the given, since the fake bypasses `_create_for_provider`).
- **Verify**: `uv run pytest tests/unit/test_throttling.py tests/unit/test_llm_adapter.py` red before the code, green after; then the four commands. `uv run mcp-auditor` quick run (see `README.md` for the syntax, for example `uv run mcp-auditor run -- uv run python tests/honeypot_server.py` with a small budget) prints no `HTTP Request` line: this closes the OPEN due-diligence item. If a line appears, stop and report.

### Step 3: Give the Google model an `httpx` transport

- **Files**: `tests/unit/test_throttling.py`, `tests/unit/support/test_throttling_given.py`, `tests/unit/test_llm_adapter.py`, `src/mcp_auditor/adapters/llm.py`, `CHANGELOG.md`, `CLAUDE.md`, `README.md` (only if it describes the providers' HTTP clients).
- **Do** (tests first):
  - `_make_google_model` passes `client_args={"transport": httpx.AsyncHTTPTransport()}` on both branches (with and without `thinking_level`), `max_retries=3` unchanged. A one-sentence comment: `client_args` also reaches the sync client, which would fail a sync call, and the auditor makes none (`LLM` only calls `ainvoke`). Do not pass `client=`.
  - `CHANGELOG.md` `### Changed`: the `google` provider talks to the API over `httpx` instead of `aiohttp`.
  - `CLAUDE.md` Landmines: one line, the throttle count reads the `httpx`/`httpx2` log format, and Google's model is given an `httpx` transport for it, so do not drop `client_args={"transport": ...}` from `_make_google_model` (without it `google-genai` switches to `aiohttp` and Google's 429s silently stop counting).
- **Test**:
  - `test_throttling.py`: a `ChatGoogleGenerativeAI(model=..., google_api_key="test", client_args={"transport": httpx.MockTransport(...)}, ...)` answering 429 then a minimal `generateContent` 200 JSON, `ainvoke` inside `counting_throttles()`: tally 1, and the call succeeds. Shorten the SDK's retry wait through its public retry options when `ChatGoogleGenerativeAI` exposes them, otherwise by patching the sleep inside the test only.
  - `TestMakeChatModel`: the Google model built by `make_chat_model` has an `httpx.AsyncHTTPTransport` under `client_args["transport"]`, for the default and the judge override.
- **Verify**: the new tests red before, green after; the four commands. If `GOOGLE_API_KEY` is set, `MCP_AUDITOR_PROVIDER=google uv run mcp-auditor run -- uv run python tests/honeypot_server.py` still audits (skip and say so otherwise).

### Step 4: CLI display (live warning, summary, Markdown report)

- **Files**: `tests/unit/test_stream_handler.py`, `tests/unit/test_console_display.py` (and `tests/unit/support/test_console_given.py` if a usage with throttles needs a given), `tests/unit/test_rendering.py` (and `tests/unit/support/test_rendering_given.py`), `src/mcp_auditor/stream_handler.py`, `src/mcp_auditor/console.py`, `src/mcp_auditor/domain/rendering.py`, `README.md`, `CHANGELOG.md`.
- **Do** (tests first):
  - `stream_handler.py`: `AuditProgressReporter.on_stream_event` checks every `state_update` (whatever the graph level) for a `provider_usage` list, and at the first `ProviderUsage` with `throttled_requests > 0` calls `self._display.print_warning("the model provider is throttling requests (HTTP 429): they are retried, the audit slows down")`, then never again for that reporter (one reporter per audit). Keep the new logic in a small private method below its caller.
  - `console.py`: `_format_provider_usage` appends `  |  Throttled: N` when `N > 0`; the CI `render_summary` path carries it (check how the summary line is built for CI and reuse the same formatter).
  - `domain/rendering.py`: after the token line of the Markdown report, `**Throttled by the model provider**: N requests, retried` when `N > 0`, nothing at 0.
  - `README.md`: the report section names the throttled count and what it means (requests the provider answered HTTP 429, retried by its client, a sign to lower concurrency or expect a slower audit).
  - `CHANGELOG.md` `### Added`: the audit counts the requests the model provider throttled (HTTP 429), warns at the first, and reports the total.
- **Test**:
  - Stream handler: two updates each carrying a throttled usage print one warning; updates with `throttled_requests == 0` print none.
  - Console: summary shows `Throttled: 3` with a usage of 3, no `Throttled` with 0; same in CI mode.
  - Rendering: Markdown carries the throttled line with `N > 0`, not with 0; JSON carries `provider_usage.throttled_requests`.
- **Verify**: new tests red before, green after; the four commands.

### Step 5: Evals and CVE benchmark display (per audit, session total, reports)

- **Files**: `tests/unit/test_eval_metrics.py` (and its given), `tests/unit/test_cve_oracle.py` (and `tests/unit/support/test_cve_oracle_given.py`), a test for `eval_display.print_summary` (in the existing module that covers `eval_display`, or `tests/unit/test_eval_display.py` new), `evals/metrics.py`, `evals/run_evals.py`, `evals/eval_display.py`, `evals/cve_audit.py`, `evals/run_cve_benchmark.py`, `evals/cve_oracle.py`, `CHANGELOG.md`.
- **Do** (tests first):
  - Session tally, one type for both suites, in `evals/metrics.py` next to `refused_steps` (decided here: that module already reads per-report incidents): `@dataclass class SessionThrottles: requests: int = 0` with `def count(self, report: AuditReport) -> int` that adds the report's `provider_usage.throttled_requests` and returns it.
  - `run_evals.py`: `run_evals` creates a `SessionThrottles` and passes it to `_announced_audit(session, concurrency, throttles)`; the `audit` closure counts each report and, when its count is `> 0`, prints `[yellow]{honeypot.name} was throttled {N} time(s) by the model provider (HTTP 429)[/yellow]` (check the honeypot's display attribute name). Replays go through the same closure, so they are counted. `EvalReport.config["throttled_requests"] = throttles.requests`, next to `"concurrency"`.
  - `eval_display.print_summary`: when `report.config.get("throttled_requests", 0) > 0`, prints `[yellow]Throttled by the model provider: N requests at concurrency C[/yellow]` (C from `report.config["concurrency"]`). `.get` because older reports have no key.
  - `cve_audit.py`: `audit_target(budget, concurrency, throttles)`; the closure counts each completed report; `_print_incidents` gains `CVE-x: throttled N time(s) by the model provider (HTTP 429)` in yellow when `N > 0` (pass the count, or read it from the report). Update `tests/unit/test_cve_audit.py`'s call.
  - `run_cve_benchmark.py`: `_run_graded` creates the `SessionThrottles`, passes it through `_harness(budget, concurrency, throttles)`, reads `throttles.requests` after `run_gated` returns, sets it on `CVEBenchmarkReport`, and `_print_session(session, throttled_requests)` prints the yellow total line `Throttled by the model provider: N requests at concurrency C` when `> 0` (so it takes the concurrency too, or the report: choose the report, at most three arguments).
  - `cve_oracle.CVEBenchmarkReport.throttled_requests: int = 0` next to `concurrency`, same comment (an execution observation, never compared nor recorded in a baseline). `_render_conditions` shows it on the conditions line when `> 0` (for example `, 4 requests throttled by the model provider`).
  - `CHANGELOG.md` `### Added`: the evals and the CVE benchmark print the throttled count per audit and per session.
- **Test**:
  - `SessionThrottles.count` over two reports (2 and 0 throttles) returns each count and totals 2.
  - `print_summary` prints the throttled line with `config["throttled_requests"] = 4`, not with 0 nor with the key absent.
  - `render_markdown` shows the throttled count on the conditions line when `> 0`, not at 0; the report's JSON (`model_dump_json`) carries `throttled_requests`.
  - `_print_incidents` (or the closure through a scripted report, if cheap) prints the per-CVE throttled line with a report of 2 throttles, none at 0.
- **Verify**: new tests red before, green after; the four commands. If Docker, the CVE images and an LLM key are available: `uv run python -m evals.run_cve_benchmark --ungated --cve CVE-2025-53355 --runs 1 --concurrency 1`, the written report carries `throttled_requests` (skip and say so otherwise).
