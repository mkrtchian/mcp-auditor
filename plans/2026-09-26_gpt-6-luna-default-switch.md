# Switch the default model to `gpt-6-luna` at reasoning effort `none`

## Context

[ADR 021](../docs/adr/021-gpt-6-luna-default.md) (Accepted, `2cd755f`) makes `gpt-6-luna` at reasoning effort `none` the default model for both roles: the default provider moves from `google` to `openai`, and the default setting of the `openai` provider moves from `medium` to `none`. Its two other decisions are already implemented: the completion of missing categories (`f282ef7`, `53fac7e`) and the probe without an admission verdict (`43add09`).

The code and the living docs still carry the old default:

- `src/mcp_auditor/config.py`: `Settings.provider` defaults to `"google"`, and `_PROVIDERS["openai"]` has `reasoning="medium"`.
- `tests/unit/test_config.py` pins the default provider (`test_default_settings`) and `openai` at `medium` (`test_openai_resolves_luna_at_medium_reasoning_by_default`). `tests/unit/test_llm_adapter.py` pins the built OpenAI model at `medium` (`test_openai_builds_luna_at_medium_reasoning`).
- `.env.example` sets `MCP_AUDITOR_PROVIDER=google` and lists `medium` as the `openai` default.
- `README.md`: the quick start exports `GOOGLE_API_KEY` with a Google AI Studio note, the CVE benchmark prerequisite cites `GOOGLE_API_KEY`, the environment table gives `google` as the default provider, and the paragraph under it describes `google` as the default and `openai` at `medium`.
- `CONTRIBUTING.md`: the eval key sentence names `GOOGLE_API_KEY` as the default provider's key.
- `CLAUDE.md`, Commands: `run_evals` and `run_judge_eval` need `GOOGLE_API_KEY` by default.
- `CHANGELOG.md`, `[Unreleased]`: the *Added* entry gives `openai` at `medium`.
- `.github/workflows/evals.yml` and `.github/workflows/eval-command.yml` pass `GOOGLE_API_KEY` to the judge eval and the e2e eval, so after the switch CI would fail to build the default model.

## Approach

One commit, since the default, its tests, its docs and the CI key only make sense together: a default provider whose key CI does not pass breaks CI, and docs that describe the old default mislead users.

1. `Settings.provider` defaults to `"openai"`, and the `openai` provider's default reasoning becomes `"none"`. No other provider changes.
2. The three pinned tests move to the new values, test-first.
3. The living docs describe the new default and its key.
4. The two workflows pass `OPENAI_API_KEY` instead of `GOOGLE_API_KEY` to the eval steps.

The repository secret `OPENAI_API_KEY` must exist on GitHub before the next CI eval run. Adding it is a manual step outside this plan.

## Files to modify

### `src/mcp_auditor/config.py`

- `provider: str = "openai"`.
- `_PROVIDERS["openai"]`: `reasoning="none"`. `accepted_reasoning` unchanged.

Nothing else: `resolve_model`, `resolve_reasoning`, `_check_reasoning_accepted` and the other providers stay as they are.

### `tests/unit/test_config.py`

- `test_default_settings`: asserts `settings.provider == "openai"` and `settings.resolve_model() == "gpt-6-luna"`, and also that `settings.resolve_reasoning(settings.resolve_model()) == "none"`. It already clears `MCP_AUDITOR_PROVIDER`, `MCP_AUDITOR_MODEL` and `MCP_AUDITOR_JUDGE_MODEL`, and it also clears `MCP_AUDITOR_REASONING`, so a developer's `.env` or shell cannot change what it reads.
- `test_openai_resolves_luna_at_medium_reasoning_by_default` becomes `test_openai_resolves_luna_at_reasoning_none_by_default`, asserting `"none"`.
- The Google tests (`test_google_resolves_minimal_reasoning_for_its_default_model`, the override tests) keep `google` explicitly and do not change.

### `tests/unit/test_llm_adapter.py`

`test_openai_builds_luna_at_medium_reasoning` becomes `test_openai_builds_luna_at_reasoning_none`, asserting `reasoning_effort == "none"`. The timeout and output cap assertions stay.

### `.env.example`

- First line: `"openai" (default), "google", "anthropic", "fireworks" or "alibaba"`.
- `MCP_AUDITOR_PROVIDER=openai`.
- Model override examples: `gpt-6-luna` for both lines.
- Reasoning comment: `google: minimal (default for the default model), low, medium, high.` stays, `openai: none (default for the default model), low, medium, high, xhigh, max.`, and the commented example becomes `# MCP_AUDITOR_REASONING=none`.
- API keys: `OPENAI_API_KEY` listed first.

### `README.md`

- Quick start: `export OPENAI_API_KEY=your-key-here`, with a comment pointing at the OpenAI API keys page (`platform.openai.com/api-keys`). The Google AI Studio free-tier note goes.
- CVE benchmark prerequisite comment: `(e.g. OPENAI_API_KEY)`.
- Environment table: `MCP_AUDITOR_PROVIDER` default `openai`, provider list starting with `openai`.
- The paragraph under the table: with the default `openai` provider, both roles run `gpt-6-luna` at reasoning effort `none`, with `google` they run `gemini-3.5-flash-lite` at thinking level `minimal`, and the other providers are unchanged. The sentence on the default reasoning applying to the default model only stays.
- *Safety* paragraph: after "The same secret reaches the judge model", add that with the default `openai` provider, OpenAI keeps abuse-monitoring logs of API requests for up to 30 days by default (source already cited in `evals/probe_method.md`, *Data retention per provider*). A secret read to prove impact now leaves for a provider that keeps it, and the reader of the Safety paragraph is the one who needs to know.

### `CONTRIBUTING.md`

The eval key sentence: `OPENAI_API_KEY` (default provider), then `GOOGLE_API_KEY`, `ANTHROPIC_API_KEY`, `FIREWORKS_API_KEY` or `DASHSCOPE_API_KEY`. The probe section keeps its explicit reference settings, which do not depend on the default.

### `CLAUDE.md`, Commands

`run_evals` and `run_judge_eval`: `needs an LLM key: OPENAI_API_KEY by default`.

### `CHANGELOG.md`, `[Unreleased]`

- *Added*, the provider entry: `openai` default model `gpt-6-luna` at reasoning effort `none`.
- *Changed*, a new first bullet, prefixed **Breaking.** like the container entry: the default provider is now `openai`, running `gpt-6-luna` at reasoning effort `none` for the main model and the judge, and an audit with no configuration needs `OPENAI_API_KEY`. Its list prices are $0.10 input and $0.50 output per million tokens, against $0.30 and $2.50 for `gemini-3.5-flash-lite`. To keep Google, set `MCP_AUDITOR_PROVIDER=google` (its default model stays `gemini-3.5-flash-lite` at `minimal`). A configuration that sets a Gemini model or `MCP_AUDITOR_REASONING=minimal` without `MCP_AUDITOR_PROVIDER=google` now fails. See ADR 021.
- The existing bullet on the default Google model (`gemini-3.5-flash-lite`) stays: it still describes the `google` provider's default.

### `.github/workflows/evals.yml`, `.github/workflows/eval-command.yml`

Every `GOOGLE_API_KEY: ${{ secrets.GOOGLE_API_KEY }}` passed to an eval step becomes `OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}`. No other change to the workflows (triggers, fork refusal, pinned SHAs, conditions).

## What stays unchanged

- `adapters/llm.py`, the providers, the output cap, the timeouts, the structured-output modes.
- The `google` provider's default model and setting, and every other provider.
- The probe: `REFERENCE` (Gemini 3.1 Flash-Lite `minimal`), the candidates, the corpus capture, which refuses any setting but the reference and sets it explicitly (`CONTRIBUTING.md`). `evals/probe_method.md` does not change.
- The evals' code. The baseline conditions record the provider, model and reasoning of a run, and no baseline is recorded yet, so nothing is invalidated.
- ADRs and past plans.
- The developer's own `.env`, which sets the Google provider explicitly and keeps doing so until its owner changes it.

## Edge cases

- **A user with only `GOOGLE_API_KEY` and no `MCP_AUDITOR_PROVIDER`**: the audit now fails with `OPENAI_API_KEY is not set.` (raised by `_make_openai_model`), which the CHANGELOG entry names as breaking with the fix.
- **`MCP_AUDITOR_REASONING=minimal` with no provider set**: `resolve_reasoning` refuses it for `openai` with the accepted values, the existing error path.
- **`MCP_AUDITOR_MODEL=gemini-...` with no provider set**: the OpenAI API rejects the model at the first call. The CHANGELOG entry covers it.
- **CI before the secret exists**: the eval steps fail at model construction. The plan names the secret as a prerequisite.

## Test scenarios

- `test_default_settings` fails before the change (provider `google`, model `gemini-3.5-flash-lite`), passes after with `openai`, `gpt-6-luna`, `none`.
- `test_openai_resolves_luna_at_reasoning_none_by_default` fails before (`medium`), passes after.
- `test_openai_builds_luna_at_reasoning_none` fails before, passes after.
- The whole unit suite passes otherwise: the tests that exercise Google set the provider explicitly.

## Verification

```bash
uv run pytest tests/unit
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run pyright
grep -rn "GOOGLE_API_KEY" .github/workflows   # no output
```

## After this plan

By hand: add the `OPENAI_API_KEY` secret to the GitHub repository, with a usage cap on the key, since the `/eval` comment workflow runs a pull request's code with it. Then remove `MCP_AUDITOR_PROVIDER` and `MCP_AUDITOR_REASONING` from the local `.env`, since `--record-baseline` refuses conditions that differ from the defaults, and record the two honeypot baselines on the new default, as ADR 020 sets.

## Commit message

`feat(config): default to gpt-6-luna at reasoning none`, naming ADR 021, the breaking change for users relying on the Google default, and the CI secret it now needs. No plan, step or phase named.

## Due diligence record

What the due-diligence pass concluded, on 2026-09-26, about each external fact this plan cites or defers. Later passes, the implementation-phase fact check included, read it. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, not what is true now. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- SETTLED: `gpt-6-luna` list prices $0.10 input and $0.50 output per million tokens, short context (verified against https://developers.openai.com/api/docs/pricing, standard tier)
- SETTLED: `gemini-3.5-flash-lite` list prices $0.30 input and $2.50 output per million tokens, text input (verified against https://ai.google.dev/gemini-api/docs/pricing, paid tier, standard)
- SETTLED: `reasoning_effort == "none"` is accepted by `gpt-6-luna`, whose API default is `medium` (verified against https://developers.openai.com/api/docs/models/gpt-6-luna)
- SETTLED: OpenAI abuse-monitoring logs of API requests are retained for up to 30 days by default (verified against https://developers.openai.com/api/docs/guides/your-data)
- SETTLED: `platform.openai.com/api-keys` is the page where OpenAI API keys are created (confirmed by the user on 2026-09-26, the primary source answering 403 to an unauthenticated fetch)

## Implementation steps

### Step 1: Switch the default to `gpt-6-luna` at reasoning `none`, with its tests, docs and CI key

- **Files**:
  - `tests/unit/test_config.py`, `tests/unit/test_llm_adapter.py` (modify, first)
  - `src/mcp_auditor/config.py` (modify)
  - `.env.example`, `README.md`, `CONTRIBUTING.md`, `CLAUDE.md`, `CHANGELOG.md` (modify, living docs)
  - `.github/workflows/evals.yml`, `.github/workflows/eval-command.yml` (modify)
- **Do**:
  1. Tests first, and run them to see them red:
     - `tests/unit/test_config.py::test_default_settings`: add `monkeypatch.delenv("MCP_AUDITOR_REASONING", raising=False)` beside the three existing `delenv`, then assert `settings.provider == "openai"`, `settings.resolve_model() == "gpt-6-luna"` and `settings.resolve_reasoning(settings.resolve_model()) == "none"`.
     - Rename `test_openai_resolves_luna_at_medium_reasoning_by_default` to `test_openai_resolves_luna_at_reasoning_none_by_default`, asserting `"none"`.
     - `tests/unit/test_llm_adapter.py`: rename `test_openai_builds_luna_at_medium_reasoning` to `test_openai_builds_luna_at_reasoning_none`, asserting `reasoning_effort == "none"`. Timeout and output cap assertions unchanged.
     - Leave every Google, Fireworks and other provider test as is (they set the provider explicitly).
  2. `src/mcp_auditor/config.py`: `provider: str = "openai"`, and `_PROVIDERS["openai"]` gets `reasoning="none"` (`accepted_reasoning` unchanged). Nothing else in the module changes.
  3. Living docs, exactly as listed under *Files to modify* in this plan: `.env.example` (provider list, `MCP_AUDITOR_PROVIDER=openai`, `gpt-6-luna` override examples, reasoning comment and `# MCP_AUDITOR_REASONING=none`, `OPENAI_API_KEY` first), `README.md` (quick start key and API keys page comment, CVE benchmark prerequisite, environment table, paragraph under the table, *Safety* paragraph sentence on OpenAI's 30-day abuse-monitoring retention), `CONTRIBUTING.md` (eval key sentence, probe section untouched), `CLAUDE.md` Commands (`run_evals` and `run_judge_eval`: `OPENAI_API_KEY by default`), `CHANGELOG.md` `[Unreleased]` (*Added* provider entry at `none`, new first **Breaking.** bullet under *Changed* with prices, the `MCP_AUDITOR_PROVIDER=google` fallback, the failing configurations, and ADR 021; the Gemini default bullet stays).
     - The API keys page URL `platform.openai.com/api-keys` is settled in the due diligence record.
     - Follow the user's writing preferences in all prose: no em dashes, avoid semicolons.
  4. Workflows: the four `GOOGLE_API_KEY: ${{ secrets.GOOGLE_API_KEY }}` lines (`evals.yml` lines ~32 and ~54, `eval-command.yml` lines ~102 and ~109) become `OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}`. Nothing else in the workflows changes.
  - Do not touch `adapters/llm.py`, `evals/`, `docs/adr/`, past plans, or the local `.env`.
- **Test**:
  - `test_default_settings`: red before (provider `google`, model `gemini-3.5-flash-lite`), green after with `openai`, `gpt-6-luna`, `none`.
  - `test_openai_resolves_luna_at_reasoning_none_by_default`: red before (`medium`), green after.
  - `test_openai_builds_luna_at_reasoning_none`: red before (`medium`), green after.
  - The rest of the unit suite stays green unchanged.
- **Verify**:
  - `uv run pytest tests/unit` all green, then `uv run pytest` all green (the Docker test may skip).
  - `uv run ruff check .` and `uv run ruff format --check .` clean.
  - `uv run pyright` with 0 errors.
  - `grep -rn "GOOGLE_API_KEY" .github/workflows` prints nothing.
  - `grep -rn "medium" README.md .env.example CHANGELOG.md` shows no remaining claim that `openai` defaults to `medium`.
