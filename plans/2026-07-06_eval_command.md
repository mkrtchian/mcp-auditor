# Plan: `/eval` command on pull requests

## Context

The LLM evals (`evals.yml`) do not run on Dependabot PRs: PRs opened by `dependabot[bot]` have no access to Actions secrets, so `GOOGLE_API_KEY` is empty. Two mitigations already landed: (1) `judge-eval` is skipped on those PRs, and (2) a `workflow_dispatch` trigger lets a maintainer run the evals on demand. But `workflow_dispatch` lives in the Actions tab and forces re-selecting the branch every time.

This plan adds a trigger **from the PR itself**: commenting `/eval` (or `/eval full`) runs the evals against the PR's HEAD branch. The `issue_comment` event is triggered by the comment author (a maintainer), so secrets become available again.

Load-bearing finding uncovered while scoping: `evals/run_judge_eval.py::main()` computes `report["passed"]` (F1 above threshold) but never calls `raise SystemExit(1)`, unlike `run_evals.py`. Without a fix, an `/eval` running judge-eval would always report green even on an F1 regression, which would make the check meaningless. The plan therefore includes this one-line fix.

## Approach

A dedicated `issue_comment` workflow, separate from `evals.yml`: the trigger type, the checkout (PR HEAD), the command parsing, and the feedback differ too much to share cleanly. The ~5 install lines (uv/python/deps) are duplicated with `evals.yml`: accepted duplication (three similar lines beat a premature abstraction, per the project standards), no reusable-workflow extraction for now.

Action pins (`actions/checkout@v4`, `astral-sh/setup-uv@v4`) match `evals.yml` on purpose. Newer majors exist (checkout v7, setup-uv v7), but the just-added Dependabot `github-actions` ecosystem will bump them repo-wide together, so this file stays on v4 rather than diverging from `evals.yml`.

Decisions:
- **Surface**: `/eval` = judge-eval only (cheap); `/eval full` = judge-eval + e2e.
- **Authorization**: `author_association` in {OWNER, MEMBER, COLLABORATOR}.
- **PR scope**: no restriction on the PR author. The maintainer takes responsibility for reviewing before typing `/eval` (accepted risk, see Edge cases).

## Files to modify

### 1. `.github/workflows/eval-command.yml` (new)

Workflow triggered on `issue_comment`.

```yaml
name: Eval command

on:
  issue_comment:
    types: [created]

permissions:
  contents: read
  issues: write
  pull-requests: write

concurrency:
  group: eval-command-${{ github.event.issue.number }}
  cancel-in-progress: true

jobs:
  eval:
    if: >-
      github.event.issue.pull_request &&
      startsWith(github.event.comment.body, '/eval') &&
      contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)
    runs-on: ubuntu-latest
    steps:
      - name: Parse command
        id: cmd
        env:
          BODY: ${{ github.event.comment.body }}
        run: |
          first=$(printf '%s' "$BODY" | head -n1 | tr -d '\r' | sed 's/[[:space:]]*$//')
          case "$first" in
            "/eval") echo "mode=judge" >> "$GITHUB_OUTPUT" ;;
            "/eval full") echo "mode=full" >> "$GITHUB_OUTPUT" ;;
            *) echo "mode=none" >> "$GITHUB_OUTPUT" ;;
          esac

      - name: Acknowledge command
        if: steps.cmd.outputs.mode != 'none'
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          gh api -X POST \
            repos/${{ github.repository }}/issues/comments/${{ github.event.comment.id }}/reactions \
            -f content=eyes

      - name: Checkout PR head
        if: steps.cmd.outputs.mode != 'none'
        uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.issue.number }}/head

      - name: Install uv
        if: steps.cmd.outputs.mode != 'none'
        uses: astral-sh/setup-uv@v4
        with:
          enable-cache: true

      - name: Set up Python
        if: steps.cmd.outputs.mode != 'none'
        run: uv python install 3.13

      - name: Install dependencies
        if: steps.cmd.outputs.mode != 'none'
        run: uv sync --dev

      - name: Run judge eval
        if: steps.cmd.outputs.mode == 'judge' || steps.cmd.outputs.mode == 'full'
        env:
          GOOGLE_API_KEY: ${{ secrets.GOOGLE_API_KEY }}
        run: uv run python -m evals.run_judge_eval

      - name: Run e2e eval
        if: steps.cmd.outputs.mode == 'full'
        env:
          GOOGLE_API_KEY: ${{ secrets.GOOGLE_API_KEY }}
        run: uv run python -m evals.run_evals --runs 2 --budget 7

      - name: Report result
        if: always() && steps.cmd.outputs.mode != 'none'
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          MODE: ${{ steps.cmd.outputs.mode }}
        run: |
          run_url="${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
          if [ "${{ job.status }}" = "success" ]; then
            gh pr comment ${{ github.event.issue.number }} \
              --body "Evals passed ($MODE). [Run details]($run_url)"
          else
            gh pr comment ${{ github.event.issue.number }} \
              --body "Evals failed ($MODE). [Run details]($run_url)"
          fi
```

Note: `MODE` is passed as a step `env` var (rather than inline `${{ }}` in the shell) so it can be interpolated into the comment body.

Design points:
- **Shell injection**: the comment body (`github.event.comment.body`) is **never** interpolated as `${{ }}` inside a `run`. It flows through the `BODY` env var (the Parse step). This is the standard mitigation for command injection via user-controlled content, essential for a security repo.
- **Strict parse**: only `/eval` or `/eval full` (first line, trailing whitespace stripped) trigger a run. `/evaluation`, `/eval xyz` → `mode=none`, zero LLM cost (install and eval steps are guarded on `mode != 'none'`). The job-level `startsWith` is a coarse pre-filter; the Parse step decides.
- **Feedback**: an immediate `eyes` reaction (acknowledgement), then a result comment at the end (`if: always()`) with the job status and a link to the run. Needed because an `issue_comment` workflow produces **no** status check on the PR.
- **Concurrency**: a re-issued `/eval` cancels the previous run for the same PR.
- **Permissions**: `contents: read` (checkout) + `issues: write` + `pull-requests: write`. A PR conversation comment is an *issue comment*: the `eyes` reaction (`issues/comments/{id}/reactions`) and the `gh pr comment` endpoints each accept **either** the `issues` **or** the `pull-requests` write scope. Granting both is belt-and-suspenders robustness, not a strict requirement of one over the other.

### 2. `evals/run_judge_eval.py`

Make the process fail when the F1 threshold is not met. In `main()` (currently lines 49-54), after `_print_summary(report)`:

```python
def main() -> None:
    report = asyncio.run(run_judge_eval())
    output_path = Path(DEFAULT_REPORT_PATH)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2))
    _print_summary(report)
    if not report["passed"]:
        raise SystemExit(1)
```

Symmetric with `run_evals.py`, which already does `raise SystemExit(1)`.

## What stays unchanged

- `.github/workflows/evals.yml`: unchanged. Positive side effect of fix (2): its `judge-eval` job now genuinely gates PRs/pushes to main (it did not before).
- `.github/workflows/ci.yml`, `publish.yml`, `dependabot.yml`: untouched.
- Eval logic, metric computation, prompts, `domain/`, `graph/`: no change. Fix (2) only touches the runner's exit code, not the `passed` computation.
- The JSON report format (`report["passed"]` already exists).

## Edge cases

- **Comment on an issue (not a PR)**: `github.event.issue.pull_request` is null → job not triggered.
- **Unauthorized author** (CONTRIBUTOR, NONE): `author_association` off the list → job not triggered. Critical point: `issue_comment` fires for **any** comment by anyone; this guard is the only barrier against a third party triggering a run. Caveat: `author_association` is a *relationship*, not a permission level, so `COLLABORATOR` also matches read-only/triage collaborators, not strictly write-access ones. Fine for a solo repo; if strict write-access gating is ever needed, check the actor's permission via the API instead.
- **Malformed command** (`/evaluation`, `/eval please`): `mode=none`, only Parse + guard run, zero LLM calls.
- **Untrusted PR code runs with the secret**: running the evals executes the PR HEAD code (`evals/`, deps) with `GOOGLE_API_KEY` present. A malicious PR could modify `evals/run_judge_eval.py` to exfiltrate the key. Risk **accepted** (project decision): the maintainer reviews the PR before typing `/eval`, and the `author_association` guard stops a third party from triggering. For the real use case (Dependabot PRs) the risk is low: Dependabot only touches `uv.lock`/`pyproject.toml`, never `evals/` code.
- **Workflow read from the default branch**: an `issue_comment` workflow always runs the version present on `main`, never the PR's. Consequence: `/eval` only works once `eval-command.yml` is merged to `main` (it cannot be exercised on the PR that introduces it). Security property in passing: a PR cannot alter the trigger.
- **`/eval full`: judge fails before e2e**: if judge-eval fails (SystemExit 1), the e2e step is skipped (no `if: always()` on it), the job is red, and the result comment says "failed". Intended (fail-fast, no e2e cost if the judge already breaks).

## Test scenarios

No automated tests. GitHub Actions workflows are not unit-testable in this repo (outside the hexagon), validated manually (see Verification). The Python change (fix 2) is a one-line `SystemExit`, left untested for parity with `run_evals.py`, whose `SystemExit` has no test either (`evals/` sits outside the hexagon, where exhaustive unit testing does not apply).

## Verification

```bash
uv run ruff check .            # the one-line Python change
uv run ruff format --check .
python -c "import yaml; yaml.safe_load(open('.github/workflows/eval-command.yml'))"  # YAML valid
```

Manual end-to-end validation (after `eval-command.yml` is merged to `main`):
1. Open any PR (or wait for a Dependabot PR).
2. Comment `/eval` → check the `eyes` reaction, then a "Evals passed/failed (judge)" comment with a link to the run.
3. Comment `/eval full` → check the e2e step runs too.
4. Comment `/eval please` → check no eval runs (job green, no result comment).
5. Bonus: have a non-collaborator account comment `/eval` → check nothing triggers.

## Implementation steps

### Step 1: `/eval` command workflow + non-zero exit for judge eval

Single atomic step. The whole plan is one new workflow file plus a one-line behavior fix in a Python runner. Well within context budget (2 files modified).

**Files**:
- `.github/workflows/eval-command.yml` (new)
- `evals/run_judge_eval.py` (modify `main()`)

**Do**:

1. **Fix `evals/run_judge_eval.py`** — in `main()` (currently lines 49-54), after `_print_summary(report)`, add:
   ```python
       if not report["passed"]:
           raise SystemExit(1)
   ```
   Symmetric with `run_evals.py`. This is the load-bearing fix: without it `/eval` running judge-eval would always show green even on an F1 regression. `run_judge_eval()` and `_build_report()` already compute `report["passed"]` — no other change to the runner.

2. **Create `.github/workflows/eval-command.yml`** — copy the YAML verbatim from the plan's "Files to modify → 1." block. Load-bearing details that must not drift:
   - `on: issue_comment: types: [created]`.
   - `permissions: contents: read` + `issues: write` + `pull-requests: write` (a PR conversation comment is an issue comment; the reaction and `gh pr comment` endpoints accept either the `issues` or `pull-requests` write scope, both granted for robustness).
   - `concurrency` group keyed on `github.event.issue.number`, `cancel-in-progress: true`.
   - Job-level `if`: PR guard (`github.event.issue.pull_request`), `startsWith(...comment.body, '/eval')`, and `author_association` in `["OWNER","MEMBER","COLLABORATOR"]`.
   - Parse step reads the body via the `BODY` **env var**, never inline `${{ }}` in the shell (command-injection mitigation, essential for a security repo). First line only, trailing whitespace stripped; exact match `"/eval"` → `mode=judge`, `"/eval full"` → `mode=full`, else `mode=none`.
   - Every subsequent step guarded on `steps.cmd.outputs.mode != 'none'` (or the mode-specific value) so a malformed command incurs zero LLM cost.
   - `eyes` reaction via `gh api` for acknowledgement.
   - Checkout `refs/pull/${{ github.event.issue.number }}/head`.
   - Install: `astral-sh/setup-uv@v4` (enable-cache), `uv python install 3.13`, `uv sync --dev`.
   - Judge step runs on `mode == 'judge' || mode == 'full'`; e2e step (`uv run python -m evals.run_evals --runs 2 --budget 7`) runs on `mode == 'full'` only (no `if: always()` → skipped if judge fails, fail-fast).
   - Report step `if: always() && mode != 'none'`, `MODE` passed as env, comments passed/failed with a link to the run URL.

**Test**: none automated. The workflow is not unit-testable (outside the hexagon); the Python change is left untested for parity with `run_evals.py` (see Test scenarios). Validated by YAML parse + manual end-to-end after merge to `main` (the `issue_comment` trigger only runs from the default branch, so it cannot be exercised on the introducing PR).

**Verify**:
```bash
uv run ruff check .          # the one-line Python change
uv run ruff format --check .
python -c "import yaml; yaml.safe_load(open('.github/workflows/eval-command.yml'))"  # YAML valid
```
Expect: ruff clean, YAML loads without error.
