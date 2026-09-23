# Contributing

Thanks for considering a contribution. This document explains how to get started and what to expect.

## Setup

```bash
git clone https://github.com/mkrtchian/mcp-auditor.git
cd mcp-auditor
uv sync                                # install runtime + dev dependencies
uv run pytest                          # should be green before you touch anything
```

You'll need Python 3.13+. The project uses [uv](https://docs.astral.sh/uv/) for dependency management. Don't add a `requirements.txt`. Docker is needed to audit a server under the default regime, which launches it in a container, and by the CVE benchmark (below). One integration test exercises that confined path and skips when Docker does not answer. The unit tests and the regular evals need none.

```bash
uv run pytest tests/unit               # unit tests
uv run pytest tests/integration        # integration tests
uv run ruff check .                    # lint
uv run ruff format .                   # format
uv run pyright                         # type-check
uv run python -m evals.run_evals       # e2e evals (requires API key)
uv run python -m evals.run_evals --record-baseline  # record the e2e baseline (clean tree, see below)
uv run python -m evals.run_evals --ungated          # e2e evals on the floors alone, at any conditions
uv run python -m evals.run_judge_eval  # judge isolation eval (requires API key)
```

Evals run real LLM calls and require an API key. Copy `.env.example` to `.env` and set `GOOGLE_API_KEY` (default provider) or `ANTHROPIC_API_KEY`. Unit and integration tests don't need any key.

### CVE benchmark

A separate benchmark runs the auditor against real, pinned-vulnerable MCP servers in throwaway Docker containers. It needs Docker running plus an API key. Build the images once, confirm each fixture is live (no LLM), then run the graded audit:

```bash
docker compose -f evals/docker/compose.yml build      # one-time, builds the pinned vulnerable-server images
uv run python -m evals.run_cve_benchmark --calibrate  # no LLM, checks each fixture is live
uv run python -m evals.run_cve_benchmark --runs 3 --budget 10  # graded run
```

See the README for the reproducibility rationale and the safety note (deliberately-vulnerable images, run on a non-sensitive host).

### Running evals on a pull request

The judge isolation eval runs automatically on a pull request that touches `src/**`, `evals/**`, a honeypot server, or `pyproject.toml`, and it fails the check when the judge falls below its F1 threshold. It needs an API key from repository secrets: a Dependabot pull request is skipped outright, and a pull request from a fork triggers the job but can't read the key, so its run fails rather than being skipped. The e2e evals never run automatically on a pull request. They run on main after merge, where they gate the build. A maintainer can run either on demand by commenting on the PR:

- `/eval` runs the judge isolation eval only (fast).
- `/eval full` also runs the e2e evals (slower, more API calls).

The workflow checks out the PR's head branch, runs the evals against it, and posts the outcome back as a comment. The trigger is restricted to repository owners, members, and collaborators.

Pull requests that touch the CVE benchmark (`evals/docker/**`, `evals/cve_*.py`, `evals/run_cve_benchmark.py`, the deps `pyproject.toml`/`uv.lock`, or the workflow itself) trigger a deterministic calibration gate. It builds the fixture images and runs `--calibrate` (no API key), and fails if any fixture is dead, minus any target marked CI-unstable. Today that is CVE-2025-68143, whose `git_diff_staged` hangs on GitHub-hosted runners and stays covered by local calibration. The graded detection run is not a gate and has no CI workflow: it runs locally (`uv run python -m evals.run_cve_benchmark`), reported not gated.

### Recording an e2e baseline

The e2e evals gate against `evals/baselines/honeypot_e2e.json` once it exists, cell by cell, with an absolute floor per metric ([ADR 016](docs/adr/016-eval-gate-governance.md)). Until then the absolute thresholds stand. `uv run python -m evals.run_evals --record-baseline` writes that file, and it refuses to start on a tree with tracked modifications. The first recording is exploratory: only the floors gate. A second recording at the same commit confirms it when it classifies the same cells as stable, and from then on a flip on a stable cell is replayed and fails the build when it reproduces. Commit the file by hand. CI never records.

Record under the provider and model settings CI resolves, that is with no `MCP_AUDITOR_PROVIDER`, `MCP_AUDITOR_MODEL` or `MCP_AUDITOR_JUDGE_MODEL` override in `.env` or the environment that differs from the defaults. CI sets only the API key, so a baseline recorded under an override makes every CI run not comparable.

`--ungated` runs the e2e evals on the floors alone, with no condition check and no baseline comparison, for a cheap local run at other conditions (fewer runs, a smaller budget, another model). It is never used in CI and cannot be combined with `--record-baseline`.

## Coding, testing, and architecture standards

The project's standards are defined in [`CLAUDE.md`](CLAUDE.md). This file serves as the single source of truth, both for human contributors and for AI-assisted development.

The key points: hexagonal architecture, small pure functions, fakes over mocks. Read the full details there.

## AI-assisted development

If you're using an AI coding agent for non-trivial changes, write a plan in `plans/` before implementation. Naming convention: `YYYY-MM-DD_short_description.md`. The plan gets reviewed and approved before any code is written.

The repo ships two [Claude Code](https://docs.anthropic.com/en/docs/claude-code) skills in `.claude/skills/`:

- `/standards` reviews uncommitted changes against CLAUDE.md and fixes violations automatically.
- `/commit` stages changes and creates a conventional commit.

## Architecture decisions

Architecture decisions are documented in `docs/adr/` as immutable ADRs. To change a past decision, write a new ADR that supersedes it.

## What makes a good contribution

- Bug fixes with a regression test.
- New audit categories backed by real-world MCP failure modes.
- Eval improvements: better ground truth, new honeypot scenarios. A ground truth change follows the discipline in [ADR 016](docs/adr/016-eval-gate-governance.md): revisions go by rubric, never cell by cell.
- Documentation fixes.

If you're unsure whether something fits, open an issue first.

User-facing changes (new flags, behavior changes, notable fixes) should come with an entry under the `[Unreleased]` section of [`CHANGELOG.md`](CHANGELOG.md), in the same pull request.

## Releasing (maintainers)

Publishing is automated: pushing a `v*` tag triggers `publish.yml`, which builds the package and publishes it to PyPI via trusted publishing. The manual steps are:

1. Make sure `main` is green: `uv run pytest && uv run ruff check . && uv run pyright`.
2. In `CHANGELOG.md`, rename the `[Unreleased]` section to the new version with today's date, add a fresh empty `[Unreleased]` section above it, and update the comparison links at the bottom.
3. Bump `version` in `pyproject.toml`, then run `uv lock` so the lock file picks it up.
4. Commit and push: `git commit -m "chore(release): vX.Y.Z"`.
5. Tag and push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z`. This triggers the PyPI publication.
6. Create the GitHub release, using the changelog section for that version as the body:

   ```bash
   gh release create vX.Y.Z --title "vX.Y.Z" \
     --notes-file <(awk '/^## \[X.Y.Z\]/{f=1; next} f && (/^## \[/ || /^\[.*\]: http/){exit} f' CHANGELOG.md)
   ```

   Or paste the section by hand. The changelog is the single source of truth for release notes.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
