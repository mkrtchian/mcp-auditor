# Contributing

Thanks for considering a contribution. This document explains how to get started and what to expect.

## Setup

```bash
git clone https://github.com/mkrtchian/mcp-auditor.git
cd mcp-auditor
uv sync                                # install runtime + dev dependencies
uv run pytest                          # should be green before you touch anything
```

You'll need Python 3.13+. The project uses [uv](https://docs.astral.sh/uv/) for dependency management. Don't add a `requirements.txt`. Docker is only needed for the CVE benchmark (below), not for the tests or the regular evals.

```bash
uv run pytest tests/unit               # unit tests
uv run pytest tests/integration        # integration tests
uv run ruff check .                    # lint
uv run ruff format .                   # format
uv run pyright                         # type-check
uv run python -m evals.run_evals       # e2e evals (requires API key)
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

Evals don't run automatically on every pull request: they need an API key, and pull requests from forks or Dependabot can't read repository secrets. A maintainer can run them on demand by commenting on the PR:

- `/eval` runs the judge isolation eval only (fast).
- `/eval full` also runs the e2e evals (slower, more API calls).

The workflow checks out the PR's head branch, runs the evals against it, and posts the outcome back as a comment. The trigger is restricted to repository owners, members, and collaborators.

Pull requests that touch the CVE benchmark (`evals/docker/**`, `evals/cve_*.py`, `evals/run_cve_benchmark.py`, or the deps `pyproject.toml`/`uv.lock`) trigger a deterministic calibration gate. It builds the fixture images and runs `--calibrate` (no API key), and fails if any fixture is dead. The graded detection run is not a gate: it stays on-demand (`/eval` or `workflow_dispatch`), reported not gated.

## Coding, testing, and architecture standards

The project's standards are defined in [`CLAUDE.md`](CLAUDE.md). This file serves as the single source of truth — both for human contributors and for AI-assisted development.

The key points: hexagonal architecture, small pure functions, fakes over mocks. Read the full details there.

## AI-assisted development

If you're using an AI coding agent for non-trivial changes, write a plan in `plans/` before implementation. Naming convention: `YYYY-MM-DD_short_description.md`. The plan gets reviewed and approved before any code is written.

The repo ships two [Claude Code](https://docs.anthropic.com/en/docs/claude-code) skills in `.claude/skills/`:

- `/standards` — reviews uncommitted changes against CLAUDE.md and fixes violations automatically.
- `/commit` — stages changes and creates a conventional commit.

## Architecture decisions

Architecture decisions are documented in `docs/adr/` as immutable ADRs. To change a past decision, write a new ADR that supersedes it.

## What makes a good contribution

- Bug fixes with a regression test.
- New audit categories backed by real-world MCP failure modes.
- Eval improvements — better ground truth, new honeypot scenarios.
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

   Or paste the section by hand — the changelog is the single source of truth for release notes.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
