# README follow-ups: word cap, living pages, timeout example, PyPI links

## Context

The README was cut to a short version in `881a257`, with two new living pages, `docs/usage.md` and `docs/evals.md`. Four code-side consequences were left for after the docs commit:

1. `CLAUDE.md` says the README's prose stays under 2,500 words, tables and code blocks aside, but nothing checks it. The README grew from 2,668 to 8,132 words without anyone noticing, so the cap needs a test that fails.
2. The retired-word scan reads a closed list of whole Markdown files (`_WHOLE_FILES` in `tests/unit/support/retired_word_scan.py`). The two new pages are living text and are not in it, so a retired word written there goes unseen. A dry run of the scan with both pages added finds no violation and no stale entry today.
3. `docs/usage.md` documents `MCP_AUDITOR_TOOL_CALL_TIMEOUT` (default 60, read by `config.py` through the `MCP_AUDITOR_` prefix), but `.env.example` lists every other variable of that table and not this one.
4. `pyproject.toml` declares `readme = "README.md"`, so the README is the PyPI page. PyPI resolves no relative link: today the demo GIF (`docs/demo/demo.gif`) is broken there, and the short README now leans on relative links to `docs/usage.md`, `docs/evals.md`, the rules, the ADRs and `evals/cve/holdout_runs/`. The links stay relative in the repository (they work on GitHub and in a checkout), and the package build rewrites them to absolute links pinned on the release tag.

This plan precedes the 0.5.0 release. It changes no instrument, fixture, baseline, rule, prompt or behavior of the auditor.

## Approach

Items 1 to 3 are small and independent. Item 4 uses `hatch-fancy-pypi-readme`, a hatchling metadata hook: the project already builds with `hatchling`, and the hook builds the `readme` metadata from fragments of files, then applies regex substitutions in order, then replaces `$HFPR_VERSION` with the package version. Checked in the source of version 25.1.0 (`_builder.build_text`, `_substitutions.Substituter`): each substitution is a Python `re.sub(pattern, replacement, text)`, and `$HFPR_VERSION` is replaced after every substitution has run, so it can sit inside a replacement. Release tags are `v` plus the version (`v0.1.0` to `v0.4.0`, `publish.yml` triggers on `v*`), so `v$HFPR_VERSION` names the tag of the build's version.

Rewriting rules, decided in discussion (2026-11-21):

| README link | Rewritten to |
|---|---|
| Image with a relative target `![alt](path)` | `https://raw.githubusercontent.com/mkrtchian/mcp-auditor/v<version>/path` (a `blob` URL serves an HTML page, not the image) |
| Relative link to a directory, target ending in `/` | `https://github.com/mkrtchian/mcp-auditor/tree/v<version>/path/` |
| Any other relative link, anchor included (`docs/usage.md#confinement`) | `https://github.com/mkrtchian/mcp-auditor/blob/v<version>/path` |
| In-page anchor `[text](#anchor)` | unchanged: PyPI renders with `readme-renderer[md]==46.0`, which gives each heading a `user-content-` id and rewrites `href="#x"` to `#user-content-x`. Rendering the README at `HEAD` with that version on 2026-11-21, every in-page link (`#measurement`, `#example-auditing-a-real-server`) resolves to a heading id. |
| Absolute link (`https://…`), badges included | unchanged |

## Files to modify

### `tests/unit/project/test_readme_policy.py`

Add the word cap:

```python
PROSE_WORD_CAP = 2500


def test_the_readme_prose_stays_under_the_word_cap():
    words = _prose_words(README.read_text())

    assert words <= PROSE_WORD_CAP, f"README.md has {words} words of prose, the cap is {PROSE_WORD_CAP}"


def _prose_words(markdown: str) -> int:
    ...
```

`_prose_words` counts whitespace-separated tokens on the lines that are neither inside a fenced code block nor a table row:
- a fence is a line whose stripped form starts with three backticks, and it toggles the in-block state; the fence lines themselves are not counted;
- a table row is a line whose stripped form starts with `|`.

Headings, list items, link and image syntax all count as written (`[Measurement](#measurement)` is one token). The README at `HEAD` counts 2,128 under this definition, and `wc -w` gives 2,684. Place `_prose_words` below the tests, with the existing private helpers.

Test-first: the cap must be shown red on the long README before it is shown green on the short one. Run the new test with the README of `40cded1` (8,132 words by `wc -w`) swapped in, `git show 40cded1:README.md > README.md`, see it fail with the count in the message, then `git checkout README.md` and see it pass. Never commit the swapped file.

### `tests/unit/support/retired_word_scan.py`

Add `"docs/usage.md"` and `"docs/evals.md"` to `_WHOLE_FILES`, after `"docs/glossary.md"`. Add both pages to the list of living text in the module docstring. `evals/README.md` is already covered by `_CODE_ROOTS` and needs nothing. No new test: `test_living_files_use_no_retired_word` in `tests/unit/project/test_glossary.py` reads the list, and the dry run found the two pages clean.

### `.env.example`

Add, after the OpenRouter providers block and before the API keys:

```
# Tool call timeout in seconds (optional, default 60). A tool whose calls time out 3 times in a row is no longer called.
# MCP_AUDITOR_TOOL_CALL_TIMEOUT=60
```

The wording follows the row of `docs/usage.md`. `.env.example` is in `_WHOLE_FILES`, so the scan reads the new lines.

### `pyproject.toml`

- In `[project]`, replace `readme = "README.md"` with `dynamic = ["readme"]`. hatchling refuses a field that is both set and dynamic.
- `[build-system]`: `requires = ["hatchling", "hatch-fancy-pypi-readme==25.1.0"]`. Pinned exactly, decided in discussion: the release build runs outside `uv.lock` under build isolation, so a lower bound would let the published page come from a version the tests never ran, and a new release of the hook would run unseen in the job that holds the publishing token.
- `[dependency-groups] dev`: add `"hatch-fancy-pypi-readme==25.1.0"`, the same pin, for the test below, which runs the hook's command-line renderer. Then `uv lock`, and commit `uv.lock` with it.
- Add the hook's configuration, regexes in TOML literal strings (single quotes) so backslashes stay as written, substitutions in the order of the table above (images first, so the link rules never see an image; directories before the generic file rule). Every rule skips a target that is absolute or starts with `#`:

```toml
[tool.hatch.metadata.hooks.fancy-pypi-readme]
content-type = "text/markdown"

[[tool.hatch.metadata.hooks.fancy-pypi-readme.fragments]]
path = "README.md"

# The README's links stay relative for GitHub and a checkout. PyPI resolves no relative path, so
# the build points each at the release tag, which is `v` plus the version. In-page anchors work there.
[[tool.hatch.metadata.hooks.fancy-pypi-readme.substitutions]]
pattern = '(!\[[^\]]*\]\()(?!https?://|#)([^)\s]+)\)'
replacement = '\1https://raw.githubusercontent.com/mkrtchian/mcp-auditor/v$HFPR_VERSION/\2)'

[[tool.hatch.metadata.hooks.fancy-pypi-readme.substitutions]]
pattern = '(\[[^\]]*\]\()(?!https?://|#)([^)\s]+/)\)'
replacement = '\1https://github.com/mkrtchian/mcp-auditor/tree/v$HFPR_VERSION/\2)'

[[tool.hatch.metadata.hooks.fancy-pypi-readme.substitutions]]
pattern = '(\[[^\]]*\]\()(?!https?://|#)([^)\s]+)\)'
replacement = '\1https://github.com/mkrtchian/mcp-auditor/blob/v$HFPR_VERSION/\2)'
```

A badge, `[![PyPI version](https://img.shields.io/…)](https://pypi.org/…)`, is left alone: the image rule's lookahead rejects the absolute inner target, the link rules starting at the outer `[` stop at the inner `](` (`[^\]]*` cannot cross the image's `]`) and reject that absolute target, and no link rule ever reaches the outer target, which no `[…](` immediately precedes.

### `tests/unit/project/test_pypi_readme.py` (new), with `tests/unit/project/support/test_pypi_readme_given.py`

The tests run the hook's own renderer, `python -m hatch_fancy_pypi_readme <pyproject>`, a public command-line entry point that loads the configuration of `pyproject.toml`, resolves fragments against the working directory and prints the rendered text with the version `42.0` (and exits 1 with a message on a configuration error, for instance a `readme` that is not dynamic). It is run with `sys.executable` and `subprocess.run(..., check=True, capture_output=True, text=True, cwd=...)`, so the test needs no private import of the hook.

Given module:
- `rendered(project_dir: Path) -> str`: runs the renderer with `cwd=project_dir` on `project_dir / "pyproject.toml"`, returns stdout.
- `a_project_with_readme(tmp_path: Path, readme: str) -> Path`: copies the repository's `pyproject.toml` into `tmp_path`, writes `readme` as `README.md`, returns `tmp_path`.
- `LINK_KINDS_README`: a small fixture README carrying one of each kind: a relative image, an in-page anchor, a directory link, a file link with an anchor, a badge (image link inside a link, both absolute), and a plain absolute link.
- `link_targets(markdown: str) -> list[str]`: the targets of every `](…)` in order.

Tests (asserts inline, they are one-liners):
- `test_a_relative_image_is_served_raw_from_the_release_tag`: the fixture's image target becomes `https://raw.githubusercontent.com/mkrtchian/mcp-auditor/v42.0/<path>`.
- `test_an_in_page_anchor_is_left_as_written`: `#measurement` stays `#measurement`.
- `test_a_directory_link_points_at_the_tree_of_the_release_tag`: `evals/cve/holdout_runs/` becomes `…/tree/v42.0/evals/cve/holdout_runs/`.
- `test_a_file_link_keeps_its_anchor_on_the_release_tag`: `docs/usage.md#confinement` becomes `…/blob/v42.0/docs/usage.md#confinement`.
- `test_absolute_links_and_badges_are_left_as_written`: the badge's two targets and the plain absolute link are unchanged.
- `test_the_rendering_changes_nothing_but_link_targets`: on the fixture, the rendered text with every `](…)` target blanked equals the fixture README with every target blanked (compared after `rstrip`, since the renderer prints a trailing newline).
- `test_every_link_of_the_real_readme_is_absolute_on_pypi`: on the repository itself (`cwd` the repository root), every target of the rendered README starts with `https://` or `#`. This is the guard that catches a future relative link of a form the rules miss.

Run the renderer once per project with a module-scoped pytest fixture where several tests read the same rendering. `tmp_path` is function-scoped, so the module-scoped fixture of the fixture README takes its directory from `tmp_path_factory.mktemp(...)`.

### `CLAUDE.md`

In the Workflow bullet "Update the living docs", the sentence on `README.md` names the guard: "keep its prose under 2,500 words, tables and code blocks aside, which `tests/unit/project/test_readme_policy.py` checks."

### `CONTRIBUTING.md`

In "Releasing (maintainers)", one sentence before the numbered steps: the build rewrites the README's relative links into absolute links on the tag `v` plus the `pyproject.toml` version (the `fancy-pypi-readme` hook in `pyproject.toml`), so the tag of step 7 must be exactly that, and links in `README.md` stay relative.

### `CHANGELOG.md`

Under `[Unreleased]`, in `### Fixed` (create it if absent, after the sections already there in the file's order): the README's links and demo GIF now work on the PyPI page, the package build pointing them at the release on GitHub.

## What stays unchanged

- The README's text and links: every link stays relative in the repository. The note "This README describes the `main` branch" and its `uvx --from git+…` command stay until the release.
- `docs/usage.md`, `docs/evals.md`, `evals/README.md`, the rules, the logs, ADRs and plans.
- `publish.yml`: `uv build` already runs the metadata hook, no step changes.
- The version in `pyproject.toml` (bumped at the release, not here).
- `tests/unit/support/retired_words.py` and its exemptions: adding "nuisance run" belongs to the separate renaming plan.
- The two existing tests of `test_readme_policy.py`.

## Edge cases

- A local `uv build` before the release tag exists points the links at `v0.4.0`, where the new pages do not exist. Only a published build matters, and it is built from its own tag.
- A link written inside a fenced code block of the README would be rewritten too: the substitutions do not know Markdown structure. The README has none today, and an absolute URL inside a code example would still read correctly.
- Reference-style links (`[text][ref]` with `[ref]: path`) and HTML `<img>` tags are not rewritten. The README uses neither. The real-README test catches neither, so this is stated here and in nothing else.
- A target containing whitespace or a closing parenthesis is not matched (`[^)\s]+`). GitHub-style relative paths in this repository contain neither.
- An image inside a link with relative targets (`[![alt](img)](page)`): the image rule rewrites the inner target, but no link rule reaches the outer one (for the reason given under the badge above), so `page` stays relative. Checked by running the substitutions on that line. Not present today, and `test_every_link_of_the_real_readme_is_absolute_on_pypi` fails the day one is written.

## Verification

- `uv run pytest tests/unit/project -n 0` while writing, then the short loop.
- The red-then-green check of the word cap described above, on the README of `40cded1`.
- `uv build -o <scratchpad>/dist`, then `unzip -p <scratchpad>/dist/*.whl '*/METADATA'`: the long description must carry `https://raw.githubusercontent.com/mkrtchian/mcp-auditor/v0.4.0/docs/demo/demo.gif` and no `](docs/`, `](evals/` or other relative path target (`](#…` stays). Then `uvx twine check <scratchpad>/dist/*` must pass. Build into the scratchpad, never into the repository's `dist/`.
- Closing check: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`.

## Due diligence record

What the due diligence pass concluded, on 2026-11-21, about each external fact this plan cites or defers. Later passes, the implementation-phase fact check included, read it. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: each substitution is `re.sub(pattern, replacement, text)` applied in configuration order, and `$HFPR_VERSION` is replaced after every substitution (verified against the 25.1.0 source, `_builder.build_text` and `_substitutions.Substituter`, from the uv cache)
- SETTLED: `[tool.hatch.metadata.hooks.fancy-pypi-readme]` with `content-type`, `fragments` (`path`, resolved against the working directory) and `substitutions` (`pattern`, `replacement`) (verified against the 25.1.0 source, `_config.py`, `_fragments.py`)
- SETTLED: `python -m hatch_fancy_pypi_readme <pyproject>` prints the rendering with version `42.0`, exits 1 when `readme` is not in `project.dynamic`, and reads a `hatch.toml` of the working directory when one exists (verified against the 25.1.0 source, `__main__.py`, `_cli.py`, and the project README)
- SETTLED: `dynamic = ["readme"]` with no static `readme`: hatchling refuses a field both statically defined and listed in `project.dynamic` (verified against the cached hatchling source, `metadata/core.py`)
- SETTLED: `docs/demo/demo.gif` exists at tag `v0.4.0`, so the local-build check of the plan's Verification finds a live raw URL (verified with `git cat-file` on the tag)
- OPEN (unverified): `raw.githubusercontent.com` serves the GIF as an image and a `blob` URL serves an HTML page. Common knowledge, not checked against a live source.

## Implementation steps

Verification commands (from `CLAUDE.md`): `uv run pytest <test files> -n 0` while a test is red, then the short loop `uv run pytest tests/unit -n auto --maxprocesses 6`, and to close each step `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` (no file argument). Neither step builds a Docker image or runs a command that needs Docker.

### Step 1: README word cap, living pages in the retired-word scan, timeout in `.env.example`

- **Files**:
  - `tests/unit/project/test_readme_policy.py` (modify)
  - `tests/unit/support/retired_word_scan.py` (modify)
  - `.env.example` (modify)
  - `CLAUDE.md` (modify)
- **Do**:
  1. Test first, in `tests/unit/project/test_readme_policy.py`: add `PROSE_WORD_CAP = 2500` beside `OVERCLAIMS`, the test `test_the_readme_prose_stays_under_the_word_cap` exactly as in the plan (assert message `f"README.md has {words} words of prose, the cap is {PROSE_WORD_CAP}"`), placed after the two existing tests, and the private helper `_prose_words(markdown: str) -> int` below the tests with the other private helpers (newspaper order). `_prose_words` walks the lines with an in-block flag: a line whose stripped form starts with three backticks toggles the flag and is not counted; a line inside a block is not counted; a line whose stripped form starts with `|` is not counted; every other line adds `len(line.split())`. The two existing tests stay unchanged.
  2. Red-then-green check of the cap: `git show 40cded1:README.md > README.md`, run `uv run pytest tests/unit/project/test_readme_policy.py -n 0` and see the new test fail with the count in its message, then `git checkout README.md` and see it pass (the README at `HEAD` counts 2,128). Never commit the swapped file, and confirm `git status` shows `README.md` unmodified afterwards.
  3. `tests/unit/support/retired_word_scan.py`: add `"docs/usage.md"` and `"docs/evals.md"` to `_WHOLE_FILES`, right after `"docs/glossary.md"`. In the module docstring, add both pages to the list of living text (for instance "the glossary, `docs/usage.md`, `docs/evals.md`, the two rules, ..."), rewrapping the paragraph to the existing width. `evals/README.md` needs nothing (already under `_CODE_ROOTS`).
  4. `.env.example`: after the OpenRouter providers block (`# MCP_AUDITOR_OPENROUTER_PROVIDERS=sail-research`) and its blank line, before `# API keys ...`, add the two lines of the plan followed by a blank line:
     ```
     # Tool call timeout in seconds (optional, default 60). A tool whose calls time out 3 times in a row is no longer called.
     # MCP_AUDITOR_TOOL_CALL_TIMEOUT=60
     ```
     Check the wording against the `MCP_AUDITOR_TOOL_CALL_TIMEOUT` row of `docs/usage.md` and the default in `src/mcp_auditor/config.py`; if either disagrees with "default 60" or "3 times in a row", follow the code and the usage page.
  5. `CLAUDE.md`, Workflow bullet "Update the living docs": replace "keep its prose under 2,500 words, tables and code blocks aside." with "keep its prose under 2,500 words, tables and code blocks aside, which `tests/unit/project/test_readme_policy.py` checks."
- **Test**:
  - `test_the_readme_prose_stays_under_the_word_cap`: red on the README of `40cded1` (message names a count far above 2,500), green on the README at `HEAD`.
  - `test_living_files_use_no_retired_word` in `tests/unit/project/test_glossary.py` (existing, unchanged) stays green with the two pages and the new `.env.example` lines read. If it reports a hit, the fix goes in the page's wording only if the hit is a real retired word; report it rather than adding an exemption.
- **Verify**: `uv run pytest tests/unit/project -n 0` green, then the short loop green, then the closing check (`uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`) green.

### Step 2: README links made absolute on the PyPI page

- **Files**:
  - `tests/unit/project/support/test_pypi_readme_given.py` (new)
  - `tests/unit/project/test_pypi_readme.py` (new)
  - `pyproject.toml` (modify)
  - `uv.lock` (regenerated by `uv lock`)
  - `CONTRIBUTING.md` (modify)
  - `CHANGELOG.md` (modify)
- **Do**:
  1. `pyproject.toml`, dev dependency first so the tests can run the renderer: add `"hatch-fancy-pypi-readme==25.1.0"` to `[dependency-groups] dev`, then run `uv lock` (and `uv sync` if the environment does not pick it up).
  2. Test first. Given module `tests/unit/project/support/test_pypi_readme_given.py`, following the style of `test_workflow_path_filters_given.py` (`REPO_ROOT` from `evals.honeypots`):
     - `rendered(project_dir: Path) -> str`: `subprocess.run([sys.executable, "-m", "hatch_fancy_pypi_readme", str(project_dir / "pyproject.toml")], check=True, capture_output=True, text=True, cwd=project_dir).stdout`.
     - `a_project_with_readme(directory: Path, readme: str) -> Path`: copies `REPO_ROOT / "pyproject.toml"` into `directory`, writes `readme` as `directory / "README.md"`, returns `directory`.
     - `LINK_KINDS_README`: a short Markdown string carrying one of each kind: a relative image (`![demo](docs/demo/demo.gif)`), an in-page anchor (`[Measurement](#measurement)`), a directory link (`[runs](evals/cve/holdout_runs/)`), a file link with an anchor (`[confinement](docs/usage.md#confinement)`), a badge (`[![PyPI version](https://img.shields.io/pypi/v/mcp-auditor)](https://pypi.org/project/mcp-auditor/)`), and a plain absolute link (`[ADR](https://github.com/mkrtchian/mcp-auditor)`), each on its own line with a little prose around.
     - `link_targets(markdown: str) -> list[str]`: `re.findall(r"\]\(([^)]*)\)", markdown)`, the targets of every `](…)` in order.
     - A helper for the "nothing but link targets" test, e.g. `without_link_targets(markdown: str) -> str` replacing every `](…)` target with `]()`, if it reads better than inlining the regex in the test.
  3. Test file `tests/unit/project/test_pypi_readme.py`, asserts inline:
     - a module-scoped pytest fixture that builds the fixture project under `tmp_path_factory.mktemp("pypi_readme")` with `a_project_with_readme(..., given.LINK_KINDS_README)` and returns its rendering (one renderer run for the fixture's six tests);
     - the seven tests of the plan: `test_a_relative_image_is_served_raw_from_the_release_tag`, `test_an_in_page_anchor_is_left_as_written`, `test_a_directory_link_points_at_the_tree_of_the_release_tag`, `test_a_file_link_keeps_its_anchor_on_the_release_tag`, `test_absolute_links_and_badges_are_left_as_written`, `test_the_rendering_changes_nothing_but_link_targets` (compare after `rstrip`), and `test_every_link_of_the_real_readme_is_absolute_on_pypi` (renders `REPO_ROOT`, every target starts with `https://` or `#`). The renderer uses version `42.0`, so expected URLs carry `v42.0`.
     - Run them and see them red (the renderer exits 1 while `readme` is static: `check=True` raises).
  4. `pyproject.toml`, the hook:
     - in `[project]`, replace `readme = "README.md"` with `dynamic = ["readme"]`;
     - `[build-system] requires = ["hatchling", "hatch-fancy-pypi-readme==25.1.0"]`;
     - append the `[tool.hatch.metadata.hooks.fancy-pypi-readme]` table, its `fragments` entry and the three `substitutions` entries exactly as written in the plan (TOML literal strings, order: image, directory, file), with the two-line comment above the first substitution. Place the block after `[tool.hatch.build.targets.wheel]`.
     - Run the tests and see them green.
  5. `CONTRIBUTING.md`, section "Releasing (maintainers)": one sentence before the numbered steps (after the paragraph "Publishing is automated: ..."): the build rewrites the README's relative links into absolute links on the tag `v` plus the `pyproject.toml` version (the `fancy-pypi-readme` hook in `pyproject.toml`), so the tag of step 7 must be exactly that, and the links in `README.md` stay relative.
  6. `CHANGELOG.md`, `[Unreleased]`: append to the existing `### Fixed` section one bullet: the README's links and demo GIF now work on the PyPI page, the package build pointing them at the release on GitHub.
  7. Package check, into the scratchpad only (never the repository's `dist/`): `uv build -o <scratchpad>/dist`, then `unzip -p <scratchpad>/dist/*.whl '*/METADATA'`. The long description carries `https://raw.githubusercontent.com/mkrtchian/mcp-auditor/v0.4.0/docs/demo/demo.gif` and no relative target (`grep -nE '\]\((docs|evals|src|tests|CONTRIBUTING|CHANGELOG|LICENSE)' ` finds nothing, `](#…` stays). Then `uvx twine check <scratchpad>/dist/*` passes. No Docker involved.
- **Test**:
  - image: `docs/demo/demo.gif` becomes `https://raw.githubusercontent.com/mkrtchian/mcp-auditor/v42.0/docs/demo/demo.gif`;
  - anchor: `#measurement` unchanged;
  - directory: `evals/cve/holdout_runs/` becomes `https://github.com/mkrtchian/mcp-auditor/tree/v42.0/evals/cve/holdout_runs/`;
  - file with anchor: `docs/usage.md#confinement` becomes `https://github.com/mkrtchian/mcp-auditor/blob/v42.0/docs/usage.md#confinement`;
  - badge and absolute link: the badge's two targets and the plain absolute link are unchanged;
  - only targets change: the rendering with every target blanked equals the fixture with every target blanked, after `rstrip`;
  - the real README: every rendered target starts with `https://` or `#`.
- **Verify**: `uv run pytest tests/unit/project/test_pypi_readme.py -n 0` red before the hook configuration, green after; the short loop green; the package check of item 7 passes; the closing check (`uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`) green.
