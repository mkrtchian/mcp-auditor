# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The auditor now proves injection non-destructively: the generator is instructed to prefer benign reflected evidence, and a deterministic guard refuses to send a payload containing an enumerated destructive construct (`rm -rf`, `DROP TABLE`, a shutdown command, a fork bomb, and a handful more). A refused payload is reported as blocked with its reason in every output format, never sent to the server and never judged. Writes are still permitted: auditing a tool that writes writes. The generator is also told to prove impact by reading rather than writing, so a report can now carry a secret read from the audited server. See ADR 013 and ADR 014.
- JSON reports now always include the `owasp` key on eval results, with `null` for categories without an OWASP MCP mapping. The key used to be absent in that case. OWASP data is derived on the model itself and appears in every `EvalResult` serialization. See ADR 012.

## [0.2.0] - 2026-07-10

### Added

- Multi-step attack chains: the auditor plans multi-step attack scenarios against a single tool, executes them step by step against the live server, and judges the outcome. Opt-in via `--chains`, rendered in all output formats. See ADR 010.
- CVE benchmark: graded runs of the auditor against real, pinned-vulnerable MCP servers in throwaway Docker containers, with a no-LLM calibration mode and a `--cve` filter. See `plans/2026-07-06_cve_benchmark.md`.
- `/eval` PR comment command: maintainers can run the judge eval (`/eval`) or the full eval suite (`/eval full`) on a pull request.
- CI gates: judge eval fails on F1 regression, CVE fixture calibration gates benchmark PRs, `ruff format --check` gates all PRs.
- Dependabot updates for uv dependencies and GitHub Actions.

### Changed

- Default Google model bumped to `gemini-3.1-flash-lite`.
- LangSmith tracing env vars migrated to the current `LANGSMITH_*` names.

### Fixed

- Audit verdicts could be attributed to a hallucinated tool name: the graph now dispatches on the tool actually under audit.
- Chain verdicts are now counted in eval aggregation.

## [0.1.0] - 2026-03-23

Initial public release on PyPI.

- Dynamic adversarial testing of live MCP servers: tool discovery, LLM-generated test cases across five categories (input validation, error handling, injection, information leakage, resource abuse), execution over the MCP protocol, LLM-as-a-judge verdicts with severity ratings.
- OWASP MCP Top 10 mapping in all output formats.
- Cross-tool learning: attack context extracted from earlier tools informs later probes.
- Config file support (`.mcp-auditor.yml`), `--tools` filter, `--budget` control, token usage reporting.
- Three-level test strategy: unit tests with fakes, integration tests against a honeypot server, LLM evals scored against planted ground truth.

[Unreleased]: https://github.com/mkrtchian/mcp-auditor/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/mkrtchian/mcp-auditor/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mkrtchian/mcp-auditor/releases/tag/v0.1.0
