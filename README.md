# mcp-auditor

Agentic security testing for MCP servers.

[![PyPI version](https://img.shields.io/pypi/v/mcp-auditor)](https://pypi.org/project/mcp-auditor/)
[![CI](https://github.com/mkrtchian/mcp-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/mkrtchian/mcp-auditor/actions/workflows/ci.yml)
[![Evals](https://github.com/mkrtchian/mcp-auditor/actions/workflows/evals.yml/badge.svg)](https://github.com/mkrtchian/mcp-auditor/actions/workflows/evals.yml)
[![LangGraph](https://img.shields.io/badge/built%20with-LangGraph-orange.svg)](https://langchain-ai.github.io/langgraph/)

![mcp-auditor demo](docs/demo/demo.gif)

## The problem

MCP servers expose tools that LLM agents call with untrusted input. There is no automated way to test whether a server handles adversarial inputs safely. Manual testing doesn't scale, and generic fuzzers don't understand the MCP protocol or its threat model.

MCP security tools today focus on **static analysis** of tool descriptions (detecting poisoning before any call is made) and **runtime proxies** that intercept traffic in production. `mcp-auditor` takes a third approach: **dynamic adversarial testing**. It connects to a live server, generates adversarial inputs, executes them, and judges whether the responses reveal vulnerabilities. Think SAST vs. DAST in web security.

`mcp-auditor` probes for input validation failures, injection, information leakage, error handling gaps, and resource abuse. It produces structured verdicts with justifications and severity ratings.

## Quick start

```bash
# Clone and install
git clone https://github.com/mkrtchian/mcp-auditor.git
cd mcp-auditor
uv sync

# Set your API key (copy .env.example to .env and edit, or export directly)
export GOOGLE_API_KEY=your-key-here

# Audit an MCP server
mkdir -p /tmp/sandbox
uv run mcp-auditor run -- npx @modelcontextprotocol/server-filesystem /tmp/sandbox
```

## What it does

The audit runs in four phases:

1. **Discover tools**: connect to the MCP server, list available tools with their schemas.
2. **Generate adversarial test cases**: for each tool, the LLM generates payloads across five categories (input validation, error handling, injection, information leakage, resource abuse).
3. **Execute against the real server**: each payload is sent via the MCP protocol. Real responses, real behavior.
4. **Judge each response**: an LLM-as-a-judge classifies each response as PASS or FAIL with a justification and severity rating. Findings are mapped to the [OWASP MCP Top 10](https://owasp.org/www-project-model-context-protocol-top-10/) when applicable.

## Architecture

**Parent graph** (iterates over discovered tools):

```mermaid
graph LR
    A[discover_tools] --> B[prepare_tool]
    B --> C[audit_tool]
    C --> D[build_tool_report]
    D --> E[extract_attack_context]
    E -->|more tools| B
    E -->|done| F[generate_report]
```

**audit_tool subgraph** (runs per tool, loops over test cases):

```mermaid
graph LR
    S1[generate_test_cases] --> S2[execute_tool]
    S2 --> S3[judge_response]
    S3 -->|more cases| S2
    S3 -->|done| S4((end))
```

**Why this design:**

- **Hexagonal architecture.** `domain/` and `graph/` form the inside of the hexagon (business logic, ports as `Protocol` classes), `adapters/` sits outside (LLM clients, MCP transport). Swapping the LLM provider means changing one adapter, zero graph code. [ADR 002](docs/adr/002-hexagonal-architecture.md)
- **Subgraph per tool.** Each tool audit is a self-contained subgraph with checkpointing: if the process crashes at tool 8 of 14, `--resume` picks up where it left off. [ADR 001](docs/adr/001-why-langgraph.md)
- **Cross-tool learning.** After each tool audit, the graph extracts intelligence from the results (database engine, framework, exposed internals). Subsequent tools receive this context for targeted payloads, e.g. SQLite-specific injection after seeing `sqlite3.OperationalError` in a read tool. Read-like tools are audited first to maximize reconnaissance value. [ADR 009](docs/adr/009-cross-tool-learning.md)
- **LLM-as-a-judge.** The LLM evaluates each response against security criteria and produces structured verdicts. No heuristics, no regex. Quality is measured through evals. [ADR 003](docs/adr/003-testing-philosophy.md)

## Example: auditing a real server

```bash
mkdir -p /tmp/sandbox
uv run mcp-auditor run \
  --budget 10 \
  --output output/filesystem-audit.json \
  --markdown output/filesystem-audit.md \
  -- npx @modelcontextprotocol/server-filesystem /tmp/sandbox
```

This audits `@modelcontextprotocol/server-filesystem`, the official MCP reference server for filesystem operations. The server exposes 14 tools (read_file, write_file, search_files, etc.), each sandboxed to `/tmp/sandbox`.

Results: **140 test cases, 11 findings** (2 low, 9 medium). All findings were information leakage: the server exposes internal filesystem paths in error messages.

### read_file / info_leakage / MCP-10 (low)

**Payload**: `{'path': '/nonexistent/path/sensitive_file_test'}`

The error message discloses the absolute path of the sandbox directory, revealing the underlying filesystem structure and process environment to the caller.

### move_file / info_leakage / MCP-10 (medium)

**Payload**: `{'source': 'file.txt', 'destination': '/non_existent_folder/sub/file.txt'}`

The error message reveals the full internal filesystem path of the host, including the user's home directory and project structure.

## Eval results

Evaluated against two honeypot MCP servers with known vulnerabilities (3 runs, budget 10, 6 tools). The first honeypot has loud vulnerabilities (SQL echo, path leaks in errors), the second has subtle ones (PII in normal responses, silent validation gaps).

**Gemini 3.1 Flash-Lite** (`gemini-3.1-flash-lite-preview`):

| Metric       | Result | Threshold | Status |
|:-------------|-------:|----------:|:-------|
| Recall       |   1.00 |      0.80 | PASS   |
| Precision    |   0.88 |      0.85 | PASS   |
| Consistency  |   0.98 |      0.70 | PASS   |
| Distribution |   1.00 |      0.80 | PASS   |

All thresholds met. A separate judge isolation eval (32 fixed cases, no generator involved) scores F1 = 1.00. Full eval methodology in [ADR 005](docs/adr/005-llm-model-selection.md).

## Configuration

Copy `.env.example` to `.env` and edit, or export variables directly. All `MCP_AUDITOR_*` variables are optional and have sensible defaults.

### Environment variables

| Variable                     | Default                | Description                               |
|:---------------------------|:---------------------|:------------------------------------------|
| `MCP_AUDITOR_PROVIDER`     | `google`             | LLM provider: `google` or `anthropic`     |
| `MCP_AUDITOR_MODEL`        | per-provider default | Override the main model name              |
| `MCP_AUDITOR_JUDGE_MODEL`  | same as main model   | Separate model for verdict classification |
| `GOOGLE_API_KEY`           | --                   | Required when provider is `google`        |
| `ANTHROPIC_API_KEY`        | --                   | Required when provider is `anthropic`     |
| `LANGSMITH_API_KEY`        | --                   | Enables LangSmith tracing when set        |
| `LANGCHAIN_TRACING_V2`     | --                   | Set to `true` to activate tracing         |
| `LANGCHAIN_PROJECT`        | `mcp-auditor`        | LangSmith project name for traces         |

### CLI options

| Option       | Default    | Description                                       |
|:-------------|:-----------|:--------------------------------------------------|
| `--budget`   | `10`       | Max test cases per tool                           |
| `--tools`    | all        | Comma-separated tool names to audit               |
| `--output`   | none       | Path for JSON report                              |
| `--markdown` | none       | Path for Markdown report                          |
| `--resume`   | off        | Resume from last checkpoint                       |
| `--dry-run`  | off        | Discover tools and generate cases, skip execution |
| `--ci`       | off        | CI mode: no Rich UI, exit 1 on findings           |
| `--severity-threshold` | `medium` | Minimum severity to trigger CI failure    |

### Configuration file

Place a `.mcp-auditor.yml` in your project root to avoid repeating CLI flags:

```yaml
budget: 15
severity_threshold: high
tools:
  - get_user
  - list_items
output: report.json
ci: true
```

CLI flags override config file values.

## Run in CI

`--ci` replaces Rich UI with plain text, keeps all diagnostic output, and exits with code 1 if any finding meets the severity threshold.

```yaml
# .github/workflows/mcp-audit.yml
- name: Audit MCP server
  run: uvx mcp-auditor run --ci -- python my_server.py
```

Use `--severity-threshold` to control which findings trigger a failure:

```bash
# Only fail on high or critical findings
mcp-auditor run --ci --severity-threshold high -- python my_server.py
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, commands, and conventions.

## License

MIT. [Roman Mkrtchian](https://github.com/mkrtchian)

---

Built using [spec-driven-dev](https://github.com/mkrtchian/spec-driven-dev) workflow.
