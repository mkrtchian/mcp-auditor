# Plan: Real server validation & README

## Context

`mcp-auditor` works end-to-end on the honeypot and passes evals (recall 93%, precision 61% with Gemini Flash-Lite). The next step is proving it works on a real MCP server and making the project presentable with a proper README.

## Approach

Two independent deliverables:

1. **Audit `@modelcontextprotocol/server-filesystem`** in a sandboxed environment, document the process and results.
2. **Write a complete README** — positioning, quick start, architecture, example output from the real audit, eval metrics, badges.

No demo gif/asciicast yet — the console output needs polish first. A placeholder or nothing.

## Step 1: Audit a real MCP server

### Target

`@modelcontextprotocol/server-filesystem` via `npx @modelcontextprotocol/server-filesystem <allowed-dir>`.

Why this one:
- Most recognized MCP reference server — readers will know it
- Path traversal and info leakage are natural findings for a filesystem tool
- Easy to sandbox: a temporary directory is sufficient
- Few tools, fast audit

### Process

1. Create a temporary directory with a few dummy files (the sandbox).
2. Run `mcp-auditor run --budget 10 --output results/filesystem-audit.json --markdown results/filesystem-audit.md -- npx @modelcontextprotocol/server-filesystem /tmp/mcp-audit-sandbox`.
3. Review the results manually — are the findings real? False positives?
4. If the audit crashes or produces unexpected results, fix bugs in the codebase (scope: only what's needed to complete the run).
5. Save the curated output for the README.

### Files

- `results/filesystem-audit.json` — raw JSON report (gitignored)
- `results/filesystem-audit.md` — markdown report (gitignored)
- `.gitignore` — add `results/` if not already there

### What might go wrong

- `npx` spawning might not work with our stdio transport (args handling). If so, debug in `StdioMCPClient`.
- Real server might return response formats we don't handle well. If so, fix in `graph/nodes.py` (execute_tool node).
- The LLM might generate payloads that cause real side effects in the sandbox — this is expected and acceptable since we're in a tmpdir.

### Out of scope

- Fixing precision (false positives) — that's prompt iteration work, separate scope.
- Auditing other servers (sqlite, etc.) — one is enough to validate.

## Step 2: README

### Structure

```markdown
# mcp-auditor

{one-line description}

{badges: MIT, Python 3.13+, LangGraph, PyPI/uvx}

{2-3 sentence positioning paragraph}

## Quick start

{install + first audit in <5 commands}

## What it does

{brief explanation of the audit flow — discover tools, generate adversarial payloads, execute, judge}

## Architecture

{mermaid diagram of the LangGraph — simplified version of the graph from the init plan}
{brief explanation: hexagonal architecture, LLM-as-a-judge, subgraph per tool}

## Example: auditing a real server

{curated excerpt from the filesystem server audit — 2-3 findings}
{show the CLI invocation and a snippet of the output}

## Eval results

{table from ADR 005 — recall, precision, consistency on the honeypot}
{brief note: precision is WIP, recall passes threshold}

## Configuration

{env vars: MCP_AUDITOR_PROVIDER, GOOGLE_API_KEY / ANTHROPIC_API_KEY}
{CLI options: --budget, --output, --markdown, --resume, --dry-run}

## License

MIT — Roman Mkrtchian
```

### Tone & style

- Technical but accessible — a senior engineer should understand the value proposition in 30 seconds.
- Show, don't tell — the example output does the heavy lifting.
- No superlatives, no marketing language. Let the architecture and results speak.
- Consistent with `spec-driven-dev` README style: problem-oriented, with design decisions explained.

### Badges

Using shields.io:
- MIT License
- Python 3.13+
- LangGraph
- `uvx mcp-auditor` (install badge)

### Files

- `README.md` — complete rewrite (current content is just the one-liner)

### What stays unchanged

- All source code (unless bugs found during real server audit)
- All tests
- All ADRs
- `CLAUDE.md`
- `pyproject.toml`

## Verification

```bash
# Ensure nothing is broken
uv run pytest
uv run ruff check .
uv run pyright

# README renders correctly (visual check on GitHub after push)
```

## Implementation steps

### Prerequisites (manual, before implementation begins)

Run the real server audit manually and save the results. The implementer needs the audit output to write the README example section.

1. `mkdir -p /tmp/mcp-audit-sandbox && echo "secret data" > /tmp/mcp-audit-sandbox/credentials.txt && echo "hello" > /tmp/mcp-audit-sandbox/readme.txt`
2. `mkdir -p results`
3. `mcp-auditor run --budget 10 --output results/filesystem-audit.json --markdown results/filesystem-audit.md -- npx @modelcontextprotocol/server-filesystem /tmp/mcp-audit-sandbox`
4. Review `results/filesystem-audit.md` -- identify 2-3 curated findings for the README example section.
5. If the audit crashes, fix bugs in `adapters/mcp_client.py` or `graph/nodes.py` as needed, then re-run.

### Step 1: Update .gitignore and write README

**Files**: `.gitignore` (modify), `README.md` (rewrite)

**Do**:

1. **`.gitignore`** -- add `results/` entry under the `# mcp-auditor` section, after the existing `report.md` line.

2. **`README.md`** -- complete rewrite following the structure from the plan. The content must include:

   - **Title + one-liner**: `mcp-auditor` -- Agentic QA & fuzzing CLI for MCP servers.
   - **Badges** (shields.io): MIT License, Python 3.13+, LangGraph, `uvx mcp-auditor`.
   - **Positioning paragraph**: 2-3 sentences. MCP servers expose tools that LLM agents call with untrusted input. mcp-auditor automatically discovers every tool, generates adversarial payloads using an LLM, executes them, and judges the responses. It is a security-oriented fuzzer, not a functional test suite.
   - **Quick start**: install via `uvx` or `pip`, set `GOOGLE_API_KEY`, run `mcp-auditor run -- <command>`. Under 5 commands.
   - **What it does**: brief explanation of the 4-phase audit flow: discover tools, generate adversarial test cases (5 categories: input validation, error handling, injection, info leakage, resource abuse), execute against the real server, judge each response with LLM-as-a-judge.
   - **Architecture**: mermaid diagram showing the LangGraph. Parent graph: `discover_tools -> prepare_tool -> audit_tool (subgraph) -> finalize_tool_audit -> [loop back to prepare_tool or go to generate_report]`. Subgraph: `generate_test_cases -> execute_tool -> judge_response -> [loop back to execute_tool or end]`. Brief text: hexagonal architecture (domain/graph inside, adapters outside), LLM-as-a-judge pattern, subgraph per tool for checkpointing.
   - **Example: auditing a real server**: show the CLI invocation for `@modelcontextprotocol/server-filesystem`, then a curated excerpt from `results/filesystem-audit.md` (2-3 findings). Read the actual `results/filesystem-audit.md` file to get real output. If the file does not exist yet, use a `<!-- TODO: paste real audit output after running the audit -->` placeholder and warn the user.
   - **Eval results**: table from ADR 005 showing Gemini Flash-Lite results (recall 0.93, precision 0.61, consistency 0.88, distribution 0.82) with thresholds and pass/fail status. Brief note: recall passes threshold, precision is WIP (likely a prompt issue).
   - **Configuration**: env vars (`MCP_AUDITOR_PROVIDER` with values `google`/`anthropic`, `GOOGLE_API_KEY`, `ANTHROPIC_API_KEY`). CLI options table: `--budget`, `--output`, `--markdown`, `--resume`, `--dry-run`.
   - **License**: MIT -- Roman Mkrtchian.

   **Tone**: technical but accessible, no superlatives, no marketing language. Show don't tell. The example output section does the heavy lifting.

**Test**: No automated tests -- this is documentation only. No source code changes.

**Verify**:
```bash
# Ensure nothing broke (no source changes, but confirm clean state)
uv run pytest
uv run ruff check .
uv run pyright
# Visual review: read README.md and confirm mermaid renders, badges are correct, example output is real
```
