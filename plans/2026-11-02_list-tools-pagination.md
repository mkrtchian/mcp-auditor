# list_tools pagination and stable rule references

## Context

`StdioMCPClient.list_tools` (`src/mcp_auditor/adapters/mcp_client.py`) sends one `tools/list` request and returns its tools, without following `nextCursor`. A server that paginates `tools/list` therefore exposes only its first page to the audit: discovery (`make_discover_tools` in `graph/nodes.py`, through `AuditedServer.list_tools`) never sees the tools of the later pages, so they are never audited. The nuisance suite admits one such server, `PyPI:praisonai` (86 tools, pages of 50, `DEFAULT_PAGE_SIZE = 50` in its `mcp_server/registry.py`): its two counted tools, `praisonai.workflow.show` and `praisonai.rules.show`, are on the second page, so the server cannot be flagged by construction and its contribution to the nuisance figure is a guaranteed zero rather than a measurement. Found on 2026-11-02 while checking the benign calls of the nuisance servers. No nuisance, gate or holdout run has taken place.

The SDK side effect: `ClientSession.call_tool` validates structured content against an output-schema cache that `ClientSession.list_tools` fills page by page without clearing it (mcp 1.30.0, `client/session.py`). When a called tool is missing from the cache, the SDK refreshes it with an un-paginated `list_tools()` and, the tool still missing, logs `Tool <name> not listed by server, cannot validate any structured content` and skips validation. Following every page fills the cache with every tool, so the validation runs for the later pages too.

The calibration kit's client (`evals/holdout_kit/kit_client.py`, `KitMCPClient.list_tools`, the concrete client behind the `KitClient` protocol, a copy free of `mcp_auditor` shipped to the isolated calibration and admission agents) has the same single request. It backs the kit's route procedure (`kit_driver.py`), the fix-check driver (`fix_check.py`) and the agents' own probing. The maintainer's own route check is not on the kit: `cve_layout_check.py` collects `route_observations` (`cve_route.py`) through `cve_environments.py`, which connects the product `StdioMCPClient`, so it is the product fix (commit 1) that changes what that collector sees on a paginating target. The praisonai fix check works around it by calling its tools by name.

Separately, eval modules cite the rules by line number (`holdout-rule.md:NNN`). Each rule edit shifts the lines, and several references no longer point at the paragraph they mean (version 9 of the holdout rule moved them again). A reference by section name survives edits.

## Decisions

1. **The product client follows `nextCursor` until a page carries none**, accumulating the tools in the order the server lists them. The whole listing stays under the one existing timeout (`_list_tools_timeout`, the initialize timeout), so its contract does not change: listing a server either completes in that time or raises `TimeoutError` as today.
2. **A cursor the server already returned is an error.** The MCP specification leaves the cursor opaque to the client, and a server that hands back a cursor it already gave would make the client loop until the timeout. `list_tools` raises `RuntimeError("tools/list returned a cursor it had already returned: <cursor>")` on the first repeated cursor. A partial list is never returned silently, since a silent partial list is the bug this plan fixes.
3. **No de-duplication.** A name listed on two pages is returned twice, as the server listed it. What a server does with duplicate names is the server's concern, and `AuditedServer` handles what it receives today.
4. **The kit client follows the cursor the same way**, with the same repeated-cursor error. It is an instrument change: it can change what the kit's route procedure sees on a paginating server, and the product fix (decision 1) can do the same to the maintainer's route-check collector. The golden masters of the route and layout checks (`tests/unit/support/test_cve_route_golden_given.py`, `test_cve_layout_check_golden_given.py`) pin the pure `route_admits` and layout decisions on a fictional corpus, so they stay unchanged by construction and cannot by themselves show that no target paginates: that is shown by the throwaway check of Verification, which covers every acceptance and holdout target on both versions. The product client counts here as part of the route procedure, since it collects what the maintainer's route check observes (the conservative reading of Versioning). An edit to the code of the route check opens a version only when it changes what the check decides: no decision changes, which the golden masters cannot show on their own and the logged result of the throwaway check shows on every drawn and acceptance target, so no version of the holdout rule opens. Logged in `docs/holdout-log.md`, one entry naming both clients, and in `docs/nuisance-log.md`, one entry per commit (decision 7).
7. **The nuisance log records both commits.** The kit client drives every nuisance fix check (`evals/holdout_kit/fix_check.py`), and the product fix makes praisonai's counted tools auditable. Commit 1 logs that praisonai's two counted tools are now discovered, with the throwaway check's result over the 59 admitted servers. Commit 2 logs that the fix-check driver follows `nextCursor`, with the CVE-2026-18905 fix check still matching its record. Neither opens a version of the nuisance rule (no admission, fix check or benign call changes).
8. **The dossiers state the kit's mcp floor.** The calibration dossier (`evals/calibration_dossier.py`) and the admission dossier (`evals/nuisance_dossier.py`) ship the kit to isolated agents who install their own mcp, and the kit now needs mcp 1.18.0 or later. Each dossier's generated README gains one line saying so, where it lists what the kit needs.
5. **Line references become section references**, written `holdout-rule.md, <Section name>` or `holdout-rule.md, <Section name> (<paragraph lead>)` when the section is long, for example `holdout-rule.md, Deployment layout (A server the layout breaks falls back)`. Every `holdout-rule.md:NNN` and `nuisance-rule.md:NNN` in `evals/`, `src/` and `tests/` is replaced, the ones that still point right included, so no line reference is left to go stale.
6. **No fingerprint moves.** `fingerprint_source` (`evals/baseline.py`) hashes the AST without comments, formatting and the module docstring, but a function or class docstring is part of the AST. A reference that sits in a `#` comment or in a module docstring is edited freely. A reference that sits in a function or class docstring of a module that some fingerprint covers (`_ENVIRONMENT_PATHS` and the places modules of `evals/cve_baseline.py`, `GRAMMAR_PATHS`, the nuisance fixture and counter fingerprints, `evals/nuisance_fingerprint.py`) is edited only if the implementer confirms that module is outside every fingerprint. Otherwise it is left as it is and listed in the commit message as left on purpose. Two are known on 2026-11-02 and stay: the docstring of `build_empty_layout` (`evals/cve_layout.py`) and that of `LaunchShape` (`evals/cve_environments.py`), both modules of `_ENVIRONMENT_PATHS`, so editing them would move every CVE target's fixture fingerprint and reset the acceptance baseline just recorded. The verification computes every fingerprint before and after (see Verification).

## Files

### `src/mcp_auditor/adapters/mcp_client.py`

```python
async def list_tools(self) -> list[ToolDefinition]:
    async with asyncio.timeout(self._list_tools_timeout):
        tools = await _list_every_page(self._session)
    return [_to_tool_definition(tool) for tool in tools]


async def _list_every_page(session: ClientSession) -> list[Tool]:
    tools: list[Tool] = []
    seen: set[str] = set()
    cursor: str | None = None
    while True:
        params = None if cursor is None else PaginatedRequestParams(cursor=cursor)
        result = await session.list_tools(params=params)
        tools.extend(result.tools)
        cursor = result.nextCursor
        if cursor is None:
            return tools
        if cursor in seen:
            raise RuntimeError(f"tools/list returned a cursor it had already returned: {cursor}")
        seen.add(cursor)
```

`PaginatedRequestParams` from `mcp.types`. The first request sends no params, as today, so an un-paginated server sees the exact request it sees now. The `cursor=` keyword of `ClientSession.list_tools` is deprecated in mcp 1.30.0, so `params=` is used. The helper sits below `StdioMCPClient` (newspaper order), next to `_to_tool_definition`.

### `evals/holdout_kit/kit_client.py`

The same helper, written in the kit (the kit imports nothing from `mcp_auditor`, so the helper is duplicated, not shared): `KitMCPClient.list_tools` calls it under its existing timeout and maps with `_to_kit_tool`. `evals/calibration_dossier.py` copies `kit_client.py` verbatim (`KIT_MODULES`, through `copy_clean_sources`), and `evals/nuisance_dossier.py` reuses `KIT_MODULES`, so both dossiers gain the fix with no other change.

### `tests/integration/support/paginated_server.py` (new)

A stdio MCP server on the low-level `mcp.server.lowlevel.Server`, whose `list_tools` handler takes the `ListToolsRequest` and returns a `ListToolsResult` (the new-style handler the SDK accepts). The parameter is typed `ListToolsRequest` with no default, and the handler treats both a request whose `params` is `None` and a `None` request as the first page: on a `tools/call` for a tool missing from its cache, the low-level server calls the handler with `None` (mcp 1.30.0, `Server._get_cached_tool_definition`). Without that, the call to `tool_5` fails server-side before the fix too, and the validation test below is never red. The annotation says `ListToolsRequest` (the SDK's wrapper matches the exact type), so the `None` case is read with `getattr(request, "params", None)` rather than a `request is None` test that strict pyright reports as unnecessary. Five tools, `tool_1` to `tool_5`, served two per page, with the cursor the index of the next page as a string. `tool_5`, on the last page, declares an `outputSchema` requiring an integer field `count`, and its `call_tool` handler returns a `CallToolResult` built by hand, with `structuredContent={"count": "not a number"}` and `isError` left false (the client SDK validates only a result that is not an error, `ClientSession.call_tool`), which breaks that schema. Every tool's `inputSchema` is `{"type": "object"}`, so the server's own input validation accepts the `{}` the tests pass. Returning a `CallToolResult` matters: the low-level server passes it through unvalidated, whereas a dict return would be validated server-side against the tool it cached, and since the server caches every page the client lists, that server-side rejection would make the test pass after the fix for a reason other than the client's validation. A launch argument `--repeat-cursor` makes the second page return `nextCursor="1"` again, the cursor the first page returned. Every tool returns a fixed text otherwise. It sits beside the other stub servers of `tests/integration/support/` (`cve_replay_stub_server.py`, `env_echo_server.py`), not beside the honeypots of `tests/`: it is a test fixture, not a honeypot, it is not in `evals/ground_truth.py`, and it carries no planted flaw.

### `tests/integration/support/test_mcp_client_given.py` (new)

`PAGINATED_SERVER_PATH` and a `paginated_launch(*flags)` returning the `ServerLaunch.unconfined(sys.executable, [str(PAGINATED_SERVER_PATH), *flags])`, the way `test_mcp_client_transport_given.py` holds `STUB_PATH` and its launch. `test_holdout_kit_client.py` imports `PAGINATED_SERVER_PATH` from it, as it already imports `STUB_PATH` from a support module, never from a test module.

### `tests/integration/test_mcp_client.py`

A `TestPagination` class:

- `test_lists_the_tools_of_every_page`: `list_tools` on the paginated server returns `tool_1` to `tool_5`, in that order.
- `test_validates_structured_content_of_a_later_page`: on one connection, `list_tools()` first, then `call_tool("tool_5", {})` returns `is_error=True` with `error_type == "RuntimeError"` (the SDK's `Invalid structured content returned by tool tool_5`, caught by `StdioMCPClient.call_tool`), because the SDK validated its structured content against the schema it learned from the last page. Without pagination the SDK skips validation and the call succeeds, so this test fails before the fix. The `list_tools()` call is required: on a cache miss the SDK refreshes with its own un-paginated `list_tools()` (mcp 1.30.0, `ClientSession._validate_tool_result`), so a `call_tool` with no prior adapter listing skips validation even after the fix.
- `test_a_repeated_cursor_raises`: with `--repeat-cursor`, `list_tools` raises `RuntimeError` naming the cursor.

The honeypot `TestDiscovery` tests stay as they are and keep passing (an un-paginated server).

### `tests/integration/test_holdout_kit_client.py`

The first and third scenarios above against `KitMCPClient` (`KitMCPClient.connect(sys.executable, [str(PAGINATED_SERVER_PATH), ...])`, as the existing test there launches its stub), on the same paginated server.

### Rule references

Every file that `grep -rn "holdout-rule\.md:[0-9]\|nuisance-rule\.md:[0-9]" evals src tests` returns (30 references on 2026-11-02, in `evals/nuisance_run.py`, `holdout_vetting.py`, `holdout_run.py`, `holdout_report.py`, `holdout_markdown.py`, `holdout_fixtures/cve_2026_45555_roslyncodelens.py`, `cve_targets.py`, `cve_route.py`, `cve_layout.py`, `cve_layout_check.py`, `cve_environments.py`, `cve_benchmark_modes.py`, `cve_baseline.py`). For each, the implementer reads the sentence and the rule as it stands at version 9 and names the section (and paragraph lead) the sentence means, not the one the stale number now lands on.

### Living docs

- `CHANGELOG.md`, `[Unreleased]`, Fixed: an audit now discovers every tool of a server that paginates `tools/list`, where it saw the first page only.
- `docs/holdout-log.md`: one entry for the kit client (decision 4), stating that the route check's decisions are unchanged and no rule version opens.
- `README.md`, `CLAUDE.md`, `CONTRIBUTING.md`: nothing, unless a passage describes discovery as a single `tools/list` (check).

## What stays unchanged

- `AuditedServer`, the graph and every port: `MCPClientPort.list_tools` keeps its signature and returns the full list.
- `FakeMCPClient` and the unit tests built on it.
- The SDK version, the timeouts, the honeypot servers and `evals/ground_truth.py`.
- Every fixture, Dockerfile, admission, census and baseline. No fingerprint moves (decision 6).
- The praisonai fix check: it calls its tools by name and does not depend on the listing.

## Edge cases

- A server that returns `nextCursor` as an empty string: an empty string is a cursor, sent back as is. Only `None` ends the listing.
- A page with no tools and a cursor: the loop continues.
- A server that times out on a later page: `TimeoutError` from the one overall timeout, as for a first page today.
- A server that errors on a later page (a JSON-RPC error): the `McpError` propagates as it does on a first page today.

## Commits (one change each)

1. `fix(audit): follow nextCursor when listing a server's tools`: the product client, the paginated test server, its given module and its integration tests, the floor `mcp>=1.18.0,<2` in `pyproject.toml` with the `uv.lock` it rewrites, the CHANGELOG entry, the nuisance log entry. The commit message answers the four questions of ADR 016 (`docs/adr/016-eval-gate-governance.md`): the artifact is the system under test, and the justification (an audit must see every tool a server lists) survives the deletion of every mention of a measurement. It states which baselines can move: the honeypot suite and the CVE acceptance layer only if one of their servers paginates (the verification below says none does), the holdout route check's decisions on the same condition (its collector runs on this client), the nuisance figure through praisonai, whose counted tools become auditable (no nuisance run has taken place).
2. `fix(evals): follow nextCursor in the calibration kit's client`: the kit client, its test, the mcp floor line in the two dossiers' READMEs, the holdout and nuisance log entries.
3. `docs(evals): cite the rules by section rather than by line`: the reference rewording, nothing else.

## Verification

- `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .`, `uv run pyright`.
- Before commit 1, a throwaway check, not committed, that no server of the honeypot suite, the CVE acceptance layer (4 targets, both versions) or the holdout (30 targets, both versions) paginates `tools/list`: launch each through its existing launch path (`evals/cve_environments.py` and the planting, or the honeypot launch), send `tools/list`, record whether the response carries `nextCursor`. Expected: none does, so no honeypot or CVE baseline and no route decision moves. It also covers the 59 admitted nuisance servers, through the launch a nuisance run uses: praisonai alone is expected to paginate (vet investigation of 2026-11-02, gitlab serving its 211 tools in one page), and the check confirms it as a logged fact, and its praisonai part runs again once the fix is in (see the vet line below). It prints only the presence of `nextCursor` and tool counts for a holdout server, never a tool name or description. Any other paginating server is named in the commit message of commit 1.
- After commit 2, `uv run python -m evals.run_nuisance calibrate --cve CVE-2026-18905` (the contextforge fix check lists the tools through the kit client) stays green against its recorded fix_check (Docker, no LLM).
- `uv run python -m evals.run_nuisance vet --server PyPI:praisonai` stays `ok` after commit 1. It does not show the fix: `benign_call_failure` (`evals/nuisance_audit.py`) calls the counted tools with no `list_tools` first, so the SDK's own un-paginated refresh still misses them and the `not listed by server` warning stays. The fix is shown by the throwaway check above: on praisonai, the product `StdioMCPClient.list_tools` returns 50 tools before commit 1 and every tool after, `praisonai.workflow.show` and `praisonai.rules.show` among them (this settles the OPEN line of the due diligence record).
- Before and after commit 3: every fingerprint unchanged. Compute, on both trees, `grammar_fingerprint()`, the `fixture_fingerprint` of every acceptance and holdout target, and the nuisance fixture and counter fingerprints of every admitted server, and diff them. The grammar, route-check and layout-check golden masters (`tests/unit/support/test_cve_grammar_golden_given.py`, `test_cve_route_golden_given.py`, `test_cve_layout_check_golden_given.py`) stay green without regeneration.

## Due diligence record

What the plan-diligence pass concluded about the plan's external facts on 2026-11-02, read by the implementation-phase fact check. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, not what is true now. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- SETTLED: `session.list_tools(params=PaginatedRequestParams(cursor=cursor))`, with `PaginatedRequestParams` from `mcp.types` and the `cursor=` keyword deprecated (verified against the installed mcp 1.30.0, `client/session.py`, the version `uv.lock` pins)
- SETTLED: `ClientSession.list_tools` fills `_tool_output_schemas` page by page without clearing it, and `_validate_tool_result` refreshes with an un-paginated `list_tools()` then logs `Tool <name> not listed by server, cannot validate any structured content` (verified against mcp 1.30.0, `client/session.py`)
- SETTLED: `Invalid structured content returned by tool tool_5` raised as `RuntimeError` on a schema mismatch (verified against mcp 1.30.0, `client/session.py`)
- SETTLED: the low-level server's `list_tools` decorator accepts a handler typed `ListToolsRequest` returning `ListToolsResult`, caches page by page without clearing, calls the handler with `None` from `_get_cached_tool_definition`, and passes a returned `CallToolResult` through unvalidated (verified against mcp 1.30.0, `server/lowlevel/server.py` and `func_inspection.py`)
- SETTLED: the cursor is opaque, a missing `nextCursor` ends the results, `tools/list` is paginated (verified against the MCP specification 2025-11-25, server/utilities/pagination)
- SETTLED: `DEFAULT_PAGE_SIZE = 50` in praisonai's `mcp_server/registry.py` (verified in the built `mcp-auditor-nuisance-praisonai:local` image, `praisonai==4.6.40`, mcp 1.30.0)
- SETTLED (maintainer, 2026-11-02): the keyword-only `params=` of `ClientSession.list_tools` exists from mcp 1.18.0 (absent in 1.17.0, present in 1.18.0, checked on the python-sdk tags), so commit 1 raises the floor in `pyproject.toml` to `mcp>=1.18.0,<2` (the lock stays at 1.30.0, `uv lock` rewrites only the recorded specifier)
- OPEN (unverified): praisonai's 86 tools and the page position of `praisonai.workflow.show` and `praisonai.rules.show`, taken from the vet investigation, not re-checked here

## Implementation steps

### Step 1: follow `nextCursor` in the product client

- **Files**: `tests/integration/support/paginated_server.py` (new), `tests/integration/support/test_mcp_client_given.py` (new), `tests/integration/test_mcp_client.py`, `src/mcp_auditor/adapters/mcp_client.py`, `pyproject.toml`, `uv.lock`, `CHANGELOG.md`.
- **Do**:
  1. Write `tests/integration/support/paginated_server.py` exactly as specified in Files: low-level `mcp.server.lowlevel.Server`, a `list_tools` handler typed `ListToolsRequest` (no default) returning `ListToolsResult`, reading the cursor through `getattr(request, "params", None)` so a `None` request and a `None` params both mean the first page. Five tools `tool_1` to `tool_5`, two per page, cursor = index of the next page as a string. `tool_5` declares an `outputSchema` requiring an integer `count`, and its `call_tool` returns a hand-built `CallToolResult` with `structuredContent={"count": "not a number"}` and `isError` false. Every `inputSchema` is `{"type": "object"}`. `--repeat-cursor` makes the second page return `nextCursor="1"` again, the cursor the first page returned. Other tools return a fixed text. Write `tests/integration/support/test_mcp_client_given.py` with `PAGINATED_SERVER_PATH` and `paginated_launch(*flags)` (see Files).
  2. Add `TestPagination` to `tests/integration/test_mcp_client.py`, launching the server with `given.paginated_launch()` (and `given.paginated_launch("--repeat-cursor")`). Run it and confirm all three are red: the first lists two tools, the second returns no error, the third raises nothing (the client sends one request before the fix, so it cannot loop).
  3. In `mcp_client.py`, replace the single request in `StdioMCPClient.list_tools` with `_list_every_page(self._session)` under the existing timeout, as given in Files. Import `PaginatedRequestParams` from `mcp.types`. Place the helper below the class, next to `_to_tool_definition`.
  4. `pyproject.toml`: raise the floor to `mcp>=1.18.0,<2`, the first version whose `ClientSession.list_tools` takes `params=`, then `uv lock` (the resolved mcp stays 1.30.0: check the lock diff touches only the specifier).
  5. `CHANGELOG.md`, `[Unreleased]`, Fixed: an audit now discovers every tool of a server that paginates `tools/list`, where it saw the first page only. Check `README.md`, `CLAUDE.md`, `CONTRIBUTING.md` for a passage describing discovery as one `tools/list` (expected: none).
- **Test**:
  - `test_lists_the_tools_of_every_page`: names `tool_1` .. `tool_5`, in order.
  - `test_validates_structured_content_of_a_later_page`: one connection, `list_tools()` then `call_tool("tool_5", {})` gives `is_error=True`, `error_type == "RuntimeError"`.
  - `test_a_repeated_cursor_raises`: with `--repeat-cursor`, `list_tools` raises `RuntimeError` whose message names the repeated cursor.
  - Existing `TestDiscovery` keeps passing.
- **Verify**:
  - `uv run pytest tests/integration/test_mcp_client.py -n 0` red before step 3, green after.
  - Throwaway check (not committed): through the existing launch paths, send `tools/list` to every honeypot server, the 4 CVE acceptance targets and the 30 holdout targets on both versions, and the 59 admitted nuisance servers on the launch a nuisance run uses, and record whether a response carries `nextCursor`. Launch paths: `evals.honeypots.connected` for the honeypots, `CVETarget.launched(..., version=...)` (`evals/cve_targets.py`) then `evals.cve_environments.connect` for the acceptance (`evals/cve_targets.py`) and holdout (`evals/holdout_targets.py`, `HOLDOUT_TARGETS`) targets, after `docker compose -f evals/docker/compose.yml build`, and `evals.nuisance_audit.nuisance_environment` for the nuisance servers (their backends brought up as `run_nuisance vet` does, images built as it does, never in parallel with a calibration). `StdioMCPClient.list_tools` drops `nextCursor`, so the script reads it from the raw `ClientSession.list_tools()` result (`client._session`, acceptable in a throwaway script). It prints, per server and version, only whether `nextCursor` is present and the tool count, never a tool name or description of a holdout server. For praisonai it also prints the count `StdioMCPClient.list_tools` returns and whether the two counted tools are in it, run once before step 3 and once after. Expected: only praisonai paginates. Any other paginating server is named in the commit message. The result (servers and versions listed, commit, which carried `nextCursor`) is kept for the log entries of `docs/holdout-log.md` (step 2) and `docs/nuisance-log.md` (this step and step 2). Needs Docker. If Docker is unavailable, report it rather than skipping silently.
  - `uv run python -m evals.run_nuisance vet --server PyPI:praisonai` stays `ok` after the change. The `not listed by server` warning stays too, since vet calls the tools without listing them first (see Verification): what shows the fix is the praisonai line of the throwaway check, `list_tools` returning 50 tools before step 3 and every tool after, the two counted tools included.
  - Closing check: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .`, `uv run pyright`.
  - `docs/nuisance-log.md`: one entry (decision 7): praisonai's two counted tools are now discovered, and the throwaway check's result over the 59 admitted servers. No version of the nuisance rule opens.
  - Commit message `fix(audit): follow nextCursor when listing a server's tools`, answering the four questions of ADR 016 and naming the baselines that can move, as Commits item 1 says.

### Step 2: follow `nextCursor` in the calibration kit's client

- **Files**: `tests/integration/test_holdout_kit_client.py`, `evals/holdout_kit/kit_client.py`, `evals/calibration_dossier.py`, `evals/nuisance_dossier.py`, `docs/holdout-log.md`, `docs/nuisance-log.md`.
- **Do**:
  1. In `test_holdout_kit_client.py`, add the listing and repeated-cursor scenarios against `KitMCPClient.connect(sys.executable, [str(PAGINATED_SERVER_PATH), ...])`, reusing the server from step 1 and `PAGINATED_SERVER_PATH` imported from `tests/integration/support/test_mcp_client_given.py`. Run them red.
  2. In `kit_client.py`, add a kit-local `_list_every_page` (duplicated from the product, the kit imports nothing from `mcp_auditor`), same repeated-cursor `RuntimeError`, `PaginatedRequestParams` from `mcp.types`. `KitMCPClient.list_tools` calls it under `self._list_tools_timeout` and maps with `_to_kit_tool`. `calibration_dossier.py` and `nuisance_dossier.py` copy the module verbatim, so the fix reaches both kits. Each gains one line in the README it generates, where it lists what the kit needs: the kit requires mcp 1.18.0 or later (decision 8). If a dossier test pins the README text, update it.
  3. `docs/holdout-log.md`: one entry (decision 4) naming both clients, stating the route check's decisions are unchanged and that no rule version opens. It records the result of step 1's throwaway check whatever it found: how many servers and versions it listed (honeypots, acceptance targets, holdout targets, praisonai), on which commit, and which ones carried `nextCursor`, so the claim that no route decision moved rests on a logged result. Follow the format of existing entries.
  4. `docs/nuisance-log.md`: one entry (decision 7): the fix-check driver follows `nextCursor`, the CVE-2026-18905 fix check still matches its record, and the dossier states the kit's mcp floor. No version of the nuisance rule opens.
- **Test**:
  - `KitMCPClient.list_tools` on the paginated server returns `tool_1` .. `tool_5` in order.
  - With `--repeat-cursor`, it raises `RuntimeError` naming the cursor.
  - The existing noisy-shutdown test keeps passing.
- **Verify**:
  - `uv run pytest tests/integration/test_holdout_kit_client.py -n 0` red, then green.
  - `uv run python -m evals.run_nuisance calibrate --cve CVE-2026-18905` stays green against its recorded fix_check (Docker, no LLM).
  - Golden masters of route and layout checks green without regeneration (part of the full run).
  - Closing check: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .`, `uv run pyright`.
  - Commit message `fix(evals): follow nextCursor in the calibration kit's client`.

### Step 3: cite the rules by section rather than by line

- **Files**: the files `grep -rn "holdout-rule\.md:[0-9]\|nuisance-rule\.md:[0-9]" evals src tests` returns (30 references in 13 files on 2026-11-02, listed in Files, Rule references). Text edits only, so the file count does not drive the context budget, but each reference needs the rule read at its current version.
- **Do**:
  1. Before editing, compute and save, outside the tree, every fingerprint: `grammar_fingerprint()`, the `fixture_fingerprint` of every acceptance and holdout target, and the nuisance fixture and counter fingerprints of every admitted server (`evals/nuisance_fingerprint.py`).
  2. For each reference, read the sentence and the rule (`evals/holdout-rule.md` at version 9, the nuisance rule at its current version), name the section the sentence means (not the one the stale number lands on), and rewrite as `holdout-rule.md, <Section name>` or `holdout-rule.md, <Section name> (<paragraph lead>)` for long sections. Same for `nuisance-rule.md`.
  3. Decision 6: a reference in a `#` comment or a module docstring is edited freely. A reference in a function or class docstring is edited only if its module is outside every fingerprint (`_ENVIRONMENT_PATHS` and the places modules of `evals/cve_baseline.py`, `GRAMMAR_PATHS`, the nuisance fixture and counter fingerprints). Otherwise leave it and list it in the commit message as left on purpose.
- **Test**: no new test. The grep above returns nothing afterwards, except references left on purpose under decision 6.
- **Verify**:
  - Recompute every fingerprint and diff against the saved ones: identical.
  - `tests/unit/support/test_cve_grammar_golden_given.py`, `test_cve_route_golden_given.py`, `test_cve_layout_check_golden_given.py` green without regeneration.
  - Closing check: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .`, `uv run pyright`.
  - Commit message `docs(evals): cite the rules by section rather than by line`.
