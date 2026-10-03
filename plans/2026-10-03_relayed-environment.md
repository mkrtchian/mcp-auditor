# Relayed environment

## Context

ADR 026 decides that `--env NAME` relays a variable from the auditor's environment to the server under audit and redacts its value everywhere the server can send it back, and that `--env-plain` relays a variable without redaction. This plan implements it. A server on the stdio transport takes its credentials from its environment, and today no clean way exists to give it one: the workarounds put the value in the command, which the report records as the target.

The redaction is the part with reach. Under ADR 014 the generator proves an injection by reading the process environment, so a relayed token comes back in tool responses, and from there it would flow into the state, the checkpoints, the prompts sent to the two models, the LangSmith trace, the report and the terminal. The redaction happens once, at the only boundary the graph has with the server, `AuditedServer`, so that nothing downstream ever holds the value. Two outputs bypass that boundary and get their own treatment: the server's stderr and the MCP SDK's logging.

## Decisions taken before this plan

1. **Marker**: `[value of NAME, redacted by mcp-auditor]`.
2. **Redaction is a pure domain object** (names and values to markers), applied in `AuditedServer` to every tool response and to the tool list, before the graph, the checkpoints and the report see them.
3. **Server stderr is redacted before it is stored.** The MCP SDK hands the stderr file descriptor to the child process (`anyio.open_process(..., stderr=errlog)` in `mcp/client/stdio/__init__.py`, mcp 1.26.0), so no Python `write()` ever sees the bytes and a file that redacts on write cannot work. The SDK receives the write end of an `os.pipe()`. A reader thread reads the other end, redacts, and keeps the text in memory. The value never reaches the disk, unlike today's `SpooledTemporaryFile`, which rolls over to a real temporary file as soon as the SDK asks for its `fileno()`.
4. **Prompt notice**: every prompt that carries text the server sent states that a marker stands for a value the server returned, only when at least one `--env` variable is relayed, so that the prompts of the evals stay byte-identical.
5. **SDK logging**: while at least one `--env` value is relayed, the level of the `mcp.client.stdio` logger is raised so that its `logger.exception("Failed to parse JSONRPC message from server")`, whose exception quotes the raw stdout line, prints nothing.
6. **CLI warnings, never refusals**: `--env` whose value is shorter than 8 characters. `--env-plain` whose name contains `TOKEN`, `KEY`, `SECRET`, `PASSWORD`, `PASS`, `CREDENTIAL` or `AUTH`, also under `--ci`. A declared `docker run` that does not name the variable in an environment flag (`-e`, `--env`, `--env=`, `--env-file`).
7. **Refusals before launch**: `--env NAME=value` (the message suggests exporting the variable and passing `--env NAME`, or `--env-plain` for a value that is not secret), a variable absent from the auditor's environment, `HOME` under the confined regime. No short form `-e`.
8. **`ExecutionRecord`** records the names of the `--env` variables, and the name-value pairs of the `--env-plain` ones.
9. **Mechanism by regime**: confined, `-e NAME` without a value in `container_argv` and the value added to the environment of the `docker` process. Unconfined, the variables added to the environment the SDK starts the server with (`get_default_environment() | variables`). Declared container, the value added to the `docker` process only, the user's argv untouched.
10. **No key in `.mcp-auditor.yml`. `compute_thread_id` unchanged.**
11. **Living docs**: README (usage and Safety), `CLAUDE.md`, `CHANGELOG.md` `[Unreleased]`.

## Readings decided here

These close gaps the decisions above leave open. Each follows from ADR 026 or from a refusal already decided.

1. **An empty value is refused** for `--env`: replacing the empty string would put a marker between every character. The refusal says so. Same reason as the refused `NAME=value`: a launch the redaction cannot honor stops before it starts. `--env-plain` accepts an empty value, nothing is replaced.
2. **A name given twice is refused**, whether twice to the same option or once to each: `--env X --env-plain X` has no single meaning. Repeating the same option with the same name is the same refusal, kept for simplicity.
3. **A name must be a shell variable name** (`[A-Za-z_][A-Za-z0-9_]*`), refused otherwise. It is the form `docker run -e` and the shell export both take, and a name with `=` in it is what the `NAME=value` refusal catches first.
4. **The SDK's root-logger warnings are covered too.** `mcp/shared/session.py` calls `logging.warning(f"Failed to validate request: {e}")` and the same for a notification, on the root logger, and both quote data the server sent. When the root logger has no handler, these module-level calls first run `logging.basicConfig()`, which attaches a stderr handler to the root logger, so they print to stderr. Raising the root logger's level would silence every library. A `logging.Filter` installed on the root logger, which applies the redaction to the formatted message, keeps them and redacts them. It is installed only for the duration of an audit, in the composition root. A filter on a logger is consulted only for records created on that logger, never for records propagated from a child logger: that is exactly the root-level calls of `session.py`, and of the child loggers, `mcp.client.stdio` quotes the raw stdout line and is silenced by its level (decision 5), while `mcp.client.session` quotes a tool name in `logger.warning(f"Tool {name} not listed by server ...")` and gets the same filter as the root. Both the level and the filters apply only while a value is relayed, so an audit without `--env` keeps today's diagnostics, the `Failed to parse JSONRPC message` line included. The filter redacts the traceback too (`record.exc_text`), since `logging.exception(f"Unhandled exception in receive loop: {e}")` in the same module carries the exception in `exc_info`, which a handler formats apart from the message.
5. **The tool list is redacted in descriptions, input schemas and names.** A name is what `call_tool` sends back to the server, so `AuditedServer` keeps the map from redacted name to original and calls the server with the original. A tool name that holds a relayed value is unlikely, and the map costs a dictionary. Under `--resume` the `discover_tools` node does not run again, the tools come from the checkpoint, so the map is also filled lazily: the first `attempt` that finds it unbuilt, with the redaction active, lists the server's tools once to build it.
6. **Streaming redaction keeps a carry.** The stderr reader receives chunks of arbitrary size, so a value can be split across two reads, or across a line break. The redactor holds back the last `L - 1` characters of its buffer, `L` being the length of the longest value, and emits them at the end of the stream. A line-by-line reader would miss a value that contains a newline.
7. **Longest values are replaced first.** When one relayed value contains another, replacing the shorter one first would leave part of the longer one in the clear.
8. **A `--env-plain` value is never redacted**, including where it appears inside an `--env` value. Its value is in the report by decision.
9. **The stderr text kept in memory is bounded** to its last 1 MiB, as the spool kept 1 MiB in memory before rolling over. The tail is what a failed launch needs.
10. **The prompt notice goes into the prompts of the seven builders**: generation (the tool header and the attack context come from the server), context extraction, judge, chain planning, step planning, step observation and chain judge. The dry-run graph takes it too, through generation.

11. **A name that steers the `docker` client is refused under the two container regimes**: any name starting with `DOCKER_`, plus `PATH` and `HOME`. The relayed values join the environment of the `docker` process, so `--env-plain DOCKER_HOST=tcp://elsewhere` would retarget it after `_require_a_local_runtime` checked the local endpoint, `DOCKER_DEFAULT_PLATFORM` would change the image variant pulled, `PATH` would change which `docker` binary runs, and `HOME` would move the client's configuration directory, whose `config.json` can name a remote context. The Docker CLI reference lists more `DOCKER_` variables than `docker_client_env` forwards, so the rule is the prefix, not a list. It holds whatever the value: one rule, and a server that needs these names inside its container is the `--unconfined` case. Under the confined regime `HOME` is also the profile's own value, which the same refusal covers.

## Approach

```
CLI options --env / --env-plain
        │  (pure parse against os.environ snapshot, in target_execution)
        ▼
RelayedEnvironment ──► ServerLaunch (argv -e NAME, spawn environment, record)
        │
        └──► Redaction ──► AuditedServer (responses, tool list)
                     ├──► RedactingStderr (pipe + reader thread + StreamRedactor)
                     ├──► root logging filter during the audit
                     └──► build_graph reads server.redacting ──► with_redaction_notice
```

## Files

### New: `src/mcp_auditor/domain/relayed_environment.py`

The relayed variables and their parsing. Pure: the environment is passed in.

```python
NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
SHORT_VALUE = 8
SECRET_WORDS = ("TOKEN", "KEY", "SECRET", "PASSWORD", "PASS", "CREDENTIAL", "AUTH")

@dataclass(frozen=True)
class RelayedVariable:
    name: str
    value: str
    redacted: bool

@dataclass(frozen=True)
class RelayRequest:
    redacted: tuple[str, ...]   # raw --env arguments
    plain: tuple[str, ...]      # raw --env-plain arguments

@dataclass(frozen=True)
class RelayedEnvironment:
    variables: tuple[RelayedVariable, ...] = ()

    @classmethod
    def resolved(cls, request: RelayRequest, environ: Mapping[str, str]) -> "RelayedEnvironment": ...
    @property
    def names(self) -> tuple[str, ...]: ...
    @property
    def values(self) -> dict[str, str]: ...          # name -> value, both kinds
    def redaction(self) -> "Redaction": ...           # the --env variables only
    def warnings(self) -> tuple[str, ...]: ...        # short values, secret-looking plain names

class RelayRefusedError(ValueError): ...              # carries the user-facing message
```

`resolved` raises `RelayRefusedError` for: a `--env` argument holding `=` (message: `--env NAME=value puts the value in your shell history and the process list: export NAME and pass --env NAME, or use --env-plain for a value that is not secret`), a name that does not match `NAME_PATTERN`, a name absent from `environ`, an empty `--env` value, a name given twice. `--env-plain NAME=value` splits on the first `=` and takes the value from the argument. `--env-plain NAME` takes it from `environ`, refused when absent. The `HOME` refusal is regime-dependent and lives in `target_execution.py`.

`warnings` returns, in option order: for each `--env` value shorter than `SHORT_VALUE`, `the value of NAME is N characters long: every occurrence of it in the server's output is replaced, including where it has nothing to do with the variable`. For each `--env-plain` name whose uppercase contains a `SECRET_WORDS` entry, `NAME looks like a secret and --env-plain records its value in the report: pass --env NAME to redact it`.

### New: `src/mcp_auditor/domain/redaction.py`

```python
def marker(name: str) -> str:
    return f"[value of {name}, redacted by mcp-auditor]"

@dataclass(frozen=True)
class Redaction:
    secrets: Mapping[str, str]                   # name -> value, non-empty values only

    @classmethod
    def none(cls) -> "Redaction": ...
    @property
    def active(self) -> bool: ...
    def text(self, text: str) -> str: ...         # longest value first
    def response(self, response: ToolResponse) -> ToolResponse: ...
    def tool(self, tool: ToolDefinition) -> ToolDefinition: ...   # name, description, every string in input_schema, keys included
    def stream(self) -> "StreamRedactor": ...

class StreamRedactor:
    def feed(self, chunk: str) -> str: ...        # emits all but the last longest-value-length - 1 characters
    def flush(self) -> str: ...
```

`Redaction.none().text(x)` returns `x` unchanged, and `StreamRedactor` with no secret holds nothing back. `tool` walks `input_schema` recursively (dicts, lists, strings), leaving numbers, booleans and `None` as they are.

### `src/mcp_auditor/domain/audited_server.py`

`AuditedServer(client, redaction: Redaction = Redaction.none())`. `list_tools` redacts each definition and records `redacted name -> original name`. On a resumed audit `list_tools` is never called (reading 5), so `attempt`, when the redaction is active and the map is still unbuilt, calls `self._client.list_tools()` once to build it. `attempt` sends `self._original_names.get(tool.name, tool.name)` to `call_tool` and redacts the `ToolResponse`. New property `redacting: bool` (`redaction.active`). Evals and tests that build `AuditedServer(client)` are unchanged.

### `src/mcp_auditor/graph/prompts.py` and `src/mcp_auditor/graph/chain_prompts.py`

```python
REDACTION_NOTICE = (
    "REDACTED VALUES. A marker such as `[value of NAME, redacted by mcp-auditor]` stands for a value "
    "the server returned: mcp-auditor replaced the value of the environment variable NAME before "
    "showing you the output. Read the marker as that value."
)
```

```python
def with_redaction_notice(prompt: str) -> str:
    return f"{prompt}\n\n{REDACTION_NOTICE}"
```

The seven builders keep their signatures: three of them already take four arguments (`build_attack_generation_prompt`, `build_chain_planning_prompt`, `build_step_planning_prompt`), and a fifth, a boolean, would go against the argument limit of `CLAUDE.md`. The notice and `with_redaction_notice` live in `prompts.py`, the one place a prompt is built, and the builders' output is byte-identical to today's by construction. `chain_prompts.py` does not change.
### `src/mcp_auditor/graph/nodes.py`, `src/mcp_auditor/graph/chain_nodes.py`, `src/mcp_auditor/graph/builder.py`

The factories that build a prompt (`make_generate_test_cases`, `make_judge_response`, `make_extract_attack_context`, `make_plan_chains`, `make_observe_step`, `make_plan_step`, `make_judge_chain`) take `redacting: bool = False` and, when it is `True`, pass their builder's prompt through `with_redaction_notice`. In `nodes.py` the generation prompt is built by `GenerationRequest.call_for`, so `GenerationRequest` gains a `redacting: bool` field that `make_generate_test_cases` fills, and `call_for` applies the notice. `build_graph` and `build_dry_run_graph` read `server.redacting` and pass it down. No new parameter on `build_graph`: the server under audit already carries the fact.

### `src/mcp_auditor/adapters/server_launch.py`

`ServerLaunch` gains `relayed: RelayedEnvironment = RelayedEnvironment()`. The named constructors take it as an optional keyword. New property:

```python
@property
def spawn_environment(self) -> Mapping[str, str] | None:
    """Variables added to the SDK's default environment, None when there are none to add."""
```

Confined and declared container: `client_env | relayed.values`.

Unconfined: `relayed.values`, or `None` when nothing is relayed, so that an unconfined launch without `--env` builds the same `StdioServerParameters` as today. `container_argv` appends `-e NAME` for each relayed name, after `-e HOME=...`. `record` fills two new fields for every regime: `relayed_variables` (the `--env` names) and `plain_variables` (the `--env-plain` name-value pairs), `None` when empty, so that the Markdown of a record without relays reads as today. The JSON does change: `render_json` dumps the model without `exclude_none`, so every JSON report gains `"relayed_variables": null` and `"plain_variables": null` under `execution`, and `test_json_carries_the_execution_record_with_the_full_digest` in `tests/unit/test_rendering.py`, which pins the exact key set, gains the two keys. The evals do not set `execution`, so their reports are unaffected.

### `src/mcp_auditor/adapters/mcp_client.py`

`_server_parameters` reads `launch.spawn_environment` instead of `launch.client_env`: `None` builds the parameters without `env`, otherwise `env=get_default_environment() | dict(...)`.

### New: `src/mcp_auditor/adapters/stderr_capture.py`

```python
class RedactingStderr:
    """The server's stderr, redacted before it is kept, and never written to disk."""

    def __init__(self, redaction: Redaction, keep: int = 1024 * 1024): ...
    def __enter__(self) -> Self: ...      # os.pipe(), the reader thread started, daemon
    def __exit__(self, *exc) -> None: ... # closes the write end, joins the thread (2 s timeout)
    @property
    def writer(self) -> TextIO: ...       # os.fdopen(write_fd, "w"), handed to the SDK as errlog
    def text(self) -> str: ...            # the redacted tail, at most `keep` characters
```

The thread reads bytes, decodes them with an incremental UTF-8 decoder (`errors="replace"`), feeds the `StreamRedactor`, and appends to a buffer trimmed to its last `keep` characters. At end of stream it flushes the decoder and the redactor. `text()` first closes the write end and joins the reader, idempotently with `__exit__`, so that `_give_up`, which runs inside the `with`, reads a finished tail. The buffer is guarded by a lock: a grandchild of the server that keeps the inherited stderr open delays the end of stream past the 2 s join, and the thread may still be appending. In that case the redactor's carry stays unflushed, which errs on the side of holding text back.

### `src/mcp_auditor/audit.py`

`Audit.run` replaces the `SpooledTemporaryFile` with `RedactingStderr(launch.relayed.redaction())` and passes its `writer` as `errlog`. `_give_up` takes the `RedactingStderr` and redacts its own message with the same `Redaction`, since an exception string can quote the server. `_probe_the_target` builds `AuditedServer(mcp_client, redaction)`. The root-logger filter is installed at the start of `run` and removed in a `finally`. The `RedactingStderr` block wraps the `try` that calls `_probe_the_target`, so it outlives the client's own block (the server process is gone when `_give_up` reads the tail).

### `src/mcp_auditor/console.py`

`print_server_stderr(text: str, display)` takes the redacted text instead of the file.

### `src/mcp_auditor/cli.py`

Two options, repeatable, CLI only:

```python
@click.option("--env", "env", multiple=True, help="Relay the variable NAME from your environment to the server, its value redacted from everything the server sends back (repeatable).")
@click.option("--env-plain", "env_plain", multiple=True, help="Relay NAME or NAME=value to the server without redaction, the value recorded in the report (repeatable).")
```

No short form. `LaunchOptions` gains `relay: RelayRequest = RelayRequest()` (both tuples default to `()`), and `Host` gains `environ: Mapping[str, str] = field(default_factory=dict[str, str])`, filled with `dict(os.environ)` in `_launch_context`. The defaults keep the existing builders compiling: `tests/unit/support/test_target_execution_given.py` and `tests/integration/test_confined_launch.py` build both without the new fields. `run` reads `params["env"]` and `params["env_plain"]` into the `RelayRequest`. The SDK loggers are handled in `Audit.run`, not here (see `log_redaction.py`). `config_file.KNOWN_KEYS` does not change, so an `env` key in the file is refused as an unknown key, which is the existing behavior.

### `src/mcp_auditor/target_execution.py`

`decide_launch` resolves `RelayedEnvironment.resolved(options.relay, host.environ)`, mapping `RelayRefusedError` to `LaunchRefused`, before the regime branch, so that a refusal happens before any image pull. Under the confined and declared container regimes, a name that steers the `docker` client is refused, whatever its value (reading 11): a pure predicate `steers_docker_client(name)` in `domain/confinement.py`, true for a name starting with `DOCKER_`, for `PATH` and for `HOME`. Message: `NAME steers the docker client that launches the container and cannot be relayed under this regime: run with --unconfined to pass it to the server`. `adapters/docker.py` does not change. Warnings: the relay's own, plus, under the declared container, one per relayed name the user's `docker run` does not pass: `your docker run does not pass NAME to the container: add -e NAME to it`. A pure helper in `domain/confinement.py`, `environment_names_passed(args) -> tuple[frozenset[str], bool]`, returns the names a `docker run` argv passes with `-e NAME`, `-e NAME=...`, `--env NAME`, `--env=NAME`, `--env=NAME=...`, and whether it holds `--env-file` or `--env-file=`. With an env file the auditor cannot tell, so no warning. The arguments read are those before the image, which is the first argument after `run` that is neither a flag nor a flag's value: to keep the helper simple and correct, it scans the whole argv, since an `-e` after the image belongs to the server's own command and a false negative there only suppresses a warning.

### New: `src/mcp_auditor/adapters/log_redaction.py`

```python
class RedactingFilter(logging.Filter):
    def __init__(self, redaction: Redaction): ...
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self._redaction.text(record.getMessage())
        record.args = None
        if record.exc_info:
            record.exc_text = self._redaction.text(logging.Formatter().formatException(record.exc_info))
        return True
```

Installed by `Audit.run` on the root logger and on `mcp.client.session`, only when the redaction is active, and removed in a `finally`. In the same `try`, and under the same condition, `Audit.run` raises `mcp.client.stdio` to `logging.CRITICAL` and restores its previous level afterwards, with a comment saying its exception quotes the raw line the server wrote. `cli.py` does not touch that logger.

### `src/mcp_auditor/domain/models.py` and `src/mcp_auditor/domain/rendering.py`

`ExecutionRecord` gains `relayed_variables: list[str] | None = None` and `plain_variables: dict[str, str] | None = None`. `_render_execution_lines` adds, for every regime, `**Relayed environment**: GITHUB_TOKEN (redacted), AWS_REGION=eu-west-1` when either is set, `--env` names first.

## What stays unchanged

- `compute_thread_id` and its pinned hash. The relayed names are not part of the target's identity (ADR 026, Consequences).
- `config_file.KNOWN_KEYS`.
- Everything the evals and the CVE benchmark build: `AuditedServer(client)`, `build_graph(...)` without a redacting server, `ServerLaunch.unconfined` and `declared_container` without `relayed`, `StdioMCPClient.connect(..., errlog=devnull)`. Their prompts, their launches and their reports stay byte-identical, so no baseline, fixture fingerprint or judge case id moves, and no declared flip is needed.
- `JudgeInputs` and `case_id`: the judge's inputs do not change, only an optional suffix of the prompt.
- `payload_safety`: a payload holding a marker is sent as written.
- The judge isolation eval calls `build_judge_prompt(tool, case)` and keeps doing so.

## Edge cases

| Case | Expected |
|---|---|
| `--env TOKEN=abc` | refused before launch, message names `--env TOKEN` and `--env-plain` |
| `--env TOKEN`, `TOKEN` unset | refused: `TOKEN is not set in your environment` |
| `--env TOKEN`, `TOKEN=""` | refused: an empty value cannot be redacted |
| `--env TOKEN --env-plain TOKEN` | refused: named twice |
| `--env 1BAD` | refused: not a variable name |
| `--env HOME`, confined or declared container | refused. Unconfined: relayed |
| `--env-plain DOCKER_HOST=tcp://elsewhere` or `--env PATH`, confined or declared container | refused, whatever the value. Unconfined: relayed |
| `--env-plain REGION=eu-west-1`, `REGION` unset | relayed with `eu-west-1`, recorded |
| `--env-plain API_KEY` | relayed, warning, also under `--ci` |
| `--env PIN` with a 4-character value | relayed, warning |
| `--env A --env B`, `B`'s value contains `A`'s | `B` replaced first, `A` inside it never shows |
| a value split across two stderr chunks, or across a newline | redacted |
| a tool whose name holds a value | the graph sees the marker name, the server is called with the original |
| declared `docker run` without `-e TOKEN` | relayed to the `docker` process, warning |
| declared `docker run --env-file f` | no warning |
| unconfined, no `--env` | `StdioServerParameters` built without `env`, as today |
| a server writing a non-JSON stdout line holding the value | nothing printed by `mcp.client.stdio` |
| a server sending an invalid notification holding the value | the root warning prints with the marker |
| `--resume` with a different `--env` set | resumes, nothing flagged (ADR 026) |
| `--resume` with `--env` of an audit first run without it | the checkpoint already holds the raw value, which the resumed run sends to the models, the trace and the report: accepted, stated in the README bullet |
| `--env-plain DOCKER_DEFAULT_PLATFORM=...` or `--env-plain HOME=...`, declared container | refused. Unconfined: relayed |
| a server writing junk to stdout, no `--env` | the `Failed to parse JSONRPC message` diagnostic still prints, as today |
| `env:` key in `.mcp-auditor.yml` | refused as an unknown key |

## Test scenarios

Unit, with fakes, under the given/then convention of each file:

- `tests/unit/test_relayed_environment.py` (new): every refusal and every warning of the table above, `NAME=value` for `--env-plain`, order of `names`, `values` merging both kinds, `redaction()` holding the `--env` ones only.
- `tests/unit/test_redaction.py` (new): `text` with no secret, one, two overlapping (longest first), a value occurring several times. `response` keeps `is_error` and `error_type`. `tool` on a nested schema with a value in a key, a string in a list and a description, numbers untouched. `StreamRedactor`: a value fed in two chunks, in one chunk per character, across a newline, nothing held back when inactive, `flush` returning the carry.
- `tests/unit/test_audited_server.py`: a fake client returning a response that holds the value yields the marker. `list_tools` redacts, and `attempt` on a redacted tool name calls the fake client with the original name, also on a fresh `AuditedServer` whose `list_tools` was never called (the resume case). `redacting` follows the redaction.
- `tests/unit/test_prompts.py`: `with_redaction_notice` returns the prompt followed by the notice, asserting on the returned text.
- `tests/unit/test_graph.py` (its given/then under `tests/unit/support/`): with an `AuditedServer` built on a redaction, the prompts of the seven steps that the fake LLM receives hold the notice, and none of them holds the value. Without it, no prompt holds the notice. `FakeLLM` in `tests/fakes/llm.py` gains a `prompts: list[str]` attribute that `generate_structured` appends to, which the test reads.
- `tests/unit/test_server_launch.py`: `container_argv` carries `-e NAME` without a value. `spawn_environment` per regime, `None` for an unconfined launch with nothing relayed. `record` fills both fields under each regime and leaves them `None` without relays.
- `tests/unit/test_target_execution.py`: `HOME`, `PATH` and a `DOCKER_`-prefixed name (`DOCKER_HOST`, `DOCKER_DEFAULT_PLATFORM`) refused under the two container regimes and relayed unconfined, `steers_docker_client` on each, the relay refusal mapped to `LaunchRefused` before any runtime call (a fake runtime that records calls stays untouched), the declared container warning and its absence with `-e NAME`, `--env=NAME`, `--env-file`.
- `tests/unit/test_cli.py`: `--env` and `--env-plain` reach `LaunchOptions`. `tests/unit/test_cli_config_file.py`: an `env` key is refused.
- `tests/unit/test_rendering.py`: the relayed environment line under each regime, its absence without relays, the JSON key set with the two new keys.
- `tests/unit/test_log_redaction.py` (new): a root-logger record whose message and whose exception both hold the value is emitted with the marker in both.
- `tests/unit/test_checkpointing.py`: the pinned hash unchanged for a launch with relays.

Integration, real subprocess, no LLM:

- `tests/integration/test_relayed_environment.py` (new): a small FastMCP server under `tests/integration/support/` with a tool that returns `os.environ.get(name)` and writes it to stderr and as a non-JSON line to stdout. Unconfined, `--env` relayed: the tool response through `AuditedServer` holds the marker, `RedactingStderr.text()` holds the marker and not the value, and a `caplog` on `mcp.client.stdio` at the level `Audit.run` sets captures nothing that holds the value. The server also sends an invalid notification whose params hold the value: the root warning `session.py` emits holds the marker, not the value, once the filter is installed. `--env-plain`: the value comes back in the clear.
- `tests/integration/test_confined_launch.py`: under Docker (the existing skip without it), a confined launch with `--env` reaches the variable inside the container.

## Living docs

- `README.md`: the two options in the table under `### CLI options`. A short paragraph under usage on servers that need a credential, with the `export` then `--env NAME` form. A bullet under `## Scope and limitations` (the README has no Safety section): it must not name ADR 013, since `tests/unit/test_readme_policy.py` requires exactly one bullet there to do so, the payload-safety one. The bullet: what is redacted, what is not (encoded, split or truncated values, secrets read from mounted files, `docker inspect` until the container is removed, `/proc/<pid>/environ` of the `docker` client to the same user while it runs, a checkpoint written by an earlier run without `--env` and then resumed, the server itself holds the value), and that the report records the names, and the values of `--env-plain`. Point to ADR 026. The existing `**Safety:**` paragraph of the same section says a finding "can quote a live secret, and nothing redacts it": rewrite that clause so it excepts the values relayed with `--env`, which are redacted, and keeps saying that any other secret is not.
- `CLAUDE.md`, Landmines: the stderr goes through a pipe because the SDK hands the file descriptor to the child, so a Python wrapper on the file sees nothing, and the `mcp.client.stdio` logger level and the filters on the root logger and `mcp.client.session`, set only while a value is relayed, are what keep a raw server line off the terminal. An SDK upgrade can add a log call that quotes server data: the integration test of the relayed environment is the guard, and a new call site needs a case there.
- `CHANGELOG.md`, `[Unreleased]` under Added: `--env` and `--env-plain`, the redaction, the report fields (the JSON `execution` object gains `relayed_variables` and `plain_variables`, `null` without relays).

## Verification

```bash
uv run pytest tests/unit -n auto
uv run pytest tests/integration -n auto
uv run ruff check . && uv run ruff format --check .
uv run pyright
FOO=supersecretvalue uv run mcp-auditor run --unconfined --dry-run --env FOO -- uv run python tests/integration/support/env_echo_server.py
```

The last command needs an LLM key, since a dry run generates payloads. The evals are not run: nothing they build changes.

## Due diligence record

What the plan-diligence pass concluded about the external facts this plan cites or defers, read by the later passes. A line here records what was concluded once, not what is true now: no pass may treat it as a reason to skip a verification. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- SETTLED: `mcp` 1.26.0, the version in `uv.lock`, hands `errlog` to the child as `anyio.open_process(..., stderr=errlog)` in `mcp/client/stdio/__init__.py` (verified against the installed package source)
- SETTLED: `logger.exception("Failed to parse JSONRPC message from server")` on the `mcp.client.stdio` logger (`logging.getLogger(__name__)`), mcp 1.26.0 (verified against the installed package source)
- SETTLED: `logging.warning(f"Failed to validate request: {e}")`, `logging.warning(f"Failed to validate notification: {e}. Message was: ...")`, `logging.exception(f"Unhandled exception in receive loop: {e}")` and `logging.warning(f"Response ID {response_id!r} cannot be normalized ...")` on the root logger in `mcp/shared/session.py`, mcp 1.26.0 (verified against the installed package source)
- SETTLED: `get_default_environment()` in `mcp.client.stdio`, and `stdio_client` itself merges `server.env` over it when `env` is not `None` (verified against the installed package source)
- SETTLED: a filter on a logger is not consulted for records propagated from descendant loggers (verified against docs.python.org/3/library/logging.html)
- SETTLED: module-level `logging.warning()` and siblings call `basicConfig()` when the root logger has no handler (verified against docs.python.org/3/library/logging.html, corrected in reading 4)
- SETTLED: `Formatter.format` reuses a preset `record.exc_text` instead of formatting `exc_info` again (verified against the CPython 3.13 stdlib source)
- SETTLED: `SpooledTemporaryFile.fileno()` calls `rollover()` (verified against the CPython 3.13 stdlib source)
- SETTLED: `docker run -e NAME` without `=` takes the value from the docker client's environment (verified against docs.docker.com/reference/cli/docker/container/run/)
- SETTLED (accepted): `mcp` stays locked at 1.26.0 under `mcp>=1.0.0` (PyPI's latest 1.30.0, 2026-09-07). No tighter pin: the integration test covers the stdout line, the root warning and the tool response, and the `CLAUDE.md` landmine says a new log call site needs a case there
- SETTLED: the refused names are the `DOCKER_` prefix plus `PATH` and `HOME` (reading 11), which covers `DOCKER_API_VERSION`, `DOCKER_TLS`, `DOCKER_CUSTOM_HEADERS`, `DOCKER_DEFAULT_PLATFORM` and the `$HOME/.docker` configuration directory listed in docs.docker.com/reference/cli/docker/

## Implementation steps

Verification commands for every step: `uv run pytest tests/unit -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` (strict). Steps 5 and 6 also run `uv run pytest tests/integration -n auto`. Each step is one commit and leaves the suite green. The order keeps every intermediate commit safe: no CLI option reaches a server before the redaction, the stderr capture and the logging filter are in place (step 6 comes last).

### Step 1: Redaction and the redacting `AuditedServer`

- **Files**: `tests/unit/test_redaction.py` (new), `tests/unit/test_audited_server.py`, `src/mcp_auditor/domain/redaction.py` (new), `src/mcp_auditor/domain/audited_server.py`
- **Do**:
  - Tests first (given/then helpers only where they abstract something, see the testing standards).
  - `domain/redaction.py` as in the plan section of the same name: `marker(name)`, frozen `Redaction(secrets: Mapping[str, str])` with `none()`, `active`, `text` (longest value first, reading 7), `response(ToolResponse)` (keeps `is_error`, `error_type`), `tool(ToolDefinition)` (name, description, every string of `input_schema` recursively, dict keys included, numbers, booleans and `None` untouched), `stream() -> StreamRedactor`. `StreamRedactor.feed(chunk)` emits everything but the last `L - 1` characters of its buffer (`L` the longest value length), after redaction, `flush()` emits the redacted carry. No secret: nothing held back.
  - `AuditedServer(client, redaction: Redaction = Redaction.none())`: `list_tools` redacts each definition and records redacted name to original name. `attempt` (after the destructive guard, unchanged) builds the map lazily when the redaction is active and the map is unbuilt, by calling `self._client.list_tools()` once (resume case, reading 5), sends `self._original_names.get(tool.name, tool.name)` to `call_tool`, and returns the redacted `ToolResponse`. `BlockedPayload` is returned as today. New property `redacting -> bool`. Callers building `AuditedServer(client)` stay unchanged.
- **Test**:
  - `text`: no secret returns input unchanged. One secret replaced by `[value of NAME, redacted by mcp-auditor]`. Several occurrences all replaced. `A` contained in `B`: `B`'s marker, no fragment of `B` left.
  - `response` redacts `content`, keeps `is_error` and `error_type`.
  - `tool` on a nested schema: value in a key, in a string inside a list, in the description, in the name are replaced, an integer and a boolean untouched.
  - `StreamRedactor`: value split over two chunks, fed one character per chunk, spanning a newline, all redacted after `flush`. Inactive redaction returns each chunk as is. `flush` returns the held carry.
  - `AuditedServer`: a `FakeMCPClient` response holding the value comes back with the marker. `list_tools` returns redacted definitions. `attempt` with a redacted tool name reaches the fake client under the original name, both after `list_tools` and on a fresh server whose `list_tools` was never called. `redacting` is `False` with `Redaction.none()`, `True` with a secret. Assert on what the fake client received through its observable state (check how `tests/fakes` exposes calls, add a recorded-calls attribute to `FakeMCPClient` if none exists).
- **Verify**: the four commands above, all green, the new tests seen red before the implementation.

### Step 2: The `RelayedEnvironment` domain object

- **Files**: `tests/unit/test_relayed_environment.py` (new), `src/mcp_auditor/domain/relayed_environment.py` (new)
- **Do**:
  - Tests first.
  - As in the plan section of the same name: `NAME_PATTERN`, `SHORT_VALUE = 8`, `SECRET_WORDS`, frozen `RelayedVariable(name, value, redacted)`, frozen `RelayRequest(redacted: tuple[str, ...] = (), plain: tuple[str, ...] = ())` (defaults needed by step 6), frozen `RelayedEnvironment(variables=())` with `resolved(request, environ)`, `names` (option order, `--env` ones first then `--env-plain`, matching the rendering order), `values` (both kinds), `redaction()` (the `--env` ones only, so a `--env-plain` value is never redacted, reading 8), `warnings()`, and `RelayRefusedError(ValueError)`.
  - Refusals with the exact messages of the plan: `--env NAME=value` (message names `--env NAME` and `--env-plain`), invalid name (reading 3), absent from `environ` (`NAME is not set in your environment`), empty `--env` value (says an empty value cannot be redacted, reading 1), a name given twice in any combination (reading 2). `--env-plain NAME=value` splits on the first `=`, `--env-plain NAME` reads `environ`, refused when absent, an empty plain value accepted.
  - Warnings with the exact texts of the plan, in option order.
- **Test**: every refusal above, `--env-plain REGION=eu-west-1` with `REGION` unset relayed, `--env-plain X=a=b` gives `a=b`, empty plain value accepted, `names` order, `values` merging both kinds, `redaction()` holding only `--env` values, warnings for a 4-character `--env` value and for `--env-plain API_KEY` (and lowercase `api_key`), no warning for an 8-character value or `--env-plain REGION`. Group refusals with `pytest.mark.parametrize` to keep the file short.
- **Verify**: the four commands, all green.

### Step 3: The redaction notice in the prompts

- **Files**: `tests/fakes/llm.py`, `tests/unit/test_prompts.py`, `tests/unit/test_graph.py`, `tests/unit/support/test_graph_given.py`, `tests/unit/support/test_graph_then.py`, `src/mcp_auditor/graph/prompts.py`, `src/mcp_auditor/graph/nodes.py`, `src/mcp_auditor/graph/chain_nodes.py`, `src/mcp_auditor/graph/builder.py`
- **Do**:
  - Tests first. `FakeLLM` gains `prompts: list[str]`, appended by `generate_structured`.
  - `prompts.py`: `REDACTION_NOTICE` (exact text of the plan) and `with_redaction_notice(prompt) -> str` returning `f"{prompt}\n\n{REDACTION_NOTICE}"`. No builder signature changes, `chain_prompts.py` untouched.
  - `nodes.py`: `GenerationRequest` gains `redacting: bool = False` (filled by `make_generate_test_cases`), `call_for` applies the notice when set. `make_generate_test_cases`, `make_judge_response`, `make_extract_attack_context` take `redacting: bool = False`.
  - `chain_nodes.py`: `make_plan_chains`, `make_observe_step`, `make_plan_step`, `make_judge_chain` take `redacting: bool = False` and wrap their prompt when set.
  - `builder.py`: `build_graph` and `build_dry_run_graph` read `server.redacting` and pass it to the seven factories through the subgraph builders. No new parameter on `build_graph`.
- **Test**:
  - `with_redaction_notice("P")` returns `"P"` followed by a blank line and the notice.
  - `test_graph.py`: a graph built on `AuditedServer(FakeMCPClient(...), Redaction({"TOKEN": value}))` whose fake server returns the value, with chains enabled so the seven steps run: every prompt in `FakeLLM.prompts` holds the notice, none holds the value. The same graph on `AuditedServer(client)`: no prompt holds the notice. Reuse the scripted responses of the existing chain-enabled graph test in `test_graph_given.py`.
- **Verify**: the four commands, all green. The eval prompts stay byte-identical by construction (no builder output changes without a redacting server).

### Step 4: Relayed variables in the launch and the execution record

- **Files**: `tests/unit/test_server_launch.py` (and `tests/unit/support/test_server_launch_given.py` if a helper earns its place), `tests/unit/test_rendering.py` (and its given/then under `tests/unit/support/`), `tests/unit/test_checkpointing.py`, `src/mcp_auditor/adapters/server_launch.py`, `src/mcp_auditor/adapters/mcp_client.py`, `src/mcp_auditor/domain/models.py`, `src/mcp_auditor/domain/rendering.py`
- **Do**:
  - Tests first.
  - `ServerLaunch` gains `relayed: RelayedEnvironment = RelayedEnvironment()`, each named constructor takes it as an optional keyword. New property `spawn_environment`: confined and declared container `client_env | relayed.values`, unconfined `relayed.values` or `None` when nothing is relayed. `container_argv` appends `-e NAME` (no value) for each relayed name right after `-e HOME=...`. Its only caller is `spawn_args`, so its signature becomes `container_argv(launch: ServerLaunch, profile: ContainerProfile)`, reading `command`, `args` and `relayed.names` from the launch, rather than growing a fourth argument. `record` fills `relayed_variables` (the `--env` names) and `plain_variables` (the `--env-plain` name-value pairs) under every regime, `None` when empty.
  - `mcp_client._server_parameters` reads `launch.spawn_environment`: `None` builds without `env`, otherwise `env=get_default_environment() | dict(...)`.
  - `ExecutionRecord` gains `relayed_variables: list[str] | None = None` and `plain_variables: dict[str, str] | None = None`.
  - `_render_execution_lines` appends, under every regime, `**Relayed environment**: GITHUB_TOKEN (redacted), AWS_REGION=eu-west-1` when either field is set, `--env` names first. Restructure so the line is added after the regime-specific lines, keeping the function under 20 lines.
- **Test**:
  - `container_argv` holds `-e`, `NAME` with no `=` after `HOME=...`. `spawn_environment` per regime, `None` for an unconfined launch without relays, the relayed values merged over `client_env` under the container regimes. `record` fills both fields under each regime, both `None` without relays.
  - Rendering: the relayed environment line under each regime, absent without relays. `test_json_carries_the_execution_record_with_the_full_digest` gains the two keys.
  - `test_checkpointing.py`: `compute_thread_id` of an unconfined launch with relays equals the pinned literal hash.
- **Verify**: the four commands, all green. `evals/` unchanged (`git diff --stat evals` empty).

### Step 5: Redacted stderr, SDK logging and the `Audit` wiring

- **Files**: `tests/unit/test_log_redaction.py` (new), `tests/integration/support/env_echo_server.py` (new), `tests/integration/test_relayed_environment.py` (new), `src/mcp_auditor/adapters/stderr_capture.py` (new), `src/mcp_auditor/adapters/log_redaction.py` (new), `src/mcp_auditor/audit.py`, `src/mcp_auditor/console.py`, `CLAUDE.md`
- **Do**:
  - Tests first.
  - `env_echo_server.py`: a FastMCP stdio server with one tool taking a variable name, returning `os.environ.get(name)`, writing the value to stderr and a non-JSON line holding it to stdout (`sys.stdout.write` then flush, raw, outside the JSON-RPC framing), and sending a notification with invalid params holding the value so that `mcp/shared/session.py` logs its root-level `Failed to validate notification` warning. Look at the installed `mcp` 1.26.0 source to pick a notification the client validates and rejects.
  - `log_redaction.py`: `RedactingFilter` as in the plan. Add a context manager there, e.g. `redacted_sdk_logging(redaction)`, that does nothing when the redaction is inactive, otherwise installs the filter on the root logger and on `mcp.client.session`, raises `mcp.client.stdio` to `logging.CRITICAL` (comment: its exception quotes the raw line the server wrote), and restores everything on exit.
  - `stderr_capture.py`: `RedactingStderr` as in the plan (pipe, daemon reader thread, incremental UTF-8 decoder with `errors="replace"`, `StreamRedactor`, buffer trimmed to the last `keep` characters under a lock, `writer`, idempotent close-and-join in `text()` and `__exit__` with a 2 s join timeout).
  - `audit.py`: `run` opens `RedactingStderr(launch.relayed.redaction())` around the `try` that calls `_probe_the_target`, and enters `redacted_sdk_logging` for the same span, passes `writer` as `errlog`. `_probe_the_target` builds `AuditedServer(mcp_client, redaction)`. `_give_up` takes the `RedactingStderr`, redacts its message with the same `Redaction`, prints `stderr.text()`. Drop the `tempfile` import.
  - `console.print_server_stderr(text: str, display)`: strips and prints when non-empty.
  - `CLAUDE.md` Landmines: the bullet of the plan's Living docs section (pipe because the SDK hands the fd to the child, the logger level and the two filters active only while a value is relayed, the integration test as the guard against a new SDK log call site).
- **Test**:
  - Unit `test_log_redaction.py`: a record on a logger carrying the filter, whose message (with `%s` args) and exception both hold the value, formatted by a handler, holds the marker in both and not the value. An inactive `redacted_sdk_logging` leaves levels and filters untouched.
  - Integration `test_relayed_environment.py`, unconfined launch of `env_echo_server.py` with `--env` relayed via `ServerLaunch.unconfined(..., relayed=RelayedEnvironment.resolved(...))` and `StdioMCPClient.connect(..., errlog=stderr.writer)`: the tool response through `AuditedServer` holds the marker. `RedactingStderr.text()` holds the marker, not the value. With `redacted_sdk_logging` active, `caplog` captures nothing holding the value from `mcp.client.stdio`, and the root `session.py` warning holds the marker. `--env-plain`: the value comes back in the clear. Without relays, the `Failed to parse JSONRPC message` record is still emitted.
- **Verify**: the four commands plus `uv run pytest tests/integration -n auto`, all green.

### Step 6: CLI options, launch decision and living docs

- **Files**: `tests/unit/test_target_execution.py` (and `tests/unit/support/test_target_execution_given.py`), `tests/unit/test_cli.py` (and `tests/unit/support/test_cli_given.py`), `tests/unit/test_cli_config_file.py`, `tests/integration/test_confined_launch.py`, `src/mcp_auditor/domain/confinement.py`, `src/mcp_auditor/target_execution.py`, `src/mcp_auditor/cli.py`, `README.md`, `CHANGELOG.md`
- **Do**:
  - Tests first.
  - `confinement.py`: pure `steers_docker_client(name) -> bool` (`DOCKER_` prefix, `PATH`, `HOME`) and `environment_names_passed(args) -> tuple[frozenset[str], bool]` (`-e NAME`, `-e NAME=...`, `--env NAME`, `--env=NAME`, `--env=NAME=...`, and whether `--env-file` or `--env-file=` appears, scanning the whole argv).
  - `target_execution.py`: `LaunchOptions` gains `relay: RelayRequest = RelayRequest()`, `Host` gains `environ: Mapping[str, str] = field(default_factory=dict[str, str])`. `decide_launch` resolves the relay first (`RelayRefusedError` to `LaunchRefused`), before the regime branch and any runtime call. Under the two container regimes, refuse a name for which `steers_docker_client` holds, with the plan's message. Pass `relayed=` to each `ServerLaunch` constructor. Warnings: the relay's own under every regime, plus, under the declared container, `your docker run does not pass NAME to the container: add -e NAME to it` for each relayed name missing from `environment_names_passed`, none when an env file is present. Keep `decide_launch` under 20 lines by extracting a helper.
  - `cli.py`: `--env` and `--env-plain` options (`multiple=True`, help texts of the plan, no short form), `LaunchOptions(relay=RelayRequest(redacted=tuple(params["env"]), plain=tuple(params["env_plain"])))`, `Host(environ=dict(os.environ))` in `_launch_context`. `config_file.KNOWN_KEYS` unchanged.
  - `test_confined_launch.py`: under Docker (existing skip), a confined launch with `--env` reaches the variable inside the container (`HOME`-free name, value from `monkeypatch.setenv`).
  - `README.md`: the two options in the `### CLI options` table, the usage paragraph on servers needing a credential (`export` then `--env NAME`), the `## Scope and limitations` bullet listing what is and is not redacted (never naming ADR 013, `tests/unit/test_readme_policy.py` must stay green), pointing to ADR 026, and the `**Safety:**` clause rewritten to except the `--env` values.
  - `CHANGELOG.md` `[Unreleased]` under Added: the two options, the redaction, the report fields (`relayed_variables` and `plain_variables` in the JSON `execution` object, `null` without relays).
- **Test**:
  - `test_target_execution.py`: `HOME`, `PATH`, `DOCKER_HOST`, `DOCKER_DEFAULT_PLATFORM` refused under confined and declared container, relayed unconfined. `steers_docker_client` per name (parametrized). A relay refusal raised as `LaunchRefused` with the fake runtime recording no call. The declared container warning, absent with `-e NAME`, `--env=NAME`, `--env-file f`. The relay warnings surfaced in `LaunchDecision.warnings`. `environment_names_passed` cases parametrized.
  - `test_cli.py`: `--env` and `--env-plain`, repeated, reach `LaunchOptions.relay`. `test_cli_config_file.py`: an `env` key is refused as unknown.
- **Verify**: the four commands plus `uv run pytest tests/integration -n auto`, all green. Then by hand, with an LLM key: `FOO=supersecretvalue uv run mcp-auditor run --unconfined --dry-run --env FOO -- uv run python tests/integration/support/env_echo_server.py`, no `supersecretvalue` on the terminal.
