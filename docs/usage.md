# Using mcp-auditor

This page is the reference for running an audit.

## What an audit does

### Generation

A batch that comes back short of the budget or of the categories is asked for once more, a batch still missing categories after the retry is asked for those categories alone, and a tool whose batch is still incomplete after that is flagged, with the cases received and the categories missing, in every output format. A model call (a generation, a judgment, a chain step) that the model provider refuses on policy grounds, whose answer still matches no expected format after the parse attempts, that the provider throttled past every retry, or whose prompt the model provider rejected as longer than the model's context window, is reported the same way, as a missed model call with its cause (the report's `missed_model_calls`) and a detail, such as the provider's message, the number of attempts or the seconds waited, and the audit carries on without it. The usage of a missed model call is counted. `--resume` does not retry a missed model call, so a model call throttled past every retry stays missed on resume even though its cause was transient.

### Execution

When the server stops answering, through a lost connection or a call that timed out on a server that then leaves a ping unanswered, the auditor relaunches it from the same server command. A tool whose calls time out 3 times in a row on a server that still answers the ping is no longer called, and when the next tool's calls do the same the server is taken as stuck and relaunched. A tool whose calls lead to 2 relaunches in a row is no longer called either, and a relaunch that fails takes the server as down: the auditor sends it no further call and writes the report. The report names each relaunch under its tool, with the arguments of the call before it and its cause, and counts them in its summary (`relaunches` in the JSON report). The cases and chains not sent are counted in the tool's coverage gap with their cause (`unsent_cases`, `unsent_chains` and `unsent_cause`), so the audit is incomplete, and a chain cut by a relaunch is judged on the steps it made. [ADR 036](adr/036-stopped-server-relaunched.md)

### Judgment

The judge's criteria are written rules, the rules shared by every category (`JUDGING_RULES` in `graph/prompts.py`) and one guidance per category in `domain/category_guidance.py`, versioned and reviewable, not pattern matches over the response. They follow the clauses that label the judge cases, in [`docs/labeling-log.md`](labeling-log.md), and the chain judge reads the same criteria as the single-call judge. The judge is scoped to the single category under test so it cannot report a leak while grading an injection.

A response or error longer than 20,000 characters is shown to the model with its middle cut, its start and end kept around a marker naming how many characters were cut (`[N characters cut by mcp-auditor]`), so a huge response neither overflows the model's context window nor costs a prompt of a million tokens. The report and the JSON export keep the response whole, and count per tool the responses shown cut (`cut_responses` in the JSON report).

### Cross-tool learning

After each tool audit, the graph extracts intelligence from the results (database engine, framework, exposed internals). Subsequent tools receive this context for targeted payloads, e.g. SQLite-specific injection after seeing `sqlite3.OperationalError` in a read tool. The extraction reports what the current tool's results show, and the auditor merges it in code into a context of bounded size, so it does not grow with the number of tools. Read-like tools are audited first to front-load reconnaissance. [ADR 009](adr/009-cross-tool-learning.md), [ADR 035](adr/035-attack-context-merged-in-code.md)

### Attack chains

Chains call one tool repeatedly, so they catch vulnerabilities that need an earlier probe to surface internal state before a later payload uses it. Sequencing a discovery on one tool into an exploit on another is not built yet. [ADR 010](adr/010-multi-step-attack-chains.md)

## Token usage and throttling

Every audit run reports its token usage, and the number of requests the model provider throttled (answered with HTTP 429). The audit warns at the first one. A throttled request is retried by the provider's client, and when those retries run out the auditor waits and tries again: it honours the delay the provider sends, otherwise waits a growing delay, spreads each delay randomly upward so concurrent calls do not retry together, and logs one warning per wait. The auditor's waiting is bounded at five minutes per model call, on top of the provider client's own retries. A 429 the provider marks as not worth retrying (no credit left, or a spend or usage limit reached) is not waited on and stops the audit with the provider's error. A call that has waited its five minutes is a missed model call, and the later calls of the same audit, generator and judge alike, are not sent and are missed too, so an audit on a provider that does not recover ends quickly. A count above zero is a sign to lower the concurrency of what shares the API key or to expect a slower audit.

## Confinement

By default the audited server runs in a Docker container (the `confined` regime): Docker has to be installed and its daemon running, or the audit stops before anything is launched. A command that is already a `docker run` is audited as you wrote it, flags included (`declared_container`). `--unconfined` runs the server directly on this host with your privileges (`unconfined`), which is the form to use for a server whose code you wrote and trust, or on a machine without Docker. Starting containers requires membership in the `docker` group, which is equivalent to root on the host.

In the default container the server does not see the rest of your filesystem, the services bound to your host's loopback interface, your privileges (all capabilities dropped, no privilege escalation, your own uid), or the auditor's environment and API key, except the variables you relay with `--env` or `--env-plain`. What it does see: the paths your command names, mounted writable at the same absolute path, and the Internet, since egress stays open. An argument counts as a path only when the whole argument is spelled like one (absolute, `.`, `..`, `./…`, `../…`), so `--root=./data` is not mounted and a bare word like `build` never is. The report records the regime, the image and its digest, and the mounted paths. [ADR 017](adr/017-confined-target-execution.md), [ADR 018](adr/018-container-confinement.md)

The confinement options, like every other option, go before the `--` that starts the server's own command:

```bash
mcp-auditor run --mount /etc/ssl/certs -- npx some-mcp-server ./workdir
```

With `--image`, the image has to carry the server's dependencies: `--image my-image -- python ./server.py` mounts `server.py`, not the virtual environment it runs in.

### Default images

The image follows from the launcher, the first word of the server command: `npx` runs in `node:24-bookworm-slim` and `uvx` in `ghcr.io/astral-sh/uv:python3.14-trixie-slim`. A default image carries the launcher and little else, so a server that calls another program (`git`, `kubectl`) needs an image that has it, which you pass with `--image`.

### Removing the container

The auditor removes its container, with its logs, its files and its anonymous volumes, before each relaunch and when a run ends, however it ends. A declared `docker run` is removed before a relaunch and when the audit ends only when its command sets a `--name`: without one it is left as it is, so a blocked server can keep running in it beside the relaunched one, and a server that ignores the end of its input can keep running after the audit. Under the confined regime a relaunch fetches the server package again, so an `npx` or `uvx` command without a pinned version can launch another version of the server than the one audited before it. If a container of the auditor is ever left behind, they all carry the same label:

```bash
docker rm -f $(docker ps -aq --filter label=mcp-auditor)
```

## Relaying a credential

A server that needs a credential reads it from its environment. Export the variable in your shell, then name it with `--env`, never its value:

```bash
export GITHUB_TOKEN=...
mcp-auditor run --env GITHUB_TOKEN -- npx some-mcp-server
```

`--env GITHUB_TOKEN=...` is refused, since the value would stay in your shell history and the process list. `--env-plain AWS_REGION=eu-west-1` relays a value that is not secret, unredacted. Neither option has a key in the configuration file. Under a container regime, a name that steers the `docker` client (`HOME`, `PATH`, any `DOCKER_…` name) is refused: run with `--unconfined` to relay it. A `docker run` you wrote yourself receives a relayed variable only through its own `-e NAME`.

The value of a variable relayed with `--env` is replaced by `[value of NAME, redacted by mcp-auditor]` in the tool responses, the tool list and the server's error output before anything stores or forwards them, so the models, the checkpoints, the trace, the report and the terminal see the marker. What it does not catch: a value the server returns encoded, split or truncated, a secret it reads from a mounted file or anywhere else than a relayed variable, the container's configuration that `docker inspect` shows until the container is removed, the environment of the `docker` client, readable under `/proc` by your own user while it runs, and a checkpoint written by an earlier run without `--env` and then resumed with it. The server itself holds the value in the clear, and every tool call runs with the real credential. A short value is replaced wherever it occurs, including where it has nothing to do with the variable. The report records the names of the relayed variables, and the values of those relayed with `--env-plain`. [ADR 026](adr/026-relayed-environment.md)

## Safety

Run the auditor only against a server whose state you can restore, never against production. A secret the audited server reads under a mounted path is a live secret of your host, not of a copy. And treat the audit report as sensitive. To prove impact, the auditor reads real data, environment variables included, so a finding can quote a live secret. Only the values you relay with `--env` are redacted, any other secret is not ([ADR 014](adr/014-proving-impact.md)). The same secret reaches the judge model, and your LangSmith traces if tracing is enabled. With the default `anthropic` provider, Anthropic does not retain prompts and outputs by default, but it may keep a call its automated trust and safety systems flag for up to 2 years, and an audit sends attack payloads such systems may flag. With `openai`, OpenAI keeps abuse-monitoring logs of API requests for up to 30 days by default, so a secret quoted to the model stays on its side that long. With `openrouter`, retention and training depend on the host that serves the call and on your OpenRouter account settings.

## Configuration

Copy `.env.example` to `.env` and edit, or export variables directly. The options of the command line are listed in the [README](../README.md#configuration).

### Environment variables

| Variable                     | Default                | Description                               |
|:---------------------------|:---------------------|:------------------------------------------|
| `MCP_AUDITOR_PROVIDER`     | `anthropic`          | LLM provider: `anthropic`, `openai`, `google`, `fireworks`, `alibaba` or `openrouter` |
| `MCP_AUDITOR_MODEL`        | per-provider default | Override the main model name              |
| `MCP_AUDITOR_JUDGE_MODEL`  | same as main model   | Separate model for verdict classification |
| `MCP_AUDITOR_REASONING`    | per-provider default | Reasoning setting sent to the main and judge models: `minimal`, `low`, `medium` or `high` for `google`, `none`, `low`, `medium`, `high`, `xhigh` or `max` for `openai`, `low`, `medium` or `high` for `fireworks`, `none`, `low`, `medium`, `high`, `xhigh` or `max` for `anthropic` (`none` turns thinking off), `none`, `minimal`, `low`, `medium`, `high`, `xhigh` or `max` for `openrouter` (OpenRouter's `reasoning.effort`: a level the model's OpenRouter listing does not publish is refused when the model is built, and when the listing gives no list or cannot be read, a warning is logged and a level the routed model does not take fails at call time), not accepted for `alibaba` |
| `OPENAI_API_KEY`           | --                   | Required when provider is `openai`        |
| `GOOGLE_API_KEY`           | --                   | Required when provider is `google`        |
| `ANTHROPIC_API_KEY`        | --                   | Required when provider is `anthropic`     |
| `FIREWORKS_API_KEY`        | --                   | Required when provider is `fireworks`     |
| `DASHSCOPE_API_KEY`        | --                   | Required when provider is `alibaba` (Alibaba Cloud Model Studio, international) |
| `OPENROUTER_API_KEY`       | --                   | Required when provider is `openrouter`    |
| `MCP_AUDITOR_OPENROUTER_PROVIDERS` | unset (OpenRouter routes) | Comma-separated OpenRouter provider slugs (`sail-research`, `deepinfra/fp4`) the `openrouter` calls are pinned to, in that order, with no fallback to another host. Your OpenRouter account privacy settings filter hosts first, so a pinned host they exclude fails every call. Ignored by the other providers |
| `LANGSMITH_TRACING`        | --                   | Set to `true` to activate tracing         |
| `LANGSMITH_API_KEY`        | --                   | LangSmith API key (required for tracing)  |
| `LANGSMITH_PROJECT`        | --                   | LangSmith project name for traces (unset, LangSmith uses its own default) |
| `LANGSMITH_ENDPOINT`       | US region            | Set to the EU URL if your workspace is EU |
| `MCP_AUDITOR_TOOL_CALL_TIMEOUT` | `60`           | Seconds before a tool call is abandoned and judged as a timeout error. A tool whose calls time out 3 times in a row is no longer called, so raise it to give a slow tool more time before its calls count as timeouts |

With the default `anthropic` provider, the main model and the judge both run `claude-haiku-5-5` at reasoning effort `low`. With `openai` they run `gpt-6-luna` at reasoning effort `none`. With `google` they run `gemini-3.5-flash-lite` at thinking level `minimal`. With `fireworks` they run GLM-5.3-Flash (`accounts/fireworks/models/glm-5p3-flash`) at reasoning effort `medium`: it is a thinking-only model, and the schema Fireworks enforces does not stop its reasoning. With `alibaba` they run `qwen3.8-flash` on Alibaba Cloud Model Studio's international endpoint, with thinking always off. With `openrouter` they run GLM 5.3 (`z-ai/glm-5.3`) at reasoning effort `low`, its cheapest setting, on the hosts `MCP_AUDITOR_OPENROUTER_PROVIDERS` pins. Pin them: unpinned, OpenRouter's routing may land on a host that filters security content or serves a lower quantization, and your account privacy settings can exclude a pinned host, which then fails every call. The default reasoning applies to the provider's default model only: a model named by `MCP_AUDITOR_MODEL` or `MCP_AUDITOR_JUDGE_MODEL` is sent no reasoning setting, so its API default applies, unless `MCP_AUDITOR_REASONING` is set.

### Configuration file

Place a `.mcp-auditor.yml` in your project root to avoid repeating CLI flags:

```yaml
budget: 15
chains: 2
severity_threshold: high
tools:
  - get_user
  - list_items
output: report.json
ci: true
```

CLI flags override config file values. `unconfined`, `image` and `mount` are deliberately not file keys: the file is read from the audited project's own directory, so a file could otherwise turn off the confinement of the server it ships.

## Exit codes

Without `--ci`, an audit that reaches its report exits with code 0 whatever it found. With or without `--ci`, the audit exits with code 1 before any server is launched when the launch is refused (Docker not running, a launcher with no default image, a path the auditor will not mount, a variable it will not relay) or when the model cannot be set up (a missing API key, for instance). The auditor prints the reason of the launch refusal or of the failed setup before it exits.

`--ci` replaces Rich UI with plain text, keeps all diagnostic output, and exits with code 1 if any finding meets the severity threshold. It exits with code 3 when the audit is incomplete: a model call was missed, or a tool was left with a coverage gap, which includes cases or chains not sent (a tool the auditor stopped calling, or a server taken as down). A clean result then covers less than was asked for. A relaunch alone does not make the audit incomplete. Findings take precedence: an incomplete audit with a finding at or above the threshold exits with code 1.

## Troubleshooting

- **`confined execution needs Docker`**: the `docker` client reaches no daemon (Docker not installed, not running, or your user outside the `docker` group). Fix that, or pass `--unconfined` for a server you trust.
- **`no confinement profile for 'python'`**: only `npx` and `uvx` have a default image. Pass `--image`, or `--unconfined`.
- **The server does not start, or its tools answer `kubectl: not found`**: the default image lacks a program the server calls. Pass an image that carries it with `--image`.
- **`refusing to mount /home/you into the container`**: the command names your home directory or a system directory (`/`, `/etc`, `/usr`, `/var`, `/home`, `/root`, `/opt`, `/srv`). The auditor mounts one only when you name it with `--mount` (`PATH:rw` to mount it writable).
- **`could not initialize LLM`**: the message that follows names the cause, most often a provider API key that is not set (see [Environment variables](#environment-variables)).
