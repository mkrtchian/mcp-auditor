# Confined target execution

## Context

ADR 017 decides that the server under audit runs confined by default, with `--unconfined` as the one way out, and ADR 018 picks the mechanism: a Docker container on a generic base image chosen by the launcher (`npx` runs in a Node image, `uvx` in a uv image), the paths named on the command line mounted writable at the same path, the invoking user's identity, no capabilities, no privilege escalation, process and memory bounds, egress open. Both ADRs are accepted and committed. This plan is the implementation, and it carries the mechanics the ADRs deliberately leave out.

Today `StdioMCPClient.connect(command, args)` spawns the target as a plain subprocess on the host (`src/mcp_auditor/adapters/mcp_client.py:20-41`), and the CLI passes the user's command through untouched (`src/mcp_auditor/cli.py:150-176`). Three other call sites take the same raw command: `evals/run_evals.py:215`, `evals/run_cve_benchmark.py:274`, and the three files under `tests/integration/`.

Four facts were measured on 2026-09-22 and shape the profile below. `npx` without `--yes`, on a cold cache and with stdin taken by the MCP channel, does not prompt: it installs and the handshake completes, so the user's arguments are never rewritten. A hardened container (`--cap-drop ALL`, `--security-opt no-new-privileges`, `--pids-limit`, `--memory`, `--init`, `--user <uid>:<gid>`) runs `npx` and `uvx` servers only if the home directory inside the container is a tmpfs created with the invoking user's uid and gid, otherwise npm fails with `EACCES` on its cache. `--read-only` breaks legitimate servers and is not part of the profile (ADR 018). A service bound to the host's `127.0.0.1` is unreachable from a container on the default bridge, and the Internet is reachable.

Decisions taken during this plan's discussion, on top of the ADRs, and after its due-diligence pass: the uv image is the tag its publisher rebuilds, the memory bound has no swap behind it, an argv element is a path only when it is spelled like one, a remote Docker endpoint stops the launch, the integration test pins its server version and asserts a stable tool name, the release is 0.3.0 with a migration line, and Docker Hub stays the source of the table's images with a CI login as the answer to a pull limit. Each is written where it lands below. The two that shaped the plan first: The memory bound ships together with a minimal reader of the container's kill state: the container gets a name and no `--rm`, the CLI reads `.State.OOMKilled` after the audit and records it in the report beside the regime, without changing any verdict. This is the reader that both ADR 018 and the CVE benchmark's own hardening (`evals/cve_environments.py`, module docstring) say the bound waits for. And the integration test of the confined path launches a public npm server through the real default table, so no image is built or hosted for tests.

Architecture reviews of the first draft settled the shape below, and each choice is justified where it lands. In short: the mount policy is pure domain code over facts the adapter resolves in one probe; the launch type is an adapter value whose confined argv is derived from its profile, so a launch cannot claim a regime it does not run; the decision (`target_execution.py`, where ADR 017's "composition root" lands) returns a value and never prints; Docker sits behind a `ContainerRuntime` port with a fake; the container lifecycle is one context manager; the report records the mounted paths; the unconfined thread id keeps today's hash; and the acceptance test of the confined path is written before any of the code that makes it pass.

## Approach

The launch becomes a value object, `ServerLaunch`, built by named constructors that force every execution path to declare its regime. It keeps the user's command and arguments, which are the audit's identity, and derives the argv it spawns from them: the command itself when unconfined or when the caller wrote the container, `docker` and the hardened `run` argv when confined, computed from a `ContainerProfile` the launch carries. `__post_init__` refuses a `confined` regime without a profile, a profile under any other regime, and a `declared_container` regime whose command is not a `docker run`, so the regime the report records is the one that ran. `StdioMCPClient.connect` takes a `ServerLaunch` instead of a raw command, so a raw command is a type error under strict `pyright` at every call site.

The domain gains what the report says (the regime and the execution record) and the mount policy, a pure module that turns argv, the declared mounts, the refused roots and a map of resolved paths into a mount plan. The filesystem is probed once, by an adapter function, for exactly the spellings the policy names, and the policy never touches it. The launch type, the profile and its rendering into `docker run` flags are an adapter module, pure. The Docker I/O is a `DockerRuntime` adapter satisfying a `ContainerRuntime` protocol declared by its consumer, the composition-root module `target_execution.py`, which holds the launcher table, the launch decision and the container's lifecycle and is tested with a `FakeContainerRuntime`.

The CLI decides the regime in this order, before anything runs: `--unconfined` gives an unconfined launch with no Docker involved; a command that is already `docker run` passes through as a declared container; otherwise the launcher must be in the table or `--image` must be given, and Docker must answer, or the CLI stops with the ways forward. The thread id, the `target` in the graph state and the report are computed from the launch's command and arguments, which are the user's by construction, and the regime joins the thread id of the two container regimes so an audit cannot be resumed under another regime.

## Files to modify

### `src/mcp_auditor/domain/models.py`

Add two types next to the report models. `ExecutionRegime(StrEnum)` with values `confined`, `declared_container`, `unconfined`. `ExecutionRecord(BaseModel)` with `regime: ExecutionRegime`, `image: str | None = None` (the reference the CLI asked for, e.g. `node:24-bookworm-slim`), `image_digest: str | None = None` (the `RepoDigest` of the local image at launch), `writable_paths: list[str] | None = None` and `read_only_paths: list[str] | None = None` (the host paths mounted into the container, absolute, `None` when the regime has no container the auditor built), `oom_killed: bool | None = None`. `AuditReport` gains `execution: ExecutionRecord | None = None`. The JSON key is always present, `null` when the CLI did not fill it, following the `owasp` precedent of ADR 012.

`oom_killed` is read together with the regime, and the model's field docstring says so: under `confined`, `None` means the kill state could not be read. Under the other two regimes it is always `None`, because there is no container of the auditor's to read. A third value in an enum would say the same thing the regime already says.

The mounted paths belong in the record because they are the part of the host the confinement does not bound (ADR 018): a confined report that names its image but not what the target could write answers the second question and not the first.

### `src/mcp_auditor/domain/__init__.py`

`ExecutionRegime` and `ExecutionRecord` join the re-exports and `__all__`, as every other report type does. The confinement types are imported from their module, as `payload_safety` already is.

### `src/mcp_auditor/domain/confinement.py` (new)

The mount policy of ADR 017, pure: no filesystem call, no environment read. `Path` appears only as a value. Written top-down.

- `MountPolicy`, a frozen dataclass: `declared: tuple[DeclaredMount, ...]` (the `--mount` options), `refused: frozenset[Path]`. Two methods:
  - `spellings_to_resolve(args) -> list[str]`: every argv element that `looks_like_path`, every bare word (an element that neither `looks_like_path` nor starts with `-`), every declared spelling, and the string form of every refused root. This is the one list the adapter probes, so which elements count as paths, which ones only earn a warning and which roots are compared stays a domain decision.
  - `plan(args, resolved: Mapping[str, Path]) -> MountPlan`: `resolved` maps each spelling that exists on the host to its absolute resolved path, and omits the ones that do not exist.
    - Every path-shaped argv element present in `resolved` becomes a writable mount at its resolved path, and a relative spelling enters `rewrites`. A path-shaped element absent from `resolved` is not mounted. The rule applies to whole argv elements: `--root=./data` is one element, neither path-shaped nor a bare word, so it is not mounted, not rewritten and not probed.
    - Every bare word present in `resolved` enters `unmounted_existing`, and nothing else happens to it.
    - Every declared mount joins with its own writable flag, and a declared spelling absent from `resolved` raises `MissingMountError(spelling)`: `-v` on a missing host path makes the daemon create it, owned by root (measured, see the due diligence record).
    - The refused set the policy compares against is each root as written plus its resolved form when `resolved` has one. An argv element whose resolved path is in that set raises `RefusedMountError(root)` **unless the same resolved path is declared**, which is the whole point of the escape hatch: `npx server /home --mount /home:rw` must run. An element under a refused root is fine.
    - A host path reached twice, in argv twice or in argv and in `--mount`, yields one `MountSpec`, since Docker rejects a duplicate mount point, and the declared flag wins.
- `MountPlan`, a frozen dataclass: `mounts: tuple[MountSpec, ...]`, `rewrites: Mapping[str, str]` (each relative argv spelling that was mounted, mapped to its absolute path), `unmounted_existing: tuple[str, ...]` (the bare words that name something on the host). The argv rendering reads the first two, the decision turns the third into warnings, and none of them touches the filesystem.
- `MountSpec`, a frozen dataclass: `host: Path` (absolute), `writable: bool`.
- `DeclaredMount`, a frozen dataclass: `spelling: str`, `writable: bool`.
- `parse_mount_option(raw: str) -> DeclaredMount`: a trailing `:ro` or `:rw` is the mode, anything else is part of the path, read-only by default. A `--mount` names a root explicitly, so it bypasses the refused roots.
- `looks_like_path(element: str) -> bool`: an argv element is treated as a path when it is absolute, is `.` or `..`, or starts with `./` or `../`. A bare word is never a path, even when a file or directory of that name exists in the working directory: `npx some-server build` next to a `build/` directory must not mount it, and, since the container argv rewrites a mounted relative path to its absolute form, must not turn the word `build` into `/home/alice/proj/build` either, which would corrupt an argument that was never a path. ADR 018 says "each argument that is an existing path"; this predicate is what the plan means by it. The README states the rule in one sentence.
- `refused_roots(home: Path) -> frozenset[Path]`: `/`, `/etc`, `/usr`, `/var`, `/home`, `/root`, `/opt`, `/srv`, and the invoking user's home directory. `home` is a parameter: the domain reads no environment. The refusal is on the root itself, not on its descendants: `/home/alice/project` is mountable, `/home/alice` is not.
- `is_declared_container(command: str, args: Sequence[str]) -> bool`: `command == "docker" and tuple(args[:1]) == ("run",)`. It is ADR 017's passthrough rule, read by the decision and by `ServerLaunch`'s invariant, and the literal `docker run` is part of the rule rather than an infrastructure detail: the rule is "a command that already is a container passes through".
- `RefusedMountError(root)`, `MissingMountError(spelling)`.

### `src/mcp_auditor/adapters/server_launch.py` (new)

The launch and the container profile it carries. Pure: no subprocess, no environment read, no filesystem probe, no clock, no randomness. Written top-down.

- `ServerLaunch`, a frozen dataclass: `command: str`, `args: tuple[str, ...]` (the user's command, verbatim), `regime: ExecutionRegime`, `profile: ContainerProfile | None = None`, `client_env: Mapping[str, str] | None = None` (variables for the host-side `docker` client, see `docker_client_env`). `args` is a tuple so the invariant checked at construction cannot be broken by mutating the list afterwards, and so the launch hashes. The constructors take any `Sequence[str]` and convert. `__post_init__` raises `ValueError` when `regime` is `confined` and `profile` is `None`, when a profile is given under another regime, and when `regime` is `declared_container` and `is_declared_container(command, args)` is false. Three named constructors, and no call to the bare initializer outside them:
  - `ServerLaunch.confined(command, args, profile, client_env)`: regime `confined`. Only `target_execution.py` calls it.
  - `ServerLaunch.declared_container(command, args, client_env)`: a `docker run` the caller wrote, regime `declared_container`. The CLI's passthrough and the CVE benchmark use it. It takes the Docker client environment too: the caller's `docker run` is spawned by the MCP SDK like the confined one, with the same restricted environment, so under a rootless `DOCKER_HOST` it would otherwise reach the wrong socket.
  - `ServerLaunch.unconfined(command, args)`: the raw subprocess, regime `unconfined`. The CLI under `--unconfined`, the evals and the integration tests use it.
- `spawn_command` and `spawn_args`, properties: `"docker"` and `container_argv(profile, command, args)` when a profile is present, `command` and `list(args)` otherwise. This is what `connect` spawns, and the only place the container argv is produced, so the regime and the argv cannot disagree.
- `record(oom_killed: bool | None) -> ExecutionRecord`: the regime, the image and digest from the profile's identity, the writable and read-only host paths from its mount plan, and the kill state. All container fields `None` without a profile.
- `ContainerIdentity`, a frozen dataclass: `image: str`, `image_digest: str | None`, `name: str`. The three travel together from the decision to the report entry.
- `ContainerProfile`, a frozen dataclass: `identity: ContainerIdentity`, `mount_plan: MountPlan`, `uid: int`, `gid: int`, `home: str = "/home/audit"`, `pids_limit: int = 256`, `memory: str = "2g"`. The three defaulted fields come last, as `AuditConfig` already does with `tools_filter`, since a dataclass refuses a field without a default after one that has one.
- `container_argv(profile, command, args) -> list[str]`: the argv after `docker`. In order: `run`, `-i`, `--init`, `--name <identity.name>`, `--label mcp-auditor`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--pids-limit <n>`, `--memory <m>`, `--memory-swap <m>`, `--user <uid>:<gid>`, `--tmpfs <home>:exec,uid=<uid>,gid=<gid>`, `-e HOME=<home>`, one `-v <host>:<host>[:ro]` per mount, the image, then the command and its args with each element equal to a key of `rewrites` replaced by its absolute path. `--memory-swap` equal to `--memory` means no swap: without it Docker grants the container as much swap again, so a runaway server thrashes 4 GiB of swap before the kill fires and `oom_killed` reads `false` in the very case the reader is shipped for (measured on 2026-09-22 on a host with 11 GiB of swap). On a kernel without swap accounting Docker prints a warning and applies `--memory` alone, which lands in the server's stderr stream, as ADR 018 already accepts. No `--rm` (the kill state is read after exit, then the container is removed). No `--network` flag (default bridge). No other `-e`: the environment is the image's. The tmpfs `uid`/`gid` options are the measured requirement: without them the tmpfs is root-owned and npm cannot write its cache. A comment says so next to the flag, and one at `--memory-swap` says it is what makes the bound bite.

### `src/mcp_auditor/adapters/host_paths.py` (new)

`existing_paths(spellings: Iterable[str]) -> dict[str, Path]`: each spelling that exists, mapped to `Path(spelling).resolve()`, relative ones against the working directory. The only filesystem access of the confined path. Nothing else lives here.

### `src/mcp_auditor/adapters/docker.py` (new)

`docker_client_env(environ: Mapping[str, str]) -> dict[str, str]`, a pure module function: the Docker client variables present in `environ` (`DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_CONFIG`, `DOCKER_TLS_VERIFY`, `DOCKER_CERT_PATH`). The CLI and the CVE benchmark call it with `os.environ`. The MCP SDK does not pass the host's environment to the process it spawns: `mcp.client.stdio.DEFAULT_INHERITED_ENV_VARS` is `HOME, LOGNAME, PATH, SHELL, TERM, USER` and nothing else. So on a rootless Docker where `DOCKER_HOST` points at the socket, `available()` succeeds (it inherits the environment) and the launch would then fail against the default socket, with the runtime's error mixed into the server's stderr. This is the environment of the `docker` **client process on the host**, not of the container, so ADR 018's "the environment is the image's" is untouched. It is not a runtime method because it asks nothing of Docker: it is a fact of the host, like the uid.

`DockerRuntime`, a class with no state, each method a thin `subprocess.run` with `check=False`, `capture_output=True`, `text=True`. It satisfies `ContainerRuntime` structurally and imports nothing from `target_execution.py`.

- `available() -> bool`: `docker version --format '{{.Server.Version}}'` returns 0.
- `endpoint() -> str`: `docker context inspect --format '{{.Endpoints.docker.Host}}'`, the endpoint the client will actually talk to, whatever selected it (`DOCKER_HOST`, `DOCKER_CONTEXT`, or a `docker context use`). Measured on 2026-09-22: it reads `unix:///var/run/docker.sock` by default and `tcp://example:2375` under that `DOCKER_HOST`. Reading `DOCKER_HOST` alone would miss a remote context selected without any variable.
- `ensure_image(image: str) -> str | None`: pulls the image if `docker image inspect` fails, then reads `{{index .RepoDigests 0}}` and returns the part after `@`, i.e. `sha256:…`. `None` when the image has no repo digest, which is the normal case for an image the user built locally and named with `--image`: that must not stop the launch. Raises `DockerError(message)` with the daemon's stderr when the pull fails. The digest is resolved before the launch because the container is removed after it.
- `pids_limit_enforced() -> bool`: `docker info --format '{{.PidsLimit}}'` does not read `false`. The same check `evals/run_cve_benchmark.py:_warn_if_pids_limit_discarded` makes, duplicated rather than shared: the benchmark is an instrument and the product does not import from `evals/`. A comment says so.
- `oom_killed(container_name: str) -> bool | None`: `docker inspect --format '{{.State.OOMKilled}}'`, `None` when the container does not exist or the command fails.
- `remove(container_name: str) -> None`: `docker rm -f`, best-effort, a failure logs a warning and never raises. Orphans carry the `mcp-auditor` label, and the README gives the sweep command.

`DockerError(ValueError)` carries the daemon's message.

### `src/mcp_auditor/target_execution.py` (new)

A composition-root module, outside the hexagon like `cli.py`. It holds the launcher table, the launch decision and the container lifecycle.

- `IMAGE_BY_LAUNCHER: Mapping[str, str] = {"npx": "node:24-bookworm-slim", "uvx": "ghcr.io/astral-sh/uv:python3.14-trixie-slim"}`. The table is closed. Docker's MCP Gateway maps the same launchers to the same image families, which is where the mapping comes from. The tag is the one its publisher still rebuilds, not necessarily the Gateway's: the Gateway pins `python3.14-bookworm-slim`, whose last build dates from 2026-02-04 (uv 0.9.30, Python 3.14.2) and which uv's documentation no longer lists, while `python3.14-trixie-slim` was rebuilt on 2026-09-18 and, measured on 2026-09-22, runs `uvx` under the full profile with uv 0.12.17 and Python 3.14.7. A base image nobody rebuilds receives no Debian security update, which is the wrong base under a feature whose point is confinement. The comment on the table says both things: mapping from the Gateway, tag from the publisher.
- `ContainerRuntime(Protocol)`: the six methods of `DockerRuntime` above. Declared here, by its only consumer, and not in `domain/ports.py`: nothing inside the hexagon reads it.
- `LaunchOptions`, frozen dataclass: `unconfined: bool`, `image: str | None`, `mounts: tuple[str, ...]`. It lives here so `cli.py` imports it alongside `decide_launch` without a cycle.
- `Host`, frozen dataclass: `uid: int`, `gid: int`, `home: Path`, `docker_env: Mapping[str, str]`. The facts about the invoking machine the decision needs. The CLI fills it from `os.getuid()`, `os.getgid()`, `Path.home()` and `docker_client_env(os.environ)`.
- `LaunchContext`, frozen dataclass: `options: LaunchOptions`, `runtime: ContainerRuntime`, `host: Host`, `container_name: str`. The CLI generates the name (`f"mcp-auditor-{uuid4().hex[:12]}"`), so this module holds no randomness either. No display: the module decides and never prints.
- `LaunchDecision`, frozen dataclass: `launch: ServerLaunch`, `warnings: tuple[str, ...]`.
- `LaunchRefused(Exception)`, carrying the message that tells the user the ways forward.
- `decide_launch(command, args, context) -> LaunchDecision`, raising `LaunchRefused(message)` to stop. It reads as the ordered list below, each stop a private helper right beneath it, and no function passes 20 lines:
  1. `options.unconfined`: a warning when `image` or `mounts` was also given (they mean nothing outside a container), and `ServerLaunch.unconfined(command, args)`. The runtime is not touched.
  2. `is_declared_container(command, args)`: `ServerLaunch.declared_container(command, args, host.docker_env)`, no warning. The runtime is not touched.
  3. The image is `options.image` or `IMAGE_BY_LAUNCHER.get(command)`. With neither, refuse: `no confinement profile for '<command>': pass --image IMAGE to run it in a container of your choice, or --unconfined to run it on this host with your privileges`.
  4. `runtime.available()` or refuse: `confined execution needs Docker: install it and start the daemon, or run with --unconfined to launch '<command>' on this host with your privileges`.
  5. `runtime.endpoint()`, and refuse unless its scheme is `unix://` or `npipe://`: `the Docker endpoint '<endpoint>' is not on this host, so the paths this command names would be mounted from that machine: run with --unconfined, or write the docker run yourself`. `-v <host>:<host>` resolves on the daemon's filesystem, so against a remote daemon the audit would silently run against other files, or none, which is a wrong report that looks right. A rootless local daemon (`unix:///run/user/1000/docker.sock`) passes, which is correct.
  6. `policy = MountPolicy(declared, refused_roots(host.home))`, the declared mounts parsed from `options.mounts` through `parse_mount_option`, then `plan = policy.plan(args, existing_paths(policy.spellings_to_resolve(args)))`. A `RefusedMountError` becomes `LaunchRefused("refusing to mount <root> into the container: pass --mount <root>:rw to do it on purpose")`, a `MissingMountError` becomes `LaunchRefused("--mount <spelling>: no such path on this host")`. Each word of `plan.unmounted_existing` gives the warning `'<word>' exists here but is not mounted: write ./<word> to mount it`, never a refusal, since a bare word is not a path and the server may mean it as one. The mounts are planned before the pull, so a refusal costs no download.
  7. `runtime.ensure_image(image)` for the digest, refusing with the daemon's message on `DockerError`.
  8. `ServerLaunch.confined(command, args, ContainerProfile(ContainerIdentity(image, digest, container_name), plan, host.uid, host.gid), host.docker_env)`.
  9. When `runtime.pids_limit_enforced()` is false, the warning `this Docker host cannot enforce --pids-limit, the server runs without it`.

  Warnings are collected in the order the checks run and returned with the launch. A refusal discards the warnings gathered before it: the user sees the one thing that stopped the run.
- `TargetExecution(launch, runtime)`, an async context manager around the connection. On exit, under a confined launch, it reads `runtime.oom_killed(name)` and then calls `runtime.remove(name)` in a `finally`, whatever ended the block: a normal return, `_run_dry_run` returning from inside, a dead server. Under the two other regimes it touches nothing. Its attribute `record: ExecutionRecord | None` is `None` until `__aexit__` sets it to `launch.record(oom_killed)`. After a block that raised it is set too, but the CLI never reads it since the exception propagates to the `except` clauses.

### `src/mcp_auditor/checkpointing.py` (new)

A composition-root module for the thread identity, moved out of `cli.py` so the file does not grow. It holds `resume_or_reset` (moved verbatim with its docstring), `checkpoint_db_path() -> str` (the three lines that build `~/.mcp-auditor/checkpoints.db` today), and `compute_thread_id(launch) -> str`.

`compute_thread_id` hashes `" ".join([command, *args])` exactly as `_compute_thread_id` does today when the regime is `unconfined`, and appends `"\0" + regime` to the hashed string under the two container regimes. The NUL separator is a character no argv element can contain, so a confined `npx srv` can never hash like an unconfined `npx srv confined`. Every audit run before this change was unconfined, so an audit interrupted before the upgrade resumes with `--unconfined -- <same command>`, and a confined audit of the same command gets its own thread. Hashing the regime for all three would have orphaned every existing checkpoint in `checkpoints.db` without a word.

### `src/mcp_auditor/report_files.py` (new)

`ReportPaths` and `write_reports(report, paths, display)`, moved verbatim from `cli.py` (`_write_reports` loses its underscore). `cli.py` imports both. The move is part of the size budget below, not a fallback.

### `src/mcp_auditor/adapters/mcp_client.py`

`connect(cls, launch: ServerLaunch, errlog=None, tool_call_timeout=...)`. The body builds `StdioServerParameters(command=launch.spawn_command, args=launch.spawn_args)`, and passes `env=get_default_environment() | dict(launch.client_env)` when `launch.client_env` is not `None`, leaving the parameter out otherwise so the SDK's default applies. Nothing else changes: the adapter reads two properties and knows nothing of Docker.

Every call site loses the two-positional form. `connect(*CONNECT_ARGS)` in the integration tests is a tuple unpack of `(command, args)` and must become `connect(LAUNCH)` at each of its seventeen occurrences.

### `src/mcp_auditor/cli.py`

Three options on `run`: `--unconfined` (flag, default off, help: `Launch the server on this host with your privileges, outside any container`), `--image TEXT` (help: `Container image to run the server in, for a launcher the default table does not cover`), `--mount TEXT` (multiple, help: `Host path to mount into the container, PATH or PATH:rw, read-only by default`). None of the three is a configuration-file key: `KNOWN_KEYS` in `config_file.py` is unchanged and a test asserts that `unconfined:` in the file raises `UnknownKeyError`. `AuditConfig` gains `launch: LaunchOptions`, declared before `tools_filter`, the only field with a default. The click parameter for `--mount` is named `mount` and arrives as a tuple, so it is read as `params["mount"]`. The `run` docstring, which is the `--help` text, shows `mcp-auditor run --unconfined -- python my_server.py` and `mcp-auditor run --ci --unconfined -- python my_server.py` in place of the two examples the new default would refuse, and keeps the `npx` example as is.

`_run_audit` gets its context from a new `_launch_context(config) -> LaunchContext` (a `DockerRuntime()`, the `Host`, the container name), which keeps `_run_audit`, already about 80 lines, from growing by that much. It calls `decision = decide_launch(command, args, context)` **before the LLM initialization block**, not merely before the client. On `LaunchRefused` it calls `display.print_error(message)` and raises `SystemExit(1)`, as it already does for a failed LLM initialization. Otherwise it prints each of `decision.warnings` through `display.print_warning` and goes on with `launch = decision.launch`. The order matters twice. It is what ADR 017 means by "the refusal happens before any of the target's code runs", and it is what makes the CLI test below deterministic: with `load_settings()` first, `run -- python x.py` on a machine with no API key exits 1 on `could not initialize LLM`, not on `no confinement profile`. The header moves with it: `display.print_header(target_str, launch.regime)`.

The thread id becomes `compute_thread_id(launch)` from `checkpointing.py`. `target_str` and the graph state's `target` are built from `launch.command` and `launch.args`, the user's command by construction.

`TargetExecution` joins the existing multi-item `async with`, **first**, inside the existing `try`: `async with (execution, AsyncSqliteSaver.from_conn_string(...) as checkpointer, StdioMCPClient.connect(launch, ...) as mcp_client)`. Context managers exit in reverse order, so the client disconnects, then the checkpointer closes, then `TargetExecution` reads the kill state of a container that has exited and removes it. The three `except` clauses (`ConnectionError`, `OSError`, `BaseExceptionGroup`) stay where they are and see the same exceptions as today. `_run_full_audit` returns the `AuditReport` instead of printing and writing it. After the `async with` exits, `report = report.model_copy(update={"execution": execution.record})`, then the summary, the findings recap, the report writing and the CI exit decision, in today's order. `--dry-run` goes through the same decision and the same `TargetExecution`: it launches the server too.

The size budget, so that `cli.py` ends this change no longer than its current 333 lines. Out, measured: `resume_or_reset`, `_compute_thread_id` and the checkpoint path to `checkpointing.py` (about 28 lines), `_show_server_stderr` and `_summarize_exception_group` to `console.py` (about 17), `ReportPaths` and `_write_reports` to `report_files.py` (about 18). In, estimated by the counter-review: the three options and their parameters (about 22), the `LaunchOptions` construction (about 5), `_launch_context` (about 10), the refusal handling and the warnings loop (about 7), new imports (about 6), the report copy and the tail moved after the block (about 5), about 55 in all. That lands near 325. The step's Verify runs `wc -l`.

### `src/mcp_auditor/console.py`

`print_header(target_command, regime)` prints the regime under the target in the panel: `execution: confined` / `execution: declared container` / `execution: unconfined`. `print_warning(message)` does not exist yet and is added. `print_server_stderr(stream)` and `summarize_exception_group(exc_group)` arrive from `cli.py`, unchanged in behaviour.

The signature change breaks `tests/unit/test_console_display.py`, which calls `display.print_header("python server.py")` at lines 8 and 71. Both pass a regime, and one of them asserts the regime reaches the panel. All of this lands in the same step as the `cli.py` wiring, since `cli.py:156` calls `print_header` and would break otherwise.

### `src/mcp_auditor/domain/rendering.py`

`_render_summary_section` gains an `**Execution**` line right after `**Target**`: `confined, <image>@<digest>` (digest shortened to 12 hex characters after the `sha256:` prefix in Markdown, full in JSON, and the image alone when the digest is `None`), `declared container`, or `unconfined`. Under a confined record, a `**Writable on host**` line lists the writable paths (`none` when empty), a `**Read-only on host**` line lists the read-only ones when there are any, and a `**Killed on memory**` line reads `yes` when `oom_killed` is true and `unknown` when it is `None`. Nothing is printed for `false`. `render_json` needs nothing: the field serializes with the model.

### `evals/run_evals.py`, `evals/run_cve_benchmark.py`

Line 215 of `run_evals.py` becomes `StdioMCPClient.connect(ServerLaunch.unconfined(honeypot.command, honeypot.args), errlog=devnull)`. `_silent_client` in `run_cve_benchmark.py` becomes `StdioMCPClient.connect(ServerLaunch.declared_container(launch.command, launch.args, docker_client_env(os.environ)), errlog=devnull)`: every fixture of `evals/cve_environments.py` launches with `command="docker"` and `args` starting with `run`, so the invariant holds, and a unit test pins it (below). Both import `ServerLaunch` from `mcp_auditor.adapters.server_launch`, as they already import `StdioMCPClient` from the adapters. `evals/cve_environments.py` and its `Launch` dataclass are not touched: the benchmark keeps building its own argv, and the conversion happens at the one call site.

### `tests/integration/test_mcp_client.py`, `test_subtle_server.py`, `test_chain_honeypot.py`

`CONNECT_ARGS` becomes `LAUNCH = ServerLaunch.unconfined("uv", ["run", "python", str(SERVER_PATH)])`, and `connected_subtle_server()` builds the same. Every `StdioMCPClient.connect(*CONNECT_ARGS)` loses its star and becomes `connect(LAUNCH)`: nine occurrences in `test_mcp_client.py`, eight in `test_chain_honeypot.py`. The assertions stay as they are.

### `tests/integration/test_confined_launch.py` (new)

The acceptance test of the confined path, written in step 5, after `connect` takes a `ServerLaunch` and before any of the code that makes it pass, and made green in step 7. One test: `decide_launch(...).launch` for `npx @modelcontextprotocol/server-filesystem@2026.8.31 <tmp_path>` with a real `DockerRuntime`, then `async with TargetExecution(launch, runtime)` around `StdioMCPClient.connect(launch)`, `list_tools`, assert `list_directory` is among the tool names, and after the block, `execution.record` reads `oom_killed is False` with `tmp_path` among the writable paths, and `docker ps -a --filter name=<container name>` lists nothing.

In steps 5 and 6 the file carries three things that step 7 removes:
- `pytest.mark.xfail(strict=True, raises=ImportError, reason="confined path not wired yet")`. `raises=ImportError` limits the expected failure to the missing modules, so an unrelated error is red even before step 7. `strict=True` makes an unexpected pass red.
- The imports of the not-yet-existing modules (`target_execution`, the `DockerRuntime` class) inside the test body, so they fail the test at run time instead of the collection.
- Two file-level pragmas, `# pyright: basic` and `# pyright: reportMissingImports=false`. `pyproject.toml` runs pyright in strict mode on `tests/` too, and an unresolved import is an error there, as is everything typed from it. Verified on 2026-09-22 that the two pragmas silence exactly that. The call to `StdioMCPClient.connect(launch)` already type-checks, since step 4 changed its signature.

The skip condition, `pytest.mark.skipif` when Docker does not answer, runs `docker version` directly until `DockerRuntime` exists, then becomes `not DockerRuntime().available()`.

This is the quick start's command with the version pinned, as `README.md:118` already pins the demo's: the test is the only instrument of the product's confined path, and it must go red on a confinement regression and never on an upstream rename (`read_file` is registered as deprecated in 2026.8.31 in favour of `read_text_file`). The pin removes nothing the test exercises, since the cache is empty at each launch and npm is still fetched from. It needs Docker Hub and the npm registry, which the quick start already needs. If Docker Hub's anonymous pull limit on shared CI runners ever bites, the fix is a `docker/login-action` step in `ci.yml`, conditional on a repository secret, which touches the runner only. The table's Node entry does not change for that: the table is what every user pulls and what the report records, and moving the product's default to relieve the instrument is the move ADR 016 forbids in the eval domain. Nor does the test skip on a failed pull, which would turn the only instrument of the confined path green whenever it does not run. Fork and Dependabot PRs will not hold the secret and pull anonymously, the same exposure as today.

### `tests/fakes/container_runtime.py` (new), `tests/fakes/__init__.py`

`FakeContainerRuntime`, beside `FakeMCPClient` and `FakeLLM`, and re-exported from `tests/fakes/__init__.py` like them: a real implementation of `ContainerRuntime` with configurable answers (availability, endpoint, digest or pull error, pids enforcement, kill state), and the list of images it pulled and containers it removed. Built with `untouchable=True`, every method raises, which is how a test states that a regime reaches no Docker at all.

### Unit tests

- `tests/unit/test_confinement.py` with `tests/unit/support/test_confinement_given.py`, pure, no `tmp_path`: `resolved` maps are written by hand.
  - `spellings_to_resolve` returns the path-shaped elements, the bare words, the declared spellings and the refused roots, and never a flag or a `--flag=value` element.
  - A path-shaped element present in `resolved` is mounted writable at its resolved path, and a relative one (`./data`, `.`) enters the rewrites. A path-shaped element absent from `resolved` is not mounted.
  - A bare word present in `resolved` is in `unmounted_existing` and is neither mounted nor rewritten.
  - `parse_mount_option` reads `/data` as read-only, `/data:rw` writable, `/data:ro` read-only, and keeps any other colon in the path. A declared mount absent from `resolved` raises `MissingMountError`.
  - A refused root in argv raises `RefusedMountError`, the same root declared is accepted **including when it is also in argv**, and a path under a refused root is accepted.
  - A symlinked refused root: with `resolved` mapping `/home` to `/var/home` and `/home/x/..` to `/var/home`, the element is refused.
  - A path reached twice yields one mount with the declared flag winning.
  - `refused_roots(Path("/home/alice"))` contains `/home/alice` and not `/home/alice/project`.
  - `is_declared_container("docker", ("run", "img"))` is true, and so is the list form. `("docker", ["container", "run"])` and `("podman", ["run"])` are false.
- `tests/unit/test_server_launch.py`: a confined launch spawns `docker` whatever the user's command, and keeps the user's command and arguments. Building a `ServerLaunch` with regime `confined` and no profile raises, so does a profile under `unconfined`, and so does `declared_container("python", ["x.py"], {})`. The unconfined and declared-container launches spawn their command verbatim, and the declared one carries the client environment it was given. The quick-start profile renders exactly the expected argv as a single list equality, the snapshot that goes red if anyone re-adds `--read-only` or `--rm`, drops `--memory-swap`, or loses the tmpfs uid/gid. A read-only mount renders `-v /data:/data:ro`, and a rewrite replaces its spelling in the container argv only. `record()` carries regime, image, digest, the writable and read-only paths, and the kill state, and carries `None` in every container field without a profile.
- `tests/unit/test_cve_launches.py`: the launches yielded by `with filesystem_env("s") as launch` and `with command_injection_env("img", "s") as launch` from `evals/cve_environments.py` build a `ServerLaunch.declared_container` without raising. Both are public, and neither needs Docker (the first only creates a temporary directory). This is the cheap, deterministic proof that the invariant accepts the benchmark's fixtures, where `--calibrate` needs Docker and the built images.
- `tests/unit/test_docker_client_env.py`: `docker_client_env` keeps the five Docker variables present in the mapping it is given and nothing else.
- `tests/unit/test_host_paths.py`, on `tmp_path` with the working directory changed to it: `existing_paths` maps an existing absolute and an existing relative spelling to their resolved paths, follows a symlink to its target, and omits a missing one.
- `tests/unit/test_target_execution.py` with `tests/unit/support/test_target_execution_given.py` (a `LaunchContext` over a `FakeContainerRuntime` and `tmp_path`): the decision cases listed in step 7, and the lifecycle: a confined execution removes its container on a normal exit and on an exception raised inside the block, its `record` carries the kill state the runtime reported and is `None` inside the block, and an unconfined execution reaches an untouchable runtime without error.
- `tests/unit/test_checkpointing.py` (the renamed `tests/unit/test_cli_resume.py`, whose `resume_or_reset` cases move with the function): `compute_thread_id(ServerLaunch.unconfined("python", ["server.py"]))` is the literal `7cc34ebdac143b58`, today's id for that command, so an existing checkpoint still resumes. `unconfined("docker", ["run", "img"])` and `declared_container("docker", ["run", "img"], {})` get different ids. `declared_container("docker", ["run", "img"], {})` and `unconfined("docker", ["run", "img", "declared_container"])` get different ids too, which pins the separator. Two equal launches get equal ids.
- `tests/unit/test_console_display.py`: the panel carries the regime, and the two existing `print_header` calls take the new argument.
- `tests/unit/test_cli.py`: `--unconfined`, `--image`, `--mount` appear in `--help`. A `CliRunner` invocation of `run -- python x.py` without `--unconfined` exits 1 with the `no confinement profile` message and never reaches Docker or the LLM (the check order guarantees it, and the test runs on a machine with or without Docker and with or without an API key).
- `tests/unit/test_config_file.py`: `unconfined: true` in the file raises `UnknownKeyError`.
- `tests/unit/test_rendering.py`: the Markdown summary shows the execution line for each regime, the writable line under a confined record only, the read-only line only when non-empty, and the kill line as `yes` when true, `unknown` when `None` under `confined`, and absent otherwise. The JSON carries `execution` (and `null` when absent).

### `README.md`

Quick start: the existing `npx` command stays, preceded by one sentence that Docker is required by default, and followed by the `--unconfined` form for the reader without Docker or auditing their own server, both commands shown. Scope and limitations: the `Transport: local stdio only` bullet says the auditor audits "servers you launch as a subprocess (`-- npx ...`)", which the default no longer does, so it says subprocess or container. A new bullet, `Confined by default`, saying what the container bounds (the rest of the filesystem, loopback-bound services of the host, privileges, the auditor's environment) and what it does not (the paths the command names, mounted writable, and egress), that the report lists the mounted paths, that a `docker run` command is audited as a declared container with its own flags, with the `docker` group note, and pointing at ADR 017 and ADR 018. The `Safety` paragraph gains one sentence: a secret read under a mounted path is a live host secret. CLI options table: `--unconfined`, `--image`, `--mount`, the last one noting that the path must exist. Configuration file section: one sentence that `unconfined` is deliberately not a file key, because the file loads from the target's own directory. Run in CI: the recipe becomes `uvx mcp-auditor run --ci --unconfined -- python my_server.py` with the sentence that this is your own code, and the second example likewise. A sweep command for orphaned containers, `docker rm -f $(docker ps -aq --filter label=mcp-auditor)`, next to the safety note. The argv path rule in one sentence: an argument is treated as a path only when it is a whole argument spelled like one (absolute, `.`, `..`, `./…`, `../…`), so `--root=./data` is not mounted.

Two constraints `tests/unit/test_readme_policy.py` already enforces on this section, and the new bullet has to respect both. Exactly one bullet under `## Scope and limitations` may contain the string `ADR 013`, so the `Confined by default` bullet points at ADR 017 and ADR 018 and never at ADR 013. And that one ADR 013 bullet may not contain `sandbox`, `security boundary`, `read-only`, `no side effects` or the other overclaims in the test's list, so the new confinement wording stays out of it: a container is not a sandbox this repository claims, and ADR 017's own consequence says the guard stays in force.

### `CHANGELOG.md`

Under `[Unreleased]`, `### Changed`, a first bullet opening with **Breaking.** and carrying the migration line: `-- python server.py`, `-- node server.js` and `-- uv run ...` stop under the default and run with `--unconfined -- ...`, and the quick start's `npx` form needs Docker. It also says that an audit interrupted before the upgrade resumes only with `--unconfined` and the same command. Then what the profile does, `--unconfined`, `--image`, `--mount`, the regime, image digest and mounted paths in the report, the kill state recorded without changing verdicts, and the pointers to ADR 017 and ADR 018. Keep a Changelog has no Breaking section, so the word opens the bullet. The next release is 0.3.0, not 0.2.1: the repository's history reserves the minor for behaviour changes, and a reader who only reads the number gets the signal. The version bump in `pyproject.toml` happens at release, outside this plan, as it always has: `[Unreleased]` already describes the guard and the `--resume` fix that the published package does not carry, and the convention is that the README describes `main`.

### `CLAUDE.md`

Commands: a comment on `uv run pytest tests/integration` that one test needs Docker and network and skips without Docker. Landmines: the tmpfs uid/gid requirement, and that the unconfined thread id must keep its pre-0.3.0 hash (a test pins it) or every interrupted audit becomes unresumable.

### `CONTRIBUTING.md`

Setup: `Docker is only needed for the CVE benchmark (below), not for the tests or the regular evals` is false after this change. It becomes Docker as a prerequisite for auditing a server under the default regime, one integration test that needs it and skips without it, and the evals still needing none.

### `.github/workflows/`

`ci.yml` runs `uv run pytest tests/integration` on `ubuntu-latest`, which ships Docker, so the new test runs on every push and PR and no change is needed now. If Docker Hub's anonymous pull limit turns a PR red, the change is a `docker/login-action` step conditional on a secret, added then, not now: adding it today costs a Docker Hub account and a token for a limit that has not bitten.

## What stays unchanged

`graph/` in full, the prompts, `AuditedServer`, `payload_safety.py` and `domain/ports.py`, `config_file.py` and `KNOWN_KEYS`, `evals/cve_environments.py`, the oracle, the ground truth, the honeypots, the judge and its fixtures, the ADRs. The report's `target` field and the thread's identity keep the user's command. No `--env`: the environment is the image's, and a server that needs a credential file under a refused root takes `--mount` or `--unconfined`. No network policy beyond the default bridge. No verification probe: the report records the regime the CLI applied.

## Edge cases

- `--unconfined` with `--image` or `--mount`: `--unconfined` wins and the other two are ignored with a warning, since they only mean something in a container.
- `--image` with a launcher in the table: the user's image replaces the table's.
- `--image` with local code (`python server.py`): the file is mounted, its virtual environment is not, and the README says the container has to carry the server's dependencies.
- A relative existing path in argv (`npx server .`, `npx server ./data`): resolved against the working directory, mounted at its absolute path, and rewritten to that absolute path in the container's argv only. The launch, the thread id and the report keep the user's spelling, and the report's mounted paths are absolute.
- A path inside a `--flag=value` element (`--root=./data`): the element is neither path-shaped nor a bare word, so it is not probed, mounted or rewritten, and the server sees a path that does not exist in the container. Writing `--root ./data` as two elements mounts it. The README states the whole-element rule.
- A bare word in argv that happens to name an existing entry (`npx server build` next to `build/`, `--config config.json`): not a path by the rule, so not mounted and not rewritten. The CLI warns that the entry exists and is not mounted, and the server fails inside the container if it did mean a file, with its error in the shared stderr stream. Writing `./build` mounts it.
- A `--mount` path that does not exist: the launch stops. `-v` would make the daemon create it on the host, owned by root.
- A `--mount` given as a relative path (`--mount ./data:rw`): resolved against the working directory like an argv path, mounted at its absolute path.
- A remote Docker endpoint (`DOCKER_HOST=tcp://…`, `DOCKER_HOST=ssh://…`, or a `docker context use` pointing off the host): the endpoint is not a local socket, the CLI stops before planning the mounts or pulling anything, with `--unconfined` and a user-written `docker run` as the ways forward.
- An argv element that is both a flag value and an existing path (`--repository /data/repo`): mounted like any other, the flag is untouched.
- Two argv paths nested in each other: two `-v`, Docker resolves the nesting.
- A refused root reached through `--mount /home:rw`: accepted, that is the escape hatch. It is accepted even when the same root is also an argv element, which is the usual shape (`npx ... /home --mount /home:rw`), so the policy consults the declared mounts before refusing.
- A refused root spelled differently (`/home/.`) or reached through a symlink (`/home -> /var/home` on Fedora Silverblue, a home directory that is itself a link): refused, since the policy compares resolved argv paths against the refused roots in both their written and resolved forms.
- The same host path twice, in argv twice or in argv and in `--mount`: one `-v`. Docker refuses a duplicate mount point.
- Docker installed but the daemon down: `available()` is false, same stop as not installed.
- Rootless local Docker driven by `DOCKER_HOST=unix:///run/user/<uid>/docker.sock`: the endpoint is a local socket, so the launch proceeds, and the variable reaches the spawned `docker` client through the launch's `client_env`, under the confined regime and the declared-container one alike, because the MCP SDK passes only `HOME, LOGNAME, PATH, SHELL, TERM, USER` and the availability check would otherwise pass while the launch went to the wrong socket.
- `docker container run ...` or `podman run ...` as the user's command: not a declared container by the rule, so the CLI stops with `no confinement profile for 'docker'`. The message names `--image` and `--unconfined`, both of which work, and `docker run` is the recognized spelling.
- A refused mount: the launch stops before the image is pulled.
- The image pull fails (offline, rate limit): stop with the daemon's message, nothing launched.
- The host cannot enforce `--pids-limit`: warning printed, launch proceeds, as the benchmark does.
- The audit dies before the container starts (LLM init failure): no container started, nothing to read or remove, `execution` stays `None`. The launch decision runs first, so an unknown launcher stops the run before the LLM is even initialized.
- An exception escapes the connection block (dead server, a missing report): `TargetExecution` still reads the kill state and removes the container on its way out. The CI threshold exit happens after the block, once the report carries its execution record.
- The kill state cannot be read (the daemon went away mid-audit): `oom_killed` is `None` under `confined`, and the Markdown reads `**Killed on memory**: unknown`.
- `--image` naming an image the user built locally: it has no repo digest, `image_digest` is `None`, and the launch proceeds.
- The container is killed on memory mid-audit: the client reports a closed connection as an error response (unchanged), the audit may end early or with error verdicts, and the report carries `oom_killed: true` so a reader knows why. No verdict is rewritten.
- `--resume` after the upgrade, on an audit interrupted before it: resumes under `--unconfined` with the same command, starts fresh under the confined default.
- `--resume` after switching regime: different thread id, `nothing to resume for this target` and a fresh audit.
- Two audits of the same target and regime at once: they share a thread as today (CHANGELOG, `--resume` entry), and now also race on nothing else, since container names are random.
- `podman` aliased as `docker`: `docker version` answers, the flags used are in the common subset, no guarantee beyond that.
- macOS and WSL: Docker Desktop mounts only under its shared paths and resolves the host by name. Not exercised, documented as such in ADR 018.

## Test scenarios

- Integration, written before the code that makes it pass: the confined quick-start launch lists the filesystem server's tools through a real container, the kill state reads `False`, the mounted path is recorded, and the container is gone afterwards.
- The mount policy, pure: path-shaped existing elements rw, bare words never mounted and reported when they exist, `--flag=value` elements ignored, `--mount` ro by default and required to exist, refused roots refused from argv in written and resolved form and accepted from `--mount`, one mount per host path.
- A confined launch spawns the hardened container whatever command it wraps, and cannot be built without a profile. A declared-container launch cannot be built from anything but a `docker run`, carries the Docker client environment, and the benchmark's fixtures pass that check.
- The container argv for the quick-start command matches a snapshot, the regression pin against `--read-only`, `--rm`, a missing `--memory-swap` or a root-owned tmpfs.
- The launcher table is closed: `python`, `node`, `uv`, `bun` map to nothing.
- The decision stops on a non-local Docker endpoint before any mount planning or pull, refuses an unknown launcher before touching Docker, and refuses a mount before any pull, against `FakeContainerRuntime`.
- The container is removed on every exit path of the connection block.
- The CLI refuses `unconfined` as a file key.
- The unconfined thread id is today's, the container regimes get their own, and no argv can forge another regime's id.
- Rendering of the execution record in Markdown and JSON, mounted paths and unknown kill state included.
- Existing integration and eval paths still connect through `ServerLaunch.unconfined` / `declared_container` with their argv unchanged.

## Verification

```bash
uv run pytest tests/unit
uv run pytest tests/integration          # one test needs Docker and network, skips without Docker
uv run ruff check . && uv run ruff format --check .
uv run pyright                            # a raw command passed to connect must be a type error

# the two that stop need no API key, the others generate test cases and need one
uv run mcp-auditor run --dry-run -- python tests/honeypot_server.py                           # stops: no confinement profile
uv run mcp-auditor run --dry-run -- npx @modelcontextprotocol/server-filesystem /home         # stops: refused root, nothing pulled
uv run mcp-auditor run --dry-run -- npx @modelcontextprotocol/server-filesystem /tmp/sandbox   # confined, header says so
uv run mcp-auditor run --dry-run --unconfined -- python tests/honeypot_server.py              # runs, header says unconfined
uv run mcp-auditor run --dry-run -- npx @modelcontextprotocol/server-filesystem /home --mount /home:rw  # runs, /home mounted on purpose
docker ps -a --filter label=mcp-auditor   # empty after each run above
uv run python -m evals.run_cve_benchmark --calibrate   # unchanged, all six fixtures live
```

A full audit with a JSON report (`-o report.json`) shows `"execution": {"regime": "confined", "image": "node:24-bookworm-slim", "image_digest": "sha256:…", "writable_paths": ["/tmp/sandbox"], "read_only_paths": [], "oom_killed": false}`, and the same run with `--unconfined` shows `"regime": "unconfined"` with the other fields `null`.

## Due diligence record

What the due-diligence pass concluded on 2026-09-22 about the external facts this plan cites or defers. Later passes read this section. No pass may treat a line here as a reason to skip a verification: it says what was concluded once, not what is true now. A human who edits one of these facts by hand deletes the corresponding line rather than updating it.

- SETTLED: `node:24-bookworm-slim` (Docker Hub tag exists, last pushed 2026-09-19; it is also the default Docker MCP Gateway computes in `pkg/catalog/npm.go`, which is the provenance the table claims).
- SETTLED: the launcher table's provenance, `ghcr.io/astral-sh/uv:python3.14-bookworm-slim` being the default of Docker MCP Gateway's `pkg/catalog/pypi.go` and `node:24-bookworm-slim` that of `pkg/catalog/npm.go` (read in the `docker/mcp-gateway` sources).
- SETTLED: the hardened flag set runs as written on Docker 29.8.1, `--init --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 --memory 2g --user <uid>:<gid> --tmpfs /home/audit:exec,uid=<uid>,gid=<gid> -e HOME=/home/audit` (the container reports the invoking uid/gid and writes into the tmpfs home).
- SETTLED: the quick-start command runs end to end under exactly that profile: `npx @modelcontextprotocol/server-filesystem <path>` in `node:24-bookworm-slim`, no `--yes`, no prompt, handshake completes, 14 tools listed.
- SETTLED: `docker inspect --format '{{.State.OOMKilled}}'` reads `true` after a container is killed on memory, `--init` in place.
- SETTLED: `docker image inspect --format '{{index .RepoDigests 0}}'` yields `<repo>@sha256:…`, so the digest is the part after `@`.
- SETTLED: Docker's own default is that `--memory 2g` with no `--memory-swap` also allows 2g of swap (an OOM probe tripped only once `--memory-swap` was set).
- SETTLED: `mcp.client.stdio.DEFAULT_INHERITED_ENV_VARS` is `['HOME', 'LOGNAME', 'PATH', 'SHELL', 'TERM', 'USER']` and `get_default_environment()` exists, in the SDK version this repository pins.
- SETTLED: GitHub's `ubuntu-latest` ships Docker (Docker Server 28.0.4 in the runner image), so the new integration test runs in CI rather than skipping.
- SETTLED (2026-09-22, after the diligence pass): `ghcr.io/astral-sh/uv:python3.14-trixie-slim` runs `uvx mcp-server-time` under the full profile including `--memory-swap 2g`, with uv 0.12.17 and Python 3.14.7.
- SETTLED (2026-09-22, after the diligence pass): `docker context inspect --format '{{.Endpoints.docker.Host}}'` reads `unix:///var/run/docker.sock` by default and `tcp://example:2375` under `DOCKER_HOST=tcp://example:2375`.
- OPEN (deferred): `image_digest`, the value the report records, is produced at launch by `ensure_image` and no value can be pinned in the plan.
- SETTLED (2026-09-22, measured on Docker 29.8.1): `docker run -v <missing path>:/x` exits 0 and leaves `<missing path>` on the host as a `root:root` directory, while `--mount type=bind,src=<missing path>` refuses to start. This is the reason `MissingMountError` exists.
- SETTLED (2026-09-22): `sha256("python server.py")[:16]` is `7cc34ebdac143b58`, the value `test_checkpointing.py` pins as today's unconfined thread id.
- SETTLED (2026-09-22, run by the plan's counter-review): under this repository's strict pyright configuration, `# pyright: basic` plus `# pyright: reportMissingImports=false` at the top of a test file silence an unresolved import made inside the test body. A call to a function with the wrong arity stays an error under those pragmas, which is why the acceptance test is written only after `connect` takes a `ServerLaunch`.

## Implementation steps

Verification commands for every step, discovered from `CLAUDE.md` and `pyproject.toml`:

```bash
uv run pytest tests/unit
uv run pytest tests/integration
uv run ruff check . && uv run ruff format --check .
uv run pyright
```

Each step is test-first: write the test files listed under **Do** before the production code, run them red, then implement. Step 5 is the exception that proves the rule: its acceptance test stays red, as a strict expected failure limited to `ImportError`, until step 7.

### Step 1: the execution record and its rendering

**Files**
- `tests/unit/support/test_rendering_given.py` (modify)
- `tests/unit/support/test_rendering_then.py` (modify, where a new assertion abstracts something)
- `tests/unit/test_rendering.py` (modify)
- `src/mcp_auditor/domain/models.py` (modify)
- `src/mcp_auditor/domain/__init__.py` (modify)
- `src/mcp_auditor/domain/rendering.py` (modify)

**Do**

1. The report builders in `tests/unit/support/test_rendering_given.py` (`a_report_with_execution(record)`, and the existing `a_report(...)` for `execution=None`), any assertion helper that earns its place in `test_rendering_then.py`, then the new cases in `tests/unit/test_rendering.py`.
2. `src/mcp_auditor/domain/models.py`, next to the report models: `ExecutionRegime(StrEnum)` with `CONFINED = "confined"`, `DECLARED_CONTAINER = "declared_container"`, `UNCONFINED = "unconfined"`. `ExecutionRecord(BaseModel)` with `regime`, `image`, `image_digest`, `writable_paths`, `read_only_paths`, `oom_killed`, all but `regime` defaulting to `None`, and the field docstring on `oom_killed` saying it is read with the regime. `AuditReport` gains `execution: ExecutionRecord | None = None`.
3. `src/mcp_auditor/domain/__init__.py`: `ExecutionRecord` and `ExecutionRegime` join the imports and `__all__`, alphabetically.
4. `src/mcp_auditor/domain/rendering.py`, in `_render_summary_section`, when `report.execution` is not `None`: the `**Execution**` line right after `**Target**` (`confined, node:24-bookworm-slim@sha256:abc123def456`, the image alone without a digest, `declared container` and `unconfined` alone), then under a confined record `**Writable on host**`, `**Read-only on host**` when non-empty, and `**Killed on memory**` as `yes` or `unknown`. `render_json` is untouched.

**Test**
- Markdown: a confined report shows `**Execution**: confined, node:24-bookworm-slim@sha256:` plus exactly 12 hex characters, and a confined report whose digest is `None` shows the image and no `@`. A declared-container report shows `declared container`, an unconfined one `unconfined`, and neither shows a mount or kill line.
- A confined report lists its writable paths, shows `none` when there are none, and shows the read-only line only when it has read-only paths.
- Under `confined`, `**Killed on memory**` reads `yes` when `oom_killed` is true, `unknown` when it is `None`, and is absent when it is false. A report with `execution=None` has no `**Execution**` line.
- JSON: `execution` is a dict with the six keys and the full digest for a confined report, and `null` for a report without one.

**Verify** `uv run pytest tests/unit`, `uv run ruff check . && uv run ruff format --check .`, `uv run pyright`. All green.

### Step 2: the mount policy

**Files**
- `tests/unit/support/test_confinement_given.py` (new)
- `tests/unit/test_confinement.py` (new)
- `src/mcp_auditor/domain/confinement.py` (new)

**Do**

1. The given module: a `MountPolicy` with the refused roots of a fixed home (`/home/alice`) and optional declared mounts, and the `resolved` maps the cases need. Only what actually abstracts something.
2. `tests/unit/test_confinement.py`, red.
3. `src/mcp_auditor/domain/confinement.py`, top-down as described under its section: `MountPolicy` with `spellings_to_resolve` and `plan`, `MountPlan`, `MountSpec`, `DeclaredMount`, `parse_mount_option`, `looks_like_path`, `refused_roots`, `is_declared_container`, `RefusedMountError`, `MissingMountError`. `plan` stays under 20 lines by delegating the argv scan, the declared join and the refusal check to private helpers below it.

**Test** The cases listed for `tests/unit/test_confinement.py` under Unit tests above. No test touches the filesystem.

**Verify** `uv run pytest tests/unit`, `uv run ruff check . && uv run ruff format --check .`, `uv run pyright`. All green.

### Step 3: the launch and its container profile

**Files**
- `tests/unit/support/test_server_launch_given.py` (new)
- `tests/unit/test_server_launch.py` (new)
- `tests/unit/test_cve_launches.py` (new)
- `src/mcp_auditor/adapters/server_launch.py` (new)

**Do**

1. The given module: a `ContainerProfile` for the quick-start command, with a `MountPlan` holding one writable mount, and a variant with a read-only mount and a rewrite. The plans are built directly, not through the policy.
2. `tests/unit/test_server_launch.py` and `tests/unit/test_cve_launches.py`, red (`ServerLaunch` does not exist yet).
3. `src/mcp_auditor/adapters/server_launch.py`, top-down as described under its section: `ServerLaunch` with its three constructors, `__post_init__` checks, `spawn_command` / `spawn_args` and `record()`, then `ContainerIdentity`, `ContainerProfile`, and `container_argv` with its two comments (`--memory-swap`, tmpfs uid/gid).

**Test**
- `ServerLaunch.confined("python", ["s.py"], profile, {})` spawns `docker`, its spawn args end with the image, `python`, `s.py`, and its `command` and `args` stay `python`, `("s.py",)`.
- Building a `ServerLaunch` with regime `confined` and no profile raises `ValueError`, so does a profile with regime `unconfined`, and so does `ServerLaunch.declared_container("python", ["x.py"], {})`.
- `unconfined` and `declared_container` spawn their command and args verbatim, and the declared one carries the client environment it was given.
- The quick-start profile renders exactly the expected argv, flag by flag, as a single list equality.
- A read-only mount renders `-v /data:/data:ro`, and a rewrite replaces `./data` by its absolute path in the spawn args while `args` keeps `./data`.
- `record(False)` on a confined launch carries regime, image, digest, the writable and read-only paths as strings, and `oom_killed is False`. `record(None)` on an unconfined launch carries `None` in every other field.
- The CVE fixtures' launches are accepted by `declared_container`, as described under Unit tests.

**Verify** `uv run pytest tests/unit`, `uv run ruff check . && uv run ruff format --check .`, `uv run pyright`. All green.

### Step 4: `connect` takes a `ServerLaunch`

**Files**
- `tests/unit/test_docker_client_env.py` (new)
- `src/mcp_auditor/adapters/docker.py` (new, `docker_client_env` only)
- `src/mcp_auditor/adapters/mcp_client.py` (modify)
- `src/mcp_auditor/cli.py` (modify)
- `evals/run_evals.py` (modify)
- `evals/run_cve_benchmark.py` (modify)
- `tests/integration/test_mcp_client.py` (modify)
- `tests/integration/test_subtle_server.py` (modify)
- `tests/integration/test_chain_honeypot.py` (modify)

**Do**

1. The tests first. `tests/unit/test_docker_client_env.py`, red. Then the three integration test files, since they are this step's red-then-green signal:
   - `test_mcp_client.py` and `test_chain_honeypot.py`: `CONNECT_ARGS = ("uv", [...])` becomes `LAUNCH = ServerLaunch.unconfined("uv", ["run", "python", str(SERVER_PATH)])`, imported from `mcp_auditor.adapters.server_launch`. Every `StdioMCPClient.connect(*CONNECT_ARGS)` loses its star: nine occurrences in `test_mcp_client.py`, eight in `test_chain_honeypot.py`.
   - `test_subtle_server.py`: `connected_subtle_server()` builds the same `ServerLaunch.unconfined(...)` and passes it. The five call sites are unchanged.
   - No assertion changes anywhere.
2. `src/mcp_auditor/adapters/docker.py` with `docker_client_env` alone. `DockerRuntime` joins it in step 7.
3. `src/mcp_auditor/adapters/mcp_client.py`: `connect(cls, launch: ServerLaunch, errlog=None, tool_call_timeout=...)`, spawning `launch.spawn_command` and `launch.spawn_args`, with `env=get_default_environment() | dict(launch.client_env)` (imported from `mcp.client.stdio`) only when `launch.client_env` is not `None`.
4. `evals/run_evals.py` line ~215: `StdioMCPClient.connect(ServerLaunch.unconfined(honeypot.command, honeypot.args), errlog=devnull)`.
5. `evals/run_cve_benchmark.py`, `_silent_client`: `StdioMCPClient.connect(ServerLaunch.declared_container(launch.command, launch.args, docker_client_env(os.environ)), errlog=devnull)`. `evals/cve_environments.py` and its `Launch` dataclass are not touched.
6. `src/mcp_auditor/cli.py`: the one existing `connect(command, args, ...)` call becomes `connect(ServerLaunch.unconfined(command, args), ...)`, so the step leaves the product behaving exactly as before. Step 8 replaces it with the decision.

**Test** `tests/unit/test_docker_client_env.py` is the one new test. Beyond it, `pyright` is the assertion: after this step a raw `(command, args)` passed to `connect` is a type error at every call site. A preparatory refactoring: the behaviour is unchanged, the next change becomes easy.

**Verify** `uv run pytest tests/unit`, `uv run pytest tests/integration` (all connect through `ServerLaunch.unconfined` with argv unchanged), `uv run ruff check . && uv run ruff format --check .`, `uv run pyright`. All green. On a machine with Docker and the built fixture images, `uv run python -m evals.run_cve_benchmark --calibrate` still reports all six fixtures live.

### Step 5: the acceptance test of the confined path

**Files**
- `tests/integration/test_confined_launch.py` (new)

**Do**

1. Write the test as described under its section above, against the final API (`DockerRuntime`, `Host`, `LaunchContext`, `decide_launch`, `TargetExecution`, `StdioMCPClient.connect(launch)`), with every import of the not-yet-existing names inside the test body.
2. Add the two pyright pragmas at the top of the file, the `xfail(strict=True, raises=ImportError, ...)` marker, and the `skipif` on a direct `docker version`.

**Test** The test is the one this plan exists to turn green. It is written before any of the confined path's code (the probe, the runtime, the decision, the lifecycle).

**Verify** `uv run pytest tests/integration`: the new test reports `xfailed` on a machine with Docker, `skipped` without, and nothing else changes. `uv run pyright` is green with the pragmas. Lint and format green.

### Step 6: the host path probe

**Files**
- `tests/unit/test_host_paths.py` (new)
- `src/mcp_auditor/adapters/host_paths.py` (new)

**Do**

1. `tests/unit/test_host_paths.py`, red.
2. `src/mcp_auditor/adapters/host_paths.py`: `existing_paths`.

**Test** The cases listed for `tests/unit/test_host_paths.py` under Unit tests above.

**Verify** `uv run pytest tests/unit`, `uv run pytest tests/integration` (acceptance test still `xfailed`), `uv run ruff check . && uv run ruff format --check .`, `uv run pyright`. All green.

### Step 7: the container runtime, the decision and the lifecycle

**Files**
- `tests/fakes/container_runtime.py` (new)
- `tests/fakes/__init__.py` (modify)
- `tests/unit/support/test_target_execution_given.py` (new)
- `tests/unit/test_target_execution.py` (new)
- `tests/integration/test_confined_launch.py` (modify)
- `src/mcp_auditor/adapters/docker.py` (modify)
- `src/mcp_auditor/target_execution.py` (new)

**Do**

1. `FakeContainerRuntime` and its re-export, then `tests/unit/test_target_execution.py` and its given module.
2. `src/mcp_auditor/adapters/docker.py`: `DockerRuntime` and `DockerError` join `docker_client_env`, as described under its section.
3. `src/mcp_auditor/target_execution.py`: `IMAGE_BY_LAUNCHER`, `ContainerRuntime`, `LaunchOptions`, `Host`, `LaunchContext`, `LaunchDecision`, `LaunchRefused`, `decide_launch` and its helpers, `TargetExecution`, as described under its section. The module imports nothing from `console.py`.
4. `tests/integration/test_confined_launch.py`: remove the `xfail` marker and the two pyright pragmas, move the imports to module level, and skip on `not DockerRuntime().available()`.

`console.py` is not touched in this step: `cli.py` still calls `print_header(target_str)` until step 8, and the decision prints nothing. `DockerRuntime`'s methods get no unit tests: each is a `subprocess.run` wrapper, pyright checks that the class satisfies `ContainerRuntime` where the acceptance test passes it into a `LaunchContext`, and the acceptance test exercises it end to end.

**Test** (`tests/unit/test_target_execution.py`, `FakeContainerRuntime` throughout, `tmp_path` for the filesystem). Every case asserts on the returned `LaunchDecision` or on the raised `LaunchRefused` and its message, never on console output.
- `IMAGE_BY_LAUNCHER` maps `uvx` to the uv image, and `python`, `node`, `uv`, `bun` to nothing.
- `--unconfined` returns regime `unconfined` with command and args verbatim against an untouchable runtime, and with `--image` or `--mount` also given the decision carries a warning.
- `docker run <image>` as the command returns regime `declared_container`, args verbatim, carrying the host's `docker_env`, against an untouchable runtime.
- An unknown launcher without `--image` raises `LaunchRefused` with `no confinement profile` against an untouchable runtime.
- `--image` with an unknown launcher proceeds and uses that image, and `--image` with `npx` replaces the table's image.
- Docker unavailable raises `LaunchRefused` with a message naming `--unconfined`.
- A `tcp://` endpoint raises `LaunchRefused` and the fake records no pull, and `unix:///run/user/1000/docker.sock` proceeds.
- A refused root in argv raises `LaunchRefused` with `--mount` named in the message, and the fake records no pull. A `--mount` on a missing path raises `LaunchRefused` naming that path.
- A pull error raises `LaunchRefused` carrying the daemon's message.
- `npx <pkg> <tmp_path>` returns a confined launch whose record carries the image, the digest the fake returned and `tmp_path` as writable, and whose `client_env` is the host's `docker_env`.
- A bare word naming an existing entry of the working directory yields a decision carrying the warning.
- A runtime that does not enforce the pids limit yields a decision carrying the warning.
- `TargetExecution` over a confined launch removes the container on a normal exit and when the block raises, its `record` is `None` inside the block and carries the kill state the fake reported after it. Over an unconfined launch it touches an untouchable runtime without error.

**Verify** `uv run pytest tests/unit`, `uv run pytest tests/integration` (the acceptance test now **passes** on a machine with Docker, skips without), `uv run ruff check . && uv run ruff format --check .`, `uv run pyright`. All green.

### Step 8: CLI wiring, the display, the checkpoint and report modules

**Files**
- `tests/unit/test_cli.py` (modify)
- `tests/unit/test_cli_resume.py` (renamed to `tests/unit/test_checkpointing.py`)
- `tests/unit/test_config_file.py` (modify)
- `tests/unit/test_console_display.py` (modify)
- `src/mcp_auditor/checkpointing.py` (new)
- `src/mcp_auditor/report_files.py` (new)
- `src/mcp_auditor/console.py` (modify)
- `src/mcp_auditor/cli.py` (modify)

**Do**

1. The test files first: `test_cli.py`, `test_checkpointing.py` (the renamed file, its import moved to `mcp_auditor.checkpointing`, plus the thread-id cases), `test_config_file.py`, and the two `print_header` updates in `test_console_display.py`.
2. `src/mcp_auditor/checkpointing.py` and `src/mcp_auditor/report_files.py`, as described under their sections.
3. `src/mcp_auditor/console.py`: `print_header(target_command, regime)`, `print_warning(message)`, and `print_server_stderr` / `summarize_exception_group` moved from `cli.py`.
4. `src/mcp_auditor/cli.py`, as described under its section: the three options and the updated `run` docstring, `AuditConfig.launch`, `_launch_context` and `decide_launch` before the LLM initialization, `LaunchRefused` turned into `print_error` and `SystemExit(1)`, the warnings printed, the header, `compute_thread_id(launch)`, `TargetExecution` first in the `async with`, `_run_full_audit` returning the report, the `model_copy` with `execution.record` after the block, then the summary, the report writing and the CI exit decision. The moved functions and `ReportPaths` are deleted from it.
5. `wc -l src/mcp_auditor/cli.py` reads at most 333.

**Test**
- `tests/unit/test_cli.py`: `--unconfined`, `--image` and `--mount` appear in `run --help`. A `CliRunner` invocation of `run -- python x.py` without `--unconfined` exits 1, prints `no confinement profile`, and reaches neither Docker nor the LLM, with or without Docker and with or without an API key on the runner.
- `tests/unit/test_checkpointing.py`: the existing `resume_or_reset` cases, unchanged, and the thread-id cases listed under Unit tests.
- `tests/unit/test_config_file.py`: `unconfined: true` in the configuration file raises `UnknownKeyError`.
- `tests/unit/test_console_display.py`: the panel carries the regime (one test asserts `confined` reaches the panel), and the two existing `print_header` calls take the new argument.

**Verify** `uv run pytest tests/unit`, `uv run pytest tests/integration`, `uv run ruff check . && uv run ruff format --check .`, `uv run pyright`. All green. Then the manual checks of the Verification section, `docker ps -a --filter label=mcp-auditor` empty after each.

### Step 9: the living docs

**Files**
- `README.md` (modify)
- `CHANGELOG.md` (modify)
- `CLAUDE.md` (modify)
- `CONTRIBUTING.md` (modify)

**Do**

1. `README.md`, `CHANGELOG.md`, `CLAUDE.md`, `CONTRIBUTING.md` as described under their sections.
2. `.github/workflows/ci.yml` is deliberately untouched: `ubuntu-latest` ships Docker, so the acceptance test runs on every push. A `docker/login-action` step is the answer if Docker Hub's anonymous pull limit ever bites, added then, not now.

**Test** `tests/unit/test_readme_policy.py` must stay green after the README edits, and it is the assertion on the new bullet's wording.

**Verify** `uv run pytest tests/unit` (readme policy included), `uv run pytest tests/integration`, `uv run ruff check . && uv run ruff format --check .`, `uv run pyright`. Then:

```bash
docker ps -a --filter label=mcp-auditor              # empty
uv run python -m evals.run_cve_benchmark --calibrate # unchanged, all six fixtures live
```

A full audit with `-o report.json` shows the confined `execution` entry of the Verification section, and the same run with `--unconfined` shows `"regime": "unconfined"` with the other fields `null`.
