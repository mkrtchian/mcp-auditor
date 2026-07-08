import secrets
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from evals.cve_seeding import init_git_repo_with_commit, make_dir_with_file, plant_symlink

FILESYSTEM_SERVER = "@modelcontextprotocol/server-filesystem@0.6.2"
GIT_SERVER = "mcp-server-git@2025.7.1"  # < 2025.9.25 & < 2025.12.18: carries both git CVEs

# The filesystem CVEs surface the leak through a read tool, but the blind
# generator first needs list_directory to discover the planted symlink.
FILESYSTEM_READ_TOOLS = frozenset({"read_file", "list_directory"})

# Bucket-A third-party targets need an external precondition (cluster, gemini CLI,
# served endpoint) that prepare() cannot build, so they await a run-time setup
# rather than an mcp-auditor capability. Naming it keeps their status honest
# (missed_awaiting_capability, not a false missed) until the operator wires the env.
THIRD_PARTY_SETUP = "third-party env setup (confirm at run)"


@dataclass(frozen=True)
class Launch:
    command: str
    args: list[str]
    chain_budget: int = 0
    max_chain_steps: int = 3  # only consulted when chain_budget > 0


@dataclass(frozen=True)
class CVETarget:
    cve_id: str
    severity: str
    sentinel: str
    prepare: Callable[[Path], Launch]
    blocker: str | None
    note: str
    tools_filter: frozenset[str] | None


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
_GEMINI_FILE_SENTINEL = _sentinel()
_FETCH_SSRF_SENTINEL = _sentinel()


def _filesystem_launch(root: Path) -> Launch:
    return Launch(command="npx", args=["-y", FILESYSTEM_SERVER, str(root / "sandbox")])


def _git_launch(root: Path, chain_budget: int = 0, max_chain_steps: int = 3) -> Launch:
    return Launch(
        command="uvx",
        args=[GIT_SERVER, "--repository", str(root / "repo")],
        chain_budget=chain_budget,
        max_chain_steps=max_chain_steps,
    )


def _prepare_symlink_traversal(root: Path) -> Launch:
    (root / "sandbox").mkdir(parents=True)
    flag = make_dir_with_file(root / "outside", "flag.txt", _SYMLINK_TRAVERSAL_SENTINEL)
    plant_symlink(root / "sandbox" / "report", flag)
    return _filesystem_launch(root)


def _prepare_prefix_collision(root: Path) -> Launch:
    (root / "sandbox").mkdir(parents=True)
    make_dir_with_file(root / "sandbox_secret", "flag.txt", _PREFIX_COLLISION_SENTINEL)
    return _filesystem_launch(root)


def _prepare_repository_bypass(root: Path) -> Launch:
    init_git_repo_with_commit(root / "repo", "initial commit")
    init_git_repo_with_commit(root / "other", _REPOSITORY_BYPASS_SENTINEL)
    return _git_launch(root)


def _prepare_git_init_traversal(root: Path) -> Launch:
    init_git_repo_with_commit(root / "repo", "initial commit")
    make_dir_with_file(root / "secret", "flag.txt", _GIT_INIT_TRAVERSAL_SENTINEL)
    return _git_launch(root, chain_budget=3, max_chain_steps=5)


# Third-party bucket-A: the sentinel must land where a *generic* exfil surfaces
# it, since the generator is blind to targeted paths. Exact reachability (env
# var, cwd file, served internal URL) is a run-time confirmation, deferred with
# the manual benchmark run. TODO confirm the pinned tool names at run.
def _prepare_kubernetes_injection(root: Path) -> Launch:
    make_dir_with_file(root, "leak.txt", _KUBERNETES_INJECTION_SENTINEL)
    return Launch(command="npx", args=["-y", "mcp-server-kubernetes@2.4.9"])


def _prepare_gemini_file(root: Path) -> Launch:
    make_dir_with_file(root, "context.txt", _GEMINI_FILE_SENTINEL)
    return Launch(command="npx", args=["-y", "gemini-mcp-tool@1.1.5"])


def _prepare_fetch_ssrf(root: Path) -> Launch:
    make_dir_with_file(root, "internal.txt", _FETCH_SSRF_SENTINEL)
    return Launch(command="npx", args=["-y", "mcp-fetch-server@1.0.2"])


CVE_TARGETS: list[CVETarget] = [
    CVETarget(
        cve_id="CVE-2025-53109",
        severity="CVSS 8.4",
        sentinel=_SYMLINK_TRAVERSAL_SENTINEL,
        prepare=_prepare_symlink_traversal,
        blocker=None,
        note="Symlink inside the allowed dir is discoverable and read out of scope.",
        tools_filter=FILESYSTEM_READ_TOOLS,
    ),
    CVETarget(
        cve_id="CVE-2025-53110",
        severity="CVSS 7.3",
        sentinel=_PREFIX_COLLISION_SENTINEL,
        prepare=_prepare_prefix_collision,
        blocker="declared-scope awareness",
        note="Prefix-collision sibling is derivable only from the declared boundary.",
        tools_filter=FILESYSTEM_READ_TOOLS,
    ),
    CVETarget(
        cve_id="CVE-2025-68145",
        severity="CVSS 7.1",
        sentinel=_REPOSITORY_BYPASS_SENTINEL,
        prepare=_prepare_repository_bypass,
        blocker="declared-scope awareness",
        note="--repository bypass needs the generator to aim outside the declared repo.",
        tools_filter=frozenset({"git_log"}),
    ),
    CVETarget(
        cve_id="CVE-2025-68143",
        severity="CVSS 8.8",
        sentinel=_GIT_INIT_TRAVERSAL_SENTINEL,
        prepare=_prepare_git_init_traversal,
        blocker="cross-tool chains + declared-scope awareness",
        note="git_init(out-of-scope) -> git_add(.) -> git_diff_staged surfaces the content.",
        tools_filter=frozenset({"git_init", "git_add", "git_diff_staged"}),
    ),
    CVETarget(
        cve_id="CVE-2025-53355",
        severity="CVSS 7.5",
        sentinel=_KUBERNETES_INJECTION_SENTINEL,
        prepare=_prepare_kubernetes_injection,
        blocker=THIRD_PARTY_SETUP,
        note="Command injection via kubectl_scale/patch execSync; needs a cluster at run.",
        tools_filter=frozenset({"kubectl_scale", "kubectl_patch"}),
    ),
    CVETarget(
        cve_id="CVE-2026-0755",
        severity="CVSS 9.8",
        sentinel=_GEMINI_FILE_SENTINEL,
        prepare=_prepare_gemini_file,
        blocker=THIRD_PARTY_SETUP,
        note="Command injection: prompt reaches execAsync shell; needs gemini CLI at run.",
        tools_filter=frozenset({"ask-gemini"}),
    ),
    CVETarget(
        cve_id="CVE-2025-65513",
        severity="CVSS 9.3",
        sentinel=_FETCH_SSRF_SENTINEL,
        prepare=_prepare_fetch_ssrf,
        blocker=THIRD_PARTY_SETUP,
        note="SSRF via is_ip_private bypass; needs a served internal endpoint at run.",
        tools_filter=frozenset({"fetch"}),
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
