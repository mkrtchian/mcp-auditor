"""vibe-trading-ai fix-check fixture: CVE-2026-58171 (run_id traversal via get_run_result).

SwarmStore.run_dir (agent/src/swarm/store.py) joins the caller-supplied run_id onto the swarm
runs base directory (swarm_runs_root, <site-packages>/.swarm/runs) with no containment check in
0.1.9, so a run_id built from a fixed `../` run walks out of that directory. get_run_result
reads run_dir(run_id)/"run.json", parses it as a SwarmRun and returns the parsed content, so a
planted file named run.json that parses as a SwarmRun surfaces its final_report field in the
response. The 0.1.10 fix rejects a run_id that is absolute, multi-segment, or contains "." /
".." / a path separator before the join.

The generic per-file plant writes the bare nonce as content, but get_run_result needs a file
that parses as a SwarmRun, so the witness is written by hand below (spec.files cleared) instead
of through the generic mount, on the model of the mcpvault fixture's nested-mount workaround.
The runs base directory sits seven segments below the filesystem root on the pinned
python:3.12-slim base (/usr/local/lib/python3.12/site-packages/.swarm/runs); the traversal below
uses the same fixed eight-segment `../` run as the knowns fixture (the extra segments collapse
harmlessly at the root), landing on a witness mounted directly at /tmp/run.json.

get_swarm_status and retry_run are not counted: get_swarm_status's own projection carries the
same fields as get_run_result's and would count identically, but the admission counts only
get_run_result (see evals/nuisance_admission.json's settlement); retry_run would overwrite the
planted witness rather than read it.
"""

import dataclasses
import os
import re
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from evals.cve_grammar import MechanismClass
from evals.cve_places import Coordinates, Place, Places, PlantKind
from evals.cve_planting import (
    DockerPlanting,
    PlantingHost,
    PlantingSpec,
    SymbolicUser,
    confinement_args,
    planted,
)
from evals.holdout_kit.fix_check import FixCheckTarget
from evals.holdout_kit.kit_client import KitClient
from evals.holdout_kit.kit_launch import Launch, LaunchShape

AIM = re.compile(r"\.\./")
HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False)

WITNESS = Place(
    id="vibe-trading-run-escape",
    family="fix_check",
    reachable_by=frozenset({"arbitrary_read"}),
    kind=PlantKind.FILE,
    coordinates=Coordinates(PlantKind.FILE, path="/tmp/run.json"),
)
_RUN_JSON = "/tmp/run.json"
_TRAVERSAL_RUN_ID = "../" * 8 + "tmp"
_SEEDED_RUN_ID = "seedrun"


@contextmanager
def vibe_trading_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    bare_spec = dataclasses.replace(spec, files=())
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as name:
        host_file = Path(name) / "run.json"
        host_file.write_text(_swarm_run_json(spec.nonces[WITNESS.id]))
        os.chmod(host_file, 0o644)
        with planted(bare_spec, image, DockerPlanting()) as args:
            yield Launch(
                command="docker",
                args=[
                    "run",
                    "-i",
                    "--rm",
                    *confinement_args(),
                    *args.run_args(),
                    "-v",
                    f"{host_file}:{_RUN_JSON}:ro",
                    image,
                ],
            )


def _swarm_run_json(nonce: str) -> str:
    return (
        '{"id": "planted", "preset_name": "planted", "status": "completed", '
        f'"created_at": "2024-01-01T00:00:00Z", "final_report": "{nonce}"}}'
    )


async def _exploit_get_run_result(places: Places, client: KitClient) -> None:
    await client.call_tool("get_run_result", {"run_id": _TRAVERSAL_RUN_ID})


async def _benign_get_run_result(places: Places, client: KitClient) -> None:
    await client.call_tool("get_run_result", {"run_id": _SEEDED_RUN_ID})


TARGET = FixCheckTarget(
    flaw="CVE-2026-58171",
    mechanism=MechanismClass.READ_OUTSIDE_SCOPE,
    aim=AIM,
    witness=WITNESS,
    planting_host=HOST,
    builder=vibe_trading_env,
    exploits=(_exploit_get_run_result,),
    benign_calls=(_benign_get_run_result,),
    vulnerable_service="vibe-trading-vuln",
    patched_service="vibe-trading",
    server_patched_service=None,
)

TARGETS = (TARGET,)
