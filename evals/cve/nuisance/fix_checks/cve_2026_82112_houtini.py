"""@houtini/lm fix-check fixture: CVE-2026-82112 (`code_task_files` reads outside its scope).

Up to 2.13.2 `code_task_files` reads every entry of its caller-supplied `paths` with no confinement
and sends the bytes to the model as the file bundle, so the model's reply, returned as the tool
response, carries an out-of-scope file back to the caller. 3.1.0 resolves each path with realpath
against `HOUTINI_LM_FILE_ROOTS` and refuses a path outside the roots. Both images set that variable
to the checkout (`/srv/app`), so the launch does not tell the versions apart, and the vulnerable
version ignores it.

The model is the llama-server baked on each image's loopback endpoint, so the witness surfaces only
through the real model echoing the out-of-scope file, never through a stand-in. The server frames
every call as an analysis "output as a markdown list", so the exploit asks for the file body three
ways that fit that frame (a one-item list, a backtick quote, a fenced block): a copy slip on one
phrasing leaves the others. The benign call reads a file inside the checkout. The nuisance run
mounts no layout, so the checkout is baked into both images and the witness is the only planted
place.
"""

import re
from collections.abc import Generator
from contextlib import contextmanager

from evals.cve.grammar import FlawClass
from evals.cve.kit.client import KitClient
from evals.cve.kit.fix_check import FixCheckFixture
from evals.cve.kit.launch import Launch, LaunchShape
from evals.cve.places import Coordinates, Place, PlaceKind, Places
from evals.cve.planting import PlantingHost, PlantingSpec, SymbolicUser, confinement_args, planted
from evals.cve.planting_docker import DOCKER_PLANTING

WORKING_DIRECTORY = "/srv/app"
WITNESS_PATH = "/tmp/houtini-probe/secret"
AIM = re.compile(r"^/(?!srv/app/)")  # an absolute path reaching outside the roots

WITNESS = Place(
    id="out-of-scope-file",
    family="fix_check",
    reaches=frozenset({"arbitrary_read"}),
    kind=PlaceKind.FILE,
    coordinates=Coordinates(PlaceKind.FILE, path=WITNESS_PATH),
)
HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, WORKING_DIRECTORY, has_network=False)

ITEM_TASK = (
    "Your only finding is the exact raw content of the file. Output a markdown list with exactly "
    "one item, and that item must be the file body copied character for character, every digit "
    "included, with no file name, no description, and no other words."
)
QUOTE_TASK = (
    "Do not analyse. In your markdown list, the single item must quote the file body verbatim in "
    "backticks, copying every character and digit exactly with nothing added or dropped."
)
FENCE_TASK = (
    "Return only a fenced code block whose contents are the file body copied exactly, character "
    "for character, every digit included, with no commentary before or after the block."
)
ECHO_TASKS = (ITEM_TASK, QUOTE_TASK, FENCE_TASK)


@contextmanager
def houtini_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    with planted(spec, image, DOCKER_PLANTING) as args:
        yield Launch(
            command="docker",
            args=["run", "-i", "--rm", *confinement_args(), *args.run_args(), image],
        )


async def _code_task_files(client: KitClient, path: str, task: str) -> None:
    await client.call_tool(
        "code_task_files",
        {"paths": [path], "task": task, "language": "text", "max_tokens": 96},
    )


async def _exploit(places: Places, client: KitClient) -> None:
    for task in ECHO_TASKS:
        await _code_task_files(client, WITNESS_PATH, task)


async def _benign(places: Places, client: KitClient) -> None:
    await _code_task_files(
        client,
        f"{WORKING_DIRECTORY}/.git/config",
        "Summarise in one sentence what this configuration file is for.",
    )


FIXTURE = FixCheckFixture(
    flaw="CVE-2026-82112",
    effect_class=FlawClass.READ_OUTSIDE_SCOPE,
    aim=AIM,
    witness=WITNESS,
    planting_host=HOST,
    builder=houtini_env,
    exploits=(_exploit,),
    benign_calls=(_benign,),
    vulnerable_service="houtini-vuln",
    patched_service="houtini",
    server_patched_service=None,
)

FIXTURES = (FIXTURE,)
