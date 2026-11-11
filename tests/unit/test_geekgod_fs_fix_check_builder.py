from collections.abc import Awaitable, Callable
from typing import Any

from evals.cve.kit.client import KitClient
from evals.cve.nuisance.fix_checks import cve_2026_7400_geekgod_fs as geekgod_fs
from evals.cve_places import Places
from tests.fakes import FakeKitClient

DECLARED_SCOPE = "/tmp"
TOOLS = frozenset(
    {
        "read_file_tool",
        "write_file_tool",
        "list_directory_tool",
        "create_directory_tool",
        "delete_file_tool",
        "delete_directory_tool",
        "move_file_tool",
        "copy_file_tool",
        "search_files_tool",
        "get_file_info_tool",
    }
)
MODIFYING_TOOLS = frozenset(
    {
        "write_file_tool",
        "create_directory_tool",
        "delete_file_tool",
        "delete_directory_tool",
        "move_file_tool",
        "copy_file_tool",
    }
)

Call = Callable[[Places, KitClient], Awaitable[None]]


async def _record(calls: tuple[Call, ...]) -> list[tuple[str, dict[str, Any]]]:
    client = FakeKitClient()
    for call in calls:
        await call({}, client)
    return client.calls


def _path_values(args: dict[str, Any]) -> list[str]:
    return [value for value in args.values() if isinstance(value, str) and value.startswith("/")]


def test_the_witness_sits_at_a_sibling_prefix_outside_the_declared_scope():
    witness = str(geekgod_fs.WITNESS.coordinates.path)

    assert witness.startswith(DECLARED_SCOPE)
    assert not witness.startswith(f"{DECLARED_SCOPE}/")


async def test_each_of_the_ten_tools_has_an_exploit_and_a_benign_call():
    exploits = await _record(geekgod_fs.FIXTURE.exploits)
    benign = await _record(geekgod_fs.FIXTURE.benign_calls)

    assert {name for name, _ in exploits} == TOOLS
    assert {name for name, _ in benign} == TOOLS


async def test_every_exploit_leaves_the_declared_scope_through_the_sibling_prefix():
    for exploit in geekgod_fs.FIXTURE.exploits:
        paths = [value for _, args in await _record((exploit,)) for value in _path_values(args)]

        assert paths
        assert all(path.startswith(geekgod_fs.OUTSIDE_PATH) for path in paths)
        assert all(not path.startswith(f"{DECLARED_SCOPE}/") for path in paths)


async def test_no_modifying_exploit_names_the_witness_itself():
    exploits = await _record(geekgod_fs.FIXTURE.exploits)
    modifying = [args for name, args in exploits if name in MODIFYING_TOOLS]

    assert len(modifying) == len(MODIFYING_TOOLS)
    assert all(
        path.startswith(f"{geekgod_fs.OUTSIDE_PATH}/")
        for args in modifying
        for path in _path_values(args)
    )


async def test_every_benign_call_stays_inside_the_declared_scope():
    paths = [
        value
        for _, args in await _record(geekgod_fs.FIXTURE.benign_calls)
        for value in _path_values(args)
    ]

    assert paths
    assert all(path == DECLARED_SCOPE or path.startswith(f"{DECLARED_SCOPE}/") for path in paths)
