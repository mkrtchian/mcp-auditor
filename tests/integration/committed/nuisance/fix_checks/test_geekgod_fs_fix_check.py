from evals.cve.nuisance.fix_checks import cve_2026_7400_geekgod_fs as geekgod_fs
from tests.integration.committed.nuisance.fix_checks.support import (
    test_geekgod_fs_fix_check_given as given,
)

DECLARED_SCOPE = "/tmp"
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


def test_the_witness_sits_at_a_sibling_prefix_outside_the_declared_scope():
    witness = str(geekgod_fs.WITNESS.coordinates.path)

    assert witness.startswith(DECLARED_SCOPE)
    assert not witness.startswith(f"{DECLARED_SCOPE}/")


async def test_every_exploit_leaves_the_declared_scope_through_the_sibling_prefix():
    for exploit in geekgod_fs.FIXTURE.exploits:
        paths = [
            value
            for _, args in await given.tool_calls(exploit)
            for value in given.path_values(args)
        ]

        assert paths
        assert all(path.startswith(geekgod_fs.OUTSIDE_PATH) for path in paths)
        assert all(not path.startswith(f"{DECLARED_SCOPE}/") for path in paths)


async def test_no_modifying_exploit_names_the_witness_itself():
    exploits = await given.tool_calls(*geekgod_fs.FIXTURE.exploits)
    modifying = [args for name, args in exploits if name in MODIFYING_TOOLS]

    assert len(modifying) == len(MODIFYING_TOOLS)
    assert all(
        path.startswith(f"{geekgod_fs.OUTSIDE_PATH}/")
        for args in modifying
        for path in given.path_values(args)
    )


async def test_every_benign_call_stays_inside_the_declared_scope():
    paths = [
        value
        for _, args in await given.tool_calls(*geekgod_fs.FIXTURE.benign_calls)
        for value in given.path_values(args)
    ]

    assert paths
    assert all(path == DECLARED_SCOPE or path.startswith(f"{DECLARED_SCOPE}/") for path in paths)
