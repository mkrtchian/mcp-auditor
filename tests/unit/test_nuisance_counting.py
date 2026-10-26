import tests.unit.support.test_nuisance_admission_given as given
from evals.cve_grammar import VALID_CATEGORIES, MechanismClass
from evals.nuisance_counting import counted_flaws, counted_tools, flaw_counted_tools

_READ = MechanismClass.READ_OUTSIDE_SCOPE
_EXEC = MechanismClass.COMMAND_EXECUTION


def test_a_flaw_still_surfacing_on_the_patched_version_is_not_counted():
    flaw = given.a_flaw_record(
        "CVE-2025-0001", _READ, "1.2.0", fix_check=_fix_check(patched_surfaces=True)
    )
    server = given.a_server([flaw])

    assert counted_flaws(server) == []


def test_a_flaw_surfacing_on_the_servers_patched_version_is_not_counted():
    flaw = given.a_flaw_record(
        "CVE-2025-0001", _READ, "1.2.0", fix_check=_fix_check(server_patched_surfaces=True)
    )
    server = given.a_server([flaw])

    assert counted_flaws(server) == []


def test_a_flaw_without_a_grammar_class_is_not_counted():
    flaw = given.a_flaw_record("CVE-2025-0001", None, "1.2.0")
    server = given.a_server([flaw])

    assert counted_flaws(server) == []


def test_a_passing_flaw_is_counted():
    flaw = given.a_flaw_record("CVE-2025-0001", _READ, "1.2.0")
    server = given.a_server([flaw])

    assert counted_flaws(server) == [flaw]


def test_a_renamed_tool_is_keyed_by_its_patched_name():
    flaw = given.a_flaw_record(
        "CVE-2025-0001", _READ, "1.2.0", tools=[given.a_tool("old", "new", "renamed")]
    )
    server = given.a_server([flaw])

    assert set(counted_tools(server)) == {"new"}


def test_a_removed_tool_is_absent():
    flaw = given.a_flaw_record(
        "CVE-2025-0001", _READ, "1.2.0", tools=[given.a_tool("gone", None, "removed")]
    )
    server = given.a_server([flaw])

    assert counted_tools(server) == {}


def test_a_backend_needing_flaw_contributes_no_tool():
    flaw = given.a_flaw_record("CVE-2025-0001", _READ, "1.2.0")
    flaw = flaw.model_copy(update={"backend_need": "external"})
    server = given.a_server([flaw])

    assert counted_tools(server) == {}


def test_an_effect_is_function_flaw_contributes_no_tool():
    flaw = given.a_flaw_record("CVE-2025-0001", _READ, "1.2.0")
    flaw = flaw.model_copy(update={"declared_function_is_effect": True})
    server = given.a_server([flaw])

    assert counted_tools(server) == {}


def test_a_tool_of_two_classes_takes_the_union_of_their_categories():
    read_flaw = given.a_flaw_record(
        "CVE-2025-0001", _READ, "1.2.0", tools=[given.a_tool("probe", "probe", "unchanged")]
    )
    exec_flaw = given.a_flaw_record(
        "PYSEC-2025-1", _EXEC, "1.2.0", tools=[given.a_tool("probe", "probe", "unchanged")]
    )
    server = given.a_server([read_flaw, exec_flaw])

    assert counted_tools(server)["probe"] == VALID_CATEGORIES[_READ] | VALID_CATEGORIES[_EXEC]


def _fix_check(**overrides: object):
    return given.a_passing_fix_check().model_copy(update=overrides)


def test_the_counted_tools_of_a_flaw_are_the_patched_names_still_present():
    flaw = given.a_flaw_record(
        "CVE-2025-0001",
        _READ,
        "1.2.0",
        tools=[
            given.a_tool("probe", "probe", "unchanged"),
            given.a_tool("old", "new", "renamed"),
            given.a_tool("gone", None, "removed"),
        ],
    )

    assert flaw_counted_tools(flaw) == {"probe", "new"}


def test_a_backend_needing_flaw_has_no_counted_tool():
    flaw = given.a_flaw_record("CVE-2025-0001", _READ, "1.2.0")

    assert flaw_counted_tools(flaw.model_copy(update={"backend_need": "external"})) == frozenset()


def test_a_flaw_whose_backend_the_fixture_provides_keeps_its_tool():
    flaw = given.a_flaw_record(
        "CVE-2025-0001", _READ, "1.2.0", tools=[given.a_tool("probe", "probe", "unchanged")]
    )

    assert flaw_counted_tools(flaw.model_copy(update={"backend_need": "fixture"})) == {"probe"}


def test_an_effect_is_function_flaw_has_no_counted_tool():
    flaw = given.a_flaw_record("CVE-2025-0001", _READ, "1.2.0")
    flaw = flaw.model_copy(update={"declared_function_is_effect": True})

    assert flaw_counted_tools(flaw) == frozenset()


def test_a_flaw_without_a_grammar_class_has_no_counted_tool():
    flaw = given.a_flaw_record("CVE-2025-0001", None, "1.2.0")

    assert flaw_counted_tools(flaw) == frozenset()
