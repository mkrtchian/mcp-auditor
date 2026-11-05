import tests.unit.support.test_nuisance_admission_given as admission
import tests.unit.support.test_nuisance_counting_given as given
from evals.cve_grammar import VALID_CATEGORIES, MechanismClass
from evals.nuisance_counting import (
    counted_flaws,
    counted_tools,
    declared_function_tools,
    flaw_counted_tools,
    flaw_tools,
)

_READ = MechanismClass.READ_OUTSIDE_SCOPE
_EXEC = MechanismClass.COMMAND_EXECUTION


def test_a_flaw_still_surfacing_on_the_patched_version_is_not_counted():
    flaw = admission.a_flaw_record(
        "CVE-2025-0001", _READ, "1.2.0", fix_check=given.a_fix_check(patched_surfaces=True)
    )
    server = admission.a_server([flaw])

    assert counted_flaws(server) == []


def test_a_flaw_surfacing_on_the_servers_patched_version_is_not_counted():
    flaw = admission.a_flaw_record(
        "CVE-2025-0001", _READ, "1.2.0", fix_check=given.a_fix_check(server_patched_surfaces=True)
    )
    server = admission.a_server([flaw])

    assert counted_flaws(server) == []


def test_a_flaw_without_a_grammar_class_is_not_counted():
    flaw = admission.a_flaw_record("CVE-2025-0001", None, "1.2.0")
    server = admission.a_server([flaw])

    assert counted_flaws(server) == []


def test_a_passing_flaw_is_counted():
    flaw = admission.a_flaw_record("CVE-2025-0001", _READ, "1.2.0")
    server = admission.a_server([flaw])

    assert counted_flaws(server) == [flaw]


def test_an_effect_is_function_flaw_contributes_no_tool():
    flaw = admission.a_flaw_record("CVE-2025-0001", _READ, "1.2.0")
    flaw = flaw.model_copy(update={"declared_function_is_effect": True})
    server = admission.a_server([flaw])

    assert counted_tools(server) == {}


def test_a_tool_recorded_as_its_effect_under_a_flaw_recorded_otherwise_stays_counted():
    tool = given.a_probe_whose_declared_function_is_effect(True)
    flaw = admission.a_flaw_record("CVE-2025-0001", _READ, "1.2.0", tools=[tool])

    assert set(counted_tools(admission.a_server([flaw]))) == {"probe"}


def test_a_tool_of_two_classes_takes_the_union_of_their_categories():
    read_flaw = admission.a_flaw_record(
        "CVE-2025-0001", _READ, "1.2.0", tools=[admission.a_tool("probe", "probe", "unchanged")]
    )
    exec_flaw = admission.a_flaw_record(
        "PYSEC-2025-1", _EXEC, "1.2.0", tools=[admission.a_tool("probe", "probe", "unchanged")]
    )
    server = admission.a_server([read_flaw, exec_flaw])

    assert counted_tools(server)["probe"] == VALID_CATEGORIES[_READ] | VALID_CATEGORIES[_EXEC]


def test_the_counted_tools_of_a_flaw_are_the_patched_names_still_present():
    flaw = admission.a_flaw_record(
        "CVE-2025-0001",
        _READ,
        "1.2.0",
        tools=[
            admission.a_tool("probe", "probe", "unchanged"),
            admission.a_tool("old", "new", "renamed"),
            admission.a_tool("gone", None, "removed"),
        ],
    )

    assert flaw_counted_tools(flaw) == {"probe", "new"}


def test_a_backend_needing_flaw_has_no_counted_tool():
    flaw = admission.a_flaw_record("CVE-2025-0001", _READ, "1.2.0")

    assert flaw_counted_tools(flaw.model_copy(update={"backend_need": "external"})) == frozenset()


def test_a_flaw_whose_backend_the_fixture_provides_keeps_its_tool():
    flaw = admission.a_flaw_record(
        "CVE-2025-0001", _READ, "1.2.0", tools=[admission.a_tool("probe", "probe", "unchanged")]
    )

    assert flaw_counted_tools(flaw.model_copy(update={"backend_need": "fixture"})) == {"probe"}


def test_an_effect_is_function_flaw_has_no_counted_tool():
    flaw = admission.a_flaw_record("CVE-2025-0001", _READ, "1.2.0")
    flaw = flaw.model_copy(update={"declared_function_is_effect": True})

    assert flaw_counted_tools(flaw) == frozenset()


def test_a_flaw_without_a_grammar_class_has_no_counted_tool():
    flaw = admission.a_flaw_record("CVE-2025-0001", None, "1.2.0")

    assert flaw_counted_tools(flaw) == frozenset()


def test_a_tool_whose_real_software_does_not_answer_is_not_counted_and_its_flaw_still_counts():
    flaw = admission.a_flaw_record(
        "CVE-2025-0001",
        _READ,
        "1.2.0",
        tools=[admission.a_tool("probe", "probe", "unchanged"), given.a_silent_tool("capture")],
    )
    server = admission.a_server([flaw])

    assert set(counted_tools(server)) == {"probe"}
    assert counted_flaws(server) == [flaw]


def test_a_tool_without_a_real_software_record_stays_counted():
    tool = admission.a_tool("probe", "probe", "unchanged").model_copy(
        update={"real_software": None}
    )
    flaw = admission.a_flaw_record("CVE-2025-0001", _READ, "1.2.0", tools=[tool])

    assert flaw_counted_tools(flaw) == {"probe"}


def test_a_flaw_whose_positive_control_rests_on_a_relaying_stand_in_is_not_counted():
    flaw = admission.a_flaw_record(
        "CVE-2025-0001",
        _READ,
        "1.2.0",
        fix_check=given.a_fix_check(relies_on_relaying_stand_in=True),
    )
    server = admission.a_server([flaw])

    assert counted_flaws(server) == []


def test_the_tools_of_a_flaw_keep_a_tool_whose_real_software_does_not_answer():
    flaw = admission.a_flaw_record(
        "CVE-2025-0001",
        _READ,
        "1.2.0",
        tools=[
            admission.a_tool("probe", "probe", "unchanged"),
            given.a_silent_tool("capture"),
            admission.a_tool("gone", None, "removed"),
        ],
    )

    assert flaw_tools(flaw) == {"probe", "capture"}


def test_the_declared_function_tools_are_a_counted_flaws_tools_recorded_as_its_effect():
    flaw = given.a_flaw_whose_declared_function_is_effect(
        "CVE-2025-0001", _READ, [admission.a_tool("probe", "probe", "unchanged")]
    )

    assert declared_function_tools(admission.a_server([flaw])) == {"probe": VALID_CATEGORIES[_READ]}


def test_a_declared_function_tool_two_flaws_reach_takes_the_union_of_their_categories():
    read_flaw = given.a_flaw_whose_declared_function_is_effect(
        "CVE-2025-0001", _READ, [admission.a_tool("probe", "probe", "unchanged")]
    )
    exec_flaw = given.a_flaw_whose_declared_function_is_effect(
        "PYSEC-2025-1", _EXEC, [admission.a_tool("probe", "probe", "unchanged")]
    )

    assert declared_function_tools(admission.a_server([read_flaw, exec_flaw])) == {
        "probe": VALID_CATEGORIES[_READ] | VALID_CATEGORIES[_EXEC]
    }


def test_the_declared_function_tools_skip_a_removed_tool_and_one_whose_software_is_silent():
    flaw = given.a_flaw_whose_declared_function_is_effect(
        "CVE-2025-0001",
        _READ,
        [
            admission.a_tool("probe", "probe", "unchanged"),
            admission.a_tool("gone", None, "removed"),
            given.a_silent_tool("capture"),
        ],
    )

    assert set(declared_function_tools(admission.a_server([flaw]))) == {"probe"}


def test_a_flaw_with_an_external_backend_has_no_declared_function_tool():
    flaw = given.a_flaw_whose_declared_function_is_effect(
        "CVE-2025-0001", _READ, [admission.a_tool("probe", "probe", "unchanged")]
    )
    flaw = flaw.model_copy(update={"backend_need": "external"})

    assert declared_function_tools(admission.a_server([flaw])) == {}


def test_a_flaw_recorded_otherwise_has_no_declared_function_tool():
    flaw = admission.a_flaw_record(
        "CVE-2025-0001", _READ, "1.2.0", tools=[admission.a_tool("probe", "probe", "unchanged")]
    )

    assert declared_function_tools(admission.a_server([flaw])) == {}
