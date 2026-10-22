from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import ValidationError

import tests.unit.support.test_nuisance_admission_given as given
from evals import cve_baseline
from evals.nuisance_admission import (
    FlawRecord,
    NuisanceAdmission,
    admission_problems,
    load_admission,
)

_MUTATORS: list[Callable[[NuisanceAdmission], NuisanceAdmission]] = [
    given.with_a_stale_grammar_fingerprint,
    given.with_an_unsettled_disagreement,
    given.with_a_flaw_of_another_server,
    given.with_no_counted_tool,
    given.with_a_server_patched_version_of_no_flaw,
    given.with_a_server_patched_surfaces_set_on_the_servers_own_version,
]


def test_a_non_grammar_effect_class_is_refused_by_the_schema():
    with pytest.raises(ValidationError):
        FlawRecord(
            flaw="CVE-2025-0001",
            tools=[given.a_tool("read", "read", "unchanged")],
            effect_class="authorization_bypass",  # type: ignore[arg-type]
            patched_version="1.2.0",
            patched_source="advisory",
            launch_option=None,
            benign_calls=[],
            needs_backend=False,
            declared_function_is_effect=False,
            fix_check=given.a_passing_fix_check(),
        )


def test_the_clean_admission_has_no_problems():
    admission = given.an_admission()
    assert admission_problems(admission, given.a_census(), cve_baseline.grammar_fingerprint()) == []


@pytest.mark.parametrize("mutate", _MUTATORS)
def test_each_mutation_yields_exactly_one_problem(
    mutate: Callable[[NuisanceAdmission], NuisanceAdmission],
):
    admission = mutate(given.an_admission())

    problems = admission_problems(admission, given.a_census(), cve_baseline.grammar_fingerprint())

    assert len(problems) == 1, problems


def test_load_admission_returns_the_written_clean_admission(tmp_path: Path):
    admission = given.an_admission()
    path = given.written(tmp_path, admission)

    assert load_admission(path, given.a_census()) == admission


def test_load_admission_on_a_missing_file_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_admission(tmp_path / "absent.json", given.a_census())


def test_load_admission_on_a_mutated_admission_raises_with_the_problem(tmp_path: Path):
    path = given.written(tmp_path, given.with_a_flaw_of_another_server(given.an_admission()))

    with pytest.raises(ValueError, match="is not a census flaw"):
        load_admission(path, given.a_census())


def test_a_stale_fingerprint_is_the_named_problem():
    admission = given.with_a_stale_grammar_fingerprint(given.an_admission())

    [problem] = admission_problems(admission, given.a_census(), cve_baseline.grammar_fingerprint())

    assert "grammar fingerprint" in problem
