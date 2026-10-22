import dataclasses
from pathlib import Path

import pytest

import tests.unit.support.test_nuisance_gate_baseline_given as given
import tests.unit.support.test_nuisance_run_given as run_given
from evals.eval_session import Refused
from evals.holdout_run import HOLDOUT_BUDGET
from evals.nuisance_counter import counter_fingerprint
from evals.nuisance_gate_baseline import (
    baseline_file_name,
    baseline_integrity,
    condition_mismatches,
    gate_conditions,
    load_baselines,
    write_baseline,
)


def test_a_scoped_npm_package_names_a_portable_file():
    name = baseline_file_name("npm:@modelcontextprotocol/server-filesystem")

    assert name == "npm__modelcontextprotocol_server-filesystem.json"


def test_a_pypi_package_names_a_portable_file():
    assert baseline_file_name("PyPI:mcp-server-git") == "PyPI_mcp-server-git.json"


def test_a_written_baseline_loads_back_keyed_by_its_package(tmp_path: Path):
    baseline = given.a_gated_baseline()

    write_baseline(tmp_path, baseline)

    assert load_baselines(tmp_path) == {given.SERVER_PACKAGE: baseline}
    assert list(tmp_path.glob("*.tmp")) == []


def test_a_file_named_after_another_package_refuses_the_load(tmp_path: Path):
    write_baseline(tmp_path, given.a_gated_baseline())
    (tmp_path / baseline_file_name(given.SERVER_PACKAGE)).rename(tmp_path / "other.json")

    with pytest.raises(ValueError, match=r"other\.json"):
        load_baselines(tmp_path)


def test_a_missing_directory_loads_as_no_baseline(tmp_path: Path):
    assert load_baselines(tmp_path / "missing") == {}


def test_an_exploratory_baseline_holding_its_runs_is_whole():
    assert baseline_integrity(given.an_exploratory_baseline([False] * 3)) == []


def test_an_exploratory_baseline_short_of_its_runs_names_both_counts():
    [problem] = baseline_integrity(given.an_exploratory_baseline([False] * 2))

    assert given.SERVER_PACKAGE in problem
    assert "2" in problem and "3" in problem


def test_a_confirmation_holds_the_runs_of_both_recordings():
    assert baseline_integrity(given.a_confirmed_baseline([False] * 6)) == []
    assert baseline_integrity(given.a_confirmed_baseline([False] * 3)) != []


def test_only_a_confirmed_baseline_with_no_alarm_is_gated():
    flagged_once = given.a_confirmed_baseline([False] * 5 + [True])

    assert given.a_gated_baseline().gated()
    assert not given.an_exploratory_baseline().gated()
    assert not flagged_once.gated()
    assert flagged_once.alarmed()


def test_a_baseline_recorded_under_other_runs_mismatches_on_runs():
    baselines = {given.SERVER_PACKAGE: given.a_gated_baseline()}

    [mismatch] = condition_mismatches(baselines, given.conditions(runs=1))

    assert baseline_file_name(given.SERVER_PACKAGE) in mismatch
    assert "runs" in mismatch


def test_the_gate_conditions_refuse_an_unset_chain_setting():
    unset = dataclasses.replace(run_given.conditions(), tool_call_timeout=None)

    with pytest.raises(Refused) as excinfo:
        gate_conditions(run_given.SETTINGS, unset, 3)

    assert any("chain settings" in reason for reason in excinfo.value.reasons)


def test_the_gate_conditions_read_the_settings_and_the_holdout_budget():
    conditions = gate_conditions(run_given.SETTINGS, run_given.conditions(), 2)

    assert conditions.model == "gpt-6-luna"
    assert conditions.budget == HOLDOUT_BUDGET
    assert conditions.runs == 2
    assert not conditions.tools_filtered
    assert conditions.counter_fingerprint == counter_fingerprint()
