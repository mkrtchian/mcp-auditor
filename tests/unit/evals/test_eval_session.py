from pathlib import Path

import pytest

import tests.unit.evals.support.honeypot_sessions as honeypot_sessions
import tests.unit.evals.support.working_trees as working_trees
from evals.declared_flips import Instrument
from evals.eval_session import (
    REFUSED_BEFORE_ANY_LLM_CALL,
    Refused,
    TreeState,
    baseline_changed,
    declarations_of_head,
    tree_drift,
)

OTHER_COMMIT = "4567def"


def test_an_unchanged_tree_has_no_drift():
    tree = working_trees.a_clean_tree()

    assert tree_drift(tree, tree) == []


def test_a_tree_dirtied_during_the_runs_is_named():
    drift = tree_drift(
        working_trees.a_clean_tree(), TreeState(commit=working_trees.HEAD, dirty=True)
    )

    assert len(drift) == 1
    assert "tracked files changed" in drift[0]


def test_a_moved_commit_names_both_commits():
    drift = tree_drift(working_trees.a_clean_tree(), working_trees.a_clean_tree(OTHER_COMMIT))

    assert len(drift) == 1
    assert working_trees.HEAD in drift[0]
    assert OTHER_COMMIT in drift[0]


def test_no_baseline_before_nor_after_has_not_changed():
    assert baseline_changed(None, None) == []


def test_an_unchanged_baseline_has_not_changed():
    baseline = honeypot_sessions.a_baseline_at_ci_conditions()

    assert baseline_changed(baseline, baseline.model_copy()) == []


def test_a_baseline_appearing_during_the_runs_is_named():
    changed = baseline_changed(None, honeypot_sessions.a_baseline_at_ci_conditions())

    assert changed == ["the baseline file changed during the runs: record again"]


def test_a_baseline_recorded_again_during_the_runs_is_named():
    loaded = honeypot_sessions.a_baseline_at_ci_conditions()
    current = loaded.model_copy(update={"recorded_at": "2026-09-23T11:00:00+00:00"})

    assert baseline_changed(loaded, current) == [
        "the baseline file changed during the runs: record again"
    ]


def test_an_invalid_declaration_file_is_refused_before_any_git_read(tmp_path: Path):
    declarations = tmp_path / "declared_flips.json"
    declarations.write_text('{"entries": [{"instrument": "honeypot"}]}')

    with pytest.raises(Refused) as refusal:
        declarations_of_head(
            Instrument.HONEYPOT, working_trees.a_working_tree_that_must_not_read_git(declarations)
        )

    assert refusal.value.title == REFUSED_BEFORE_ANY_LLM_CALL
    assert f"{declarations} is not a valid declaration file" in refusal.value.reasons[0]


def test_an_empty_declaration_file_reads_nothing_from_git(tmp_path: Path):
    working_tree = working_trees.a_working_tree_that_must_not_read_git(
        working_trees.a_declaration_file(tmp_path)
    )

    assert declarations_of_head(Instrument.HONEYPOT, working_tree) == ([], False)
