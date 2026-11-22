import importlib.metadata

import pytest

import tests.unit.project.support.test_code_standards_given as given
from tests.unit.project.support.code_standards_debt import DEBTS, FingerprintedFile, ThirdParty
from tests.unit.project.support.code_standards_scan import Violation
from tests.unit.project.support.fingerprinted_sources import fingerprinted_sources


@pytest.fixture(scope="module")
def tree_violations() -> list[Violation]:
    return given.tree_violations()


def test_the_tree_carries_no_violation_outside_the_debt_list(tree_violations: list[Violation]):
    unlisted = given.unlisted(tree_violations)

    assert unlisted == [], "violations of the code standards (CLAUDE.md):\n" + "\n".join(unlisted)


def test_every_debt_still_matches_a_violation(tree_violations: list[Violation]):
    stale = given.stale(tree_violations)

    assert stale == [], "these debts are paid, delete them from code_standards_debt.py:\n" + (
        "\n".join(f"{debt.path}: {debt.standard} {debt.symbol}" for debt in stale)
    )


def test_every_debt_is_blocked_by_a_fingerprinted_file_or_a_third_party():
    fingerprinted = fingerprinted_sources()

    for debt in DEBTS:
        match debt.blocked_by:
            case FingerprintedFile(path):
                assert path in fingerprinted, f"{debt}: {path} is not fingerprinted"
            case ThirdParty(distribution, reason):
                assert importlib.metadata.distribution(distribution)
                assert reason, f"{debt}: a third-party blocker gives its reason"


@pytest.mark.parametrize("layer", given.HEXAGON)
def test_the_hexagon_bans_every_module_of_the_composition_root(layer: str):
    missing = {
        f"mcp_auditor.{module}" for module in given.composition_root_modules()
    } - given.banned_modules(layer)

    assert missing == set()
