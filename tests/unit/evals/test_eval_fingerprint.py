import tests.unit.evals.support.honeypot_gate_inputs as honeypot_gate_inputs
import tests.unit.evals.support.test_eval_fingerprint_given as given
from evals.baseline import fingerprint_ground_truth, fingerprint_source, fingerprint_sources
from evals.ground_truth import GroundTruth
from mcp_auditor.domain.models import EvalVerdict

VULNERABLE_CELL = honeypot_gate_inputs.VULNERABLE_CELL
SAFE_CELL = honeypot_gate_inputs.SAFE_CELL


def test_ground_truth_fingerprint_changes_with_one_verdict_flipped():
    ground_truth: GroundTruth = {VULNERABLE_CELL: EvalVerdict.FAIL, SAFE_CELL: EvalVerdict.PASS}
    flipped: GroundTruth = {VULNERABLE_CELL: EvalVerdict.FAIL, SAFE_CELL: EvalVerdict.FAIL}

    assert fingerprint_ground_truth(ground_truth) != fingerprint_ground_truth(flipped)


def test_ground_truth_fingerprint_ignores_insertion_order():
    ground_truth: GroundTruth = {VULNERABLE_CELL: EvalVerdict.FAIL, SAFE_CELL: EvalVerdict.PASS}
    reordered: GroundTruth = {SAFE_CELL: EvalVerdict.PASS, VULNERABLE_CELL: EvalVerdict.FAIL}

    assert fingerprint_ground_truth(ground_truth) == fingerprint_ground_truth(reordered)


def test_source_fingerprint_ignores_an_added_comment_line():
    commented = given.SERVER_SOURCE.replace(
        "def get_user", "# Planted flaw: no validation of user_id.\ndef get_user"
    )

    assert fingerprint_source(commented) == fingerprint_source(given.SERVER_SOURCE)


def test_source_fingerprint_ignores_blank_lines():
    spaced = given.SERVER_SOURCE.replace("import json\n", "import json\n\n\n\n")

    assert fingerprint_source(spaced) == fingerprint_source(given.SERVER_SOURCE)


def test_source_fingerprint_changes_with_a_changed_string_literal():
    changed = given.SERVER_SOURCE.replace('"id"', '"user_id"')

    assert fingerprint_source(changed) != fingerprint_source(given.SERVER_SOURCE)


def test_source_fingerprint_of_a_fixed_source_is_pinned():
    # A Python upgrade that changes the format of ast.dump moves every fingerprint at once,
    # every baseline then reads not comparable. It fails here, in the upgrade's commit.
    assert fingerprint_source(given.CANARY_SOURCE) == (
        "7c8bc659116f2457071c34ff8ede35b8da5aed57972f198e3452e822afa8cb57"
    )


def test_source_fingerprint_ignores_the_module_docstring():
    edited = given.SERVER_SOURCE.replace("A server with one tool.", "The planted flaws, explained.")

    assert fingerprint_source(edited) == fingerprint_source(given.SERVER_SOURCE)


def test_source_fingerprint_ignores_quotes_trailing_commas_and_parentheses():
    reformatted = given.SERVER_SOURCE.replace(
        'def get_user(user_id: str) -> str:\n    """Return the user."""\n'
        '    return json.dumps({"id": user_id})\n',
        'def get_user(\n    user_id: str,\n) -> str:\n    """Return the user."""\n'
        "    return (\n        json.dumps({'id': user_id})\n    )\n",
    )
    assert reformatted != given.SERVER_SOURCE

    assert fingerprint_source(reformatted) == fingerprint_source(given.SERVER_SOURCE)


def test_source_fingerprint_changes_with_a_tool_docstring():
    changed = given.SERVER_SOURCE.replace("Return the user.", "Return any user.")

    assert fingerprint_source(changed) != fingerprint_source(given.SERVER_SOURCE)


def test_source_fingerprint_changes_with_a_changed_argument_type():
    changed = given.SERVER_SOURCE.replace("user_id: str", "user_id: int")

    assert fingerprint_source(changed) != fingerprint_source(given.SERVER_SOURCE)


def test_sources_fingerprint_ignores_the_docstring_of_every_module():
    edited = given.SERVER_SOURCE.replace("A server with one tool.", "The planted flaws, explained.")

    assert fingerprint_sources([given.SERVER_SOURCE, edited]) == fingerprint_sources(
        [given.SERVER_SOURCE, given.SERVER_SOURCE]
    )


def test_sources_fingerprint_changes_with_a_change_in_any_module():
    changed = given.SERVER_SOURCE.replace("user_id: str", "user_id: int")

    assert fingerprint_sources([given.SERVER_SOURCE, changed]) != fingerprint_sources(
        [given.SERVER_SOURCE, given.SERVER_SOURCE]
    )
