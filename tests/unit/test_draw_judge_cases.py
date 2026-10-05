import random

import pytest

import tests.unit.support.test_draw_judge_cases_given as given
from evals.draw_judge_cases import (
    CVE_TARGET_QUOTA,
    DRAW_SEED,
    FAIL_CELL_QUOTA,
    PASS_CELL_QUOTA,
    candidates_from_cve,
    candidates_from_honeypot,
    complement,
    complement_refusals,
    draw,
    draw_fixture,
)
from evals.judge_draw_checks import leaked_secrets, source_refusals, source_run
from evals.judge_fixture import CaseLabel, CaseSource, JudgeInputs
from mcp_auditor.domain.models import AuditCategory

INFO_LEAKAGE = given.INFO_LEAKAGE
INJECTION = given.INJECTION
FAIL = CaseLabel.FAIL
PASS = CaseLabel.PASS
HOME = "/home/alice"
USER = "alice"


def test_chain_lines_and_cells_outside_the_ground_truth_are_not_candidates():
    lines = [
        given.a_honeypot_line("get_user", INFO_LEAKAGE),
        given.a_chain_line("get_user", INJECTION),
        given.a_honeypot_line("get_user", AuditCategory.RESOURCE_ABUSE),
    ]

    candidates = candidates_from_honeypot(lines, given.GROUND_TRUTH)

    assert {cell: len(cases) for cell, cases in candidates.items()} == {
        ("get_user", INFO_LEAKAGE): 1,
        ("get_user", INJECTION): 0,
        ("list_items", INJECTION): 0,
    }


def test_the_same_inputs_in_two_exports_count_once():
    first = given.a_honeypot_line("get_user", INFO_LEAKAGE, run_index=0, verdict="fail")
    again = given.a_honeypot_line("get_user", INFO_LEAKAGE, run_index=2, verdict="pass")

    candidates = candidates_from_honeypot([first, again], given.GROUND_TRUTH)

    assert len(candidates[("get_user", INFO_LEAKAGE)]) == 1


def test_a_honeypot_candidate_names_its_cell_and_waits_for_its_label():
    line = given.a_honeypot_line("get_user", INFO_LEAKAGE)

    [case] = candidates_from_honeypot([line], given.GROUND_TRUTH)[("get_user", INFO_LEAKAGE)]

    assert (case.source, case.origin) == (CaseSource.HONEYPOT, "cell get_user/info_leakage")
    assert (case.label, case.clause) == (None, None)
    assert case.inputs == JudgeInputs.model_validate(line)


def test_a_cve_candidate_is_filed_under_its_cve():
    lines = [given.a_cve_line("CVE-2025-0001"), given.a_cve_line("CVE-2025-0002")]

    candidates = candidates_from_cve(lines)

    [case] = candidates["CVE-2025-0001"]
    assert (case.source, case.origin) == (CaseSource.CVE, "cve CVE-2025-0001")
    assert sorted(candidates) == ["CVE-2025-0001", "CVE-2025-0002"]


def test_a_stratum_smaller_than_its_quota_yields_all_its_cases_and_a_shortfall():
    strata = {"small": given.some_cases(2, "small"), "large": given.some_cases(5, "large")}

    drawn, shortfalls = draw(strata, 3, random.Random(0))

    assert len(drawn) == 5
    assert {case.id for case in strata["small"]} <= {case.id for case in drawn}
    assert shortfalls == ["small: 2 candidates for a quota of 3"]


def test_the_quotas_are_drawn_per_stratum_honeypot_first_then_cve():
    fixture = draw_fixture(given.some_strata(), sources=[])

    origins = [case.origin.split()[0] for case in fixture.cases]
    expected_honeypot = FAIL_CELL_QUOTA + 2 * PASS_CELL_QUOTA
    assert origins == ["cell"] * expected_honeypot + ["cve"] * CVE_TARGET_QUOTA
    assert fixture.draw.seed == DRAW_SEED


def test_the_same_seed_and_sources_give_the_same_draw():
    strata = given.some_strata()
    shuffled = strata.fail_cells["get_user/info_leakage"][::-1]
    reordered = given.Strata(
        fail_cells={"get_user/info_leakage": shuffled},
        pass_cells=strata.pass_cells,
        cve_targets=strata.cve_targets,
    )

    assert draw_fixture(strata, sources=[]) == draw_fixture(reordered, sources=[])


def test_no_verdict_nor_run_index_reaches_a_drawn_case():
    lines = [given.a_honeypot_line("get_user", INFO_LEAKAGE)]
    candidates = candidates_from_honeypot(lines, given.GROUND_TRUTH)
    cve = candidates_from_cve([given.a_cve_line("CVE-2025-0001")])
    strata = given.Strata(
        fail_cells={"get_user/info_leakage": candidates[("get_user", INFO_LEAKAGE)]},
        pass_cells={},
        cve_targets=cve,
    )

    dumped = draw_fixture(strata, sources=[]).model_dump_json()

    stripped = ("verdict", "justification", "correct", "expected_verdict", "run_index", "cve_id")
    assert not [field for field in stripped if f'"{field}"' in dumped]


def test_the_complement_draws_one_new_case_per_pass_cell_with_the_next_seed():
    strata = given.some_strata()
    drawn = draw_fixture(strata, sources=[])
    labels = [FAIL] * 4 + [PASS] * 2 + [FAIL, PASS, PASS]
    fixture = given.labeled(drawn, labels)

    completed = complement(fixture, strata)

    added = completed.cases[len(fixture.cases) :]
    assert sorted(case.origin for case in added) == [
        "cell get_user_pass/injection",
        "cell list_items/injection",
    ]
    assert not {case.id for case in added} & {case.id for case in fixture.cases}
    assert all(case.label is None for case in added)
    assert completed.draw.complement_seed == DRAW_SEED + 1


def test_the_complement_is_refused_while_a_case_is_unlabeled():
    drawn = draw_fixture(given.some_strata(), sources=[])
    fixture = given.labeled(drawn, [FAIL] * 4 + [PASS] * 2 + [FAIL, PASS, None])

    assert complement_refusals(fixture, sources=[]) == [
        "1 unlabeled case(s): label every case first"
    ]


def test_the_complement_is_refused_when_fail_cases_stay_under_the_rule():
    drawn = draw_fixture(given.some_strata(), sources=[])
    labels = [FAIL] * 2 + [PASS] * 4 + [CaseLabel.UNSPECIFIED, PASS, PASS]
    fixture = given.labeled(drawn, labels)

    assert complement_refusals(fixture, sources=[]) == [
        "the complement rule does not fire: 2 FAIL cases of 8 labeled pass or fail, under 40 %"
    ]


def test_a_complement_already_drawn_is_refused():
    strata = given.some_strata()
    fixture = given.labeled(draw_fixture(strata, sources=[]), [FAIL] * 9)
    completed = given.labeled(complement(fixture, strata), [FAIL] * 11)

    assert complement_refusals(completed, sources=[]) == ["the complement is already drawn"]


def test_the_complement_is_refused_on_exports_the_draw_did_not_record():
    recorded = source_run("honeypot.jsonl", b"first run", given.a_source_report())
    rerun = source_run("honeypot.jsonl", b"another run", given.a_source_report())
    drawn = draw_fixture(given.some_strata(), sources=[recorded])
    fixture = given.labeled(drawn, [FAIL] * 9)

    assert complement_refusals(fixture, sources=[rerun]) == [
        "the exports differ from the sources the draw recorded"
    ]


def test_the_leak_check_names_the_case_and_the_kind_of_match_never_the_text():
    home = given.some_cases(1, "home")[0]
    home = home.model_copy(
        update={"inputs": home.inputs.model_copy(update={"response": f"{HOME}/.ssh"})}
    )
    user = given.some_cases(1, "user")[0]
    user = user.model_copy(
        update={"inputs": user.inputs.model_copy(update={"error": f"/srv/{USER}/db"})}
    )
    key = "sk-" + "a" * 24
    keyed = given.some_cases(1, "keyed")[0]
    keyed = keyed.model_copy(update={"inputs": keyed.inputs.model_copy(update={"response": key})})

    leaks = leaked_secrets([home, user, keyed], HOME, USER)

    assert f"case {home.id}: home path" in leaks
    assert f"case {user.id}: user name" in leaks
    assert f"case {keyed.id}: sk- key pattern" in leaks
    assert not [leak for leak in leaks if HOME in leak or key in leak or f"/{USER}" in leak]


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("sk-ant-" + "b" * 24, "sk-ant- key pattern"),
        ("AIza" + "c" * 35, "AIza key pattern"),
    ],
)
def test_the_leak_check_knows_each_key_pattern(text: str, kind: str):
    case = given.some_cases(1)[0]
    case = case.model_copy(update={"inputs": case.inputs.model_copy(update={"response": text})})

    assert f"case {case.id}: {kind}" in leaked_secrets([case], HOME, USER)


def test_the_user_name_is_a_leak_whatever_its_case():
    case = given.some_cases(1)[0]
    case = case.model_copy(
        update={"inputs": case.inputs.model_copy(update={"response": "owner: Alice"})}
    )

    assert leaked_secrets([case], HOME, USER) == [f"case {case.id}: user name"]


def test_a_user_name_inside_a_longer_word_is_not_a_leak():
    case = given.some_cases(1)[0]
    case = case.model_copy(update={"inputs": case.inputs.model_copy(update={"response": "malice"})})

    assert leaked_secrets([case], HOME, USER) == []


def test_clean_cases_leak_nothing():
    assert leaked_secrets(given.some_cases(3), HOME, USER) == []


def test_a_source_records_the_export_hash_its_commit_and_its_scalar_conditions():
    source = source_run("output/cve_judged_cases.jsonl", b"{}\n", given.a_source_report())

    assert source.commit == "c0ffee"
    assert len(source.sha256) == 64
    assert sorted(source.conditions) == sorted(
        ["runs", "budget", "provider", "model", "judge_model", "reasoning", "judge_reasoning"]
    )


def test_a_source_run_on_a_dirty_tree_is_refused():
    reports = {"a.jsonl": given.a_source_report(dirty=True), "b.jsonl": given.a_source_report()}

    assert source_refusals(reports) == ["a.jsonl ran on a tree with tracked modifications"]


def test_sources_at_two_commits_are_refused():
    reports = {"a.jsonl": given.a_source_report("c0ffee"), "b.jsonl": given.a_source_report("beef")}

    assert source_refusals(reports) == ["the sources ran at different commits: beef, c0ffee"]


def test_clean_sources_at_one_commit_are_accepted():
    reports = {"a.jsonl": given.a_source_report(), "b.jsonl": given.a_source_report()}

    assert source_refusals(reports) == []
