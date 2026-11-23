from pathlib import Path

import tests.unit.support.judged_case_exports as then
from evals.cve.nuisance.gate.gate_judged_cases_export import export_nuisance_gate_judged_cases
from evals.cve.nuisance.gate.gate_session_model import GateAudit
from tests.unit.support.grammar_inputs import a_case, a_chain, a_report, a_step


def test_each_nuisance_gate_line_carries_its_server_and_run_with_the_chains(
    tmp_path: Path,
) -> None:
    report = a_report([a_case(), a_case(verdict=None)], chains=[a_chain([a_step()])])
    audits = [
        GateAudit("npm:first", 0, True, report),
        GateAudit("npm:second", 2, True, report),
    ]

    export_nuisance_gate_judged_cases(audits, tmp_path / "nuisance_gate_report.json")

    records = then.exported_records(tmp_path / "nuisance_gate_judged_cases.jsonl")
    assert [(r["server_package"], r["run_index"], r["type"]) for r in records] == [
        ("npm:first", 0, "single_step"),
        ("npm:first", 0, "chain"),
        ("npm:second", 2, "single_step"),
        ("npm:second", 2, "chain"),
    ]
    assert set(records[0]) == then.SINGLE_STEP_FIELDS | {"server_package"}
    assert set(records[1]) == then.CHAIN_FIELDS | {"server_package"}
