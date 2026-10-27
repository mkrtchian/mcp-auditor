from collections.abc import Collection
from typing import Any

import pytest

from evals import nuisance_fixtures, run_nuisance
from evals.holdout_census import load_census
from evals.holdout_kit.fix_check import FixCheckResult, FixCheckTarget
from evals.holdout_kit.kit_client import KitResponse, KitTool
from evals.nuisance_admission import (
    ADMISSION_PATH,
    FixCheckRecord,
    FlawRecord,
    NuisanceAdmission,
    load_admission,
)
from evals.nuisance_counting import counted_flaws, flaw_counted_tools
from evals.run_census import CENSUS_PATH


def _admission_or_skip() -> NuisanceAdmission:
    if not ADMISSION_PATH.exists():
        pytest.skip("no admission committed yet")
    return load_admission(ADMISSION_PATH, load_census(CENSUS_PATH))


def _flaw_records(admission: NuisanceAdmission) -> dict[str, FlawRecord]:
    return {flaw.flaw: flaw for server in admission.servers for flaw in server.flaws}


class _RecordingClient:
    def __init__(self, tools: list[KitTool] | None = None) -> None:
        self.calls: list[str] = []
        self._tools = tools or []

    async def list_tools(self) -> list[KitTool]:
        return self._tools

    async def call_tool(self, name: str, args: dict[str, Any]) -> KitResponse:
        self.calls.append(name)
        return KitResponse("", is_error=False)


async def _exploit_tools(target: FixCheckTarget, counted_tools: Collection[str]) -> set[str]:
    # Model a server exposing exactly the admission's counted tools, each discoverable by the
    # witness-id description an exploit matches on. A static exploit calls its hard-coded name and
    # ignores the list; a dynamic one (contextforge slugifies the registered name, so it resolves
    # the name at run time via list_tools) then resolves a counted tool instead of raising.
    tools = [
        KitTool(name=tool, description=f"seeded {target.witness.id}", input_schema={})
        for tool in counted_tools
    ]
    client = _RecordingClient(tools)
    places = {target.witness.id: target.witness}
    for exploit in target.exploits:
        await exploit(places, client)
    return set(client.calls)


def test_every_counted_flaw_has_a_fix_check_target_unless_holdout_calibrated():
    admission = _admission_or_skip()
    target_flaws = {target.flaw for target in nuisance_fixtures.FIX_CHECK_TARGETS}
    for server in admission.servers:
        for flaw in counted_flaws(server):
            if flaw.fix_check.source == "holdout_calibration":
                continue
            assert flaw.flaw in target_flaws, (
                f"{server.server_package}: counted flaw {flaw.flaw} has no FixCheckTarget"
            )


async def test_each_target_mechanism_and_tools_match_the_admission_flaw():
    admission = _admission_or_skip()
    records = _flaw_records(admission)
    for target in nuisance_fixtures.FIX_CHECK_TARGETS:
        record = records[target.flaw]
        counted = flaw_counted_tools(record)
        assert target.mechanism == record.effect_class
        assert await _exploit_tools(target, counted) == counted


async def test_a_dynamic_tool_exploit_resolves_against_the_seeded_server():
    # contextforge resolves its tool name at run time from the server's tool list; the seeded fake
    # must let it find a counted tool rather than raise. Guards the parity test above, which stays
    # skipped until the admission lands.
    from evals.nuisance_fix_checks import cve_2026_18905_contextforge as contextforge

    assert await _exploit_tools(contextforge.TARGET, {"rest-ssrf"}) == {"rest-ssrf"}


def _a_result(**overrides: Any) -> FixCheckResult:
    fields: dict[str, Any] = {
        "source": "fix_check",
        "witness": "MCPAUDIT-nonce",
        "exploit_calls": ["add_comment"],
        "vulnerable_surfaces": True,
        "patched_surfaces": False,
        "server_patched_surfaces": None,
        "patched_benign_errored": False,
    }
    fields.update(overrides)
    return FixCheckResult(**fields)


def _a_record(**overrides: Any) -> FixCheckRecord:
    fields: dict[str, Any] = {
        "source": "fix_check",
        "witness": "MCPAUDIT-nonce",
        "exploit_calls": ["add_comment"],
        "vulnerable_surfaces": True,
        "patched_surfaces": False,
        "server_patched_surfaces": None,
        "patched_benign_errored": False,
    }
    fields.update(overrides)
    return FixCheckRecord(**fields)


def test_a_matching_result_and_record_have_no_mismatch():
    assert run_nuisance.fix_check_mismatches(_a_result(), _a_record()) == []


def test_a_differing_field_is_reported():
    mismatches = run_nuisance.fix_check_mismatches(_a_result(), _a_record(patched_surfaces=True))

    assert len(mismatches) == 1
    assert "patched_surfaces" in mismatches[0]


def test_a_holdout_calibration_record_excludes_the_source_field():
    result = _a_result(source="fix_check")
    record = _a_record(source="holdout_calibration")

    assert run_nuisance.fix_check_mismatches(result, record) == []


def test_a_source_difference_on_a_fix_check_record_is_a_mismatch():
    result = _a_result(source="holdout_calibration")
    record = _a_record(source="fix_check")

    mismatches = run_nuisance.fix_check_mismatches(result, record)

    assert len(mismatches) == 1
    assert "source" in mismatches[0]


def test_a_differing_witness_nonce_is_not_a_mismatch():
    # check_fix plants a fresh random nonce each run, so the result's witness never equals the one
    # the admission recorded; only the reproducible fields are compared.
    result = _a_result(witness="MCPAUDIT-freshnonce")
    record = _a_record(witness="MCPAUDIT-recordednonce")

    assert run_nuisance.fix_check_mismatches(result, record) == []


def test_calibrate_with_no_admission_prints_nothing_is_drawn(capsys: pytest.CaptureFixture[str]):
    if ADMISSION_PATH.exists():
        pytest.skip("an admission is committed")

    code = run_nuisance.main(["calibrate"])

    assert code == 0
    assert "nothing is drawn" in capsys.readouterr().out


def test_calibrate_with_empty_targets_prints_nothing_is_drawn(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(nuisance_fixtures, "FIX_CHECK_TARGETS", ())

    code = run_nuisance.main(["calibrate"])

    assert code == 0
    assert "nothing is drawn" in capsys.readouterr().out
