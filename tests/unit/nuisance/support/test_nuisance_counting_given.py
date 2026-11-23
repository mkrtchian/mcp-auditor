import tests.unit.support.nuisance_admissions as admissions
from evals.cve.grammar import FlawClass
from evals.cve.nuisance.admission.admission import FixCheckRecord, FlawRecord, ToolRecord
from evals.cve.nuisance.admission.admission_records import RealSoftwareRecord


def a_fix_check(**overrides: object) -> FixCheckRecord:
    return admissions.a_passing_fix_check().model_copy(update=overrides)


def a_silent_tool(name: str, *, declared_function_is_effect: bool = False) -> ToolRecord:
    real_software = RealSoftwareRecord(
        answers=False, cause="container_unrepairable", evidence="needs NET_RAW"
    )
    return admissions.a_tool(name, name, "unchanged").model_copy(
        update={
            "real_software": real_software,
            "declared_function_is_effect": declared_function_is_effect,
        }
    )


def a_tool_recording_declared_function(name: str, *, is_effect: bool | None) -> ToolRecord:
    return admissions.a_tool(name, name, "unchanged").model_copy(
        update={"declared_function_is_effect": is_effect}
    )


def a_removed_tool_recording_declared_function(name: str, *, is_effect: bool) -> ToolRecord:
    return admissions.a_tool(name, None, "removed").model_copy(
        update={"declared_function_is_effect": is_effect}
    )


def a_flaw_whose_declared_function_is_effect(
    identifier: str, effect_class: FlawClass, tools: list[ToolRecord]
) -> FlawRecord:
    flaw = admissions.a_flaw_record(identifier, effect_class, "1.2.0", tools=tools)
    return flaw.model_copy(update={"declared_function_is_effect": True})
