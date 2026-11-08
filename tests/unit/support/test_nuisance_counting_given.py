import tests.unit.support.test_nuisance_admission_given as admission
from evals.cve_grammar import MechanismClass
from evals.nuisance_admission import FixCheckRecord, FlawRecord, ToolRecord
from evals.nuisance_admission_records import RealSoftwareRecord


def a_fix_check(**overrides: object) -> FixCheckRecord:
    return admission.a_passing_fix_check().model_copy(update=overrides)


def a_silent_tool(name: str, *, declared_function_is_effect: bool = False) -> ToolRecord:
    verdict = RealSoftwareRecord(
        answers=False, cause="container_unrepairable", evidence="needs NET_RAW"
    )
    return admission.a_tool(name, name, "unchanged").model_copy(
        update={
            "real_software": verdict,
            "declared_function_is_effect": declared_function_is_effect,
        }
    )


def a_tool_whose_declared_function_is_effect(name: str, is_effect: bool | None) -> ToolRecord:
    return admission.a_tool(name, name, "unchanged").model_copy(
        update={"declared_function_is_effect": is_effect}
    )


def a_removed_tool_whose_declared_function_is_effect(name: str, is_effect: bool) -> ToolRecord:
    return admission.a_tool(name, None, "removed").model_copy(
        update={"declared_function_is_effect": is_effect}
    )


def a_flaw_whose_declared_function_is_effect(
    identifier: str, effect_class: MechanismClass, tools: list[ToolRecord]
) -> FlawRecord:
    flaw = admission.a_flaw_record(identifier, effect_class, "1.2.0", tools=tools)
    return flaw.model_copy(update={"declared_function_is_effect": True})
