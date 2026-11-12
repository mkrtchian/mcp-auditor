import tests.unit.support.test_nuisance_admission_given as admission
from evals.cve.grammar import FlawClass
from evals.cve.nuisance.admission import AdmittedServer
from tests.unit.support.test_nuisance_run_given import (
    FIRST_FLAW,
    LUNA_PRICE,
    SECOND_FLAW,
    a_server,
    an_audit,
    draw_entries,
)

__all__ = ["FIRST_FLAW", "LUNA_PRICE", "SECOND_FLAW", "a_server", "an_audit", "draw_entries"]


def a_server_whose_declared_function_is_its_effect() -> AdmittedServer:
    tool = admission.a_tool(f"{FIRST_FLAW}_read", f"{FIRST_FLAW}_read", "unchanged")
    flaw = admission.a_flaw_record(
        FIRST_FLAW,
        FlawClass.READ_OUTSIDE_SCOPE,
        admission.PATCHED_VERSION,
        tools=[tool.model_copy(update={"declared_function_is_effect": True})],
    )
    return a_server(flaws=[flaw.model_copy(update={"declared_function_is_effect": True})])


def a_two_flaw_server() -> AdmittedServer:
    return a_server(
        flaws=[
            admission.a_flaw_record(
                FIRST_FLAW, FlawClass.READ_OUTSIDE_SCOPE, admission.PATCHED_VERSION
            ),
            admission.a_flaw_record(
                SECOND_FLAW, FlawClass.COMMAND_EXECUTION, admission.PATCHED_VERSION
            ),
        ]
    )
