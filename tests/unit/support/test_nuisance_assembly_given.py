import tests.unit.support.test_nuisance_admission_given as admission
from evals.cve_grammar import MechanismClass
from evals.nuisance_admission import AdmittedServer
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
    flaw = admission.a_flaw_record(
        FIRST_FLAW, MechanismClass.READ_OUTSIDE_SCOPE, admission.PATCHED_VERSION
    )
    return a_server(flaws=[flaw.model_copy(update={"declared_function_is_effect": True})])


def a_two_flaw_server() -> AdmittedServer:
    return a_server(
        flaws=[
            admission.a_flaw_record(
                FIRST_FLAW, MechanismClass.READ_OUTSIDE_SCOPE, admission.PATCHED_VERSION
            ),
            admission.a_flaw_record(
                SECOND_FLAW, MechanismClass.COMMAND_EXECUTION, admission.PATCHED_VERSION
            ),
        ]
    )
