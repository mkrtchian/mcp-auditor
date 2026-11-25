import tests.unit.support.nuisance_admissions as admissions
import tests.unit.support.nuisance_holdout_runs as holdout_runs
from evals.cve.grammar import FlawClass
from evals.cve.nuisance.admission.admission import AdmittedServer


def a_server_whose_declared_function_is_its_effect() -> AdmittedServer:
    tool = admissions.a_tool(
        f"{admissions.FIRST_FLAW}_read", f"{admissions.FIRST_FLAW}_read", "unchanged"
    )
    flaw = admissions.a_flaw_record(
        admissions.FIRST_FLAW,
        FlawClass.READ_OUTSIDE_SCOPE,
        admissions.PATCHED_VERSION,
        tools=[tool.model_copy(update={"declared_function_is_effect": True})],
    )
    return holdout_runs.a_server(
        flaws=[flaw.model_copy(update={"declared_function_is_effect": True})]
    )


def a_two_flaw_server() -> AdmittedServer:
    return holdout_runs.a_server(
        flaws=[
            admissions.a_flaw_record(
                admissions.FIRST_FLAW, FlawClass.READ_OUTSIDE_SCOPE, admissions.PATCHED_VERSION
            ),
            admissions.a_flaw_record(
                admissions.SECOND_FLAW, FlawClass.COMMAND_EXECUTION, admissions.PATCHED_VERSION
            ),
        ]
    )
