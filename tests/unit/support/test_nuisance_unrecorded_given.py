from collections.abc import Callable

import tests.unit.support.test_nuisance_admission_edits_given as edits
import tests.unit.support.test_nuisance_admission_given as admission_given
import tests.unit.support.test_nuisance_admission_records_given as records_given
from evals.nuisance_admission import AdmittedServer, FlawRecord

SERVER = admission_given.SERVER_PACKAGE

_FlawChange = Callable[[FlawRecord], FlawRecord]


def a_recorded_server() -> AdmittedServer:
    return admission_given.an_admission().servers[0]


def a_server_with_every_field_unrecorded() -> AdmittedServer:
    return records_given.with_every_new_field_unrecorded(admission_given.an_admission()).servers[0]


def without_a_real_software_record(server: AdmittedServer) -> AdmittedServer:
    return edits.with_the_first_flaw(
        server,
        lambda flaw: flaw.model_copy(
            update={
                "tools": [tool.model_copy(update={"real_software": None}) for tool in flaw.tools]
            }
        ),
    )


def without_a_declared_function_record(server: AdmittedServer) -> AdmittedServer:
    return edits.with_the_first_flaw(server, _tools_without_a_declared_function_record)


def with_a_tool_left_out_by_its_declared_function_unrecorded(
    server: AdmittedServer,
) -> AdmittedServer:
    def changed(flaw: FlawRecord) -> FlawRecord:
        unrecorded = _tools_without_a_declared_function_record(flaw)
        return unrecorded.model_copy(update={"declared_function_is_effect": True})

    return edits.with_the_first_flaw(server, changed)


def a_holdout_copy_without_its_fingerprint(server: AdmittedServer) -> AdmittedServer:
    return edits.with_the_first_flaw(server, _fix_check_copied_from_the_holdout)


def without_software_releases(server: AdmittedServer) -> AdmittedServer:
    return server.model_copy(update={"software_releases": None})


def without_an_expected_text(server: AdmittedServer) -> AdmittedServer:
    return edits.with_the_first_flaw(server, _benign_calls_without("expect"))


def without_prerequisite_calls(server: AdmittedServer) -> AdmittedServer:
    return edits.with_the_first_flaw(server, _benign_calls_without("before"))


def without_a_relaying_stand_in_judgment(server: AdmittedServer) -> AdmittedServer:
    return edits.with_the_first_flaw(server, _fix_check_without_a_relaying_judgment)


def without_stand_ins(server: AdmittedServer) -> AdmittedServer:
    return server.model_copy(update={"stand_ins": None})


def without_seeds(server: AdmittedServer) -> AdmittedServer:
    return server.model_copy(update={"seeds": None})


def with_the_second_flaw_uncounted_and_unrecorded(server: AdmittedServer) -> AdmittedServer:
    first, second, *rest = server.flaws
    check = second.fix_check.model_copy(
        update={"vulnerable_surfaces": False, "relies_on_relaying_stand_in": None}
    )
    unrecorded = _benign_calls_without("expect")(second.model_copy(update={"fix_check": check}))
    return server.model_copy(update={"flaws": [first, unrecorded, *rest]})


def with_a_removed_tool_without_its_records(server: AdmittedServer) -> AdmittedServer:
    removed = admission_given.a_tool("gone", None, "removed")
    return edits.with_the_first_flaw(
        server, lambda flaw: flaw.model_copy(update={"tools": [*flaw.tools, removed]})
    )


def _benign_calls_without(field: str) -> _FlawChange:
    def changed(flaw: FlawRecord) -> FlawRecord:
        calls = [call.model_copy(update={field: None}) for call in flaw.benign_calls]
        return flaw.model_copy(update={"benign_calls": calls})

    return changed


def _fix_check_without_a_relaying_judgment(flaw: FlawRecord) -> FlawRecord:
    check = flaw.fix_check.model_copy(update={"relies_on_relaying_stand_in": None})
    return flaw.model_copy(update={"fix_check": check})


def _tools_without_a_declared_function_record(flaw: FlawRecord) -> FlawRecord:
    tools = [tool.model_copy(update={"declared_function_is_effect": None}) for tool in flaw.tools]
    return flaw.model_copy(update={"tools": tools})


def _fix_check_copied_from_the_holdout(flaw: FlawRecord) -> FlawRecord:
    check = flaw.fix_check.model_copy(update={"source": "holdout_calibration"})
    return flaw.model_copy(update={"fix_check": check})
