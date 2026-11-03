from collections.abc import Callable

import tests.unit.support.test_nuisance_admission_given as admission_given
from evals.fixture_provenance import StandInOutput, StandInRecord
from evals.nuisance_admission import (
    AdmittedServer,
    BenignCall,
    FlawRecord,
    NuisanceAdmission,
    ToolCall,
    ToolRecord,
)
from evals.nuisance_admission_records import RealSoftwareRecord, SeedRecord

_ServerChange = Callable[[AdmittedServer], AdmittedServer]


def with_a_removed_tool_carrying_a_real_software_record(
    admission: NuisanceAdmission,
) -> NuisanceAdmission:
    removed = admission_given.a_tool("gone", None, "removed").model_copy(
        update={"real_software": RealSoftwareRecord(answers=True)}
    )
    return _with_first_flaw(
        admission, lambda flaw: flaw.model_copy(update={"tools": [*flaw.tools, removed]})
    )


def with_a_silent_tool_without_a_cause(admission: NuisanceAdmission) -> NuisanceAdmission:
    return _with_first_tool_verdict(
        admission, RealSoftwareRecord(answers=False, evidence="the run answers a stack trace")
    )


def with_a_silent_tool_without_evidence(admission: NuisanceAdmission) -> NuisanceAdmission:
    return _with_first_tool_verdict(
        admission, RealSoftwareRecord(answers=False, cause="software_error")
    )


def with_an_answering_tool_carrying_a_cause(admission: NuisanceAdmission) -> NuisanceAdmission:
    return _with_first_tool_verdict(
        admission, RealSoftwareRecord(answers=True, cause="not_distributed")
    )


def with_a_tool_recorded_on_one_flaw_only(admission: NuisanceAdmission) -> NuisanceAdmission:
    return _with_the_first_tool_on_the_second_flaw(admission, None)


def with_a_tool_given_two_verdicts(admission: NuisanceAdmission) -> NuisanceAdmission:
    silent = RealSoftwareRecord(
        answers=False, cause="not_distributed", evidence="the package is yanked from PyPI"
    )
    return _with_the_first_tool_on_the_second_flaw(admission, silent)


def with_an_empty_expected_text(admission: NuisanceAdmission) -> NuisanceAdmission:
    return _with_first_benign_call(admission, lambda call: call.model_copy(update={"expect": ""}))


def with_an_expected_text_quoting_the_arguments(admission: NuisanceAdmission) -> NuisanceAdmission:
    return _with_first_benign_call(
        admission,
        lambda call: call.model_copy(
            update={"arguments": {"path": "README.md"}, "expect": "README"}
        ),
    )


def with_an_expected_text_quoting_a_prerequisite_call(
    admission: NuisanceAdmission,
) -> NuisanceAdmission:
    connect = ToolCall(tool="connect_to_database", arguments={"database": "app"})
    return _with_first_benign_call(
        admission, lambda call: call.model_copy(update={"expect": "app", "before": [connect]})
    )


def with_two_benign_calls_for_one_tool(admission: NuisanceAdmission) -> NuisanceAdmission:
    def changed(server: AdmittedServer) -> AdmittedServer:
        first, second, *rest = server.flaws
        tool = first.tools[0]
        other_call = first.benign_calls[0].model_copy(update={"arguments": {"limit": 1}})
        widened = second.model_copy(
            update={
                "tools": [*second.tools, tool],
                "benign_calls": [*second.benign_calls, other_call],
            }
        )
        return server.model_copy(update={"flaws": [first, widened, *rest]})

    return _with_server(admission, changed)


def with_the_second_flaw_not_counting(admission: NuisanceAdmission) -> NuisanceAdmission:
    def changed(server: AdmittedServer) -> AdmittedServer:
        first, second, *rest = server.flaws
        check = second.fix_check.model_copy(update={"vulnerable_surfaces": False})
        return server.model_copy(
            update={"flaws": [first, second.model_copy(update={"fix_check": check}), *rest]}
        )

    return _with_server(admission, changed)


def with_a_published_sample_without_pin(admission: NuisanceAdmission) -> NuisanceAdmission:
    seed = SeedRecord(
        item="/agents.yaml", kind="published_sample", citation="README.md, Example 1", pin=None
    )
    return _with_server(admission, lambda server: server.model_copy(update={"seeds": [seed]}))


def with_a_project_document_without_citation(admission: NuisanceAdmission) -> NuisanceAdmission:
    seed = SeedRecord(item="/rules/python.md", kind="project_document", pin="0" * 40)
    return _with_server(admission, lambda server: server.model_copy(update={"seeds": [seed]}))


def with_an_invented_stand_in_output_without_form_source(
    admission: NuisanceAdmission,
) -> NuisanceAdmission:
    stand_in = StandInRecord(
        replaces="the Jenkins HTTP API",
        reason="the real Jenkins does not start under the confinement",
        file="evals/docker/Dockerfile.jenkins-backend",
        outputs=[StandInOutput(request="GET /api/json", source="invented", citation="none")],
    )
    return _with_server(
        admission, lambda server: server.model_copy(update={"stand_ins": [stand_in]})
    )


def with_every_new_field_unrecorded(admission: NuisanceAdmission) -> NuisanceAdmission:
    def flaw_unrecorded(flaw: FlawRecord) -> FlawRecord:
        return flaw.model_copy(
            update={
                "tools": [tool.model_copy(update={"real_software": None}) for tool in flaw.tools],
                "benign_calls": [
                    call.model_copy(update={"expect": None, "before": None})
                    for call in flaw.benign_calls
                ],
                "fix_check": flaw.fix_check.model_copy(
                    update={"relies_on_relaying_stand_in": None}
                ),
            }
        )

    return _with_server(
        admission,
        lambda server: server.model_copy(
            update={
                "flaws": [flaw_unrecorded(flaw) for flaw in server.flaws],
                "stand_ins": None,
                "seeds": None,
            }
        ),
    )


def _with_the_first_tool_on_the_second_flaw(
    admission: NuisanceAdmission, verdict: RealSoftwareRecord | None
) -> NuisanceAdmission:
    def changed(server: AdmittedServer) -> AdmittedServer:
        first, second, *rest = server.flaws
        tool = first.tools[0].model_copy(update={"real_software": verdict})
        widened = second.model_copy(update={"tools": [*second.tools, tool]})
        return server.model_copy(update={"flaws": [first, widened, *rest]})

    return _with_server(admission, changed)


def _with_first_tool_verdict(
    admission: NuisanceAdmission, verdict: RealSoftwareRecord
) -> NuisanceAdmission:
    def changed(flaw: FlawRecord) -> FlawRecord:
        first, *rest = flaw.tools
        tools: list[ToolRecord] = [first.model_copy(update={"real_software": verdict}), *rest]
        return flaw.model_copy(update={"tools": tools})

    return _with_first_flaw(admission, changed)


def _with_first_benign_call(
    admission: NuisanceAdmission, change: Callable[[BenignCall], BenignCall]
) -> NuisanceAdmission:
    def changed(flaw: FlawRecord) -> FlawRecord:
        first, *rest = flaw.benign_calls
        return flaw.model_copy(update={"benign_calls": [change(first), *rest]})

    return _with_first_flaw(admission, changed)


def _with_first_flaw(
    admission: NuisanceAdmission, change: Callable[[FlawRecord], FlawRecord]
) -> NuisanceAdmission:
    def changed(server: AdmittedServer) -> AdmittedServer:
        first, *rest = server.flaws
        return server.model_copy(update={"flaws": [change(first), *rest]})

    return _with_server(admission, changed)


def _with_server(admission: NuisanceAdmission, change: _ServerChange) -> NuisanceAdmission:
    return admission.model_copy(update={"servers": [change(admission.servers[0])]})
