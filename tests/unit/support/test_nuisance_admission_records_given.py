import tests.unit.support.test_nuisance_admission_edits_given as edits
import tests.unit.support.test_nuisance_admission_given as admission_given
from evals.cve.fixture_provenance import SoftwareRelease, StandInOutput, StandInRecord
from evals.cve.nuisance.admission import (
    AdmittedServer,
    FlawRecord,
    NuisanceAdmission,
    ToolCall,
    ToolRecord,
)
from evals.cve.nuisance.admission_records import RealSoftwareRecord, SeedRecord


def with_a_removed_tool_carrying_a_real_software_record(
    admission: NuisanceAdmission,
) -> NuisanceAdmission:
    removed = admission_given.a_tool("gone", None, "removed").model_copy(
        update={"real_software": RealSoftwareRecord(answers=True)}
    )
    return edits.with_the_server(
        admission,
        lambda server: edits.with_the_first_flaw(
            server, lambda flaw: flaw.model_copy(update={"tools": [*flaw.tools, removed]})
        ),
    )


def with_a_removed_tool_carrying_a_declared_function_record(
    admission: NuisanceAdmission,
) -> NuisanceAdmission:
    removed = admission_given.a_tool("gone", None, "removed").model_copy(
        update={"declared_function_is_effect": False}
    )
    return edits.with_the_server(
        admission,
        lambda server: edits.with_the_first_flaw(
            server, lambda flaw: flaw.model_copy(update={"tools": [*flaw.tools, removed]})
        ),
    )


def with_a_software_release_without_its_source(admission: NuisanceAdmission) -> NuisanceAdmission:
    release = SoftwareRelease(software="PostgreSQL", release="16.4", day=None, source=" ")
    return edits.with_the_server(
        admission, lambda server: server.model_copy(update={"software_releases": [release]})
    )


def with_a_fix_check_record_carrying_a_holdout_fingerprint(
    admission: NuisanceAdmission,
) -> NuisanceAdmission:
    def changed(flaw: FlawRecord) -> FlawRecord:
        check = flaw.fix_check.model_copy(update={"holdout_fingerprint": "f" * 64})
        return flaw.model_copy(update={"fix_check": check})

    return edits.with_the_server(
        admission, lambda server: edits.with_the_first_flaw(server, changed)
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
    return edits.with_the_server(
        admission, lambda server: edits.with_the_first_benign_call(server, expect="")
    )


def with_an_expected_text_quoting_the_arguments(admission: NuisanceAdmission) -> NuisanceAdmission:
    return edits.with_the_server(
        admission,
        lambda server: edits.with_the_first_benign_call(
            server, arguments={"path": "README.md"}, expect="README"
        ),
    )


def with_an_expected_text_quoting_a_prerequisite_call(
    admission: NuisanceAdmission,
) -> NuisanceAdmission:
    connect = ToolCall(tool="connect_to_database", arguments={"database": "app"})
    return edits.with_the_server(
        admission,
        lambda server: edits.with_the_first_benign_call(server, expect="app", before=[connect]),
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

    return edits.with_the_server(admission, changed)


def with_the_second_flaw_not_counting(admission: NuisanceAdmission) -> NuisanceAdmission:
    def changed(server: AdmittedServer) -> AdmittedServer:
        first, second, *rest = server.flaws
        check = second.fix_check.model_copy(update={"vulnerable_surfaces": False})
        return server.model_copy(
            update={"flaws": [first, second.model_copy(update={"fix_check": check}), *rest]}
        )

    return edits.with_the_server(admission, changed)


def with_a_published_sample_without_pin(admission: NuisanceAdmission) -> NuisanceAdmission:
    seed = SeedRecord(
        item="/agents.yaml", kind="published_sample", citation="README.md, Example 1", pin=None
    )
    return edits.with_the_server(
        admission, lambda server: server.model_copy(update={"seeds": [seed]})
    )


def with_a_project_document_without_citation(admission: NuisanceAdmission) -> NuisanceAdmission:
    seed = SeedRecord(item="/rules/python.md", kind="project_document", pin="0" * 40)
    return edits.with_the_server(
        admission, lambda server: server.model_copy(update={"seeds": [seed]})
    )


def with_an_invented_stand_in_output_without_form_source(
    admission: NuisanceAdmission,
) -> NuisanceAdmission:
    stand_in = StandInRecord(
        replaces="the Jenkins HTTP API",
        reason="the real Jenkins does not start under the confinement",
        file="evals/docker/Dockerfile.jenkins-backend",
        outputs=[StandInOutput(request="GET /api/json", source="invented", citation="none")],
    )
    return edits.with_the_server(
        admission, lambda server: server.model_copy(update={"stand_ins": [stand_in]})
    )


def with_every_new_field_unrecorded(admission: NuisanceAdmission) -> NuisanceAdmission:
    def flaw_unrecorded(flaw: FlawRecord) -> FlawRecord:
        return flaw.model_copy(
            update={
                "tools": [
                    tool.model_copy(
                        update={"real_software": None, "declared_function_is_effect": None}
                    )
                    for tool in flaw.tools
                ],
                "benign_calls": [
                    call.model_copy(update={"expect": None, "before": None})
                    for call in flaw.benign_calls
                ],
                "fix_check": flaw.fix_check.model_copy(
                    update={"relies_on_relaying_stand_in": None}
                ),
            }
        )

    return edits.with_the_server(
        admission,
        lambda server: server.model_copy(
            update={
                "flaws": [flaw_unrecorded(flaw) for flaw in server.flaws],
                "stand_ins": None,
                "seeds": None,
                "software_releases": None,
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

    return edits.with_the_server(admission, changed)


def _with_first_tool_verdict(
    admission: NuisanceAdmission, verdict: RealSoftwareRecord
) -> NuisanceAdmission:
    def changed(flaw: FlawRecord) -> FlawRecord:
        first, *rest = flaw.tools
        tools: list[ToolRecord] = [first.model_copy(update={"real_software": verdict}), *rest]
        return flaw.model_copy(update={"tools": tools})

    return edits.with_the_server(
        admission, lambda server: edits.with_the_first_flaw(server, changed)
    )
