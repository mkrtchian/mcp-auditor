from evals.cve.fixture_provenance import (
    IdentifierReplacement,
    SourceKind,
    StandInOutput,
    StandInRecord,
    stand_in_problems,
)

_REPLACES = "the Jenkins HTTP API"


def _a_stand_in(*outputs: StandInOutput, capture: str | None = None) -> StandInRecord:
    return StandInRecord(
        replaces=_REPLACES,
        reason="the real Jenkins needs a licence-free plugin set the image cannot pin",
        file="evals/docker/Dockerfile.jenkins-backend",
        capture=capture,
        outputs=list(outputs),
    )


def _an_output(
    source: SourceKind,
    form_source: str | None = None,
    replacements: list[IdentifierReplacement] | None = None,
) -> StandInOutput:
    return StandInOutput(
        request="GET /api/json",
        source=source,
        citation="Jenkins remote access API documentation",
        form_source=form_source,
        replacements=replacements or [],
    )


def test_a_sourced_output_has_no_problem():
    assert stand_in_problems(_a_stand_in(_an_output("software_sources"))) == []


def test_an_invented_output_following_a_form_has_no_problem():
    output = _an_output("invented", form_source="the Jenkins job JSON of the API docs")
    assert stand_in_problems(_a_stand_in(output)) == []


def test_a_capture_backed_stand_in_without_outputs_has_no_problem():
    stand_in = _a_stand_in(capture="evals/stand_ins/api.example.com.json")
    assert stand_in_problems(stand_in) == []


def test_an_invented_output_without_its_form_source_is_one_problem():
    _assert_one_problem_naming_the_stand_in(
        _a_stand_in(_an_output("invented")),
        "invented output for 'GET /api/json' names no form source",
    )


def test_a_copied_output_with_a_form_source_is_one_problem():
    output = _an_output("server_tests", form_source="the Jenkins job JSON")
    _assert_one_problem_naming_the_stand_in(
        _a_stand_in(output), "server_tests output for 'GET /api/json' names a form source"
    )


def test_an_invented_output_with_a_replacement_is_one_problem():
    output = _an_output(
        "invented",
        form_source="the Jenkins job JSON",
        replacements=[IdentifierReplacement(original="ci.example.org", replacement="ci.local")],
    )
    _assert_one_problem_naming_the_stand_in(_a_stand_in(output), "records identifier replacements")


def test_a_stand_in_with_neither_output_nor_capture_is_one_problem():
    _assert_one_problem_naming_the_stand_in(
        _a_stand_in(), "records neither an output nor a capture"
    )


def test_a_stand_in_without_a_reason_is_one_problem():
    stand_in = _a_stand_in(_an_output("capture")).model_copy(update={"reason": " "})
    _assert_one_problem_naming_the_stand_in(stand_in, "records no reason")


def _assert_one_problem_naming_the_stand_in(stand_in: StandInRecord, fragment: str) -> None:
    [problem] = stand_in_problems(stand_in)
    assert problem.startswith(f"stand-in for {_REPLACES}: ")
    assert fragment in problem
