from pathlib import Path

import pytest

import tests.unit.support.test_benign_probe_given as given
from evals import nuisance_audit
from evals.holdout_kit.benign_probe import (
    ProbeCall,
    ProbeOutcome,
    main,
    probe_calls,
    probe_client,
    probe_launch,
    record_calls,
    report_lines,
    single_container_launch,
)
from evals.holdout_kit.kit_client import KitTool
from evals.nuisance_images import image_tag
from tests.fakes import FakeKitClient


def test_record_calls_keeps_record_order_and_drops_exact_duplicates():
    first, second, third = (
        given.a_call("read", path="a"),
        given.a_call("list"),
        given.a_call("read", path="b"),
    )
    record = given.a_record_with_benign_calls([first, second, first], [first, third])

    assert record_calls(record) == [first, second, third]


def test_probe_calls_parse_the_expected_text_and_the_prerequisite_calls():
    call = {
        "tool": "read_note",
        "arguments": {"id": 1},
        "expect": "the note",
        "before": [{"tool": "create_note", "arguments": {"text": "x"}}],
    }

    assert probe_calls([call]) == [
        ProbeCall("read_note", {"id": 1}, "the note", (("create_note", {"text": "x"}),))
    ]


def test_probe_calls_read_a_call_without_expect_or_before():
    assert probe_calls([{"tool": "list", "arguments": {}}]) == [ProbeCall("list", {}, None, ())]


def test_probe_calls_refuse_a_call_without_a_tool_naming_it():
    with pytest.raises(ValueError, match="orphan"):
        probe_calls([{"arguments": {"name": "orphan"}}])


def test_probe_calls_refuse_a_prerequisite_without_a_tool_naming_its_call():
    call: dict[str, object] = {
        "tool": "show",
        "arguments": {"name": "parent"},
        "before": [{"arguments": {}}],
    }

    with pytest.raises(ValueError, match="parent"):
        probe_calls([call])


def test_the_single_container_launch_is_the_run_launch():
    server = given.a_server()
    image = image_tag(server.service)

    with nuisance_audit.nuisance_environment(server) as run_launch:
        run_args = run_launch.args

    with single_container_launch(given.the_record_of(server), image) as probe_launch_:
        assert probe_launch_.args == run_args


def test_the_probe_launch_of_a_record_with_a_backend_is_its_lifecycle_launch(
    monkeypatch: pytest.MonkeyPatch,
):
    asked = given.a_fake_lifecycle_resolved_by_key(monkeypatch)
    record = given.a_record_with_a_backend()

    with probe_launch(record, "the-image") as launch:
        args = launch.args

    assert asked == ["fake"]
    assert launch.command == "docker"
    assert args[:2] == ["run", "--name"]
    assert args[3:] == ["the-image", record["host"]["working_directory"], *record["launch"]]


async def test_probe_client_answers_each_call_in_order():
    client = FakeKitClient(
        [KitTool("read", None, {}), KitTool("list", None, {})],
        {"read": given.ok("a"), "list": given.ok("b")},
    )

    report = await probe_client(client, [given.a_probe_call("list"), given.a_probe_call("read")])

    assert report.listed == frozenset({"read", "list"})
    assert [outcome.response for outcome in report.outcomes] == [given.ok("b"), given.ok("a")]


async def test_probe_client_makes_the_prerequisite_calls_first_and_records_them():
    client = given.PrerequisiteFakeKitClient()

    report = await probe_client(client, [given.a_probe_call("read_note", before=["create_note"])])

    (outcome,) = report.outcomes
    assert outcome.before == (given.ok("created"),)
    assert outcome.response == given.ok("the note")


def test_report_lines_render_every_call_and_prerequisite():
    report = given.a_report(
        ["read", "create"],
        given.an_outcome(
            given.a_probe_call("read", expect="note", before=["create"]),
            given.ok("the\nnote"),
            before=[given.ok("created")],
        ),
        given.an_outcome(given.a_probe_call("ghost", expect="x"), given.error("unknown")),
        given.an_outcome(given.a_probe_call("read"), given.ok("plain")),
    )

    assert report_lines(report) == [
        "tools/list: 2 tools",
        "  before create [listed] -> ok 'created'",
        "read [listed] -> ok, expect found 'the\\nnote'",
        "ghost [NOT LISTED] -> error, expect MISSING 'unknown'",
        "read [listed] -> ok 'plain'",
    ]


def test_main_passes_when_every_call_is_listed_and_answers_its_expected_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    call = given.a_probe_call("read", expect="note", before=["create"])
    probed = given.a_probe_answering(
        monkeypatch,
        given.a_report(
            ["read", "create"],
            given.an_outcome(call, given.ok("a note"), before=[given.ok("created")]),
        ),
    )
    record = given.a_record_with_one_benign_call()
    record_path = given.written(tmp_path / "admission_record.json", record)

    assert main(["--record", str(record_path), "--image", "img"]) == 0
    assert probed == [probe_calls(record_calls(record))]


def test_main_probes_the_calls_given_in_place_of_the_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    probed = given.a_probe_answering(monkeypatch, given.a_report([]))
    record_path = given.written(
        tmp_path / "admission_record.json", given.a_record_with_one_benign_call()
    )
    calls = [given.a_call("list", path="docs")]
    calls_path = given.written(tmp_path / "calls.json", calls)

    main(["--record", str(record_path), "--image", "img", "--calls", str(calls_path)])

    assert probed == [probe_calls(calls)]


@pytest.mark.parametrize(
    "outcome, listed",
    [
        (given.an_outcome(given.a_probe_call("read", expect="note"), given.ok("other")), ["read"]),
        (given.an_outcome(given.a_probe_call("read"), given.error("boom")), ["read"]),
        (given.an_outcome(given.a_probe_call("read"), given.ok("fine")), []),
        (
            given.an_outcome(
                given.a_probe_call("read", before=["create"]),
                given.ok("fine"),
                before=[given.error("refused")],
            ),
            ["read", "create"],
        ),
        (
            given.an_outcome(
                given.a_probe_call("read", before=["create"]),
                given.ok("fine"),
                before=[given.ok("created")],
            ),
            ["read"],
        ),
    ],
    ids=["missing expect", "error", "unlisted tool", "failing before", "unlisted before"],
)
def test_main_fails_on_any_call_that_does_not_pass(
    outcome: ProbeOutcome, listed: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    given.a_probe_answering(monkeypatch, given.a_report(listed, outcome))
    record_path = given.written(
        tmp_path / "admission_record.json", given.a_record_with_one_benign_call()
    )

    assert main(["--record", str(record_path), "--image", "img"]) == 1
