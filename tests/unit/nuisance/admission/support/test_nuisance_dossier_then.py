from pathlib import Path

from evals.cve.grammar import FlawClass
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.admission.unrecorded import unrecorded_fields


def unrecorded_field_names(server: AdmittedServer) -> list[str]:
    [line] = unrecorded_fields([server])
    listed = line.removeprefix(f"{server.server_package}: ")
    return [item.split(" (")[0] for item in listed.split(", ")]


def grammar_classes_send_an_unclassed_flaw_to_null(out: Path) -> None:
    text = " ".join((out / "grammar_classes.md").read_text().split())
    for flaw_class in FlawClass:
        assert f"`{flaw_class}`" in text
    assert "gets `effect_class` `null`" in text
