from pathlib import Path

from evals.cve.detection.draw_record import CalibrationCard
from evals.cve_targets import CVETarget
from evals.docker_paths import image_dockerfile
from evals.nuisance_admission import AdmittedServer
from evals.nuisance_holdout_reference import holdout_fixture_file
from evals.nuisance_unrecorded import unrecorded_fields


def unrecorded_field_names(server: AdmittedServer) -> list[str]:
    [gap] = unrecorded_fields([server])
    listed = gap.removeprefix(f"{server.server_package}: ")
    return [item.split(" (")[0] for item in listed.split(", ")]


def grammar_classes_send_an_unclassed_flaw_to_null(out: Path) -> None:
    text = " ".join((out / "grammar_classes.md").read_text().split())
    for name in ("read_outside_scope", "command_execution", "internal_fetch"):
        assert f"`{name}`" in text
    assert "gets `effect_class` `null`" in text
    assert "a class name of your own" not in text


def it_carries_the_holdout_reference_of(out: Path, target: CVETarget) -> None:
    fixture = holdout_fixture_file(target.cve_id)
    text = (out / "reference" / "holdout_fixtures" / f"{fixture.name}.txt").read_text()
    assert text.startswith(fixture.read_text())
    assert f"def {target.builder.__name__}(" in text
    card = CalibrationCard.model_validate_json(
        (out / "reference" / "cards" / f"{target.cve_id}.json").read_text()
    )
    assert card.flaw == target.cve_id
    for service in (*target.images, target.patched_image):
        dockerfile = out / "reference" / "docker" / image_dockerfile(service).name
        assert dockerfile.exists(), service
    assert list((out / "reference").rglob("*.py")) == []
