from pathlib import Path

from evals.cve.detection.draw_record import CalibrationCard
from evals.cve.detection.targets import Target
from evals.cve.docker_paths import image_dockerfile
from evals.cve.nuisance.admission.holdout_target_reference import holdout_fixture_file


def it_carries_the_holdout_target_reference_of(out: Path, target: Target) -> None:
    fixture = holdout_fixture_file(target.flaw_id)
    text = (out / "reference" / "holdout_fixtures" / f"{fixture.name}.txt").read_text()
    assert text.startswith(fixture.read_text())
    assert f"def {target.builder.__name__}(" in text
    card = CalibrationCard.model_validate_json(
        (out / "reference" / "cards" / f"{target.flaw_id}.json").read_text()
    )
    assert card.flaw == target.flaw_id
    for service in (*target.images, target.patched_image):
        dockerfile = out / "reference" / "docker" / image_dockerfile(service).name
        assert dockerfile.exists(), service
    assert list((out / "reference").rglob("*.py")) == []
