from pathlib import Path

from evals.cve.detection.targets import ACCEPTANCE_TARGETS
from evals.cve.planting_base import SENTINEL_SERVICE
from evals.repository import REPO_ROOT
from tests.unit.support import censuses


def kit_holds_its_files(out: Path) -> None:
    committed_captures = sorted((REPO_ROOT / "evals" / "stand_ins").glob("*.json"))
    for relative in (
        f"advisories/{censuses.FLAW_WITH_A_CVE}.json",
        "evals/__init__.py",
        "evals/cve/grammar.py",
        "evals/detection_places.json",
        "evals/cve/kit/driver.py",
        "docker/Dockerfile.sentinel",
        "docker/Dockerfile.stand-in",
        "evals/stand_ins/tls/fixture-authority.pem",
        *(f"evals/stand_ins/{capture.name}" for capture in committed_captures),
        "README.md",
        "fixture_format.md",
        "layout.md",
        "grammar_classes.md",
    ):
        assert (out / relative).exists(), relative


def readme_names_every_acceptance_service(readme: str) -> None:
    for service in _acceptance_services():
        assert f"`{service}`" in readme, service


def _acceptance_services() -> set[str]:
    services = {
        name for target in ACCEPTANCE_TARGETS for name in (*target.images, target.patched_image)
    }
    return services | {SENTINEL_SERVICE}
