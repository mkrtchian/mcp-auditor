"""The holdout reference a nuisance dossier ships for each census flaw of its server that is a
holdout target: the target's fixture module and its builder's source as text, its Dockerfiles and
its calibration card. Rule v4 lets the admission agents start from that fixture when the server's
patched version is the one the holdout calibration checks (Admission), and adapt it otherwise.

This module imports `holdout_targets`, which is not clean: only the files it writes must be.
"""

import inspect
import shutil
from collections.abc import Iterable, Sequence
from pathlib import Path

from evals.cve_targets import CVETarget
from evals.docker_paths import image_dockerfile
from evals.eval_session import Refused
from evals.holdout_census import HoldoutCensus
from evals.holdout_targets import HOLDOUT_TARGETS
from evals.honeypots import REPO_ROOT

HOLDOUT_FIXTURES = REPO_ROOT / "evals" / "holdout_fixtures"


def holdout_targets_among(identifiers: Iterable[str]) -> list[CVETarget]:
    wanted = set(identifiers)
    return [target for target in HOLDOUT_TARGETS if target.cve_id in wanted]


def write_holdout_references(
    out: Path, census: HoldoutCensus, targets: Sequence[CVETarget]
) -> None:
    if not targets:
        return
    cards = {card.flaw: card for card in census.draw.cards} if census.draw is not None else {}
    reference = out / "reference"
    for directory in ("holdout_fixtures", "cards", "docker"):
        (reference / directory).mkdir(parents=True, exist_ok=True)
    for target in targets:
        if target.cve_id not in cards:
            raise Refused(
                f"Refused: the holdout target {target.cve_id} has no calibration card.",
                ["Every HOLDOUT_TARGETS entry carries its card in the census's draw record."],
            )
        _write_fixture_text(reference / "holdout_fixtures", target)
        (reference / "cards" / f"{target.cve_id}.json").write_text(
            cards[target.cve_id].model_dump_json(indent=2)
        )
        for service in (*target.images, target.patched_image):
            source = image_dockerfile(service)
            shutil.copyfile(source, reference / "docker" / source.name)


def _write_fixture_text(directory: Path, target: CVETarget) -> None:
    fixture = holdout_fixture_file(target.cve_id)
    builder = target.builder
    text = (
        f"{fixture.read_text()}\n\n"
        f"# The builder {builder.__name__}, from {builder.__module__}:\n\n"
        f"{inspect.getsource(builder)}"
    )
    (directory / f"{fixture.name}.txt").write_text(text)


def holdout_fixture_file(identifier: str) -> Path:
    slug = identifier.lower().replace("-", "_")
    matches = sorted(HOLDOUT_FIXTURES.glob(f"{slug}_*.py"))
    if len(matches) != 1:
        raise Refused(
            f"Refused: the holdout flaw {identifier} matches {len(matches)} fixture modules.",
            [f"evals/holdout_fixtures/{slug}_*.py must match exactly one module"],
        )
    return matches[0]
