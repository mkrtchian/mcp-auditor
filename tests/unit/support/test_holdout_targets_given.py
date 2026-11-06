import re
from pathlib import Path

from evals.cve_images import dockerfile_instructions
from evals.docker_paths import image_dockerfile
from evals.holdout_census import load_census
from evals.run_census import CENSUS_PATH


def the_census_drawn_identifiers() -> set[str]:
    draw = load_census(CENSUS_PATH).draw
    assert draw is not None, "the committed census carries no draw"
    return set(draw.drawn)


_CERTIFICATE = re.compile(r"-----BEGIN CERTIFICATE-----\n.*?-----END CERTIFICATE-----\n", re.DOTALL)


def the_authority_inlined_in(dockerfile: Path) -> str:
    certificates = _CERTIFICATE.findall(dockerfile.read_text())
    assert len(certificates) == 1, f"{dockerfile.name} inlines {len(certificates)} certificates"
    return certificates[0]


# `/work` as a whole path component: `/work` or `/work/...`, never `/api/v1/workflows`.
_WORK_PATH = re.compile(r"(?<![\w.-])/work(?![\w.-])")


def the_instructions_naming_work_in(service: str) -> list[str]:
    instructions = dockerfile_instructions(image_dockerfile(service))
    return [line for line in instructions if _WORK_PATH.search(line)]
