from collections.abc import Sequence
from pathlib import Path

import tests.unit.support.nuisance_admissions as admissions
import tests.unit.support.nuisance_walks as walks
from evals.cve.nuisance import images as nuisance_images
from tests.unit.support import censuses

SERVER_TAG = nuisance_images.image_tag("filesystem-nuisance")
ACCEPTANCE = admissions.ACCEPTANCE_PACKAGE


def a_failing_rebuild(services: Sequence[str]) -> None:
    raise RuntimeError(f"docker compose build failed for {', '.join(services)}")


def a_vet_of_one_server_beside_the_acceptance_one(tmp_path: Path) -> list[str]:
    """The `vet` arguments of an admission of `nuisance_vets.SERVER` and of the nuisance acceptance
    server ACCEPTANCE."""
    census = admissions.a_census_with_a_nuisance_acceptance_server()
    one = admissions.an_admission()
    acceptance = admissions.admitting_the_nuisance_acceptance_server()
    both = one.model_copy(update={"servers": [*one.servers, *acceptance.servers]})
    return [
        "vet",
        *walks.census_and_walk_record_arguments(tmp_path, censuses.written(tmp_path, census)),
        "--admission",
        str(admissions.written(tmp_path, both)),
    ]
