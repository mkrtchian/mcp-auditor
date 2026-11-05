from typing import Literal

import tests.unit.support.test_nuisance_admission_given as admission_given
from evals.nuisance_admission import AdmittedServer

SERVER = admission_given.SERVER_PACKAGE
COPIED_FLAW = admission_given.FIRST_FLAW
RECORDED = "a" * 64


def a_server_copying_the_holdout_calibration_at(
    fingerprint: str | None,
    source: Literal["fix_check", "holdout_calibration"] = "holdout_calibration",
) -> AdmittedServer:
    """The admission's server whose COPIED_FLAW record carries `fingerprint` under `source`."""
    server = admission_given.an_admission().servers[0]
    first, *rest = server.flaws
    check = first.fix_check.model_copy(
        update={"source": source, "holdout_fingerprint": fingerprint}
    )
    return server.model_copy(
        update={"flaws": [first.model_copy(update={"fix_check": check}), *rest]}
    )


def not_counting(server: AdmittedServer) -> AdmittedServer:
    first, *rest = server.flaws
    check = first.fix_check.model_copy(update={"vulnerable_surfaces": False})
    return server.model_copy(
        update={"flaws": [first.model_copy(update={"fix_check": check}), *rest]}
    )
