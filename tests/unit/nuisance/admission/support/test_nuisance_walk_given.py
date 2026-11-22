from typing import Any

from evals.cve.census.classification import Primitive, Transport
from evals.cve.census.exclusions import ACCEPTANCE_TARGET_FLAWS
from evals.cve.detection.targets import ACCEPTANCE_TARGETS
from evals.cve.nuisance.admission.walk_record import IdentitySettlement, WalkInputs

ON_RESOURCES: dict[str, Any] = {"primitive": Primitive.RESOURCES}
OVER_HTTP: dict[str, Any] = {"transport": Transport.HTTP}

# `min`, since a frozenset's order varies between processes.
A_DROPPED_ACCEPTANCE_TARGET_FLAW = min(
    ACCEPTANCE_TARGET_FLAWS - {target.flaw_id for target in ACCEPTANCE_TARGETS}
)


def with_an_identity(walk_inputs: WalkInputs, flaw: str, server_package: str) -> WalkInputs:
    record = walk_inputs.record
    identity = IdentitySettlement(flaw=flaw, server_package=server_package, reason="one project")
    identified = record.model_copy(update={"identities": [*record.identities, identity]})
    return WalkInputs(census=walk_inputs.census, record=identified)
