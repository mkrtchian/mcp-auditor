"""The Python files an eval fingerprint hashes, computed from the code that fingerprints them.

Modifying one of them, even to reorder it, moves a fingerprint: the grammar's, the counter's, a
detection fixture's, a nuisance fixture's or a honeypot's source. The code standards debt list
names these files as the blockers of the violations they carry.
"""

from collections.abc import Iterable
from pathlib import Path

from evals.cve.detection.baseline import ENVIRONMENT_PATHS, GRAMMAR_PATHS
from evals.cve.detection.holdout_targets import HOLDOUT_TARGETS
from evals.cve.detection.targets import ACCEPTANCE_TARGETS
from evals.cve.nuisance import counter, fingerprint
from evals.cve.nuisance.backend_registry import BACKENDS
from evals.honeypots import HONEYPOTS

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]


def fingerprinted_sources() -> frozenset[str]:
    backend_sources = (
        path
        for target in (*ACCEPTANCE_TARGETS, *HOLDOUT_TARGETS)
        for path in target.backend_sources
    )
    served = (
        path for backend in BACKENDS.values() for path in backend.served if path.suffix == ".py"
    )
    return _relative(
        [
            *GRAMMAR_PATHS,
            *ENVIRONMENT_PATHS,
            *counter._COUNTER_PATHS,
            fingerprint.CONFINEMENT_SOURCE,
            *fingerprint._PUBLIC_NAME_SOURCES,
            *backend_sources,
            *served,
            *(honeypot.server for honeypot in HONEYPOTS),
        ]
    )


def _relative(paths: Iterable[Path]) -> frozenset[str]:
    return frozenset(path.resolve().relative_to(REPOSITORY_ROOT).as_posix() for path in paths)
