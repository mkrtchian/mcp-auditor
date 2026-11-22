"""The real acceptance targets by flaw ID, for the tests that plant a target's kept places or
fingerprint its fixture."""

import dataclasses

from evals.cve.detection.targets import ACCEPTANCE_TARGETS, Target

FILESYSTEM = "CVE-2025-53109"
KUBERNETES = "CVE-2025-53355"
GIT = "CVE-2025-68143"


def an_acceptance_target(flaw_id: str, **changes: object) -> Target:
    (target,) = [target for target in ACCEPTANCE_TARGETS if target.flaw_id == flaw_id]
    return dataclasses.replace(target, **changes)  # pyrefly: ignore[bad-argument-type]
