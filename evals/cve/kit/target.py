"""The fixture the calibration agent writes and the kit driver consumes, free of mcp_auditor.

KitTarget carries a subset of the fields of evals/cve/detection/targets.Target, so an authored
fixture transplants into a Target by swapping its client and launch imports (the calibration
dossier's fixture_format.md gives the procedure); test_kit_isolation pins the subset. LaunchMode
and FallbackScope are defined here, the repository's Target imports them, so the kit stays
standalone and a transplanted fixture keeps them.
"""

import re
from collections.abc import Awaitable, Callable, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from enum import StrEnum

from evals.cve.grammar import FlawClass
from evals.cve.kit.client import KitClient
from evals.cve.kit.launch import Launch, LaunchShape
from evals.cve.places import Place, Places
from evals.cve.planting import (
    RANDOM_NONCES,
    NonceSource,
    PlantingHost,
    PlantingSpec,
)
from evals.cve.planting import planting_spec as compute_planting_spec


class LaunchMode(StrEnum):
    """The launch a target runs under, read by `Target.environment()` to pick the launch shape.
    NORMAL is the frozen layout; FALLBACK is the launch the rule switches to on a break
    (detection-suite-rule.md, Deployment layout (A server the layout breaks)). The layout check only
    reports; the maintainer sets this field from calibration like kept_places, and every acceptance
    target keeps NORMAL (no target breaks)."""

    NORMAL = "normal"
    FALLBACK = "fallback"


class FallbackScopeKind(StrEnum):
    """The three shapes the rule distinguishes for the fallback scope (detection-suite-rule.md,
    Deployment layout (A server the layout breaks)): the default the server documents, an empty
    directory outside the layout when the server requires a scope and documents none, and no scope
    when the scope is optional."""

    DOCUMENTED_DEFAULT = "documented_default"
    EMPTY_OUTSIDE = "empty_outside"
    OPTIONAL = "optional"


@dataclass(frozen=True)
class FallbackScope:
    kind: FallbackScopeKind
    path: str | None = None  # the concrete scope for DOCUMENTED_DEFAULT and EMPTY_OUTSIDE


NO_FALLBACK_SCOPE = FallbackScope(FallbackScopeKind.OPTIONAL)

KitExploit = Callable[[Places, KitClient], Awaitable[None]]
KitBuilder = Callable[[str, PlantingSpec, LaunchShape], AbstractContextManager[Launch]]


@dataclass(frozen=True)
class KitTarget:
    flaw_id: str
    classes: frozenset[FlawClass]
    aim: re.Pattern[str]
    reaches: frozenset[str]
    kept_places: tuple[str, ...]
    images: tuple[str, ...]
    server_image: str
    patched_image: str
    planting_host: PlantingHost
    builder: KitBuilder
    exploits: tuple[KitExploit, ...]
    benign: KitExploit
    launch_mode: LaunchMode = LaunchMode.NORMAL
    fallback_scope: FallbackScope = NO_FALLBACK_SCOPE

    def planting_spec(
        self, to_plant: Sequence[Place], nonces: NonceSource = RANDOM_NONCES
    ) -> PlantingSpec:
        return compute_planting_spec(to_plant, self.planting_host, nonces)
