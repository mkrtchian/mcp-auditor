"""KitTarget: the fixture the calibration agent writes and driver consumes, free of mcp_auditor.

Parity note: it mirrors evals/cve/detection/targets.Target (with LaunchMode / FallbackScope).
KitTarget is a flat field-for-field mirror of the fields a holdout target carries, with
`exploits`/`benign` typed against KitClient and `builder` against launch.Launch. The maintainer's
transplant into evals/cve/detection/holdout_targets.py swaps the two import lines (client ->
mcp_auditor ports, launch -> cve_environments) and wraps the authored KitTarget into a Target
appended to HOLDOUT_TARGETS; nothing else changes. test_kit_isolation.py pins the field
parity so the mirror cannot drift. LaunchMode / FallbackScope are kit-local copies so the exported
kit stays standalone, depending only on the clean modules the dossier copies.
"""

import re
from collections.abc import Awaitable, Callable, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from enum import StrEnum

from evals.cve.kit.client import KitClient
from evals.cve.kit.launch import Launch, LaunchShape
from evals.cve_grammar import MechanismClass
from evals.cve_places import Place, Places
from evals.cve_planting import (
    RANDOM_NONCES,
    NonceSource,
    PlantingHost,
    PlantingSpec,
)
from evals.cve_planting import planting_spec as compute_planting_spec


class LaunchMode(StrEnum):  # mirror of evals/cve/detection/targets.LaunchMode
    NORMAL = "normal"
    FALLBACK = "fallback"


class FallbackScopeKind(StrEnum):  # mirror of evals/cve/detection/targets.FallbackScopeKind
    DOCUMENTED_DEFAULT = "documented_default"
    EMPTY_OUTSIDE = "empty_outside"
    OPTIONAL = "optional"


@dataclass(frozen=True)
class FallbackScope:
    kind: FallbackScopeKind
    path: str | None = None


_NO_FALLBACK_SCOPE = FallbackScope(FallbackScopeKind.OPTIONAL)

KitExploit = Callable[[Places, KitClient], Awaitable[None]]
KitBuilder = Callable[[str, PlantingSpec, LaunchShape], AbstractContextManager[Launch]]


@dataclass(frozen=True)
class KitTarget:
    flaw_id: str
    mechanisms: frozenset[MechanismClass]
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
    fallback_scope: FallbackScope = _NO_FALLBACK_SCOPE

    def planting_spec(
        self, to_plant: Sequence[Place], nonces: NonceSource = RANDOM_NONCES
    ) -> PlantingSpec:
        return compute_planting_spec(to_plant, self.planting_host, nonces)
