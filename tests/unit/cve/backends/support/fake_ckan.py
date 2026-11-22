from dataclasses import dataclass, field

from evals.cve.backends.ckan_holdout import CkanHoldoutDocker
from evals.cve.detection.holdout_fixtures.cve_2026_33060_ckan import TARGET
from evals.cve.places import DETECTION_PLACES, kept_records, load_places
from evals.cve.planting_base import PlantingSpec, SentinelIntent


@dataclass
class FakeCkanDocker:
    """Records what the builder stands and removes, in order, without Docker."""

    events: list[str] = field(default_factory=list[str])
    sentinel_hosts: list[str] = field(default_factory=list[str])
    removed: list[str] = field(default_factory=list[str])

    def ensure_stack(self) -> None:
        self.events.append("stack")

    def ensure_link_local_network(self) -> None:
        self.events.append("link-local network")

    def start_sentinel(self, sentinel: SentinelIntent) -> str:
        self.events.append("sentinel")
        self.sentinel_hosts.append(sentinel.host)
        return f"sentinel-{sentinel.host}"

    def remove(self, name: str) -> None:
        self.removed.append(name)

    def docker(self) -> CkanHoldoutDocker:
        return CkanHoldoutDocker(
            self.ensure_stack,
            self.ensure_link_local_network,
            self.start_sentinel,
            self.remove,
            wait=lambda _seconds: None,
        )


def the_targets_spec() -> PlantingSpec:
    return TARGET.planting_spec(kept_records(TARGET.kept_places, load_places(DETECTION_PLACES)))
