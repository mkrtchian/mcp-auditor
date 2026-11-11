from collections.abc import Sequence

from evals.cve.run_images import ContainerSweep


class FakeContainerSweep:
    """Answers each listing of the running containers with the next of `listings`, then with
    none, and records the tags listed and the containers removed. A run lists them before the
    image rebuild, after it and at its end."""

    def __init__(self, *listings: list[str]) -> None:
        self.listed_tags: list[list[str]] = []
        self.removed: list[str] = []
        self._listings = list(listings)

    @classmethod
    def running_before_the_rebuild(cls, *names: str) -> "FakeContainerSweep":
        return cls(list(names))

    @classmethod
    def appearing_after_the_rebuild(cls, *names: str) -> "FakeContainerSweep":
        return cls([], list(names))

    @classmethod
    def left_at_the_end(cls, *names: str) -> "FakeContainerSweep":
        return cls([], [], list(names))

    @property
    def sweep(self) -> ContainerSweep:
        return ContainerSweep(self.running, self.remove)

    def running(self, tags: Sequence[str]) -> list[str]:
        self.listed_tags.append(list(tags))
        return self._listings.pop(0) if self._listings else []

    def remove(self, containers: Sequence[str]) -> None:
        self.removed.extend(containers)
