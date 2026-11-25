from collections.abc import Sequence

from evals.cve.run_images import ContainerSweep


class FakeContainerSweep:
    """Answers each listing of the running containers with the next of `listings` whatever the
    tags, then with none, less the containers already removed, and records the tags listed and
    the containers removed. It stands for a command that lists one tag set (the detection holdout
    run, `run_detection`, `run_detection_holdout`, the fix check, a nuisance holdout run or vet
    whose servers have no built backend): a command listing two tag sets is tested on
    `tests/unit/support/nuisance_docker_hosts.DockerHost`. A container that refuses a run stays
    listed, so a sweep wrongly reached after the refusal would remove it."""

    def __init__(self, *listings: list[str]) -> None:
        self.listed_tags: list[list[str]] = []
        self.removed: list[str] = []
        self._listings = list(listings)

    @classmethod
    def running_before_the_rebuild(cls, *names: str) -> "FakeContainerSweep":
        return cls(list(names), list(names))

    @classmethod
    def appearing_after_the_rebuild(cls, *names: str) -> "FakeContainerSweep":
        return cls([], list(names), list(names))

    @classmethod
    def left_at_the_end(cls, *names: str) -> "FakeContainerSweep":
        return cls([], [], list(names))

    @property
    def sweep(self) -> ContainerSweep:
        return ContainerSweep(self.running, self.remove)

    def running(self, tags: Sequence[str]) -> list[str]:
        if self.listed_tags and list(tags) != self.listed_tags[0]:
            raise AssertionError(
                f"a second tag set {list(tags)} after {self.listed_tags[0]}: "
                "test this command on DockerHost"
            )
        self.listed_tags.append(list(tags))
        listing = self._listings.pop(0) if self._listings else []
        return [name for name in listing if name not in self.removed]

    def remove(self, containers: Sequence[str]) -> None:
        self.removed.extend(containers)
