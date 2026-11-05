from collections.abc import Mapping, Sequence

from evals.cve_images import FINGERPRINT_LABEL, ImageBuildFailed


class FakeImageStore:
    """Images held by tag with their fingerprint label: an absent tag is not in the mapping,
    an unlabeled one maps to None. Each build is recorded, and raises when configured to fail."""

    def __init__(self, labels: Mapping[str, str | None], *, build_error: str | None = None):
        self._labels = dict(labels)
        self._build_error = build_error
        self.builds: list[list[str]] = []

    def label(self, tag: str, key: str) -> str | None:
        return self._labels.get(tag) if key == FINGERPRINT_LABEL else None

    def build(self, services: Sequence[str]) -> None:
        self.builds.append(list(services))
        if self._build_error is not None:
            raise ImageBuildFailed(services, self._build_error)
