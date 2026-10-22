from collections.abc import Mapping, Sequence

from evals.cve_images import FINGERPRINT_LABEL, ImageBuildFailed, dockerfile_fingerprint
from evals.cve_targets import image_tag


class FakeImageStore:
    """Images held by tag with their fingerprint label: an absent tag is not in the mapping,
    an unlabeled one maps to None. A build labels each service's tag with its current
    Dockerfile fingerprint, or raises when configured to fail."""

    def __init__(self, labels: Mapping[str, str | None], *, build_error: str | None = None):
        self._labels = dict(labels)
        self._build_error = build_error

    def label(self, tag: str, key: str) -> str | None:
        return self._labels.get(tag) if key == FINGERPRINT_LABEL else None

    def build(self, services: Sequence[str]) -> None:
        if self._build_error is not None:
            raise ImageBuildFailed(services, self._build_error)
        for service in services:
            self._labels[image_tag(service)] = dockerfile_fingerprint(service)

    def label_of(self, tag: str) -> str | None:
        return self._labels.get(tag)
