from mcp_auditor.adapters.docker import DockerError

_DEFAULT_ENDPOINT = "unix:///var/run/docker.sock"
_DEFAULT_DIGEST = "sha256:abc123def456"


class FakeContainerRuntime:
    """A container runtime whose answers are configured, recording what it was asked.

    Built untouchable, every method raises: that is how a test states that a regime
    reaches no container runtime at all.
    """

    def __init__(
        self,
        *,
        untouchable: bool = False,
        available: bool = True,
        endpoint: str = _DEFAULT_ENDPOINT,
        digest: str | None = _DEFAULT_DIGEST,
        pull_error: str | None = None,
        pids_limit_enforced: bool = True,
        oom_killed: bool | None = False,
    ):
        self._untouchable = untouchable
        self._available = available
        self._endpoint = endpoint
        self._digest = digest
        self._pull_error = pull_error
        self._pids_limit_enforced = pids_limit_enforced
        self._oom_killed = oom_killed
        self.pulled: list[str] = []
        self.removed: list[str] = []

    def available(self) -> bool:
        self._refuse_when_untouchable()
        return self._available

    def endpoint(self) -> str:
        self._refuse_when_untouchable()
        return self._endpoint

    def ensure_image(self, image: str) -> str | None:
        self._refuse_when_untouchable()
        if self._pull_error is not None:
            raise DockerError(self._pull_error)
        self.pulled.append(image)
        return self._digest

    def pids_limit_enforced(self) -> bool:
        self._refuse_when_untouchable()
        return self._pids_limit_enforced

    def oom_killed(self, container_name: str) -> bool | None:
        self._refuse_when_untouchable()
        return self._oom_killed

    def remove(self, container_name: str) -> None:
        self._refuse_when_untouchable()
        self.removed.append(container_name)

    def _refuse_when_untouchable(self) -> None:
        if self._untouchable:
            raise AssertionError("this launch must not reach the container runtime")
