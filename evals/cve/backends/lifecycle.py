import threading
from collections.abc import Callable, Generator, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass

from evals.cve.planting_base import PlantingHost

type ServerArgs = Callable[
    [str, str, PlantingHost, Sequence[str]], list[str]
]  # (name, image, host, launch)

type LaunchedServerArgs = Callable[
    [str, str, PlantingHost, Sequence[str]], AbstractContextManager[list[str]]
]  # (name, image, host, launch)


@dataclass(frozen=True)
class BackendLifecycle:
    """A shared backend: stood once, it serves every launch and stays up once a launch ends."""

    key: str  # the BackendFixture.provisioner key, and the module evals.cve.backends.<key>
    lock: threading.Lock
    ensure: Callable[[], None]
    server_args: ServerArgs
    remove: Callable[[str], None]


@dataclass(frozen=True)
class PerLaunchBackend:
    """A backend stood for one launch and removed with it, since the auditor's calls change its
    state. `launch` stands the backend for the server named `name`, yields the server's docker
    run arguments, which may carry values only the stand-up knows (a token, a mounted file), and
    removes the server and its backend at exit, even when the body raises."""

    key: str  # the BackendFixture.provisioner key, and the module evals.cve.backends.<key>
    launch: LaunchedServerArgs


def launched_server_args(lifecycle: BackendLifecycle | PerLaunchBackend) -> LaunchedServerArgs:
    match lifecycle:
        case BackendLifecycle():
            return _SharedLaunch(lifecycle).launch
        case PerLaunchBackend():
            return lifecycle.launch


@dataclass(frozen=True)
class _SharedLaunch:
    lifecycle: BackendLifecycle

    @contextmanager
    def launch(
        self, name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
    ) -> Generator[list[str]]:
        # The lock serialises only the backend stand-up, not the yield: a server's concurrent
        # launches share the one backend that serves them all.
        with self.lifecycle.lock:
            self.lifecycle.ensure()
        try:
            yield self.lifecycle.server_args(name, image, host, server_launch)
        finally:
            self.lifecycle.remove(name)
