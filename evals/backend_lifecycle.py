import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from evals.cve_planting_base import PlantingHost

type ServerArgs = Callable[
    [str, str, PlantingHost, Sequence[str]], list[str]
]  # (name, image, host, launch)


@dataclass(frozen=True)
class BackendLifecycle:
    key: str  # the BackendFixture.provisioner key, and the module evals.<key>_backend
    lock: threading.Lock
    ensure: Callable[[], None]
    server_args: ServerArgs
    remove: Callable[[str], None]
