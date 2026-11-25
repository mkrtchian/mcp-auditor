from collections.abc import Callable
from typing import Any


def unreached(what: str) -> Callable[..., Any]:
    """A port the test must never reach. It raises on its first call, sync or async, since an
    async port called this way raises before anything awaits it."""

    def port(*_: object, **__: object) -> Any:
        raise AssertionError(f"{what} was reached")

    return port
