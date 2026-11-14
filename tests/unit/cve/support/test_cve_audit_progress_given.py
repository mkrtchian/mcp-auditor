import io

from rich.console import Console
from rich.progress import Progress


def a_progress() -> Progress:
    return Progress(console=Console(file=io.StringIO()))


async def an_audit(value: int) -> int:
    return value


async def an_audit_returning_none(_: int) -> None:
    return None


async def an_audit_raising(_: int) -> int:
    raise RuntimeError("launch failed")
