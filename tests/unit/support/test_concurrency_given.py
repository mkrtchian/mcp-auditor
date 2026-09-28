import asyncio
import time
from dataclasses import dataclass, field
from types import TracebackType


@dataclass
class InFlightProbe:
    current: int = 0
    highest: int = 0

    async def call(self, value: int) -> int:
        self.current += 1
        self.highest = max(self.highest, self.current)
        await asyncio.sleep(0)
        self.current -= 1
        return value


@dataclass
class RecordingManager:
    value: str = "entered value"
    enter_delay: float = 0.0
    events: list[str] = field(default_factory=list[str])
    exit_exception: BaseException | None = None

    def __enter__(self) -> str:
        time.sleep(self.enter_delay)
        self.events.append("enter")
        return self.value

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.events.append("exit")
        self.exit_exception = exc


@dataclass
class Ticker:
    ticks: int = 0

    async def run(self) -> None:
        while True:
            await asyncio.sleep(0.01)
            self.ticks += 1
