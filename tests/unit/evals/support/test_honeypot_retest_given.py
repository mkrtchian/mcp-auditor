from collections.abc import Callable

from evals.honeypot.retest import Retester
from tests.unit.evals.support.fictional_honeypots import HONEYPOTS, FakeAudit


def a_retester(
    audit: FakeAudit, announced: list[str] | None = None, warned: list[str] | None = None
) -> Retester:
    return Retester(
        audit=audit, honeypots=HONEYPOTS, announce=_recorder(announced), warn=_recorder(warned)
    )


def _recorder(sink: list[str] | None) -> Callable[[str], None]:
    return sink.append if sink is not None else lambda _: None
