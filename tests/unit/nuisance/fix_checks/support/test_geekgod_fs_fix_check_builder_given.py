from typing import Any

from evals.cve.kit.fix_check import FixCheckExploit
from evals.cve.nuisance.fix_checks import cve_2026_7400_geekgod_fs as geekgod_fs
from tests.unit.nuisance.fix_checks.support.recorded_exchanges import recorded


async def tool_calls(*calls: FixCheckExploit) -> list[tuple[str, dict[str, Any]]]:
    return [(name, args) for name, args, _ in await recorded(geekgod_fs.FIXTURE, *calls)]


def path_values(args: dict[str, Any]) -> list[str]:
    return [value for value in args.values() if isinstance(value, str) and value.startswith("/")]
