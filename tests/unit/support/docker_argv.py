"""Lookups in the `docker run` argv of a launch."""

from collections.abc import Sequence


def value_after(args: Sequence[str], flag: str) -> str:
    return args[list(args).index(flag) + 1]


def values_after(args: Sequence[str], flag: str) -> list[str]:
    return [args[index + 1] for index, arg in enumerate(args) if arg == flag]


def environment(args: Sequence[str]) -> dict[str, str]:
    return dict(pair.split("=", 1) for pair in values_after(args, "-e"))


def carries(args: Sequence[str], segment: Sequence[str]) -> bool:
    return count(args, segment) > 0


def count(args: Sequence[str], segment: Sequence[str]) -> int:
    width = len(segment)
    return sum(list(args[i : i + width]) == list(segment) for i in range(len(args)))


def mount_of(args: Sequence[str], container_path: str) -> str:
    """The full `-v host:container[:mode]` value mounted at the container path."""
    mounts = values_after(args, "-v")
    return next(mount for mount in mounts if mount.split(":")[1] == container_path)
