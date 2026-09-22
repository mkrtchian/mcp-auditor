# The mount policy of ADR 017: which host paths a command's arguments open to the
# container it runs in. Pure: no filesystem call, no environment read. The adapter
# resolves the spellings this module names, and hands them back as `resolved`.
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MountPolicy:
    declared: tuple["DeclaredMount", ...]
    refused: frozenset[Path]

    def spellings_to_resolve(self, args: Sequence[str]) -> list[str]:
        candidates = [
            *(element for element in args if looks_like_path(element) or _is_bare_word(element)),
            *(mount.spelling for mount in self.declared),
            *(str(root) for root in self.refused),
        ]
        return list(dict.fromkeys(candidates))

    def plan(self, args: Sequence[str], resolved: Mapping[str, Path]) -> "MountPlan":
        declared = self._declared_mounts(resolved)
        scan = self._scan_argv(args, resolved, declared)
        joined = dict.fromkeys(scan.paths, True) | declared
        for host in joined:
            _require_a_spellable_path(host)
        return MountPlan(
            mounts=tuple(MountSpec(host, writable) for host, writable in joined.items()),
            rewrites=scan.rewrites,
            unmounted_existing=scan.unmounted_existing,
        )

    def _scan_argv(
        self, args: Sequence[str], resolved: Mapping[str, Path], declared: Mapping[Path, bool]
    ) -> "_ArgvScan":
        forbidden = self._refused_paths(resolved) - set(declared)
        paths: list[Path] = []
        rewrites: dict[str, str] = {}
        unmounted: list[str] = []
        for element in args:
            host = resolved.get(element)
            if host is None:
                continue
            if looks_like_path(element):
                if host in forbidden:
                    raise RefusedMountError(host)
                paths.append(host)
                if not Path(element).is_absolute():
                    rewrites[element] = str(host)
            elif _is_bare_word(element):
                unmounted.append(element)
        return _ArgvScan(tuple(paths), rewrites, tuple(unmounted))

    def _declared_mounts(self, resolved: Mapping[str, Path]) -> dict[Path, bool]:
        mounts: dict[Path, bool] = {}
        for mount in self.declared:
            if mount.spelling not in resolved:
                raise MissingMountError(mount.spelling)
            mounts[resolved[mount.spelling]] = mount.writable
        return mounts

    # A refused root is compared both as written and as the host resolves it, so a home
    # directory that is itself a symlink cannot be mounted through its other spelling.
    def _refused_paths(self, resolved: Mapping[str, Path]) -> set[Path]:
        return set(self.refused) | {
            resolved[str(root)] for root in self.refused if str(root) in resolved
        }


@dataclass(frozen=True)
class _ArgvScan:
    paths: tuple[Path, ...]
    rewrites: Mapping[str, str]
    unmounted_existing: tuple[str, ...]


@dataclass(frozen=True)
class MountPlan:
    mounts: tuple["MountSpec", ...]
    rewrites: Mapping[str, str]
    unmounted_existing: tuple[str, ...]


@dataclass(frozen=True)
class MountSpec:
    host: Path
    writable: bool


@dataclass(frozen=True)
class DeclaredMount:
    spelling: str
    writable: bool


# What a container mount argument cannot carry, measured against Docker 29.8.1 rather
# than derived: a double quote closes the quoted CSV field early and fails to parse, a
# CRLF is folded to a bare newline and would mount a path nobody named, and a trailing
# blank is rejected by the docker CLI's own flag parser, before it reaches the daemon. A
# bare CR, a tab and an interior blank all mount correctly, so none is refused here.
_UNSPELLABLE_SUBSTRINGS = (('"', "a double quote"), ("\r\n", "a carriage return and line feed"))


def _require_a_spellable_path(host: Path) -> None:
    spelling = str(host)
    for substring, reason in _UNSPELLABLE_SUBSTRINGS:
        if substring in spelling:
            raise UnspellableMountError(host, reason)
    if spelling != spelling.rstrip():
        raise UnspellableMountError(host, "a name ending in a blank")


def parse_mount_option(raw: str) -> "DeclaredMount":
    spelling, separator, mode = raw.rpartition(":")
    if separator and mode in ("ro", "rw"):
        return DeclaredMount(spelling=spelling, writable=mode == "rw")
    return DeclaredMount(spelling=raw, writable=False)


# A bare word is never a path, even when the working directory holds an entry of that
# name: `npx some-server build` next to a `build/` directory must neither mount it nor
# rewrite the word into an absolute path it was never meant to be.
def looks_like_path(element: str) -> bool:
    return element.startswith("/") or element in (".", "..") or element.startswith(("./", "../"))


def _is_bare_word(element: str) -> bool:
    return not looks_like_path(element) and not element.startswith("-")


def refused_roots(home: Path) -> frozenset[Path]:
    return frozenset(
        {Path(root) for root in ("/", "/etc", "/usr", "/var", "/home", "/root", "/opt", "/srv")}
        | {home}
    )


# ADR 017's passthrough rule: a command that already is a container runs as the caller
# wrote it.
def is_declared_container(command: str, args: Sequence[str]) -> bool:
    return command == "docker" and tuple(args[:1]) == ("run",)


class RefusedMountError(ValueError):
    def __init__(self, root: Path) -> None:
        super().__init__(f"refusing to mount {root}")
        self.root = root


class MissingMountError(ValueError):
    def __init__(self, spelling: str) -> None:
        super().__init__(f"no such path on this host: {spelling}")
        self.spelling = spelling


class UnspellableMountError(ValueError):
    def __init__(self, host: Path, reason: str) -> None:
        super().__init__(f"cannot be spelled in a container mount: {host}")
        self.host = host
        self.reason = reason
