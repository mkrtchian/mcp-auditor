# The mount policy of ADR 017: which host paths a command's arguments open to the
# container it runs in. Pure: no filesystem call, no environment read. The adapter
# resolves the spellings this module names, and hands them back as `resolved`.
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
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


# What the container mount argument `_mount_flags` renders in the launch adapter cannot
# carry, so this list is tied to that spelling and goes stale if it changes. Measured
# against Docker 29.8.1 rather than derived: a double quote closes the quoted CSV field
# early and fails to parse, a CRLF is folded to a bare newline and would mount a path
# nobody named, and a trailing blank is rejected by the docker CLI's own flag parser,
# before it reaches the daemon. A bare CR, a tab and an interior blank all mount
# correctly, so none is refused here.
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


class Undecidable(Enum):
    NAME = "name"


# The name a declared container's own `docker run` gives it, read only before the image: a
# `--name` after it belongs to the server's command and names no container. Undecidable when
# an option the table does not know comes before any `--name`, or before a later `--name`
# that would override the one read, since what follows it cannot be told from the image.
def declared_container_name(args: Sequence[str]) -> str | Undecidable | None:
    if tuple(args[:1]) != ("run",):
        return None
    name: str | None = None
    remaining = iter(args[1:])
    for argument in remaining:
        if argument in ("-", "--") or not argument.startswith("-"):
            break
        option = _long_option(argument) if argument.startswith("--") else _short_options(argument)
        if option is None:
            return Undecidable.NAME if name is None or _names_again(remaining) else name
        value = next(remaining, None) if option.takes_next else option.inline_value
        if option.long_name == "name":
            name = value or None
    return name


def _names_again(arguments: Iterator[str]) -> bool:
    return any(argument == "--name" or argument.startswith("--name=") for argument in arguments)


@dataclass(frozen=True)
class _RunOption:
    long_name: str | None
    inline_value: str | None = None
    takes_next: bool = False


def _long_option(argument: str) -> _RunOption | None:
    long_name, separator, inline_value = argument.removeprefix("--").partition("=")
    if long_name in _RUN_LONG_FLAGS:
        return _RunOption(long_name)
    if long_name in _RUN_LONG_OPTIONS_WITH_A_VALUE:
        return _RunOption(long_name, inline_value, takes_next=not separator)
    return None


# `-it` is `-i -t`, and the first letter of a group that takes a value takes the rest of the
# group (`-eA=1`, `-e=A=1`), or the next argument when the group ends with it (`-ie A=1`).
def _short_options(argument: str) -> _RunOption | None:
    group = argument.removeprefix("-")
    for position, letter in enumerate(group):
        if letter in _RUN_SHORT_FLAGS:
            continue
        if letter not in _RUN_SHORT_OPTIONS_WITH_A_VALUE:
            return None
        rest = group[position + 1 :]
        return _RunOption(None, rest.removeprefix("="), takes_next=not rest)
    return _RunOption(None)


# The options of `docker run --help`, Docker CLI 29.9.3. Its hidden options (such as `--net`)
# are left out: an option missing here makes the name undecidable, never a wrong one.
_RUN_LONG_FLAGS = frozenset(
    {
        "detach",
        "help",
        "init",
        "interactive",
        "no-healthcheck",
        "oom-kill-disable",
        "privileged",
        "publish-all",
        "quiet",
        "read-only",
        "rm",
        "sig-proxy",
        "tty",
        "use-api-socket",
    }
)
_RUN_LONG_OPTIONS_WITH_A_VALUE = frozenset(
    {
        "add-host",
        "annotation",
        "attach",
        "blkio-weight",
        "blkio-weight-device",
        "cap-add",
        "cap-drop",
        "cgroup-parent",
        "cgroupns",
        "cidfile",
        "cpu-period",
        "cpu-quota",
        "cpu-rt-period",
        "cpu-rt-runtime",
        "cpu-shares",
        "cpus",
        "cpuset-cpus",
        "cpuset-mems",
        "detach-keys",
        "device",
        "device-cgroup-rule",
        "device-read-bps",
        "device-read-iops",
        "device-write-bps",
        "device-write-iops",
        "dns",
        "dns-option",
        "dns-search",
        "domainname",
        "entrypoint",
        "env",
        "env-file",
        "expose",
        "gpus",
        "group-add",
        "health-cmd",
        "health-interval",
        "health-retries",
        "health-start-interval",
        "health-start-period",
        "health-timeout",
        "hostname",
        "ip",
        "ip6",
        "ipc",
        "isolation",
        "label",
        "label-file",
        "link",
        "link-local-ip",
        "log-driver",
        "log-opt",
        "mac-address",
        "memory",
        "memory-reservation",
        "memory-swap",
        "memory-swappiness",
        "mount",
        "name",
        "network",
        "network-alias",
        "oom-score-adj",
        "pid",
        "pids-limit",
        "platform",
        "publish",
        "pull",
        "restart",
        "runtime",
        "security-opt",
        "shm-size",
        "stop-signal",
        "stop-timeout",
        "storage-opt",
        "sysctl",
        "tmpfs",
        "ulimit",
        "umask",
        "user",
        "userns",
        "uts",
        "volume",
        "volume-driver",
        "volumes-from",
        "workdir",
    }
)
_RUN_SHORT_FLAGS = frozenset("diPqt")
_RUN_SHORT_OPTIONS_WITH_A_VALUE = frozenset("acehlmpuvw")


# The relayed values join the environment of the `docker` process that launches the
# container, so these names would retarget it, change its binary or its configuration.
# HTTP_PROXY, HTTPS_PROXY and NO_PROXY stay relayable: a server behind a proxy needs them,
# and in the client they only route a TCP daemon connection through the caller's own proxy.
def steers_docker_client(name: str) -> bool:
    return name.startswith("DOCKER_") or name in ("PATH", "HOME")


# Scans the whole argv rather than stopping at the image: an `-e` after it belongs to
# the server's own command, and counting it only suppresses a warning.
def environment_names_passed(args: Sequence[str]) -> tuple[frozenset[str], bool]:
    names: set[str] = set()
    for flag, value in zip(args, [*args[1:], None], strict=True):
        if flag in ("-e", "--env") and value is not None:
            names.add(value.split("=", 1)[0])
        elif flag.startswith("--env="):
            names.add(flag.removeprefix("--env=").split("=", 1)[0])
    env_file = any(arg == "--env-file" or arg.startswith("--env-file=") for arg in args)
    return frozenset(names), env_file


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
