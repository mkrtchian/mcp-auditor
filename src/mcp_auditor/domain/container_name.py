# Reads a declared container's own `docker run` argv.
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from enum import Enum


class Undecidable(Enum):
    NAME = "name"


# ADR 017's passthrough rule: a command that already is a container runs as the caller
# wrote it.
def is_declared_container(command: str, args: Sequence[str]) -> bool:
    return command == "docker" and tuple(args[:1]) == ("run",)


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


# The variables a declared container's own `docker run` passes, and whether it reads an env
# file. The option table reads the options up to the image, short groups included.
def environment_names_passed(args: Sequence[str]) -> tuple[frozenset[str], bool]:
    remaining = iter(args[1:])
    options = list(_valued_options_up_to_the_image(remaining))
    names = {value.split("=", 1)[0] for long_name, value in options if long_name == "env"}
    env_file = any(long_name == "env-file" for long_name, _ in options)
    names_after, env_file_after = _passed_after_the_image(list(remaining))
    return frozenset(names | names_after), env_file or env_file_after


def _valued_options_up_to_the_image(arguments: Iterator[str]) -> Iterator[tuple[str, str]]:
    for argument in arguments:
        if argument in ("-", "--") or not argument.startswith("-"):
            return
        option = _long_option(argument) if argument.startswith("--") else _short_options(argument)
        if option is None or option.long_name is None:
            continue
        value = next(arguments, None) if option.takes_next else option.inline_value
        if value is not None:
            yield option.long_name, value


# Scans past the image rather than stopping at it: an `-e` after it belongs to the server's
# own command, and counting it only suppresses a warning. The option table is not used
# there, since a server `-v` would swallow a following `-e` and bring the warning back.
def _passed_after_the_image(args: Sequence[str]) -> tuple[frozenset[str], bool]:
    names: set[str] = set()
    for flag, value in zip(args, [*args[1:], None], strict=False):
        if flag in ("-e", "--env") and value is not None:
            names.add(value.split("=", 1)[0])
        elif flag.startswith("--env="):
            names.add(flag.removeprefix("--env=").split("=", 1)[0])
    env_file = any(arg == "--env-file" or arg.startswith("--env-file=") for arg in args)
    return frozenset(names), env_file


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
        return _RunOption(
            _RUN_SHORT_OPTIONS_WITH_A_VALUE[letter], rest.removeprefix("="), takes_next=not rest
        )
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
_RUN_SHORT_OPTIONS_WITH_A_VALUE = {
    "a": "attach",
    "c": "cpu-shares",
    "e": "env",
    "h": "hostname",
    "l": "label",
    "m": "memory",
    "p": "publish",
    "u": "user",
    "v": "volume",
    "w": "workdir",
}
