import re
from collections.abc import Mapping
from dataclasses import dataclass

from mcp_auditor.domain.redaction import Redaction

NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
SHORT_VALUE = 8
SECRET_WORDS = ("TOKEN", "KEY", "SECRET", "PASSWORD", "PASS", "CREDENTIAL", "AUTH")


class RelayRefusedError(ValueError):
    pass


@dataclass(frozen=True)
class RelayedVariable:
    name: str
    value: str
    redacted: bool


@dataclass(frozen=True)
class RelayRequest:
    redacted: tuple[str, ...] = ()
    plain: tuple[str, ...] = ()


@dataclass(frozen=True)
class RelayedEnvironment:
    variables: tuple[RelayedVariable, ...] = ()

    @classmethod
    def resolved(cls, request: RelayRequest, environ: Mapping[str, str]) -> "RelayedEnvironment":
        variables = tuple(_redacted_variable(argument, environ) for argument in request.redacted)
        variables += tuple(_plain_variable(argument, environ) for argument in request.plain)
        _refuse_duplicates(variables)
        return cls(variables)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(variable.name for variable in self.variables)

    @property
    def values(self) -> dict[str, str]:
        return {variable.name: variable.value for variable in self.variables}

    def redaction(self) -> Redaction:
        return Redaction({v.name: v.value for v in self.variables if v.redacted})

    def warnings(self) -> tuple[str, ...]:
        return tuple(
            warning for variable in self.variables if (warning := _warning(variable)) is not None
        )


def _redacted_variable(argument: str, environ: Mapping[str, str]) -> RelayedVariable:
    if "=" in argument:
        name = argument.split("=", 1)[0]
        raise RelayRefusedError(
            f"--env {name}=value puts the value in your shell history and the process list: "
            f"export {name} and pass --env {name}, "
            "or use --env-plain for a value that is not secret"
        )
    value = _from_environ(argument, environ)
    if not value:
        raise RelayRefusedError(
            f"{argument} is empty in your environment and an empty value cannot be redacted: "
            f"use --env-plain {argument} to relay it"
        )
    return RelayedVariable(argument, value, redacted=True)


def _plain_variable(argument: str, environ: Mapping[str, str]) -> RelayedVariable:
    name, separator, inline_value = argument.partition("=")
    if separator:
        _require_valid_name(name)
        return RelayedVariable(name, inline_value, redacted=False)
    return RelayedVariable(name, _from_environ(name, environ), redacted=False)


def _from_environ(name: str, environ: Mapping[str, str]) -> str:
    _require_valid_name(name)
    if name not in environ:
        raise RelayRefusedError(f"{name} is not set in your environment")
    return environ[name]


def _require_valid_name(name: str) -> None:
    if not NAME_PATTERN.fullmatch(name):
        raise RelayRefusedError(
            f"{name} is not a variable name: use letters, digits and underscores, "
            "not starting with a digit"
        )


def _refuse_duplicates(variables: tuple[RelayedVariable, ...]) -> None:
    seen: set[str] = set()
    for variable in variables:
        if variable.name in seen:
            raise RelayRefusedError(
                f"{variable.name} is named twice: pass it once, to --env or to --env-plain"
            )
        seen.add(variable.name)


def _warning(variable: RelayedVariable) -> str | None:
    if variable.redacted and len(variable.value) < SHORT_VALUE:
        return (
            f"the value of {variable.name} is {len(variable.value)} characters long: every "
            "occurrence of it in the server's output is replaced, including where it has "
            "nothing to do with the variable"
        )
    if not variable.redacted and any(word in variable.name.upper() for word in SECRET_WORDS):
        return (
            f"{variable.name} looks like a secret and --env-plain records its value in the "
            f"report: pass --env {variable.name} to redact it"
        )
    return None
