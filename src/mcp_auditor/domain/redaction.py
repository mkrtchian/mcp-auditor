from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from mcp_auditor.domain.models import ToolDefinition, ToolResponse


@dataclass(frozen=True)
class Redaction:
    secrets: Mapping[str, str]

    @classmethod
    def none(cls) -> "Redaction":
        return cls({})

    @property
    def active(self) -> bool:
        return bool(self.secrets)

    def text(self, text: str) -> str:
        # Longest first: a value contained in another must not break the longer one apart.
        for name, value in sorted(self.secrets.items(), key=lambda item: -len(item[1])):
            text = text.replace(value, marker(name))
        return text

    def response(self, response: ToolResponse) -> ToolResponse:
        return response.model_copy(update={"content": self.text(response.content)})

    def tool(self, tool: ToolDefinition) -> ToolDefinition:
        return ToolDefinition(
            name=self.text(tool.name),
            description=None if tool.description is None else self.text(tool.description),
            input_schema=cast(dict[str, object], self._schema_value(tool.input_schema)),
        )

    def stream(self) -> "StreamRedactor":
        return StreamRedactor(self)

    def _schema_value(self, value: object) -> object:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            entries = cast(dict[object, object], value)
            return {self._schema_value(k): self._schema_value(v) for k, v in entries.items()}
        if isinstance(value, list):
            return [self._schema_value(item) for item in cast(list[object], value)]
        return value


def marker(name: str) -> str:
    return f"[value of {name}, redacted by mcp-auditor]"


class StreamRedactor:
    """Redacts a text that arrives in chunks, a value possibly split across them."""

    def __init__(self, redaction: Redaction) -> None:
        self._redaction = redaction
        self._values = list(redaction.secrets.values())
        self._carry_length = max((len(value) for value in self._values), default=1) - 1
        self._buffer = ""

    def feed(self, chunk: str) -> str:
        if not self._redaction.active:
            return chunk
        self._buffer += chunk
        cut = self._safe_cut(len(self._buffer) - self._carry_length)
        emitted, self._buffer = self._buffer[:cut], self._buffer[cut:]
        return self._redaction.text(emitted)

    def flush(self) -> str:
        emitted, self._buffer = self._buffer, ""
        return self._redaction.text(emitted)

    def _safe_cut(self, cut: int) -> int:
        # A complete value straddling the cut is held back whole, never emitted in halves.
        cut = max(cut, 0)
        while (start := self._straddling_start(cut)) is not None:
            cut = start
        return cut

    def _straddling_start(self, cut: int) -> int | None:
        for value in self._values:
            start = self._buffer.find(value, max(cut - len(value) + 1, 0))
            if 0 <= start < cut:
                return start
        return None
