import re

import pytest

from evals import eval_display

_ANSI_ESCAPE = re.compile(r"\x1b\[")


class CapturedOutput:
    def __init__(self, capsys: pytest.CaptureFixture[str]) -> None:
        self._capsys = capsys
        self._text = ""

    def getvalue(self) -> str:
        self._text += self._capsys.readouterr().out
        assert not _ANSI_ESCAPE.search(self._text), (
            "the shared console wrote ANSI escape sequences: rich chose its colour system"
            " when it was built, on a terminal, so run the display tests without -s"
        )
        return self._text


def a_captured_console(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, width: int = 200
) -> CapturedOutput:
    """Capture what `eval_display.console`, shared by every display module, writes from now on."""
    monkeypatch.setenv("COLUMNS", str(width))
    assert eval_display.console.width == width, (
        "the shared console froze its width when it was built: unset COLUMNS in the shell"
    )
    capsys.readouterr()
    return CapturedOutput(capsys)
