# The SDK hands `errlog`'s file descriptor to the child process, so no Python `write()`
# ever sees the server's stderr: it is read back from a pipe and redacted there.
import codecs
import os
import threading
from types import TracebackType
from typing import Self, TextIO

from mcp_auditor.domain.redaction import Redaction

_READ_SIZE = 65536
_JOIN_TIMEOUT = 2.0


class RedactingStderr:
    """The server's stderr, redacted before it is kept, and never written to disk."""

    def __init__(self, redaction: Redaction, keep: int = 1024 * 1024) -> None:
        self._redaction = redaction
        self._keep = keep
        self._chunks: list[str] = []
        self._size = 0
        self._lock = threading.Lock()
        self._writer: TextIO | None = None
        self._reader: threading.Thread | None = None

    def __enter__(self) -> Self:
        read_fd, write_fd = os.pipe()
        self._writer = os.fdopen(write_fd, "w")
        self._reader = threading.Thread(target=self._drain, args=(read_fd,), daemon=True)
        self._reader.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._finish()

    @property
    def redaction(self) -> Redaction:
        return self._redaction

    @property
    def writer(self) -> TextIO:
        assert self._writer is not None, "RedactingStderr used outside its with block"
        return self._writer

    def text(self) -> str:
        """The redacted tail, at most `keep` characters."""
        self._finish()
        with self._lock:
            return "".join(self._chunks)[-self._keep :]

    def _finish(self) -> None:
        if self._writer is not None and not self._writer.closed:
            self._writer.close()
        # A grandchild holding the inherited stderr open delays the end of stream past
        # the timeout: the redactor's carry then stays unflushed, holding text back.
        if self._reader is not None:
            self._reader.join(_JOIN_TIMEOUT)

    def _drain(self, read_fd: int) -> None:
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        redactor = self._redaction.stream()
        try:
            while chunk := os.read(read_fd, _READ_SIZE):
                self._append(redactor.feed(decoder.decode(chunk)))
        finally:
            os.close(read_fd)
        self._append(redactor.feed(decoder.decode(b"", final=True)) + redactor.flush())

    def _append(self, text: str) -> None:
        with self._lock:
            self._chunks.append(text)
            self._size += len(text)
            # Trimmed at twice the bound, so that a server writing line by line costs
            # one copy of the tail per `keep` characters, not one per line.
            if self._size > 2 * self._keep:
                tail = "".join(self._chunks)[-self._keep :]
                self._chunks, self._size = [tail], len(tail)
