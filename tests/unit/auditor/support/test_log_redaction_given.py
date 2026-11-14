import io
import logging
from collections.abc import Generator
from contextlib import contextmanager

VALUE = "s3cr3t-token-value"
SDK_LOGGERS = ("", "client", "mcp.client.stdio")


@contextmanager
def sdk_output() -> Generator[dict[str, io.StringIO]]:
    outputs = {name: io.StringIO() for name in SDK_LOGGERS}
    handlers = {name: logging.StreamHandler(output) for name, output in outputs.items()}
    for name, handler in handlers.items():
        logging.getLogger(name).addHandler(handler)
    try:
        yield outputs
    finally:
        for name, handler in handlers.items():
            logging.getLogger(name).removeHandler(handler)


# At ERROR, above every effective level, so a silenced logger is the one way a record is lost.
def server_data_logged() -> None:
    for name in SDK_LOGGERS:
        logging.getLogger(name).error("server sent %s", VALUE)
