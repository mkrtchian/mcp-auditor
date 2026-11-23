import os

# Every name LangSmith turns tracing on from: `langsmith.utils.tracing_is_enabled` reads
# `TRACING_V2`, then `TRACING`, under the `LANGSMITH_` and `LANGCHAIN_` prefixes. Calling it
# instead would read a cached environment (`get_env_var` is an `lru_cache`).
TRACING_VARIABLES = (
    "LANGSMITH_TRACING",
    "LANGSMITH_TRACING_V2",
    "LANGCHAIN_TRACING",
    "LANGCHAIN_TRACING_V2",
)

TRACING_ON = f"a tracing variable is set ({', '.join(TRACING_VARIABLES)})"


def tracing_enabled() -> bool:
    return any(_tracing_flag(name) for name in TRACING_VARIABLES)


def _tracing_flag(name: str) -> bool:
    # A set-but-off flag ("false", "0") must read as off: bool() of a non-empty string is True.
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}
