import os


def tracing_enabled() -> bool:
    return _tracing_flag("LANGSMITH_TRACING") or _tracing_flag("LANGCHAIN_TRACING_V2")


def _tracing_flag(name: str) -> bool:
    # A set-but-off flag ("false", "0") must read as off: bool() of a non-empty string is True.
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}
