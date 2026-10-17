import logging
from typing import Any, cast

import httpx

_MODELS_URL = "https://openrouter.ai/api/v1/models"
_TIMEOUT_SECONDS = 10

_logger = logging.getLogger(__name__)


class OpenRouterEffortCatalog:
    def __init__(self, transport: httpx.BaseTransport | None = None):
        self._transport = transport
        self._efforts: dict[str, tuple[str, ...] | None] = {}

    # An effort the model does not take fails only at call time, mid-audit, so it is refused here.
    # When the listing cannot settle it, the audit goes on and the call decides.
    def check(self, model: str, reasoning: str) -> None:
        if model not in self._efforts:
            self._efforts[model] = self._published_efforts(model)
        efforts = self._efforts[model]
        if efforts is not None and reasoning not in efforts:
            raise ValueError(
                f"Model {model!r} on OpenRouter supports reasoning efforts "
                f"{', '.join(efforts)}, got {reasoning!r}."
            )

    def _published_efforts(self, model: str) -> tuple[str, ...] | None:
        try:
            listing = self._fetch_listing()
        except (httpx.HTTPError, ValueError, KeyError) as error:
            _logger.warning("OpenRouter model listing unreadable, effort not checked: %s", error)
            return None
        entry = next((entry for entry in listing if entry.get("id") == model), None)
        if entry is None:
            _logger.warning("Model %r absent from OpenRouter's listing, effort not checked", model)
            return None
        reasoning = entry.get("reasoning")
        if not isinstance(reasoning, dict):
            _logger.warning("OpenRouter lists no reasoning for %r, effort not checked", model)
            return None
        efforts: list[str] | None = cast(dict[str, Any], reasoning).get("supported_efforts")
        return None if efforts is None else tuple(efforts)

    def _fetch_listing(self) -> list[dict[str, Any]]:
        with httpx.Client(transport=self._transport, timeout=_TIMEOUT_SECONDS) as client:
            response = client.get(_MODELS_URL)
            response.raise_for_status()
            data: object = response.json()["data"]
        if not isinstance(data, list):
            raise ValueError(f"'data' is a {type(data).__name__}, not a list")
        entries = cast(list[object], data)
        return [cast(dict[str, Any], entry) for entry in entries if isinstance(entry, dict)]
