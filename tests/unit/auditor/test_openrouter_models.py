import logging

import httpx
import pytest

from mcp_auditor.adapters.openrouter_models import OpenRouterEffortCatalog

_GLM = "z-ai/glm-5.3"


class _Listing:
    def __init__(self, response: httpx.Response | Exception):
        self.response = response
        self.requests = 0

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _listing(*models: dict[str, object]) -> _Listing:
    return _Listing(httpx.Response(200, json={"data": list(models)}))


def _catalog(listing: _Listing) -> OpenRouterEffortCatalog:
    return OpenRouterEffortCatalog(httpx.MockTransport(listing.handle))


def _model(model_id: str, efforts: list[str] | None) -> dict[str, object]:
    return {"id": model_id, "reasoning": {"supported_efforts": efforts}}


def _warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [record for record in caplog.records if record.levelno == logging.WARNING]


class TestOpenRouterEffortCatalog:
    def test_an_effort_the_model_does_not_publish_raises_with_the_supported_ones(self):
        catalog = _catalog(_listing(_model(_GLM, ["max", "high", "low"])))

        with pytest.raises(ValueError) as raised:
            catalog.check(_GLM, "medium")

        assert str(raised.value) == (
            "Model 'z-ai/glm-5.3' on OpenRouter supports reasoning efforts max, high, low, "
            "got 'medium'."
        )

    def test_none_on_a_model_that_always_reasons_raises(self):
        catalog = _catalog(_listing(_model(_GLM, ["max", "high", "low"])))

        with pytest.raises(ValueError, match="got 'none'"):
            catalog.check(_GLM, "none")

    def test_a_published_effort_passes_without_a_warning(self, caplog: pytest.LogCaptureFixture):
        catalog = _catalog(_listing(_model("other/model", ["low"]), _model(_GLM, ["high", "low"])))

        catalog.check(_GLM, "low")

        assert _warnings(caplog) == []

    def test_a_model_that_publishes_no_effort_list_passes_without_a_warning(
        self, caplog: pytest.LogCaptureFixture
    ):
        catalog = _catalog(_listing(_model(_GLM, None)))

        catalog.check(_GLM, "medium")

        assert _warnings(caplog) == []

    @pytest.mark.parametrize(
        "listing",
        [
            pytest.param(_listing(_model("other/model", ["low"])), id="model absent"),
            pytest.param(_listing({"id": _GLM}), id="reasoning omitted"),
            pytest.param(
                _listing({"id": _GLM, "reasoning": {"supported_efforts": "high"}}),
                id="efforts not a list",
            ),
            pytest.param(
                _listing({"id": _GLM, "reasoning": {"supported_efforts": ["high", 3]}}),
                id="efforts not all strings",
            ),
            pytest.param(_Listing(httpx.Response(503)), id="http error"),
            pytest.param(_Listing(httpx.Response(200, text="<html>")), id="body not json"),
            pytest.param(_Listing(httpx.Response(200, json={})), id="body without data"),
            pytest.param(
                _Listing(httpx.Response(200, json={"data": "models"})), id="data not a list"
            ),
            pytest.param(_Listing(httpx.ConnectError("refused")), id="transport error"),
            pytest.param(_Listing(httpx.ReadTimeout("slow")), id="timeout"),
        ],
    )
    def test_an_unreadable_listing_passes_with_one_warning(
        self, caplog: pytest.LogCaptureFixture, listing: _Listing
    ):
        catalog = _catalog(listing)

        catalog.check(_GLM, "medium")

        assert len(_warnings(caplog)) == 1

    def test_an_entry_that_is_not_a_model_is_skipped(self):
        catalog = _catalog(_listing("garbage", _model(_GLM, ["high", "low"])))  # type: ignore[arg-type]

        with pytest.raises(ValueError, match="got 'medium'"):
            catalog.check(_GLM, "medium")

    def test_two_checks_of_one_model_fetch_the_listing_once(self):
        listing = _listing(_model(_GLM, ["high", "low"]))
        catalog = _catalog(listing)

        catalog.check(_GLM, "low")
        catalog.check(_GLM, "high")

        assert listing.requests == 1
