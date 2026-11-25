from __future__ import annotations

from typing import Any, cast

import httpx
import litellm
import pytest
from agents import RunConfig, Runner
from litellm.llms.vertex_ai.common_utils import VertexAIError
from openai import (
    APIConnectionError,
    APIError,
    APIStatusError,
    APITimeoutError,
    BadRequestError,
    InternalServerError,
    RateLimitError,
)

from strix.config import codex
from strix.core import execution
from strix.core.agents import AgentCoordinator


def _request() -> httpx.Request:
    return httpx.Request("POST", "https://api.openai.com/v1/responses")


def _midstream_api_error() -> APIError:
    return APIError("An error occurred while processing the request.", _request(), body=None)


def _status_error(status: int) -> APIStatusError:
    return APIStatusError(
        f"status {status}",
        response=httpx.Response(status_code=status, request=_request()),
        body=None,
    )


def _gateway_denied_error(reason: str) -> APIStatusError:
    """A model call the egress gateway denied, carrying its X-Recon-Egress reason
    the way policy_addon.py's _blocked_response sets it on the real HTTP reply."""
    return APIStatusError(
        f"recon egress gateway: api.example.test {reason}",
        response=httpx.Response(
            status_code=408, request=_request(), headers={"X-Recon-Egress": reason}
        ),
        body=None,
    )


def test_midstream_api_error_is_transient() -> None:
    assert execution._is_transient_model_error(_midstream_api_error()) is True


def test_network_errors_are_transient() -> None:
    assert execution._is_transient_model_error(APITimeoutError(_request())) is True
    assert execution._is_transient_model_error(APIConnectionError(request=_request())) is True


def test_server_errors_are_transient() -> None:
    assert (
        execution._is_transient_model_error(
            InternalServerError("boom", response=httpx.Response(500, request=_request()), body=None)
        )
        is True
    )
    for status in (502, 503, 504, 408):
        assert execution._is_transient_model_error(_status_error(status)) is True


def test_rate_limit_is_retried() -> None:
    rate_limited = RateLimitError(
        "slow down", response=httpx.Response(429, request=_request()), body=None
    )
    assert execution._is_transient_model_error(rate_limited) is True


def test_dns_and_connection_errors_are_transient() -> None:
    assert execution._is_transient_model_error(OSError("nodename nor servname provided")) is True
    assert execution._is_transient_model_error(ConnectionError("reset")) is True
    assert execution._is_transient_model_error(TimeoutError("timed out")) is True


def test_content_guardrail_is_not_retried() -> None:
    guardrail = APIError(
        "This content was flagged for possible cybersecurity risk",
        _request(),
        body=None,
    )
    assert codex.is_content_guardrail_error(guardrail) is True
    assert execution._is_transient_model_error(guardrail) is False


def test_client_errors_are_transient() -> None:
    bad_request = BadRequestError(
        "bad", response=httpx.Response(400, request=_request()), body=None
    )
    assert execution._is_transient_model_error(bad_request) is True
    for status in (401, 402, 403, 404):
        assert execution._is_transient_model_error(_status_error(status)) is False
    assert execution._is_transient_model_error(ValueError("nope")) is False


def test_gateway_elapsed_and_deadline_denials_are_not_transient() -> None:
    assert execution._is_transient_model_error(_gateway_denied_error("denied:elapsed")) is False
    assert execution._is_transient_model_error(_gateway_denied_error("denied:deadline")) is False


def test_plain_408_without_gateway_header_is_still_transient() -> None:
    # The gateway denial reason, not the bare 408 status, is what makes this
    # non-retryable - an ordinary provider timeout must keep retrying.
    assert execution._is_transient_model_error(_status_error(408)) is True


def test_other_gateway_denial_reasons_are_not_mistaken_for_elapsed_budget() -> None:
    assert execution._is_elapsed_budget_denial(_gateway_denied_error("denied:scope")) is False
    assert execution._is_elapsed_budget_denial(_gateway_denied_error("denied:rate_limit")) is False


def test_vertex_mapped_gateway_denial_is_not_transient() -> None:
    """Recon's deployed engine calls the model through vertex_ai/..., not the plain
    OpenAI SDK adapter the other tests here exercise. LiteLLM maps a Vertex HTTP error
    through its own VertexAIError -> exception_type() pipeline, which does not keep
    ``response``/``headers`` on the final litellm.Timeout it raises for a bare 408 -
    it reattaches the gateway's header as ``litellm_response_headers`` instead (the
    outer exception_type() handler's own recovery of whatever the original exception
    carried). Exercise that real mapping, not just an APIStatusError double, so a
    future LiteLLM upgrade that changes this is caught here."""

    def _map() -> None:
        original = VertexAIError(
            status_code=408,
            message="recon egress gateway: api.example.test denied:elapsed",
            headers=httpx.Headers({"X-Recon-Egress": "denied:elapsed"}),
        )
        raise litellm.utils.exception_type(
            model="gemini-2.5-pro", original_exception=original, custom_llm_provider="vertex_ai"
        )

    try:
        _map()
    except Exception as mapped:  # noqa: BLE001 - this is exactly what strix's retry loop catches
        assert type(mapped).__name__ == "Timeout"
        assert execution._is_elapsed_budget_denial(mapped) is True
        assert execution._is_transient_model_error(mapped) is False


class _FakeStream:
    def __init__(self, exc: BaseException | None = None) -> None:
        self._exc = exc
        self._events: list[Any] = []
        self.run_loop_exception: BaseException | None = None

    async def stream_events(self) -> Any:
        if self._exc is not None:
            raise self._exc
        for event in self._events:
            yield event


def _patch_fast_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(execution, "_TRANSIENT_MODEL_RETRY_BASE_DELAY_S", 0.0)
    monkeypatch.setattr(execution, "_TRANSIENT_MODEL_RETRY_MAX_DELAY_S", 0.0)


async def _run_once(
    monkeypatch: pytest.MonkeyPatch,
    streams: list[_FakeStream],
    session: Any = None,
) -> Any:
    _patch_fast_backoff(monkeypatch)
    calls = {"n": 0}

    def _fake_run_streamed(*_args: Any, **_kwargs: Any) -> _FakeStream:
        stream = streams[calls["n"]]
        calls["n"] += 1
        return stream

    monkeypatch.setattr(Runner, "run_streamed", _fake_run_streamed)

    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)

    result = await execution._run_cycle(
        object(),
        coordinator,
        "root",
        input_data="task",
        run_config=cast("RunConfig", object()),
        context={},
        max_turns=5,
        session=session,
        interactive=False,
        event_sink=None,
        hooks=None,
    )
    return result, calls["n"], coordinator


@pytest.mark.asyncio
async def test_run_cycle_retries_transient_midstream_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streams = [_FakeStream(exc=_midstream_api_error()), _FakeStream()]
    result, attempts, _coordinator = await _run_once(monkeypatch, streams)

    assert result is streams[1]
    assert attempts == 2


@pytest.mark.asyncio
async def test_run_cycle_gives_up_after_max_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streams = [
        _FakeStream(exc=_midstream_api_error())
        for _ in range(execution._MAX_TRANSIENT_MODEL_RETRIES + 1)
    ]
    with pytest.raises(APIError):
        await _run_once(monkeypatch, streams)


@pytest.mark.asyncio
async def test_run_cycle_does_not_retry_permanent_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streams = [_FakeStream(exc=ValueError("nope")), _FakeStream()]
    with pytest.raises(ValueError, match="nope"):
        await _run_once(monkeypatch, streams)


@pytest.mark.asyncio
async def test_run_cycle_does_not_retry_gateway_elapsed_denial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A second, clean stream is available; if the classifier still treated this
    # 408 as transient, _run_cycle would retry into it and return normally
    # instead of raising - exactly the wasted-retry bug this closes.
    streams = [_FakeStream(exc=_gateway_denied_error("denied:elapsed")), _FakeStream()]
    with pytest.raises(APIStatusError):
        await _run_once(monkeypatch, streams)


@pytest.mark.asyncio
async def test_run_cycle_tags_gateway_elapsed_denial_in_coordinator_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run_engine reads this tag off the coordinator's persisted agent errors
    (see recon_engine.activities._elapsed_budget_denial_reason) to tell a
    cut-short run from a clean one when the failing agent is a sub-agent, whose
    failure never raises anywhere this call's return value could carry it."""
    _patch_fast_backoff(monkeypatch)
    denial = _gateway_denied_error("denied:elapsed")
    stream = _FakeStream(exc=denial)
    monkeypatch.setattr(Runner, "run_streamed", lambda *_a, **_k: stream)

    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)

    with pytest.raises(APIStatusError):
        await execution._run_cycle(
            object(),
            coordinator,
            "root",
            input_data="task",
            run_config=cast("RunConfig", object()),
            context={},
            max_turns=5,
            session=None,
            interactive=False,
            event_sink=None,
            hooks=None,
        )

    assert coordinator.statuses["root"] == "failed"
    assert coordinator.errors["root"].startswith(execution.GATEWAY_ELAPSED_BUDGET_ERROR_PREFIX)


@pytest.mark.parametrize(
    ("status", "message", "expected"),
    [
        (
            404,
            "litellm.NotFoundError: NotFoundError: OpenrouterException - "
            '{"error":{"message":"No endpoints found that support image input","code":404,'
            '"metadata":{"failed_routing_step":"Filter by Image Support"}}}',
            True,
        ),
        (400, "Invalid content type. image_url is only supported by certain models.", True),
        (400, "my-model is not a multimodal model", True),
        (400, "This model doesn't support the image field for user messages.", True),
        (422, "messages[3]: unknown variant `image_url`, expected `text`", True),
        (400, "'Image URLs in user messages' functionality not supported.", True),
        (
            400,
            "OpenRouterException: Message: This model's maximum context length is 1048576 "
            "tokens, but the request requires 1073484 tokens (942412 input including "
            "image/vision expansion + 131072 for the completion). Reduce the input length "
            "or max_tokens.",
            False,
        ),
        (400, "At most 5 image(s) may be provided in one prompt.", False),
        (
            400,
            "Upstream error from Relace: Generation stopped with an incomplete tool call",
            False,
        ),
        (500, "No endpoints found that support image input", False),
    ],
)
def test_is_image_rejection(status: int, message: str, expected: bool) -> None:
    exc = APIStatusError(message, response=httpx.Response(status, request=_request()), body=None)
    assert execution._is_image_rejection(exc) is expected


async def _run_with_image_session(
    monkeypatch: pytest.MonkeyPatch, streams: list[_FakeStream]
) -> tuple[Any, int, int]:
    strips = {"n": 0}

    async def _fake_strip(_session: Any) -> bool:
        strips["n"] += 1
        return True

    async def _no_compact(*_args: Any, **_kwargs: Any) -> bool:
        return False

    monkeypatch.setattr(execution, "strip_all_images_from_session", _fake_strip)
    monkeypatch.setattr(execution, "_compact_session", _no_compact)
    result, attempts, _coordinator = await _run_once(monkeypatch, streams, session=object())
    return result, attempts, strips["n"]


@pytest.mark.asyncio
async def test_run_cycle_strips_images_on_image_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rejection = APIStatusError(
        "No endpoints found that support image input",
        response=httpx.Response(status_code=404, request=_request()),
        body=None,
    )
    streams = [_FakeStream(exc=rejection), _FakeStream()]
    result, attempts, strips = await _run_with_image_session(monkeypatch, streams)

    assert result is streams[1]
    assert attempts == 2
    assert strips == 1
