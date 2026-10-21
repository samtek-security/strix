"""The engine scrubs a fatal exception before it crosses to the control plane."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from openai import APIStatusError

from strix.core import runner
from strix.llm import redaction


def test_sanitized_failure_redacts_message_and_preserves_type() -> None:
    exc = RuntimeError("provider rejected key sk-ant-api03-LEAK0123456789abcdef")
    out = runner._sanitized_failure(exc)
    assert isinstance(out, RuntimeError)
    assert "sk-ant-api03-LEAK0123456789abcdef" not in str(out)
    assert redaction.REDACTED in str(out)


def test_sanitized_failure_redacts_registered_literal() -> None:
    secret = "opaque-provider-literal-9f8e7d6c5b4a"  # noqa: S105 - fixture token
    redaction.register_secret(secret)
    try:
        out = runner._sanitized_failure(RuntimeError(f"auth failed for {secret}"))
        assert secret not in str(out)
    finally:
        redaction._literal_secrets.discard(secret)


def test_sanitized_failure_falls_back_for_uninstantiable_types() -> None:
    # APIStatusError cannot be rebuilt from a bare message; fall back to a
    # RuntimeError that still names the original type, with the secret gone.
    request = httpx.Request("POST", "https://api.openai.com/v1/responses")
    response = httpx.Response(401, request=request, text="bad key sk-proj-LEAK0123456789abcdef")
    exc: Any = APIStatusError("bad key sk-proj-LEAK0123456789abcdef", response=response, body=None)
    out = runner._sanitized_failure(exc)
    assert isinstance(out, RuntimeError)
    assert "sk-proj-LEAK0123456789abcdef" not in str(out)
    assert "APIStatusError" in str(out)


def test_sanitized_failure_from_none_drops_the_cause_chain() -> None:
    # The call site raises `... from None`; the stand-in itself carries no cause.
    out = runner._sanitized_failure(RuntimeError("boom"))
    assert out.__cause__ is None

    def _raise() -> None:
        raise out from None

    with pytest.raises(RuntimeError) as caught:
        _raise()
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True
