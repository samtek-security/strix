from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import patch

import litellm
import pytest
from agents.usage import Usage
from pydantic import ValidationError

from strix.config import loader
from strix.config.settings import LlmSettings
from strix.report.pricing import resolve_litellm_model
from strix.report.usage import LLMUsageLedger


if TYPE_CHECKING:
    from pathlib import Path


PRICE_ENV = (
    "STRIX_LLM_INPUT_COST_PER_MTOK",
    "STRIX_LLM_OUTPUT_COST_PER_MTOK",
    "STRIX_LLM_CACHED_INPUT_COST_PER_MTOK",
)


@pytest.fixture(autouse=True)
def _isolated_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for name in PRICE_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("STRIX_LLM", "gateway/unpriced-model")
    monkeypatch.setattr(loader, "_override", tmp_path / "missing.json")
    monkeypatch.setattr(loader, "_cached", None)


def _usage(input_tokens: int, output_tokens: int = 0, cached_tokens: int = 0) -> Usage:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = input_tokens
    usage.output_tokens = output_tokens
    usage.total_tokens = input_tokens + output_tokens
    usage.input_tokens_details.cached_tokens = cached_tokens
    return usage


def test_resolves_common_bare_model_names() -> None:
    resolve_litellm_model.cache_clear()
    assert resolve_litellm_model("deepseek-v4-flash") == "deepseek/deepseek-v4-flash"
    assert resolve_litellm_model("openai/deepseek-v4-flash") == "deepseek/deepseek-v4-flash"
    # Resellers list grok-4.5 under their own prefixes, so the resolver
    # prefers the first-party xai/ route whatever the resellers charge.
    assert resolve_litellm_model("grok-4.5") == "xai/grok-4.5"
    assert "xai/grok-4.5" in litellm.model_cost
    # A provider-qualified model remains deterministic.
    assert resolve_litellm_model("minimax/MiniMax-M3") == "minimax/MiniMax-M3"


def test_resolver_returns_none_for_unresolvable_model() -> None:
    resolve_litellm_model.cache_clear()
    assert resolve_litellm_model("provider/not-a-real-model") is None


def test_ledger_uses_estimate_when_routed_provider_reports_no_cost() -> None:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = 1000
    usage.output_tokens = 200
    usage.total_tokens = 1200
    ledger = LLMUsageLedger()

    with patch("litellm.completion_cost", return_value=0.42):
        ledger.record(agent_id="a", usage=usage, model="openai/deepseek-v4-flash")

    assert ledger.total_cost == 0.42


def test_ledger_prefers_observed_cost_over_estimate() -> None:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = 1000
    usage.output_tokens = 200
    usage.total_tokens = 1200
    ledger = LLMUsageLedger()

    with patch("litellm.completion_cost", return_value=0.42):
        ledger.record(agent_id="a", usage=usage, model="openai/deepseek-v4-flash")
    ledger.record_observed_cost(0.17)

    assert ledger.total_cost == 0.17


def test_unpriced_model_without_manual_rates_costs_zero() -> None:
    ledger = LLMUsageLedger()

    ledger.record(agent_id="a", usage=_usage(1000, 200), model="gateway/unpriced-model")

    assert ledger.total_cost == 0.0


def test_manual_rates_price_usage_and_override_observed_cost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_LLM_INPUT_COST_PER_MTOK", "2")
    monkeypatch.setenv("STRIX_LLM_OUTPUT_COST_PER_MTOK", "8")
    ledger = LLMUsageLedger()

    ledger.record(agent_id="a", usage=_usage(1000, 200), model="gateway/unpriced-model")
    ledger.record_observed_cost(0.17)

    assert ledger.total_cost == 0.0036
    assert ledger.to_record()["agents"][0]["cost"] == 0.0036


def test_manual_rates_from_config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "env": {
                    "STRIX_LLM_INPUT_COST_PER_MTOK": "2",
                    "STRIX_LLM_OUTPUT_COST_PER_MTOK": "8",
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(loader, "_override", path)
    ledger = LLMUsageLedger()

    ledger.record(agent_id="a", usage=_usage(1000, 200), model="gateway/unpriced-model")

    assert ledger.total_cost == 0.0036


def test_manual_rates_only_price_the_configured_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM_INPUT_COST_PER_MTOK", "2")
    monkeypatch.setenv("STRIX_LLM_OUTPUT_COST_PER_MTOK", "8")
    ledger = LLMUsageLedger()

    ledger.record(agent_id="a", usage=_usage(1000, 200), model="gateway/unpriced-model")
    with patch("litellm.completion_cost", return_value=0.42):
        ledger.record(agent_id="dedupe", usage=_usage(500, 50), model="deepseek/deepseek-v4-flash")
    record = ledger.to_record()

    assert ledger.total_cost == 0.4236
    assert {agent["agent_id"]: agent["cost"] for agent in record["agents"]} == {
        "a": 0.0036,
        "dedupe": 0.42,
    }


def test_cached_tokens_fall_back_to_input_rate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM_INPUT_COST_PER_MTOK", "5")
    monkeypatch.setenv("STRIX_LLM_OUTPUT_COST_PER_MTOK", "7")
    ledger = LLMUsageLedger()

    ledger.record(
        agent_id="a", usage=_usage(10, 1, cached_tokens=2), model="gateway/unpriced-model"
    )

    assert ledger.total_cost == 0.000057


def test_hydrated_usage_uses_configured_rates_not_persisted_cost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_LLM_INPUT_COST_PER_MTOK", "2")
    monkeypatch.setenv("STRIX_LLM_OUTPUT_COST_PER_MTOK", "8")
    original = LLMUsageLedger()
    original.record(agent_id="a", usage=_usage(1000, 200), model="gateway/unpriced-model")
    persisted = original.to_record()
    persisted["cost"] = 42.0
    persisted["agents"][0]["cost"] = 42.0
    hydrated = LLMUsageLedger()

    hydrated.hydrate(persisted)

    assert hydrated.total_cost == 0.0036


@pytest.mark.parametrize("value", ["invalid", "-1", "nan", "inf"])
def test_invalid_manual_rate_is_rejected(value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM_INPUT_COST_PER_MTOK", value)
    with pytest.raises(ValidationError):
        LlmSettings()


def test_zero_cost_overrides_manual_rates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM_INPUT_COST_PER_MTOK", "10")
    ledger = LLMUsageLedger()
    ledger.zero_cost = True

    ledger.record(agent_id="a", usage=_usage(1000), model="gateway/unpriced-model")

    assert ledger.total_cost == 0.0


def test_hydrated_estimate_continues_accumulating_new_estimates() -> None:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = 1000
    usage.output_tokens = 200
    usage.total_tokens = 1200
    ledger = LLMUsageLedger()
    ledger.hydrate({"cost": 0.42})

    with patch("litellm.completion_cost", return_value=0.17):
        ledger.record(agent_id="a", usage=usage, model="openai/deepseek-v4-flash")

    assert ledger.total_cost == 0.59


def test_zero_cost_disables_both_observed_and_estimated_costs() -> None:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = 1000
    usage.output_tokens = 200
    usage.total_tokens = 1200
    ledger = LLMUsageLedger()
    ledger.zero_cost = True

    with patch("litellm.completion_cost", return_value=0.42) as estimate:
        ledger.record(agent_id="a", usage=usage, model="deepseek-v4-flash")
        ledger.record_observed_cost(1.0)

    estimate.assert_not_called()
    assert ledger.total_cost == 0.0


def test_resolver_uses_provider_when_bare_entry_has_one() -> None:
    original = litellm.model_cost
    litellm.model_cost = {
        "example": {
            "litellm_provider": "example-provider",
            "input_cost_per_token": 1.0,
            "output_cost_per_token": 2.0,
        }
    }
    try:
        resolve_litellm_model.cache_clear()
        assert resolve_litellm_model("example") == "example-provider/example"
    finally:
        litellm.model_cost = original
        resolve_litellm_model.cache_clear()


def test_resolver_does_not_guess_between_differently_priced_providers() -> None:
    original = litellm.model_cost
    litellm.model_cost = {
        "provider-a/example": {
            "input_cost_per_token": 1.0,
            "output_cost_per_token": 2.0,
        },
        "provider-b/example": {
            "input_cost_per_token": 3.0,
            "output_cost_per_token": 4.0,
        },
    }
    try:
        resolve_litellm_model.cache_clear()
        assert resolve_litellm_model("example") is None
    finally:
        litellm.model_cost = original
        resolve_litellm_model.cache_clear()


def _with_cost_map(cost_map: dict[str, dict[str, float]]) -> None:
    litellm.model_cost = cost_map
    resolve_litellm_model.cache_clear()


def test_resolver_prefers_first_party_route_when_resellers_disagree() -> None:
    original = litellm.model_cost
    # Shape of the remote cost map: one model, several resellers, three prices.
    _with_cost_map(
        {
            "xai/grok-4.5": {"input_cost_per_token": 2e-6, "output_cost_per_token": 6e-6},
            "perplexity/xai/grok-4.5": {
                "input_cost_per_token": 3e-6,
                "output_cost_per_token": 9e-6,
            },
            "openrouter/x-ai/grok-4.5": {
                "input_cost_per_token": 2.5e-6,
                "output_cost_per_token": 7e-6,
            },
        }
    )
    try:
        assert resolve_litellm_model("grok-4.5") == "xai/grok-4.5"
        assert resolve_litellm_model("openai/grok-4.5") == "xai/grok-4.5"
    finally:
        litellm.model_cost = original
        resolve_litellm_model.cache_clear()


def test_first_party_rule_applies_to_other_publishers() -> None:
    original = litellm.model_cost
    _with_cost_map(
        {
            "openrouter/deepseek/deepseek-x": {
                "input_cost_per_token": 2.0,
                "output_cost_per_token": 3.0,
            },
            "deepseek/deepseek-x": {"input_cost_per_token": 1.0, "output_cost_per_token": 2.0},
            "bedrock/claude-y": {"input_cost_per_token": 5.0, "output_cost_per_token": 6.0},
            "anthropic/claude-y": {"input_cost_per_token": 4.0, "output_cost_per_token": 5.0},
        }
    )
    try:
        assert resolve_litellm_model("deepseek-x") == "deepseek/deepseek-x"
        assert resolve_litellm_model("claude-y") == "anthropic/claude-y"
    finally:
        litellm.model_cost = original
        resolve_litellm_model.cache_clear()


def test_resolver_returns_none_when_no_first_party_route_exists() -> None:
    original = litellm.model_cost
    _with_cost_map(
        {
            "perplexity/xai/grok-9": {"input_cost_per_token": 3.0, "output_cost_per_token": 9.0},
            "openrouter/x-ai/grok-9": {"input_cost_per_token": 2.0, "output_cost_per_token": 7.0},
        }
    )
    try:
        assert resolve_litellm_model("grok-9") is None
    finally:
        litellm.model_cost = original
        resolve_litellm_model.cache_clear()


def test_first_party_rule_does_not_override_an_explicit_route() -> None:
    original = litellm.model_cost
    _with_cost_map(
        {
            "zai/glm-5": {"input_cost_per_token": 1.0, "output_cost_per_token": 2.0},
            "gateway-a/glm-5": {"input_cost_per_token": 3.0, "output_cost_per_token": 4.0},
        }
    )
    try:
        assert resolve_litellm_model("gateway-b/glm-5") is None
        assert resolve_litellm_model("glm-5") == "zai/glm-5"
    finally:
        litellm.model_cost = original
        resolve_litellm_model.cache_clear()
