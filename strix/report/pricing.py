# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""LiteLLM model-name resolution for local cost estimates."""

from __future__ import annotations

from functools import lru_cache
from typing import Any, cast


# Model-name prefix -> LiteLLM providers that sell the model first-party.
# Resellers (openrouter, perplexity, bedrock and similar) list the same models
# under their own prefix, often at different prices.
_FIRST_PARTY_PROVIDERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("grok", ("xai",)),
    ("claude", ("anthropic",)),
    ("gpt-", ("openai",)),
    ("chatgpt-", ("openai",)),
    ("o1", ("openai",)),
    ("o3", ("openai",)),
    ("o4", ("openai",)),
    ("gemini", ("gemini", "vertex_ai")),
    ("deepseek", ("deepseek",)),
    ("mistral", ("mistral",)),
    ("codestral", ("mistral", "codestral")),
    ("command", ("cohere", "cohere_chat")),
    ("minimax", ("minimax",)),
    ("kimi", ("moonshot",)),
    ("moonshot", ("moonshot",)),
    ("glm", ("zai",)),
    ("qwen", ("dashscope",)),
)


def _first_party_match(name: str, matches: list[str]) -> str | None:
    lowered = name.lower()
    for model_prefix, providers in _FIRST_PARTY_PROVIDERS:
        if not lowered.startswith(model_prefix):
            continue
        for provider in providers:
            candidate = f"{provider}/{name}"
            if candidate in matches:
                return candidate
    return None


def _pick_match(
    name: str,
    matches: list[str],
    model_cost: dict[str, dict[str, Any]],
    *,
    bare: bool,
) -> str | None:
    # A provider-qualified request named its route, so only a bare name is
    # steered to the first-party one.
    first_party = _first_party_match(name, matches) if bare else None
    if first_party is not None:
        return first_party
    prices = {
        (
            model_cost[key].get("input_cost_per_token"),
            model_cost[key].get("output_cost_per_token"),
        )
        for key in matches
        if isinstance(model_cost.get(key), dict)
    }
    if len(matches) == 1 or len(prices) == 1:
        return matches[0]
    return None


@lru_cache(maxsize=512)
def resolve_litellm_model(model: str, *, first_party: bool = True) -> str | None:
    """Return a provider-qualified model name that LiteLLM can price.

    ``first_party=False`` turns off the first-party tie-break. Callers pass it
    when they retry the bare name of a route the user qualified, so that route
    is never priced at another provider's rate.
    """
    try:
        import litellm

        normalized = model.strip()
        for prefix in ("litellm/", "any-llm/", "openai/"):
            if normalized.startswith(prefix):
                normalized = normalized.removeprefix(prefix)
                # A wrapper prefix can front a custom endpoint, so the name
                # does not identify a first-party route.
                first_party = False
                break
        if not normalized:
            return None

        model_cost = cast(
            "dict[str, dict[str, Any]]",
            getattr(litellm, "model_cost"),  # noqa: B009
        )
        bare_entry = model_cost.get(normalized)
        if "/" not in normalized and isinstance(bare_entry, dict):
            provider = bare_entry.get("litellm_provider")
            if isinstance(provider, str) and provider:
                return f"{provider}/{normalized}"
        if "/" in normalized and isinstance(bare_entry, dict):
            return normalized

        names = [normalized]
        if "/" in normalized:
            names.append(normalized.rsplit("/", 1)[-1])
        for name in names:
            matches = sorted(key for key in model_cost if key.endswith(f"/{name}"))
            if not matches:
                continue
            picked = _pick_match(
                name, matches, model_cost, bare=first_party and "/" not in normalized
            )
            if picked is not None:
                return picked
        return None  # noqa: TRY300
    except Exception:  # noqa: BLE001
        return None
