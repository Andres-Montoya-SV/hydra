"""Shared low-level LLM client primitives (docs/HYPOTHESIS_ENGINE_DESIGN.md
Part B.1): the generic "call a structured-output API, map every SDK
exception to one clear message" plumbing that used to be duplicated
between `core/reportability/client.py` and `core/reportability/openai_client.py`.
Both are now thin, task-specific wrappers over this module; the new
hypothesis engine (`core/hypotheses/provider.py`) builds on it the same
way.

Re-verified against the real installed SDKs before this module was
written (2026-09), not assumed unchanged since the reportability agent
was built: `anthropic==1.5.0`'s `messages.parse`/`messages.count_tokens`
still accept `output_format`, and `openai==3.13.0`'s `responses.parse`
still accepts `text_format`/`input`/`instructions` — confirmed via
`inspect.signature` against the actual installed packages, matching the
exact versions pinned in `requirements-optional.txt`.

Neither `anthropic` nor `openai` is imported here — both stay fully
optional dependencies. Every function below takes an already-constructed
client and, where exception introspection needs it, the already
lazy-imported SDK module, as plain arguments — the lazy import with its
own "please install this" error message stays in each package's own
thin wrapper, since that instruction is genuinely per-package (different
install commands would apply if a caller depended on a different optional
extra).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from pydantic import BaseModel

# One non-streaming request per call (matches every existing reportability
# call site) — batch sizes are capped low by each caller's own settings so
# output stays well under streaming-timeout territory even without it.
DEFAULT_MAX_TOKENS = 16000

_T = TypeVar("_T", bound="BaseModel")

# Published per-million-input-token pricing, current as of this writing —
# a point-in-time snapshot for a pre-spend cost ESTIMATE, not fetched
# live. Confirm current pricing before trusting this for a large batch.
# Anthropic prices verified at platform.claude.com/docs/en/about-claude/
# pricing; OpenAI prices verified at platform.openai.com/docs/guides/models
# (Terra, Luna only — Astra/Sol pricing was not verified and is
# deliberately left out rather than guessed; see the "no published price
# on file" fallback in `cost_line` below). Moved here verbatim from
# `core/reportability/cli.py` (design Part B.1) so both
# assess-reportability and suggest-hypotheses cite the same numbers from
# one place — two independently-drifting pricing tables would be a real
# maintenance hazard the first time a model's price changes.
INPUT_PRICE_PER_MTOK: dict[str, float] = {
    "claude-fable-5-1": 10.00,
    "claude-mythos-5-1": 10.00,
    "claude-fable-5": 10.00,
    "claude-opus-5": 5.00,
    "claude-opus-4-8": 5.00,
    "claude-opus-4-7": 5.00,
    "claude-opus-4-6": 5.00,
    "claude-sonnet-5": 2.00,
    "claude-sonnet-4-6": 3.00,
    "claude-haiku-4-5": 1.00,
    "claude-haiku-4-5-20251001": 1.00,
    "gpt-5.6-terra": 2.00,
    "gpt-5.6-luna": 0.20,
}


def estimated_cost_usd(model: str, tokens: int) -> float | None:
    """The raw dollar figure `cost_line` formats for display — factored
    out so callers that need the number itself (not a human-readable
    string), such as the paid API's monthly LLM-spend ceiling
    enforcement (docs/PAID_API_DESIGN.md Part B, Round 3), don't
    duplicate this pricing lookup. Returns `None` when there's no
    published price on file for `model`, same "don't guess" fallback
    `cost_line` already uses."""
    price_per_mtok = INPUT_PRICE_PER_MTOK.get(model)
    if price_per_mtok is None:
        return None
    return tokens / 1_000_000 * price_per_mtok


def cost_line(provider_name: str, model: str, tokens: int, *, approximate: bool) -> str:
    """Human-readable pre-spend cost estimate for one call — used by both
    `assess-reportability` and `suggest-hypotheses`'s cost-estimate step
    (design Part D)."""
    label = "~" if approximate else ""
    cost = estimated_cost_usd(model, tokens)
    if cost is None:
        return (
            f"{label}{tokens:,} tokens for {provider_name}/{model}. No published price is on "
            f"file for this model — check the provider's current pricing page."
        )
    return f"{label}{tokens:,} tokens for {provider_name}/{model} (~${cost:.4f})"


def describe_anthropic_exception(anthropic_module, exc: Exception) -> str:  # type: ignore[no-untyped-def]
    """Most-specific-first classification of an Anthropic SDK exception
    into a clear, actionable message — never a bare re-raise of the SDK's
    own message alone."""
    if isinstance(exc, anthropic_module.AuthenticationError):
        return "ANTHROPIC_API_KEY was rejected by the API — check the key is valid and active."
    if isinstance(exc, anthropic_module.PermissionDeniedError):
        return "The API key lacks permission for this request."
    if isinstance(exc, anthropic_module.NotFoundError):
        return "The requested model was not found — check ANTHROPIC_MODEL."
    if isinstance(exc, anthropic_module.RateLimitError):
        return "Rate limited by the Anthropic API — wait and retry."
    if isinstance(exc, anthropic_module.APIStatusError):
        if exc.status_code >= 500:
            return f"Anthropic API server error ({exc.status_code}) — retry later."
        return f"Anthropic API rejected the request: {exc.message}"
    if isinstance(exc, anthropic_module.APIConnectionError):
        return "Could not reach the Anthropic API — check network connectivity."
    return f"Unexpected error calling the Anthropic API: {exc}"


def describe_openai_exception(openai_module, exc: Exception) -> str:  # type: ignore[no-untyped-def]
    """Most-specific-first classification of an OpenAI SDK exception into a
    clear, actionable message — never a bare re-raise of the SDK's own
    message alone."""
    if isinstance(exc, openai_module.AuthenticationError):
        return "OPENAI_API_KEY was rejected by the API — check the key is valid and active."
    if isinstance(exc, openai_module.PermissionDeniedError):
        return "The API key lacks permission for this request."
    if isinstance(exc, openai_module.NotFoundError):
        return "The requested model was not found — check OPENAI_MODEL."
    if isinstance(exc, openai_module.RateLimitError):
        return "Rate limited by the OpenAI API — wait and retry."
    if isinstance(exc, openai_module.InternalServerError):
        return f"OpenAI API server error — retry later ({exc})."
    if isinstance(exc, openai_module.APIStatusError):
        return f"OpenAI API rejected the request: {exc}"
    if isinstance(exc, openai_module.APIConnectionError):
        return "Could not reach the OpenAI API — check network connectivity."
    return f"Unexpected error calling the OpenAI API: {exc}"


def anthropic_structured_call(
    anthropic_module,  # type: ignore[no-untyped-def]
    client,
    *,
    model: str,
    system: str,
    user_message: str,
    output_format: type[_T],
    error_cls: type[Exception],
    empty_output_message: str,
    max_tokens: int = DEFAULT_MAX_TOKENS,
) -> _T:
    """One non-streaming structured-output call via
    `anthropic.Anthropic().messages.parse()` — adaptive thinking at medium
    effort, matching every existing reportability call. Raises
    `error_cls` (the caller's own domain exception type) on any SDK error
    or an empty structured output, never a bare re-raise of the SDK's own
    exception.
    """
    try:
        response = client.messages.parse(
            model=model,
            max_tokens=max_tokens,
            thinking={"type": "adaptive"},
            output_config={"effort": "medium"},
            system=system,
            messages=[{"role": "user", "content": user_message}],
            output_format=output_format,
        )
    except Exception as exc:
        raise error_cls(describe_anthropic_exception(anthropic_module, exc)) from exc
    if response.parsed_output is None:
        raise error_cls(empty_output_message)
    return response.parsed_output


def anthropic_count_tokens(
    anthropic_module,  # type: ignore[no-untyped-def]
    client,
    *,
    model: str,
    system: str,
    user_message: str,
    output_format: type[BaseModel],
    error_cls: type[Exception],
) -> int:
    """Real input-token count for a prospective call, via the free,
    no-beta-header `count_tokens` endpoint — not a local estimate, the
    real count the Messages API would see, schema overhead included."""
    try:
        response = client.messages.count_tokens(
            model=model,
            system=system,
            messages=[{"role": "user", "content": user_message}],
            output_format=output_format,
        )
    except Exception as exc:
        raise error_cls(describe_anthropic_exception(anthropic_module, exc)) from exc
    return response.input_tokens


def openai_structured_call(
    openai_module,  # type: ignore[no-untyped-def]
    client,
    *,
    model: str,
    instructions: str,
    input_text: str,
    text_format: type[_T],
    error_cls: type[Exception],
    empty_output_message: str,
) -> _T:
    """One structured-output call via `openai.OpenAI().responses.parse()`.
    Raises `error_cls` (the caller's own domain exception type) on any SDK
    error or an empty structured output, never a bare re-raise of the
    SDK's own exception.
    """
    try:
        response = client.responses.parse(
            model=model,
            instructions=instructions,
            input=input_text,
            text_format=text_format,
        )
    except Exception as exc:
        raise error_cls(describe_openai_exception(openai_module, exc)) from exc
    parsed = response.output_parsed
    if parsed is None:
        raise error_cls(empty_output_message)
    return parsed


# Rough characters-per-token ratio for English prose — the same
# approximation OpenAI's own cookbook uses as a quick estimate before
# reaching for tiktoken. Good enough for a pre-spend cost ESTIMATE, not
# used for anything that requires an exact count. OpenAI has no free,
# no-spend token-count endpoint the way Anthropic's count_tokens is.
APPROX_CHARS_PER_TOKEN = 4


def openai_approximate_token_count(text: str) -> int:
    return max(1, len(text) // APPROX_CHARS_PER_TOKEN)
