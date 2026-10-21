# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Enclave redaction for engine telemetry.

Recon runs each engagement inside a FedRAMP-High boundary where a provider
secret must not reach disk. A secret can escape three ways, and this module
closes all three:

* **The log file / stderr.** Anything written to ``reconcore.log`` -
  ``_log_line_sink``, a provider failure logged with ``logger.exception`` in
  the agent run loop, a sink that raised - can carry an exception message or a
  full traceback that echoes a key. :class:`RedactingFilter`, attached to every
  scan/console handler, scrubs the final formatted record (merged args and
  folded traceback) whatever logger produced it.
* **The structured request-log event.** The run.json timing sink and any
  deployment sink receive an :class:`~strix.llm.request_log.LlmRequestEvent`.
  :func:`enclave_safe`, applied once at :func:`strix.llm.request_log.emit`,
  scrubs its free-form fields (message, headers, details, ids) on the delivered
  copy. Event construction stays faithful so the capture layer is still
  testable as written.
* **The agent's failure reason.** ``failure_text`` feeds ``set_status`` and is
  snapshotted to disk and surfaced to the control plane; it is scrubbed at the
  source with :func:`redact_text`.

Scrubbing keeps the operator's triage handles (error type, status code,
provider request id) and follows the "class names only" rule the rest of Recon
telemetry already keeps. A registered literal (the configured api_key, the
subscription-backend access token) is redacted even when it matches no shape.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import TYPE_CHECKING, Any, cast


if TYPE_CHECKING:
    from strix.llm.request_log import LlmRequestEvent


REDACTED = "[redacted]"

_LITELLM_HEADER_PREFIX = "llm_provider-"

# Field and header names whose value is a credential or session token. Checked
# after normalizing: lowercase, strip a ``llm_provider-`` prefix, ``_`` -> ``-``.
_SENSITIVE_NAMES: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "www-authenticate",
        "cookie",
        "set-cookie",
        "api-key",
        "apikey",
        "x-api-key",
        "x-goog-api-key",
        "x-goog-iam-authorization-token",
        "openai-api-key",
        "anthropic-api-key",
        "x-amz-security-token",
        "x-amzn-authorization",
        "access-token",
        "refresh-token",
        "id-token",
        "client-secret",
        "secret-key",
        "password",
        "passwd",
        "secret",
        "token",
    }
)

# A credential-bearing header in free text owns the rest of its line: a Cookie
# or Authorization value can hold several ``;``-separated secrets, so redact
# through end of line rather than stop at the first delimiter.
_CRED_HEADER_LINE_RE = re.compile(
    r"(?i)(?P<k>\b(?:set-cookie|cookie|authorization|proxy-authorization)\b)"
    # Spaces/tabs only, so the separator never jumps to the next log line.
    r"(?P<sep>['\"]?[ \t]*[:=][ \t]*)"
    r"(?P<v>[^\r\n]+)"
)

# Other credential assignments inside free text: ``name: value`` / ``name=value``.
# The ``Bearer``/``Basic`` schemes are swallowed so the token after them is
# consumed, not stranded. A single or double quote may wrap the key or value
# (JSON and Python-dict reprs).
_ASSIGNMENT_RE = re.compile(
    r"(?i)(?P<k>\b(?:x-api-key|x-goog-api-key|x-amz-security-token|api[-_]?key|"
    r"access[-_]?token|refresh[-_]?token|id[-_]?token|client[-_]?secret|"
    r"secret[-_]?key|password|passwd|secret|token)\b)"
    r"(?P<sep>['\"]?[ \t]*[:=][ \t]*['\"]?)"
    r"(?P<v>(?:bearer[ \t]+|basic[ \t]+)?[^\s,;\"']+)"
)

# Provider secret shapes. A left boundary keeps ``sk-`` out of ordinary words
# (``task-scheduling``, ``risk-level`` - the ``sk`` there follows a letter) while
# still catching an embedded key (``resp-sk-...``). The ``Bearer``/``Basic``
# lookaheads require a digit or punctuation so ``Bearer authentication required``
# survives.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?<![A-Za-z0-9/_])sk-(?:ant-|proj-)?[A-Za-z0-9_-]{8,}"),  # OpenAI/Anthropic
    re.compile(r"(?<![A-Za-z0-9/_])AIza[A-Za-z0-9_-]{10,}"),  # Google API key
    re.compile(r"(?<![A-Za-z0-9/_])ya29\.[A-Za-z0-9_-]{10,}"),  # Google OAuth token
    re.compile(r"(?<![A-Za-z0-9/_])A(?:KIA|SIA)[A-Z0-9]{12,}"),  # AWS access key id
    re.compile(r"(?<![A-Za-z0-9/_])gh[pousr]_[A-Za-z0-9]{20,}"),  # GitHub token
    re.compile(r"(?<![A-Za-z0-9/_])xox[baprs]-[A-Za-z0-9-]{10,}"),  # Slack token
    re.compile(r"(?i)\bbearer\s+(?=[A-Za-z0-9._~+/=-]*[0-9._/=+])[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\bbasic\s+(?=[A-Za-z0-9+/]*[0-9+/=])[A-Za-z0-9+/]{8,}={0,2}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}"),  # JWT
)

# Exact literal secrets registered at config time (the configured api_key, the
# subscription-backend access token), redacted even when they match no shape.
_literal_secrets: set[str] = set()


def register_secret(value: object) -> None:
    """Register an exact secret for redaction.

    Short values are ignored: a one- or two-character "key" would redact
    ordinary text wholesale and leak nothing worth hiding.
    """
    if isinstance(value, str) and len(value.strip()) >= 8:
        _literal_secrets.add(value.strip())


def _normalize_name(key: object) -> str:
    return str(key).lower().removeprefix(_LITELLM_HEADER_PREFIX).replace("_", "-").strip()


def is_sensitive_name(name: object) -> bool:
    """True when a header/field named ``name`` carries a credential or token."""
    return _normalize_name(name) in _SENSITIVE_NAMES


def redact_text(text: str) -> str:
    """Replace every registered literal, credential assignment, and secret shape."""
    if not text:
        return text
    for secret in _literal_secrets:
        if secret in text:
            text = text.replace(secret, REDACTED)
    text = _CRED_HEADER_LINE_RE.sub(lambda m: f"{m.group('k')}{m.group('sep')}{REDACTED}", text)
    text = _ASSIGNMENT_RE.sub(lambda m: f"{m.group('k')}{m.group('sep')}{REDACTED}", text)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


def _redact_value(value: Any, depth: int) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if value is None or isinstance(value, bool | int | float) or depth >= 8:
        return value
    if isinstance(value, Mapping):
        out: dict[Any, Any] = {}
        for key, item in cast("Mapping[Any, Any]", value).items():
            safe_key = redact_text(key) if isinstance(key, str) else key
            if _normalize_name(key) in _SENSITIVE_NAMES:
                out[safe_key] = REDACTED
            else:
                out[safe_key] = _redact_value(item, depth + 1)
        return out
    if isinstance(value, Sequence | set | frozenset):
        return [_redact_value(item, depth + 1) for item in cast("Sequence[Any]", value)]
    return value


def _redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in headers.items():
        safe_key = redact_text(key) if isinstance(key, str) else key
        if _normalize_name(key) in _SENSITIVE_NAMES:
            out[safe_key] = REDACTED
        elif isinstance(value, str):
            out[safe_key] = redact_text(value)
        else:
            out[safe_key] = value
    return out


def enclave_safe(event: LlmRequestEvent) -> LlmRequestEvent:
    """Return a copy of ``event`` with every free-form field scrubbed of secrets.

    Fails closed: if scrubbing raises, the free-form fields are dropped rather
    than delivered raw. Scalar telemetry (status, timing, sizes, tokens, cost)
    and the error type (a class name) are never touched.
    """
    try:
        changed: dict[str, Any] = {}
        if event.error_message is not None:
            changed["error_message"] = redact_text(event.error_message)
        if event.response_headers:
            changed["response_headers"] = _redact_headers(event.response_headers)
        if event.details:
            changed["details"] = _redact_value(event.details, 0)
        if event.provider_request_id:
            changed["provider_request_id"] = redact_text(event.provider_request_id)
        if event.response_id:
            changed["response_id"] = redact_text(event.response_id)
        if event.finish_reason:
            changed["finish_reason"] = redact_text(event.finish_reason)
        if not changed:
            return event
        return replace(event, **changed)
    except Exception:  # noqa: BLE001 - fail closed: never deliver an unredacted event
        return replace(
            event,
            error_message=REDACTED,
            response_headers=None,
            details=None,
            provider_request_id=None,
            response_id=None,
            finish_reason=None,
        )


class RedactingFilter(logging.Filter):
    """Scrub secrets from every record a handler writes, whatever its source.

    Merges args into the message, folds any traceback/stack into it, scrubs the
    result, and clears ``exc_info`` so the handler cannot re-append the raw
    traceback. Fails closed: a redaction error drops the record's text rather
    than writing it raw.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
            if record.exc_info:
                message = f"{message}\n{logging.Formatter().formatException(record.exc_info)}"
            if record.stack_info:
                message = f"{message}\n{record.stack_info}"
            record.msg = redact_text(message)
            record.args = ()
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
        except Exception:  # noqa: BLE001 - fail closed: never write an unredacted record
            record.msg = "[log record redaction failed]"
            record.args = ()
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
        return True
