# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Host-side mailbox poller for email-based second factors (magic-link / email-OTP).

Some target logins send a one-time code or a magic sign-in link to an inbox instead of a
TOTP app. To authenticate as that role the auth preflight needs to read the inbox, pull the
code/link, and feed it back into the browser. That read happens HERE, on the HOST (engine
process), NOT inside the sandbox: the mailbox credential never enters the sandbox env, and
the poll doesn't have to punch through the sandbox's scoped egress gateway.

Security model — the inbox is untrusted (anyone may be able to email it), so:
- **Delivery baseline, not sender dates.** We snapshot the mailbox's UIDNEXT immediately
  BEFORE the login is submitted and only consider messages delivered with a higher UID.
  Message ``Date`` headers are sender-controlled and are used only as a weak secondary
  filter, never as the freshness guarantee (a spoofed/missing Date can't smuggle a message in).
- **Magic-links are origin-bound.** A link is consumed only if its origin is on an allowlist
  (the target's own origin by default), so a link to an attacker domain in a race email is
  never opened. HTTPS is required when the target is HTTPS.
- **No operator regex.** Only the built-in (linear, non-catastrophic) OTP/link patterns run
  against email text, and the decoded body is size-capped, so a hostile message can't ReDoS
  or balloon memory.
- **TLS by default.** Plaintext IMAP (which would expose the mailbox password) needs an
  explicit unsafe-dev override.

Fail-closed + non-fatal: any IMAP/parse error yields an empty result (the preflight then
reports the role unauthenticated) rather than raising and breaking the scan. The IMAP client
is dependency-injected (``client_factory``) so this is unit-testable with no network.
"""

from __future__ import annotations

import email
import logging
import os
import re
import time
from dataclasses import dataclass, field
from email.message import Message
from typing import Any, Callable, Protocol
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# A magic-link is a full https URL; an OTP is a short digit run with word boundaries so it is
# not a fragment of a longer number (order id, phone, etc.). Both are linear (no nested
# quantifiers) so they cannot catastrophically backtrack on hostile input.
_DEFAULT_LINK_PATTERN = r"https?://[^\s\"'<>)\]]+"
_DEFAULT_OTP_PATTERN = r"(?<!\d)(\d{4,8})(?!\d)"
_MAX_BODY_BYTES = 256 * 1024  # cap decoded text scanned per message (ReDoS / memory guard)
_IMAP_SOCKET_TIMEOUT = 30.0  # per-call socket timeout so a wedged server can't hang the poll
_MAX_POLL_TIMEOUT = 600.0  # hard ceiling on the total wait, regardless of config


class _IMAPClient(Protocol):
    """The slice of imaplib.IMAP4 this module uses (so a fake can stand in)."""

    def login(self, user: str, password: str) -> Any: ...
    def select(self, mailbox: str, readonly: bool = ...) -> Any: ...
    def status(self, mailbox: str, names: str) -> Any: ...
    def uid(self, command: str, *args: Any) -> Any: ...
    def logout(self) -> Any: ...


@dataclass
class MailboxConfig:
    host: str
    user: str
    password: str
    port: int = 993
    ssl: bool = True
    folder: str = "INBOX"

    @property
    def configured(self) -> bool:
        return bool(self.host and self.user and self.password)


def config_from_env(env: dict[str, str] | None = None) -> MailboxConfig:
    """Build the mailbox config from RECON_IMAP_* (host/user/password/port/ssl/folder).

    Plaintext (RECON_IMAP_SSL=0) is REFUSED unless RECON_IMAP_ALLOW_INSECURE=1 is also set:
    a non-TLS IMAP login would put RECON_IMAP_PASSWORD on the wire in the clear."""
    e = env if env is not None else os.environ
    ssl_raw = (e.get("RECON_IMAP_SSL") or "1").strip().lower()
    port_raw = (e.get("RECON_IMAP_PORT") or "").strip()
    ssl = ssl_raw not in ("0", "false", "no")
    if not ssl:
        allow = (e.get("RECON_IMAP_ALLOW_INSECURE") or "").strip().lower() in ("1", "true", "yes")
        if not allow:
            logger.warning(
                "RECON_IMAP_SSL=0 ignored: plaintext IMAP would expose the mailbox password on "
                "the network; forcing TLS. Set RECON_IMAP_ALLOW_INSECURE=1 to override (dev only)."
            )
            ssl = True
    return MailboxConfig(
        host=(e.get("RECON_IMAP_HOST") or "").strip(),
        user=(e.get("RECON_IMAP_USER") or "").strip(),
        password=e.get("RECON_IMAP_PASSWORD") or "",
        port=int(port_raw) if port_raw.isdigit() else 993,
        ssl=ssl,
        folder=(e.get("RECON_IMAP_FOLDER") or "INBOX").strip() or "INBOX",
    )


@dataclass
class EmailFactor:
    """What the poller pulled from the inbox for one login."""

    otp: str = ""
    link: str = ""
    subject: str = ""
    found: bool = False


@dataclass
class Baseline:
    """A mailbox freshness anchor captured before login: the next UID to be assigned, plus the
    folder's UIDVALIDITY epoch (UIDs only compare within one epoch — if the folder is recreated
    the epoch changes and prior UIDs are meaningless)."""

    uid: int = 0
    validity: int = 0

    @property
    def ok(self) -> bool:
        return self.uid > 0 and self.validity > 0


_MAX_MSG_BYTES = 512 * 1024  # skip a message whose RFC822.SIZE exceeds this (bandwidth/memory guard)
_MAX_MESSAGES_PER_PASS = 25  # newest N per poll pass, so a mailbox flood can't stall one pass
_SEARCH_WINDOW = 500  # only SEARCH the newest ~N UIDs, so a flood can't return an unbounded list


def _imap_quote(s: str) -> str:
    """Quote a string for an IMAP SEARCH criterion (escape backslash + double-quote, wrap in
    quotes). Prevents a crafted filter value from breaking out into extra search tokens."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


@dataclass
class _Query:
    since_epoch: float
    baseline_uid: int = 0  # only messages with UID >= this (delivered after login) are considered
    baseline_validity: int = 0  # the UIDVALIDITY the baseline was taken under (0 = unchecked, tests)
    from_filter: str = ""
    subject_filter: str = ""
    otp_pattern: str = _DEFAULT_OTP_PATTERN  # built-in only; NOT operator-overridable (ReDoS)
    link_pattern: str = _DEFAULT_LINK_PATTERN
    link_contains: str = ""  # optional extra substring a magic-link must contain (e.g. "/verify")
    link_allowed_origins: list[str] = field(default_factory=list)  # scheme://host[:port]
    require_link_origin: bool = False  # when True, a link with NO allowlisted origin is rejected
    timeout_s: float = 60.0
    interval_s: float = 3.0
    now: Callable[[], float] = field(default=time.monotonic)  # monotonic: immune to wall-clock jumps
    sleep: Callable[[float], None] = field(default=time.sleep)


def _default_client_factory(cfg: MailboxConfig) -> _IMAPClient:
    import imaplib  # local import: only needed on the real path, not in tests

    if cfg.ssl:
        return imaplib.IMAP4_SSL(cfg.host, cfg.port, timeout=_IMAP_SOCKET_TIMEOUT)
    return imaplib.IMAP4(cfg.host, cfg.port, timeout=_IMAP_SOCKET_TIMEOUT)


def _origin(url: str) -> str:
    try:
        p = urlparse(url)
        if not p.scheme or not p.netloc:
            return ""
        return f"{p.scheme}://{p.netloc}".lower()
    except ValueError:
        return ""


def origins_for_target(target_url: str) -> list[str]:
    """The default magic-link allowlist for a target: its own origin."""
    o = _origin(target_url)
    return [o] if o else []


def _message_text(msg: Message) -> str:
    """Flatten a message to searchable text (text/plain preferred, then text/html), capped at
    _MAX_BODY_BYTES so a hostile giant body can't blow up memory or the regex scan."""
    parts: list[str] = []
    total = 0
    for part in (msg.walk() if msg.is_multipart() else [msg]):
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            chunk = payload.decode(part.get_content_charset() or "utf-8", "replace")
        elif isinstance(payload, str):
            chunk = payload
        else:
            continue
        parts.append(chunk)
        total += len(chunk)
        if total >= _MAX_BODY_BYTES:
            break
    return "\n".join(parts)[:_MAX_BODY_BYTES]


def _matches(msg: Message, q: _Query) -> bool:
    """Secondary filters only (the UID baseline is the real freshness gate): optional
    sender/subject. A weak Date sanity check drops anything CLAIMING to predate login by a lot,
    but a missing/odd Date is NOT trusted to admit a message on its own."""
    if q.from_filter and q.from_filter.lower() not in (msg.get("From") or "").lower():
        return False
    if q.subject_filter and q.subject_filter.lower() not in (msg.get("Subject") or "").lower():
        return False
    date_hdr = msg.get("Date")
    if date_hdr:
        try:
            ts = email.utils.mktime_tz(email.utils.parsedate_tz(date_hdr))
            if ts < q.since_epoch - 600:  # >10min before login by the sender's own clock: drop
                return False
        except (TypeError, ValueError):
            pass
    return True


def _link_allowed(url: str, q: _Query) -> bool:
    o = _origin(url)
    if q.require_link_origin:
        # Enforced path (the preflight): a link is opened ONLY if its origin is explicitly
        # allowlisted. An empty allowlist (e.g. an unparseable target URL) rejects EVERY link
        # rather than falling open to attacker-controlled navigation.
        return bool(o) and o in [x.lower().rstrip("/") for x in q.link_allowed_origins]
    if not q.link_allowed_origins:
        return True  # unenforced (standalone/tests) — no allowlist means no origin constraint
    return o in [x.lower().rstrip("/") for x in q.link_allowed_origins]


def _extract(msg: Message, q: _Query) -> EmailFactor:
    text = _message_text(msg)
    link = ""
    for m in re.finditer(q.link_pattern, text):
        cand = m.group(0)
        if q.link_contains and q.link_contains.lower() not in cand.lower():
            continue
        if not _link_allowed(cand, q):
            continue  # origin not on the allowlist -> never opened (attacker-domain guard)
        link = cand
        break
    otp = ""
    m = re.search(q.otp_pattern, text)
    if m:
        otp = m.group(1) if m.groups() else m.group(0)
    return EmailFactor(otp=otp, link=link, subject=msg.get("Subject") or "", found=bool(otp or link))


def _status_fields(client: _IMAPClient, cfg: MailboxConfig) -> tuple[int, int]:
    """Read (UIDNEXT, UIDVALIDITY) in ONE STATUS response, so the two can't be snapshot across an
    epoch change. 0 for either field it can't read (caller then fails closed)."""
    try:
        typ, data = client.status(cfg.folder, "(UIDNEXT UIDVALIDITY)")
        if typ == "OK" and data:
            raw = data[0] if isinstance(data[0], (bytes, bytearray)) else str(data[0]).encode()
            nx = re.search(rb"UIDNEXT\s+(\d+)", raw)
            vv = re.search(rb"UIDVALIDITY\s+(\d+)", raw)
            return (int(nx.group(1)) if nx else 0, int(vv.group(1)) if vv else 0)
    except Exception:  # noqa: BLE001
        logger.debug("could not read STATUS (UIDNEXT UIDVALIDITY)", exc_info=True)
    return (0, 0)


def uid_baseline(cfg: MailboxConfig, *, client_factory: Callable[[MailboxConfig], _IMAPClient] = _default_client_factory) -> Baseline:
    """Snapshot the mailbox (UIDNEXT, UIDVALIDITY) BEFORE login, so polling only accepts messages
    delivered after AND only if the UID epoch is unchanged. Returns a zero Baseline on failure;
    the caller treats a non-``ok`` baseline (either field 0) as 'no anchor' and fails closed."""
    if not cfg.configured:
        return Baseline()
    client: _IMAPClient | None = None
    try:
        client = client_factory(cfg)
        client.login(cfg.user, cfg.password)
        client.select(cfg.folder, readonly=True)
        uid, validity = _status_fields(client, cfg)
        return Baseline(uid=uid, validity=validity)
    except Exception:  # noqa: BLE001
        logger.exception("email-MFA: could not snapshot mailbox UID baseline")
        return Baseline()
    finally:
        if client is not None:
            try:
                client.logout()
            except Exception:  # noqa: BLE001
                pass


def _fetch_size(client: _IMAPClient, uid: bytes) -> int:
    """The message's RFC822.SIZE (bytes) — checked BEFORE downloading the body so an oversized
    message is skipped without pulling it. -1 on failure (treated as 'skip')."""
    try:
        typ, raw = client.uid("FETCH", uid, "(RFC822.SIZE)")
        if typ == "OK" and raw:
            for p in raw:
                blob = p if isinstance(p, (bytes, bytearray)) else (p[0] if isinstance(p, tuple) else b"")
                m = re.search(rb"RFC822\.SIZE\s+(\d+)", bytes(blob))
                if m:
                    return int(m.group(1))
    except Exception:  # noqa: BLE001
        logger.debug("could not read RFC822.SIZE", exc_info=True)
    return -1


def _fetch_body(client: _IMAPClient, uid: bytes) -> bytes | None:
    typ, raw = client.uid("FETCH", uid, "(RFC822)")
    if typ != "OK" or not raw:
        return None
    for p in raw:
        if isinstance(p, tuple) and isinstance(p[1], (bytes, bytearray)):
            return bytes(p[1])
    return None


def _poll_once(client: _IMAPClient, cfg: MailboxConfig, q: _Query, deadline: float) -> EmailFactor:
    """One inbox pass over UIDs delivered at/after the baseline; newest matching message wins.
    Bounded: fails closed on a UIDVALIDITY change, caps messages examined, and honours the
    deadline inside the fetch loop so a flooded mailbox can't stall the pass."""
    client.select(cfg.folder, readonly=True)
    cur_uidnext, cur_validity = _status_fields(client, cfg)  # one STATUS for both checks
    if q.baseline_validity and cur_validity != q.baseline_validity:
        # Epoch check fails CLOSED on a change OR an unreadable value (0): a mismatched/missing
        # UIDVALIDITY means the UID space may have been reset, so its UIDs can't be trusted.
        logger.warning("email-MFA: mailbox UIDVALIDITY changed/unreadable since baseline; failing closed")
        return EmailFactor()
    # Bound the SEARCH to a trailing window and (when set) FROM/SUBJECT server-side, so a mailbox
    # flood can't return a huge UID list or crowd the real code out of the newest slice.
    lo = q.baseline_uid
    if cur_uidnext > q.baseline_uid + _SEARCH_WINDOW:
        lo = cur_uidnext - _SEARCH_WINDOW  # only the newest ~window UIDs
    criteria = ["UID", f"{lo}:*"]
    if q.from_filter:
        criteria += ["FROM", _imap_quote(q.from_filter)]
    if q.subject_filter:
        criteria += ["SUBJECT", _imap_quote(q.subject_filter)]
    typ, data = client.uid("SEARCH", None, *criteria)
    if typ != "OK" or not data or not data[0]:
        return EmailFactor()
    # UID n:* always returns at least the highest UID; drop any strictly below the baseline.
    uids = [u for u in data[0].split() if u.isdigit() and int(u) >= q.baseline_uid]
    for uid in list(reversed(uids))[:_MAX_MESSAGES_PER_PASS]:  # newest first, capped
        if q.now() > deadline:  # strictly past the deadline mid-pass (flood guard); the outer
            break               # loop handles the normal single-pass stop for timeout_s=0
        size = _fetch_size(client, uid)
        if size < 0 or size > _MAX_MSG_BYTES:
            continue  # unreadable size or oversized -> skip without downloading the body
        body = _fetch_body(client, uid)
        if body is None:
            continue
        msg = email.message_from_bytes(body)
        if not _matches(msg, q):
            continue
        factor = _extract(msg, q)
        if factor.found:
            return factor
    return EmailFactor()


def poll_for_factor(
    cfg: MailboxConfig,
    query: _Query,
    *,
    client_factory: Callable[[MailboxConfig], _IMAPClient] = _default_client_factory,
) -> EmailFactor:
    """Poll the mailbox until a matching code/link arrives or the timeout elapses.

    Never raises: connection/login/parse failures are logged and reported as an empty
    (``found=False``) factor so the caller fails the role closed instead of crashing. Requires
    a real UID baseline (``query.baseline_uid > 0``): with none, freshness can't be guaranteed,
    so we refuse rather than risk consuming a pre-existing (possibly attacker-planted) message."""
    if not cfg.configured:
        logger.info("email-MFA requested but RECON_IMAP_* not configured; cannot poll a mailbox")
        return EmailFactor()
    # A COMPLETE baseline is required in production: UID for freshness + UIDVALIDITY for the epoch.
    # (A query built with baseline_validity=0 disables the epoch check — standalone/tests only.)
    if query.baseline_uid <= 0:
        logger.warning("email-MFA: no mailbox UID baseline captured before login; refusing to poll (fail closed)")
        return EmailFactor()
    timeout = max(0.0, min(query.timeout_s, _MAX_POLL_TIMEOUT))  # finite, bounded
    deadline = query.now() + timeout
    client: _IMAPClient | None = None
    try:
        client = client_factory(cfg)
        client.login(cfg.user, cfg.password)
        while True:
            factor = _poll_once(client, cfg, query, deadline)
            if factor.found:
                return factor
            if query.now() >= deadline:
                logger.info("email-MFA: no matching message within %.0fs", timeout)
                return EmailFactor()
            query.sleep(max(0.0, min(query.interval_s, deadline - query.now())))
    except Exception:  # noqa: BLE001 — mailbox polling must never break the scan
        logger.exception("email-MFA mailbox poll failed")
        return EmailFactor()
    finally:
        if client is not None:
            try:
                client.logout()
            except Exception:  # noqa: BLE001
                pass


def build_query(
    flow: dict,
    since_epoch: float,
    *,
    baseline: Baseline | None = None,
    allowed_origins: list[str] | None = None,
    require_link_origin: bool = False,
    **overrides: Any,
) -> _Query:
    """Build a poll query from an auth flow's email-MFA hints + the pre-login baseline.

    Flow hints (all optional): ``email_from`` (sender substring), ``email_subject`` (subject
    substring), ``email_link_contains`` (a magic-link must also contain this). NOTE: no
    ``otp_pattern`` from the flow — only the built-in linear pattern runs (ReDoS guard)."""
    b = baseline or Baseline()
    q = _Query(
        since_epoch=since_epoch,
        baseline_uid=b.uid,
        baseline_validity=b.validity,
        from_filter=str(flow.get("email_from") or ""),
        subject_filter=str(flow.get("email_subject") or ""),
        link_contains=str(flow.get("email_link_contains") or ""),
        link_allowed_origins=list(allowed_origins or []),
        require_link_origin=require_link_origin,
    )
    for k, v in overrides.items():
        setattr(q, k, v)
    return q
