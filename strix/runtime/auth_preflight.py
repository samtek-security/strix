# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Host-owned auth preflight (Wave 1a).

Before the agent loop runs, the HOST logs in per role inside the sandbox with the deterministic
recon-browser CLI, VERIFIES the login fail-closed, and hands the agent only the sessions that
actually authenticated. This replaces trusting the agent to log in from prompt text: what the
agent gets is a host-verified fact ("role Admin is authenticated in session recon-admin"), not a
hope.

Why host-owned + verified (per the security review):
- The credential material is already in the container env as ``RECON_CRED_<ROLE>`` (#34) - the
  preflight reads it *inside* the sandbox via ``printenv | ... --password-stdin`` so the secret
  never enters argv, the prompt, or the model context.
- Verification is THREE-part and fail-closed: (1) the semantic ``success_condition`` the operator
  declared, (2) a NON-EMPTY saved session state (real cookies), and (3) a protected post-login
  probe (the target doesn't bounce us back to a login page). A cookie merely being set is not
  enough. A role that fails ANY part is reported unauthenticated - the agent must not make
  authenticated claims for it.
- Sessions are named (``recon-<slug>``) so roles never share cookies, and state is saved to a
  durable run-dir path (not ``/tmp``) for postmortem.

Non-standard flows (custom multi-step / natural-language ``login_steps``) are intentionally NOT
scripted here - recon-browser's ``auth login`` auto-detects standard form fields; anything it
can't handle falls back to the agent's own prompt-driven login. Best-effort throughout: a role
that errors is reported failed, never crashes the scan.
"""

from __future__ import annotations

import asyncio
import binascii
import json
import logging
import os
import re
import shlex
import shutil
import time
from typing import Any, Awaitable, Callable, Protocol

logger = logging.getLogger(__name__)

# Container-local durable dir for saved session state (survives the scan; not /tmp).
_STATE_DIR = "/workspace/.recon-auth"
AUTH_STATE_DIR = _STATE_DIR  # public alias
_LOGIN_PAGE_RE = re.compile(r"(login|signin|sign-in|/auth\b|/sso\b|/oauth)", re.I)


class _ExecResult(Protocol):
    stdout: bytes
    stderr: bytes
    exit_code: int


# The session exposes: async exec(*command, timeout=..., shell=bool) -> ExecResult
ExecFn = Callable[..., Awaitable[_ExecResult]]


def _slug(role: str) -> str:
    """CLI/fs-safe per-role name - MUST match activities._role_slug so the env var + session
    names line up with what the credential broker injected."""
    s = re.sub(r"[^a-z0-9]+", "-", (role or "").strip().lower()).strip("-")
    return s or "role"


def _cred_env(role: str) -> str:
    """The container env var holding this role's password - MUST match activities._cred_env_name."""
    return "RECON_CRED_" + _slug(role).upper().replace("-", "_")


def _out(res: _ExecResult) -> str:
    try:
        return (res.stdout or b"").decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""


async def _run(session: Any, *cmd: str, shell: bool = False, timeout: float = 45.0):
    """One sandbox exec; returns (ok, stdout_text). Never raises."""
    try:
        res = await session.exec(*cmd, shell=shell, timeout=timeout)
        return res.exit_code == 0, _out(res)
    except Exception:  # noqa: BLE001 - preflight is best-effort; a failed exec is just "not ok"
        logger.exception("auth preflight exec failed: %s", cmd[:1])
        return False, ""


def purge_auth_state_dir(path: str | None = None) -> None:
    """Best-effort host-side delete of the persisted browser auth-state directory.

    Never raises. A symlink is unlinked in place and never followed, so a
    planted `.recon-auth` -> `/workspace` cannot delete the sandbox.
    """
    target = path or _STATE_DIR
    try:
        if not target:
            return
        if os.path.islink(target):
            # Unlink the link only — never rmtree through it. A planted
            # `.recon-auth` -> `/workspace` would otherwise delete the sandbox.
            os.unlink(target)
            return
        if os.path.isdir(target):
            shutil.rmtree(target, ignore_errors=True)
        elif os.path.lexists(target):
            os.unlink(target)
    except Exception:  # noqa: BLE001 - host-side TTL/test helper; never raise
        logger.exception("purge_auth_state_dir failed for %s", target)


async def purge_auth_state(session: Any) -> bool:
    """Best-effort ``rm -rf`` of the sandbox auth-state dir. Never raises."""
    if session is None:
        return False
    try:
        ok, _ = await _run(session, "rm", "-rf", "--", _STATE_DIR)
        return bool(ok)
    except Exception:  # noqa: BLE001 - abort/TTL teardown must not fail cleanup
        logger.exception("purge_auth_state failed")
        return False


def _parse_success_condition(cond: str) -> tuple[str, str]:
    """('url_contains:/dashboard') -> ('url_contains', '/dashboard'). '' -> ('', '')."""
    cond = (cond or "").strip()
    if ":" in cond:
        kind, _, val = cond.partition(":")
        return kind.strip().lower(), val.strip()
    return (cond.lower(), "") if cond else ("", "")


async def _do_login(
    session: Any, flow: dict, slug: str, session_name: str, username: str,
    pre_submit: Callable[[], Awaitable[None]] | None = None,
) -> tuple[bool, str]:
    """Deterministic form login via recon-browser's auth vault. The password is piped from the
    container env over stdin, never placed in argv. ``pre_submit`` (if given) runs AFTER the
    recipe is stored but immediately BEFORE the actual submit - the tightest point to snapshot a
    mailbox baseline so the email-MFA window between baseline and the code being sent is minimal.
    Returns (ran_ok, note)."""
    env = _cred_env(flow.get("role") or "")
    login_url = (flow.get("login_url") or "").strip()
    # The ONLY shell (pipe) command - shlex.quote every interpolated operator value.
    save_cmd = (
        f"printenv {shlex.quote(env)} | recon-browser --session-name {shlex.quote(session_name)} "
        f"auth save {shlex.quote(slug)} --url {shlex.quote(login_url)} "
        f"--username {shlex.quote(username)} --password-stdin"
    )
    saved_ok, _ = await _run(session, save_cmd, shell=True)
    if not saved_ok:
        return False, "recon-browser auth save failed (login recipe not stored)"
    if pre_submit is not None:
        await pre_submit()
    login_ok, out = await _run(session, "recon-browser", "--session-name", session_name, "auth", "login", slug)
    if not login_ok:
        # Do NOT surface raw CLI stdout in the reason: it is persisted + shown to the agent, and a
        # failing auth CLI can echo the vault/credential material. Log detail at debug only.
        logger.debug("auth login failed for %s (stdout suppressed, %d bytes)", slug, len(out))
    return login_ok, "auth login ok" if login_ok else "auth login failed (see host debug log)"


async def _verify(session: Any, flow: dict, session_name: str, state_path: str, target_url: str) -> dict:
    """Three-part fail-closed verification. Returns a checks dict + overall `authenticated`."""
    checks: dict[str, Any] = {}

    # (2) NON-EMPTY saved session state (real cookies), persisted for postmortem.
    save_ok, _ = await _run(session, "recon-browser", "--session-name", session_name, "state", "save", state_path)
    cat_ok, cat = await _run(session, "cat", state_path)
    cookies_ok = False
    if save_ok and cat_ok:
        # Fail-closed: require a PARSEABLE storage-state with real cookies (or localStorage
        # origins). A non-JSON / unparseable blob is NOT accepted (no string-substring fallback -
        # a bogus file must not count as a session).
        try:
            data = json.loads(cat)
            cookies_ok = isinstance(data, dict) and (bool(data.get("cookies")) or bool(data.get("origins")))
        except (json.JSONDecodeError, ValueError):
            cookies_ok = False
    checks["saved_state"] = cookies_ok

    # (1) semantic success_condition the operator declared.
    declared = bool((flow.get("success_condition") or "").strip())
    kind, val = _parse_success_condition(flow.get("success_condition") or "")
    success_ok: bool | None = None
    if kind == "url_contains" and val:
        ok, url = await _run(session, "recon-browser", "--session-name", session_name, "get", "url")
        success_ok = ok and val in url
    elif kind == "element_present" and val:
        ok, snap = await _run(session, "recon-browser", "--session-name", session_name, "snapshot", "-i")
        success_ok = ok and val.lower() in snap.lower()
    elif kind == "api_ok" and val:
        base = target_url.rstrip("/")
        probe = base + ("" if val.startswith("/") else "/") + val
        ok, _ = await _run(session, "recon-browser", "--session-name", session_name, "open", probe)
        _, purl = await _run(session, "recon-browser", "--session-name", session_name, "get", "url")
        success_ok = ok and not _LOGIN_PAGE_RE.search(purl)
    elif declared:
        # A condition WAS declared but we can't evaluate it (unknown kind / empty value). Fail
        # closed - never silently downgrade a declared gate to probe-only.
        success_ok = False
    if success_ok is not None:
        checks["success_condition"] = success_ok

    # (3) protected probe: load the target under the session; authenticated => not bounced to login.
    probe_ok = False
    if target_url:
        ok, _ = await _run(session, "recon-browser", "--session-name", session_name, "open", target_url)
        got, url = await _run(session, "recon-browser", "--session-name", session_name, "get", "url")
        probe_ok = ok and got and not _LOGIN_PAGE_RE.search(url or "")
    checks["protected_probe"] = probe_ok

    # Fail-closed: require saved state AND (the declared success condition, or the probe when none
    # was declared) AND the protected probe. Any missing signal => not authenticated.
    sem_ok = checks["success_condition"] if "success_condition" in checks else probe_ok
    authenticated = bool(cookies_ok and sem_ok and probe_ok)
    return {"authenticated": authenticated, "checks": checks}


def _safe_mfa_timeout(raw: str | None, default: float = 90.0) -> float:
    """Parse RECON_IMAP_TIMEOUT into a FINITE, bounded wait (guarded so a malformed/inf value
    can't raise past the poller's fail-closed handler or spin the poll loop forever)."""
    try:
        v = float(raw) if raw and raw.strip() else default
    except (TypeError, ValueError):
        return default
    if v != v or v in (float("inf"), float("-inf")):  # NaN / inf
        return default
    return max(1.0, min(v, 600.0))


async def _complete_email_mfa(
    session: Any, flow: dict, session_name: str, since_epoch: float, target_url: str, baseline: Any,
) -> tuple[bool, str]:
    """Complete an email second factor after the form login triggered it.

    The mailbox is polled HOST-SIDE (the credential stays off the sandbox, and the poll
    doesn't need to cross the scoped egress gateway); the retrieved factor is then applied
    IN the browser session:
      - magic-link -> ``recon-browser open <link>`` (only when its origin matches the target).
      - OTP code   -> fill the code field (operator ``otp_selector`` if given, else a
        single-textbox heuristic) and submit with Enter.
    Freshness is guaranteed by the pre-login UID baseline (only messages delivered after login
    are considered), so a stale/pre-planted code is never reused. Returns (ok, note); never raises."""
    from strix.runtime import mailbox as mb

    cfg = mb.config_from_env()
    if not cfg.configured:
        return False, "email MFA required but no mailbox configured (set RECON_IMAP_HOST/USER/PASSWORD)"
    if baseline is None or not getattr(baseline, "ok", False):
        return False, "email MFA: could not baseline the mailbox before login (IMAP unreachable?) - failing closed"
    query = mb.build_query(
        flow, since_epoch, baseline=baseline,
        allowed_origins=mb.origins_for_target(target_url),  # magic-link must point at the target
        require_link_origin=True,  # enforced: an unparseable target => reject every link (no fail-open)
        timeout_s=_safe_mfa_timeout(os.environ.get("RECON_IMAP_TIMEOUT")),
    )
    # imaplib is blocking; run it off the event loop so heartbeats/other roles aren't stalled.
    factor = await asyncio.to_thread(mb.poll_for_factor, cfg, query)
    if not factor.found:
        return False, "email MFA: no code/link arrived in the mailbox within the wait window"
    if factor.link:
        ok, _ = await _run(session, "recon-browser", "--session-name", session_name, "open", factor.link)
        return ok, ("email MFA: magic-link opened" if ok else "email MFA: failed to open magic-link")
    # OTP: fill the code field, then submit. A declared selector wins; otherwise fill the
    # page's single textbox (typical for a code page). Fail-closed via _verify either way.
    selector = (flow.get("otp_selector") or "").strip()
    if selector:
        ok, _ = await _run(session, "recon-browser", "--session-name", session_name, "fill", selector, factor.otp)
    else:
        ok, _ = await _run(session, "recon-browser", "--session-name", session_name,
                           "find", "role", "textbox", "fill", factor.otp)
    if not ok:
        return False, "email MFA: could not fill the OTP field (set otp_selector on the auth flow)"
    await _run(session, "recon-browser", "--session-name", session_name, "press", "Enter")
    return True, "email MFA: OTP entered"


def _totp_code(seed: str, *, now: float | None = None, step: int = 30, digits: int = 6) -> str | None:
    """P7 host-side deterministic TOTP code (RFC 6238) from a base32 seed, stdlib only (no pyotp).

    Removes the LLM from the TOTP step: the seed is brokered HOST-SIDE (RECON_TOTP_<ROLE> env, set by
    the control plane from the data-collection form, never echoed to the agent), the code is derived
    deterministically, and the preflight fills + submits it exactly like the email-OTP path. Returns
    None on a malformed/absent seed (fail closed -> the agent prompts for it as before)."""
    import base64
    import hashlib
    import hmac as _hmac
    import struct

    raw = (seed or "").strip().replace(" ", "")
    if not raw:
        return None
    try:
        key = base64.b32decode(raw.upper() + "=" * (-len(raw) % 8))
    except (ValueError, binascii.Error):
        return None
    counter = int((now if now is not None else time.time()) // step)
    msg = struct.pack(">Q", counter)
    digest = _hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


async def _complete_totp(session: Any, flow: dict, session_name: str, role: str) -> tuple[bool, str]:
    """Complete a TOTP second factor deterministically, HOST-SIDE. The seed is brokered via
    RECON_TOTP_<ROLE> (the control plane sets it from the data-collection form; it never crosses to the
    agent and is never logged). The code is derived via _totp_code (RFC 6238, stdlib) and filled +
    submitted exactly like the email-OTP path. Returns (ok, note); never raises. Fail-closed: a missing
    or malformed seed returns False (the agent then prompts for the code as before)."""
    seed = os.environ.get(f"RECON_TOTP_{role.upper().replace('-', '_')}", "").strip()
    code = _totp_code(seed)
    if not code:
        return False, "TOTP MFA: no valid seed in RECON_TOTP_<ROLE> (set it via the data-collection form)"
    selector = (flow.get("otp_selector") or "").strip()
    if selector:
        ok, _ = await _run(session, "recon-browser", "--session-name", session_name, "fill", selector, code)
    else:
        ok, _ = await _run(session, "recon-browser", "--session-name", session_name,
                           "find", "role", "textbox", "fill", code)
    if not ok:
        return False, "TOTP MFA: could not fill the code field (set otp_selector on the auth flow)"
    await _run(session, "recon-browser", "--session-name", session_name, "press", "Enter")
    return True, "TOTP MFA: code entered"


async def preflight_role(session: Any, flow: dict, *, target_url: str) -> dict:
    """Log in + verify ONE role. Returns a result dict (never raises)."""
    role = flow.get("role") or "user"
    slug = _slug(role)
    session_name = f"recon-{slug}"
    state_path = f"{_STATE_DIR}/{slug}.json"
    result = {
        "role": role, "session_name": session_name, "state_path": state_path,
        "authenticated": False, "reason": "", "checks": {},
    }
    if not (flow.get("login_url") or "").strip():
        result["reason"] = "no login_url - can't preflight; agent will handle auth"
        return result
    # username is the label half of the "<role>:<label>" cred key, surfaced on the flow.
    username = (flow.get("username") or flow.get("label") or "").strip()
    # For an email second factor, snapshot the mailbox (UIDNEXT, UIDVALIDITY) baseline right
    # before the login SUBMIT (via the _do_login pre_submit hook, after the recipe is stored),
    # so only a message DELIVERED after is ever consumed and a spoofed Date / pre-planted message
    # can't be mistaken for this login's code. login_started is a weak secondary Date bound only.
    is_email_mfa = (flow.get("mfa") or "").strip().lower() == "email"
    is_totp_mfa = (flow.get("mfa") or "").strip().lower() == "totp"
    login_started = time.time()
    email_baseline = None
    pre_submit = None
    if is_email_mfa:
        from strix.runtime import mailbox as mb

        async def _snapshot_baseline() -> None:
            nonlocal email_baseline
            email_baseline = await asyncio.to_thread(mb.uid_baseline, mb.config_from_env())

        pre_submit = _snapshot_baseline
    # P7 cross-run session resume (opt-in): if a storage_state from a PRIOR run of this role persists
    # at state_path + RECON_AUTH_STATE_RESUME=1, load it + verify BEFORE the form login. A valid session
    # skips the login (resume); an expired/invalid one falls through to the full login. Freshness guard:
    # the state file's mtime must be within RECON_AUTH_STATE_TTL_HOURS (default 12) so a stale cookie
    # never masks a rotated credential. Fail-closed: a load/verify failure is non-fatal (full login runs).
    if os.environ.get("RECON_AUTH_STATE_RESUME", "0") == "1":
        try:
            stale = True
            try:
                age_h = (time.time() - os.path.getmtime(state_path)) / 3600.0
                ttl_h = float(os.environ.get("RECON_AUTH_STATE_TTL_HOURS", "12"))
                stale = age_h > ttl_h
            except (OSError, ValueError):
                stale = True
            if not stale:
                load_ok, _ = await _run(session, "recon-browser", "--session-name", session_name,
                                        "state", "load", state_path)
                if load_ok:
                    ver = await _verify(session, flow, session_name, state_path, target_url)
                    if ver.get("authenticated"):
                        result["checks"] = ver["checks"]
                        result["authenticated"] = True
                        result["reason"] = "resumed from persisted storage_state (no re-login)"
                        return result
        except Exception:  # noqa: BLE001 - resume is best-effort; never block the full login
            pass
    ran, note = await _do_login(session, flow, slug, session_name, username, pre_submit=pre_submit)
    if not ran:
        result["reason"] = note
        return result
    if is_email_mfa:
        mfa_ok, mfa_note = await _complete_email_mfa(
            session, flow, session_name, login_started, target_url, email_baseline)
        if not mfa_ok:
            result["reason"] = mfa_note
            return result
    elif is_totp_mfa:
        mfa_ok, mfa_note = await _complete_totp(session, flow, session_name, flow.get("role") or role)
        if not mfa_ok:
            result["reason"] = mfa_note
            return result
    ver = await _verify(session, flow, session_name, state_path, target_url)
    result["checks"] = ver["checks"]
    result["authenticated"] = ver["authenticated"]
    result["reason"] = "verified" if ver["authenticated"] else f"login ran but verification failed: {ver['checks']}"
    return result


async def run_auth_preflight(session: Any, auth_flows: list[dict], *, target_url: str) -> list[dict]:
    """Preflight every flow that has a login_url. Best-effort; returns per-role results."""
    if session is None or not auth_flows:
        return []
    # Fresh preflight must not inherit leftover cookies. Resume (opt-in) keeps
    # the persisted storage_state so preflight_role can load it.
    if os.environ.get("RECON_AUTH_STATE_RESUME", "0") != "1":
        await purge_auth_state(session)
    # Ensure the durable state dir exists in the container.
    await _run(session, "mkdir", "-p", _STATE_DIR)
    results = []
    for flow in auth_flows:
        if not isinstance(flow, dict):
            continue
        try:
            results.append(await preflight_role(session, flow, target_url=target_url))
        except Exception:  # noqa: BLE001 - one role must never break the others / the scan
            role = flow.get("role") or "user"
            logger.exception("auth preflight crashed for role %s", role)
            # Never let a crashed role DISAPPEAR - record it explicitly unauthenticated so the
            # agent is told, not left to assume it's authenticated.
            results.append({
                "role": role, "session_name": f"recon-{_slug(role)}", "state_path": "",
                "authenticated": False, "reason": "preflight error (host exception)", "checks": {},
            })
    return results


def preflight_instruction(results: list[dict]) -> str:
    """Turn the host's verified results into an authoritative directive for the agent: reuse the
    sessions that authenticated, don't re-login them, and don't make authenticated claims for the
    ones that failed."""
    if not results:
        return ""
    ok = [r for r in results if r.get("authenticated")]
    bad = [r for r in results if not r.get("authenticated")]
    lines = ["\n\n== HOST-ESTABLISHED AUTH (authoritative - the host already logged these in) =="]
    if ok:
        lines.append(
            "These roles are ALREADY authenticated and verified by the host. REUSE the named "
            "session - do NOT log in again:"
        )
        for r in ok:
            lines.append(
                f"  - Role '{r['role']}': session '{r['session_name']}'. Prefix recon-browser with "
                f"`--session-name {r['session_name']}` for ALL testing as this identity."
            )
    if bad:
        lines.append(
            "These roles could NOT be pre-authenticated by the host - log in yourself following the "
            "role's login steps; if that also fails, treat the role as UNAUTHENTICATED and do not "
            "make authenticated claims for it:"
        )
        for r in bad:
            lines.append(f"  - Role '{r['role']}': {r.get('reason') or 'preflight failed'}.")
    return "\n".join(lines)
