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

Two extensions on top of the above:

- **Cross-run resume** (``external_state``): the caller (the host, outside this module) may hand
  ``preflight_role``/``run_auth_preflight`` a previously-saved ``storage_state`` blob for a role,
  already freshness-checked by the caller (keyed by tenant/target/role, not this module's
  concern). It is written into the sandbox and run through the SAME 3-part ``_verify`` before
  anything is trusted - an invalid/expired blob falls straight through to a full login, never
  reported authenticated. On ANY successful preflight (fresh login or resume) the result carries
  back the current ``storage_state`` text (``result["storage_state"]``) so the caller can persist
  it for the next run.
- **OIDC/SSO handoff** (OFF by default; ``RECON_AUTH_OIDC_HANDOFF=1`` enables it outside
  production only, and production is gated on per-flow issuer/client_id validation, issue #122
  item 3): a login that redirects to a different origin matching a known identity-provider
  pattern can't be completed by ``recon-browser``'s deterministic form-fill (the target's OWN
  login page is often just a redirect, not a form). Such a role is flagged
  (``result["needs_agent_oidc"]``) rather than just reported failed, with the provider origin
  the agent should complete the provider sign-in in. ``reverify_role`` lets a caller re-run the
  unchanged 3-part check afterward, once the agent believes it has landed on an authenticated
  page - the host verification is never weakened or bypassed for an agent-driven login.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import io
import json
import logging
import os
import re
import shlex
import shutil
import time
from pathlib import Path
from typing import Any, Awaitable, Callable, Protocol
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# Container-local durable dir for saved session state (survives the scan; not /tmp).
_STATE_DIR = "/workspace/.recon-auth"
AUTH_STATE_DIR = _STATE_DIR  # public alias
_LOGIN_PAGE_RE = re.compile(r"(login|signin|sign-in|/auth\b|/sso\b|/oauth)", re.I)
# Fixed, single-tenant identity-provider HOSTNAMES ONLY - Microsoft and Google serve every tenant
# from these exact hosts (a "tenant" there is a path segment, e.g. /common/ or a tenant GUID, not
# a subdomain), so there is no attacker-controlled tenant that could qualify by hostname alone.
# Deliberately EXCLUDES multi-tenant SaaS IdPs (Okta, Auth0, OneLogin, Ping...) where a customer
# gets their OWN subdomain of a shared base domain - a bare suffix match on "okta.com" would let
# an attacker's own paid Okta tenant ("evil.okta.com") qualify just as well as the operator's real
# one. For those, the flow must declare its EXACT tenant subdomain via "oidc_provider_host" -
# matched the same exact/subdomain way, never a substring match against the whole URL (a lookalike
# host like "okta.com.attacker.example" or a path like "https://attacker.example/authorize" must
# NOT match regardless of which list it is checked against).
_KNOWN_OIDC_HOSTS = ("login.microsoftonline.com", "accounts.google.com")


class _ExecResult(Protocol):
    stdout: bytes
    stderr: bytes
    exit_code: int


# The session exposes: async exec(*command, timeout=..., shell=bool) -> ExecResult
ExecFn = Callable[..., Awaitable[_ExecResult]]


def _role_of(flow: dict) -> Any:
    """The flow's role. Only a MISSING or empty-string role defaults to "user"; any other value,
    including falsey non-strings (0, False, [], {}), is returned as-is so callers can reject it as
    malformed instead of silently verifying it under the default session."""
    raw = flow.get("role")
    return "user" if raw is None or raw == "" else raw


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


def _looks_like_a_session_blob(raw_json: str) -> bool:
    """A cheap HOST-side shape check (parseable JSON with real cookies/origins) before a
    host-supplied blob is ever written into a live sandbox session - keeps obvious garbage from
    touching the browser at all. Not a substitute for ``_verify``'s own check, which is what
    actually gates authentication; this only avoids loading something that can't possibly pass."""
    if not raw_json or not raw_json.strip():
        return False
    try:
        data = json.loads(raw_json)
    except (json.JSONDecodeError, ValueError):
        return False
    return isinstance(data, dict) and (bool(data.get("cookies")) or bool(data.get("origins")))


async def _write_state_file(session: Any, path: str, raw_json: str) -> bool:
    """Write a HOST-provided ``storage_state`` blob into the sandbox at ``path`` via the
    session's own ``write`` (the same file-write primitive ``strix.core.runner``'s
    ``_spill_to_workspace`` already uses, not a shell command) - the blob never crosses an exec
    argv at all, so it can't appear in a HOST-side exec log, a sandbox backend's own exec audit
    trail (e.g. a K8s ``ExecTransportError``), or blow an argv size limit on a large session.
    Never trusts the content's shape: the caller's own ``_verify`` JSON-parse + cookie/origin check
    is what actually gates authentication, so a garbage blob here just fails that check, same as
    any other unreadable state file. Returns False on any failure; never raises."""
    if not raw_json:
        return False
    dirname = path.rsplit("/", 1)[0] or "/"
    await _run(session, "mkdir", "-p", dirname)
    try:
        await session.write(Path(path), io.BytesIO(raw_json.encode("utf-8")))
    except Exception:  # a write failure just means the resume attempt fails
        logger.exception("writing external_state into the sandbox failed")
        return False
    else:
        return True


def _origin(url: str) -> str:
    """scheme://host[:port] built from the parsed hostname and port - never from the raw netloc,
    which carries ``user:password@`` userinfo that must not reach a result or an agent prompt."""
    try:
        parts = urlsplit(url or "")
        host = (parts.hostname or "").lower()
        if not parts.scheme or not host:
            return ""
        if ":" in host:
            host = f"[{host}]"
        port = parts.port
    except ValueError:
        return ""
    return f"{parts.scheme.lower()}://{host}" + (f":{port}" if port else "")


# The only environment classes the hand-off may run in. Fail closed: a missing, blank or
# unrecognized RECON_ENV_CLASS (including staging, which runs production-like infrastructure) is
# NOT a safe class - an env var alone must never enable credential submission in production.
_OIDC_HANDOFF_ENV_CLASSES = ("dev", "development", "local", "test")


def _oidc_handoff_enabled() -> bool:
    """The agent-driven OIDC hand-off is OFF unless ``RECON_AUTH_OIDC_HANDOFF=1`` is set AND
    ``RECON_ENV_CLASS`` explicitly names a non-production class (dev, development, local, test);
    anything else, including an unset or unrecognized value, refuses it. A host allowlist cannot
    tell an operator's OAuth client from an attacker-registered one on the same provider, so
    production stays closed until per-flow issuer/client_id/redirect validation exists (issue
    #122 item 3). Off, a redirect to an identity provider is an ordinary login failure."""
    if os.environ.get("RECON_AUTH_OIDC_HANDOFF", "0").strip() != "1":
        return False
    if os.environ.get("RECON_ENV_CLASS", "").strip().lower() not in _OIDC_HANDOFF_ENV_CLASSES:
        logger.warning("RECON_AUTH_OIDC_HANDOFF=1 ignored: RECON_ENV_CLASS is not an explicit "
                       "non-production class")
        return False
    return True


def _can_prove_login(flow: dict) -> bool:
    """Only a flow with a declared success_condition can ever be proven authenticated after an
    agent-completed sign-in (``reverify_role`` refuses one without), so a hand-off for any other
    flow could never end in an authenticated role and is not offered."""
    return bool((flow.get("success_condition") or "").strip())


def _is_approved_oidc_host(hostname: str, flow: dict) -> bool:
    """Exact match or proper subdomain match only - never a substring match against the whole
    URL, so a lookalike host (``okta.com.attacker.example``) or a path signature on an arbitrary
    host (``https://attacker.example/authorize``) can never pass as an identity provider.

    ``flow["oidc_provider_host"]`` is the only way to approve a multi-tenant SaaS IdP (a
    customer's own Okta/Auth0/OneLogin/Ping subdomain) or any self-hosted/government IdP
    (Login.gov, Azure Government, a CMS agency's own Keycloak/ADFS) - NOT YET REACHABLE from the
    control plane today: ``store.AuthFlow`` (control-plane/internal/store/store.go) has no such
    field, and ``sanitizeAuthFlows`` (control-plane/internal/api/lifecycle.go) rebuilds the
    struct field-by-field, so it would be silently dropped even if submitted. Wiring that field
    through belongs with the already-held "fully declarative auth config" design pass (issue
    #122's third item), not bolted on here - this hatch is ready for it, callable directly today
    by anything that builds a flow dict itself (tests, a future internal caller)."""
    if not hostname or not _in_signed_scope(hostname, flow):
        return False

    def _matches(host: str) -> bool:
        return hostname == host or hostname.endswith("." + host)

    declared = (flow.get("oidc_provider_host") or "").strip().lower()
    if declared and _matches(declared):
        return True
    return any(_matches(host) for host in _KNOWN_OIDC_HOSTS)


def _in_signed_scope(hostname: str, flow: dict) -> bool:
    """The provider host must ALSO be inside the engagement's signed in-scope host list, carried
    on the flow as ``scope_hosts`` (the compiled config's ``allow_hosts``; a leading dot covers
    that domain and every subdomain, a plain entry matches exactly - the same rule the agent's
    login redirect guard states). No list means nothing is approved: fail closed, never infer
    scope from the identity provider's own name."""
    entries = flow.get("scope_hosts")
    if not isinstance(entries, (list, tuple)):
        return False
    for raw in entries:
        entry = str(raw).strip().lower()
        if not entry:
            continue
        if entry.startswith("."):
            bare = entry[1:]
            if bare and (hostname == bare or hostname.endswith(entry)):
                return True
        elif hostname == entry:
            return True
    return False


def _is_https_approved_provider(url: str, flow: dict) -> bool:
    try:
        parts = urlsplit(url or "")
    except ValueError:
        return False
    return parts.scheme.lower() == "https" and _is_approved_oidc_host(
        (parts.hostname or "").lower(), flow)


def _looks_like_oidc_redirect(login_url: str, current_url: str, flow: dict) -> bool:
    """A login that lands on a DIFFERENT, HTTPS, APPROVED identity-provider host is an OIDC/SSO
    hand-off the deterministic form-login can't complete - distinct from simply being bounced back
    to the target's own login page (``_LOGIN_PAGE_RE``), which is an ordinary failure. HTTPS and an
    approved host (a known enterprise IdP, or the flow's own declared ``oidc_provider_host``) are
    both required: this directs the agent to submit live credentials/TOTP there, so an unapproved
    or unencrypted host must never qualify, no matter what the path looks like."""
    try:
        current = urlsplit(current_url or "")
    except ValueError:
        return False
    if current.scheme.lower() != "https":
        return False
    login_origin, current_origin = _origin(login_url), _origin(current_url)
    if not current_origin or current_origin == login_origin:
        return False
    return _is_approved_oidc_host((current.hostname or "").lower(), flow)


async def _check_oidc_handoff(
    session: Any, session_name: str, login_url: str, flow: dict,
) -> dict | None:
    """Check whether we are sitting on an approved external identity provider's page rather than
    just having failed. Returns an enrichment dict (``needs_agent_oidc``, ``oidc_provider_url``)
    or None when this isn't an OIDC hand-off."""
    if not _oidc_handoff_enabled() or not _can_prove_login(flow):
        return None
    ok_url, cur_url = await _run(
        session, "recon-browser", "--session-name", session_name, "get", "url")
    if ok_url and cur_url and _looks_like_oidc_redirect(login_url, cur_url, flow):
        # Origin only, never the full URL: a real provider redirect can carry a one-time
        # sessionToken/login_hint/etc in its query string, and this value lands in the result,
        # the agent prompt and (via preflight_instruction) the model context - the agent already
        # has the full URL in its own live browser session if it needs it.
        return {"needs_agent_oidc": True, "oidc_provider_url": _origin(cur_url)}
    return None


def _oidc_handoff_reason(provider_url: str, session_name: str) -> str:
    return (
        f"login redirected to an external identity provider at {provider_url} - the "
        f"deterministic form login can't complete this; the agent must sign in through the "
        f"provider in session '{session_name}' and stop at any consent screen"
    )


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


def _is_known_provider_url(url: str, flow: dict) -> bool:
    """True when the URL's host is a known (or flow-declared) identity provider, scope aside.
    Used to refuse a verification that ENDED on a provider: provider cookies make saved_state true
    and a provider page avoids the login-page pattern, but that is not an application session."""
    try:
        host = (urlsplit(url or "").hostname or "").lower()
    except ValueError:
        return False
    declared = (flow.get("oidc_provider_host") or "").strip().lower()
    hosts = _KNOWN_OIDC_HOSTS + ((declared,) if declared else ())
    return bool(host) and any(host == h or host.endswith("." + h) for h in hosts)


def _landing_in_scope(url: str, flow: dict) -> bool:
    """True when the flow carries NO scope key (behavior unchanged), or the URL's host is inside
    it; a scope that is present but not a list fails closed. Applied to EVERY page a
    verification ends on - the starting page, the protected probe's final URL and the api_ok
    final URL - so a redirect out of scope can never prove a session or have its state
    persisted."""
    if flow.get("scope_hosts") is None:
        return True
    if not isinstance(flow["scope_hosts"], (list, tuple)):
        return False  # a scope was supplied but is malformed: never read that as "no scope"
    try:
        host = (urlsplit(url or "").hostname or "").lower()
    except ValueError:
        return False
    return _in_signed_scope(host, flow)


async def _verify(session: Any, flow: dict, session_name: str, state_path: str, target_url: str) -> dict:
    """Three-part fail-closed verification. Returns a checks dict + overall `authenticated`."""
    checks: dict[str, Any] = {}

    # A session that is still sitting on an identity provider is not an application session, and
    # a provider page can satisfy url_contains/element_present while provider cookies satisfy
    # saved_state. Look BEFORE any probe navigates away, and fail everything if so.
    on_page, current = await _run(
        session, "recon-browser", "--session-name", session_name, "get", "url")
    out_of_scope = bool(on_page) and not _landing_in_scope(current, flow)
    if not on_page or out_of_scope or _is_known_provider_url(current, flow):
        # Fail closed: if the page cannot even be read, we cannot tell that this is not still the
        # provider, and every later check could pass on it.
        return {
            "authenticated": False, "state_text": "",
            "checks": {
                "on_identity_provider": bool(on_page) and not out_of_scope, "saved_state": False,
                "protected_probe": False,
            },
        }

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
        success_ok = (ok and not _LOGIN_PAGE_RE.search(purl)
                      and not _is_known_provider_url(purl, flow)
                      and _landing_in_scope(purl, flow))
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
        probe_ok = (ok and got and not _LOGIN_PAGE_RE.search(url or "")
                    and not _is_known_provider_url(url, flow)
                    and _landing_in_scope(url, flow))
    checks["protected_probe"] = probe_ok

    # (2) NON-EMPTY saved session state (real cookies), persisted for postmortem. Done LAST,
    # after the navigations above, so both the gate and the state handed back to the caller for
    # cross-run persistence reflect the FINAL session - not a snapshot from before a probe that
    # could have rotated a cookie or seeded localStorage.
    save_ok, _ = await _run(session, "recon-browser", "--session-name", session_name, "state", "save", state_path)
    cat_ok, cat = await _run(session, "cat", state_path)
    cookies_ok = False
    state_text = ""
    if save_ok and cat_ok:
        # Fail-closed: require a PARSEABLE storage-state with real cookies (or localStorage
        # origins). A non-JSON / unparseable blob is NOT accepted (no string-substring fallback -
        # a bogus file must not count as a session).
        try:
            data = json.loads(cat)
            cookies_ok = isinstance(data, dict) and (bool(data.get("cookies")) or bool(data.get("origins")))
            if cookies_ok:
                state_text = cat
        except (json.JSONDecodeError, ValueError):
            cookies_ok = False
    checks["saved_state"] = cookies_ok

    # Fail-closed: require saved state AND (the declared success condition, or the probe when none
    # was declared) AND the protected probe. Any missing signal => not authenticated.
    sem_ok = checks["success_condition"] if "success_condition" in checks else probe_ok
    authenticated = bool(cookies_ok and sem_ok and probe_ok)
    return {
        "authenticated": authenticated, "checks": checks,
        "state_text": state_text if authenticated else "",
    }


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


async def preflight_role(
    session: Any, flow: dict, *, target_url: str, external_state: str | None = None,
) -> dict:
    """Log in + verify ONE role. Returns a result dict (never raises).

    ``external_state`` (optional): a HOST-supplied, previously-saved ``storage_state`` blob for
    THIS role, already freshness-checked by the caller (keying by tenant/target/role is the
    caller's concern, not this module's). Tried first via the same fail-closed ``_verify`` as
    everything else - an invalid/expired blob falls straight through to the normal login below,
    never reported authenticated on its own say-so."""
    role = _role_of(flow)
    if not isinstance(role, str):
        return {
            "role": str(role), "session_name": "", "state_path": "", "authenticated": False,
            "checks": {}, "reason": "malformed auth flow: role must be a string",
        }
    slug = _slug(role)
    session_name = f"recon-{slug}"
    state_path = f"{_STATE_DIR}/{slug}.json"
    result = {
        "role": role, "session_name": session_name, "state_path": state_path,
        "authenticated": False, "reason": "", "checks": {},
    }
    login_url = (flow.get("login_url") or "").strip()
    if not login_url:
        result["reason"] = "no login_url - can't preflight; agent will handle auth"
        return result
    try:
        parsed_login = urlsplit(login_url)
        login_is_idp = (_oidc_handoff_enabled() and _can_prove_login(flow)
                        and parsed_login.scheme.lower() == "https") and (
            _is_approved_oidc_host((parsed_login.hostname or "").lower(), flow))
    except ValueError:  # a malformed login_url just means "not an IdP" - never raise from here
        login_is_idp = False
    # Without a declared success_condition, _verify's "semantic" check collapses to the protected
    # probe, so a stale nonempty cookie on a target that lands on a public page would pass. A
    # cross-run resume skips the credential login entirely, so it demands explicit semantic proof.
    can_prove_resume = bool((flow.get("success_condition") or "").strip())
    if external_state and can_prove_resume and _looks_like_a_session_blob(external_state):
        # Load the host-supplied blob into the live session and run the SAME 3-part check before
        # trusting it. A clearly-garbage/tampered blob is rejected before it ever reaches the
        # sandbox (the shape check above). An expired-but-well-formed blob can still leave stale
        # cookies in this role's session when it fails verification here - the same accepted,
        # documented trade-off the pre-existing RECON_AUTH_STATE_RESUME path below already has:
        # the subsequent full login below navigates to login_url fresh, and a target that
        # redirects an authenticated-looking (even if actually expired) session away from its own
        # login form would need to independently re-validate it server-side to do so correctly.
        try:
            if await _write_state_file(session, state_path, external_state):
                load_ok, _ = await _run(session, "recon-browser", "--session-name", session_name,
                                        "state", "load", state_path)
                if load_ok:
                    # "state load" restores cookies/local-storage but leaves the browser wherever
                    # it already was (a fresh session starts blank) - navigate to the target
                    # BEFORE verifying, or success_condition's url_contains/element_present would
                    # evaluate against nothing and a genuinely valid resume would still fail.
                    await _run(session, "recon-browser", "--session-name", session_name,
                              "open", target_url)
                    ver = await _verify(session, flow, session_name, state_path, target_url)
                    if ver.get("authenticated"):
                        result["checks"] = ver["checks"]
                        result["authenticated"] = True
                        result["storage_state"] = ver.get("state_text", "")
                        result["reason"] = "resumed from host-persisted session (no re-login)"
                        return result
        except Exception:  # resume is best-effort; never block the full login
            logger.exception("external-state resume failed for role %s", role)
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
                    # Same reason as the external_state branch above: navigate before verifying.
                    await _run(session, "recon-browser", "--session-name", session_name,
                              "open", target_url)
                    ver = await _verify(session, flow, session_name, state_path, target_url)
                    if ver.get("authenticated"):
                        result["checks"] = ver["checks"]
                        result["authenticated"] = True
                        result["storage_state"] = ver.get("state_text", "")
                        result["reason"] = "resumed from persisted storage_state (no re-login)"
                        return result
        except Exception:  # noqa: BLE001 - resume is best-effort; never block the full login
            pass
    if login_is_idp:
        # The target's login_url IS the identity provider - a direct SSO entry point, not a
        # redirect we'd see partway through a form-fill. Checked only AFTER both resume paths
        # above had their chance (a valid persisted session spares the interactive SSO entirely),
        # and before the form-fill, which has no target-side form to find on a provider page.
        # Open it in the named session first (the agent continues in that session, which would
        # otherwise be blank) and hand off only if the open worked AND the browser is still on an
        # approved HTTPS provider afterward: a failed open, or an existing provider session that
        # bounces straight back to a callback, is an ordinary login attempt, not a hand-off.
        opened, _ = await _run(
            session, "recon-browser", "--session-name", session_name, "open", login_url)
        at_idp = False
        if opened:
            got_url, final_url = await _run(
                session, "recon-browser", "--session-name", session_name, "get", "url")
            at_idp = got_url and _is_https_approved_provider(final_url, flow)
        if at_idp:
            result["needs_agent_oidc"] = True
            result["oidc_provider_url"] = _origin(final_url)
            result["reason"] = _oidc_handoff_reason(_origin(final_url), session_name)
            return result
        if opened and (flow.get("success_condition") or "").strip():
            # Opening the provider landed somewhere else (typically the target's callback because
            # an existing SSO session redirected straight back). That may already be a valid
            # session, and no login form remains to fill - run the same 3-part check on the
            # landing before falling back to a form login that would find nothing to submit.
            ver = await _verify(session, flow, session_name, state_path, target_url)
            if ver.get("authenticated"):
                result["checks"] = ver["checks"]
                result["authenticated"] = True
                result["storage_state"] = ver.get("state_text", "")
                result["reason"] = "verified via an existing provider session (no re-login)"
                return result

    async def _oidc_or(fallback_reason: str) -> dict | None:
        """Check for an OIDC hand-off right now, before anything navigates the browser further
        (``_verify``'s own probes would move us away from the provider's page, which is why this
        is called at each point BEFORE a verify, never after one)."""
        oidc = await _check_oidc_handoff(session, session_name, login_url, flow)
        if oidc:
            result.update(oidc)
            result["reason"] = _oidc_handoff_reason(oidc["oidc_provider_url"], session_name)
            return result
        result["reason"] = fallback_reason
        return result

    ran, note = await _do_login(session, flow, slug, session_name, username, pre_submit=pre_submit)
    if not ran:
        # The deterministic form-fill can fail outright on an OIDC target: the target's OWN login
        # page is often just a redirect, not a standard form.
        return await _oidc_or(note)
    # The target's OWN login form may have succeeded while ALSO being just step one of an OIDC
    # flow (redirect to the provider happens right after). Check now, before MFA or verify run.
    oidc_now = await _check_oidc_handoff(session, session_name, login_url, flow)
    if oidc_now:
        result.update(oidc_now)
        result["reason"] = _oidc_handoff_reason(oidc_now["oidc_provider_url"], session_name)
        return result
    if is_email_mfa:
        mfa_ok, mfa_note = await _complete_email_mfa(
            session, flow, session_name, login_started, target_url, email_baseline)
        if not mfa_ok:
            # The MFA step itself can be where the OIDC redirect happens (the target's own
            # first-factor succeeded, then it bounces to the provider for a second factor).
            return await _oidc_or(mfa_note)
    elif is_totp_mfa:
        mfa_ok, mfa_note = await _complete_totp(session, flow, session_name, flow.get("role") or role)
        if not mfa_ok:
            return await _oidc_or(mfa_note)
    if is_email_mfa or is_totp_mfa:
        # A SUCCESSFUL OTP submit or magic-link open can itself land on an identity provider
        # (command-level success, redirect afterward). Check before _verify's probes navigate
        # away and erase the provider's location.
        oidc_after_mfa = await _check_oidc_handoff(session, session_name, login_url, flow)
        if oidc_after_mfa:
            result.update(oidc_after_mfa)
            result["reason"] = _oidc_handoff_reason(
                oidc_after_mfa["oidc_provider_url"], session_name)
            return result
    ver = await _verify(session, flow, session_name, state_path, target_url)
    result["checks"] = ver["checks"]
    result["authenticated"] = ver["authenticated"]
    if ver["authenticated"]:
        result["storage_state"] = ver.get("state_text", "")
        result["reason"] = "verified"
        return result
    result["reason"] = f"login ran but verification failed: {ver['checks']}"
    return result


async def reverify_role(session: Any, flow: dict, *, target_url: str) -> dict:
    """Re-run the SAME fail-closed 3-part check for a role the agent just finished logging in to
    directly - e.g. after completing an OIDC sign-in that ``preflight_role``
    flagged with ``needs_agent_oidc``. Never trust the agent's own claim of success without this:
    it is the identical ``_verify`` used for a host-driven login, never a weaker check. Returns the
    same result shape as ``preflight_role`` (never raises)."""
    role = _role_of(flow)
    if not isinstance(role, str):
        return {
            "role": str(role), "session_name": "", "state_path": "", "authenticated": False,
            "checks": {}, "reason": "malformed auth flow: role must be a string",
        }
    slug = _slug(role)
    session_name = f"recon-{slug}"
    state_path = f"{_STATE_DIR}/{slug}.json"
    if not (flow.get("success_condition") or "").strip():
        # Without a declared success_condition, _verify's "semantic" check collapses to the
        # protected probe, and a failed provider sign-in can still pass it (provider cookies make
        # saved_state true, a public target page makes the probe true). An agent-completed login
        # is only believed on explicit semantic proof.
        return {
            "role": role, "session_name": session_name, "state_path": state_path,
            "authenticated": False, "checks": {},
            "reason": "no success_condition declared - an agent-completed login cannot be proven",
        }
    try:
        ver = await _verify(session, flow, session_name, state_path, target_url)
    except Exception:  # best-effort; a crashed re-check is just "not authenticated"
        logger.exception("reverify_role crashed for role %s", role)
        return {
            "role": role, "session_name": session_name, "state_path": state_path,
            "authenticated": False, "reason": "reverify error (host exception)", "checks": {},
        }
    result = {
        "role": role, "session_name": session_name, "state_path": state_path,
        "authenticated": ver["authenticated"], "checks": ver["checks"],
        "reason": "verified" if ver["authenticated"] else f"verification failed: {ver['checks']}",
    }
    if ver["authenticated"]:
        result["storage_state"] = ver.get("state_text", "")
    return result


async def run_auth_preflight(
    session: Any, auth_flows: list[dict], *, target_url: str,
    external_states: dict[str, str] | None = None,
) -> list[dict]:
    """Preflight every flow that has a login_url. Best-effort; returns per-role results.

    ``external_states`` (optional): {role_name: storage_state_text} for a cross-run resume - keyed
    by the ROLE NAME exactly as it appears on each flow dict (not the slug), already
    freshness-checked by the caller. Passed straight through to ``preflight_role``."""
    if session is None or not auth_flows:
        return []
    # Fresh preflight must not inherit leftover cookies. Resume (opt-in) keeps
    # the persisted storage_state so preflight_role can load it.
    if os.environ.get("RECON_AUTH_STATE_RESUME", "0") != "1":
        await purge_auth_state(session)
    # Ensure the durable state dir exists in the container.
    await _run(session, "mkdir", "-p", _STATE_DIR)
    results = []
    # One flow per exact role name: the first that CAN log in (has a login_url), else the first.
    # A header/api-key flow listed ahead of the browser flow for the same role must not cause the
    # usable browser flow to be skipped.
    chosen: dict[str, dict] = {}
    for flow in auth_flows:
        if isinstance(flow, dict) and isinstance(_role_of(flow), str):
            name = _role_of(flow)
            current = chosen.get(name)
            if current is None or (not (current.get("login_url") or "").strip()
                                   and (flow.get("login_url") or "").strip()):
                chosen[name] = flow
    # Roles whose names slug to the same session name also share a brokered credential env var
    # and a browser session, so logging the first in would already leave it racing the others'
    # credential. Find every colliding role UP FRONT and refuse ALL of them before any login.
    members: dict[str, list[str]] = {}
    for flow in auth_flows:
        if isinstance(flow, dict) and isinstance(_role_of(flow), str):
            name = _role_of(flow)
            names = members.setdefault(_slug(name), [])
            if name not in names:  # the same role name twice is one identity, not a collision
                names.append(name)
    for flow in auth_flows:
        if not isinstance(flow, dict):
            continue
        role = _role_of(flow)
        if isinstance(role, str) and chosen.get(role) is not flow:
            # The broker holds ONE credential per role and every flow for a role shares one
            # browser session, so a second flow for the same role is the same identity. Running
            # it would overwrite the first's session and yield contradictory results for one
            # role: collapse to the first flow.
            logger.warning("auth preflight: ignoring a duplicate flow for role %r", role)
            continue
        if not isinstance(role, str):
            # A malformed flow is recorded on its own; it must not abort the other roles.
            results.append({
                "role": str(role), "session_name": "", "state_path": "",
                "authenticated": False, "checks": {},
                "reason": "malformed auth flow: role must be a string",
            })
            continue
        slug = _slug(role)
        if len(members[slug]) > 1:
            others = ", ".join(f"'{r}'" for r in members[slug] if r != role) or "another role"
            logger.error("auth preflight: role %r collides with %s on session name recon-%s",
                         role, others, slug)
            results.append({
                "role": role, "session_name": f"recon-{slug}", "state_path": "",
                "authenticated": False, "checks": {}, "session_collision": True,
                "reason": f"role name collides with {others} on session recon-{slug}; "
                          f"rename one of them",
            })
            continue
        try:
            ext = (external_states or {}).get(role)
            results.append(
                await preflight_role(session, flow, target_url=target_url, external_state=ext))
        except Exception:  # one role must never break the others / the scan
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
    clash = [r for r in results if r.get("session_collision")]
    oidc = [r for r in results if not r.get("authenticated") and r.get("needs_agent_oidc")]
    bad = [r for r in results if not r.get("authenticated") and not r.get("needs_agent_oidc")
           and not r.get("session_collision")]
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
    if oidc:
        lines.append(
            "These roles redirect to an external identity provider. The host could not complete "
            "the login deterministically - YOU must complete the provider sign-in yourself, in "
            "the SAME named session (do not open a new one), using recon-browser with "
            "`--session-name <that session>`. NEVER click or grant any consent or permission "
            "screen (\"Accept\", \"Allow\", \"Consent\", \"Grant access\"): if the provider "
            "shows one, stop and report the role as NOT authenticated:"
        )
        lines.extend(
            f"  - Role '{r['role']}': session '{r['session_name']}', provider at "
            f"{r.get('oidc_provider_url', '?')}. If the provider asks for a TOTP/MFA code, "
            f"compute and submit it exactly the same way you already do for this role's "
            f"primary login - do not invent a new mechanism and do not ask the operator for "
            f"the code. Once you land back on an authenticated page, the host re-verifies this "
            f"role with the same check it uses everywhere else."
            for r in oidc
        )
    if clash:
        lines.append(
            "These roles share a browser session name with an earlier role. Logging them in "
            "would overwrite that role's cookies, so do NOT log in or test as them at all, and "
            "make no authenticated claims for them:"
        )
        lines.extend(f"  - Role '{r['role']}': {r.get('reason')}." for r in clash)
    if bad:
        lines.append(
            "These roles could NOT be pre-authenticated by the host - log in yourself following the "
            "role's login steps; if that also fails, treat the role as UNAUTHENTICATED and do not "
            "make authenticated claims for it:"
        )
        for r in bad:
            lines.append(f"  - Role '{r['role']}': {r.get('reason') or 'preflight failed'}.")
    return "\n".join(lines)
