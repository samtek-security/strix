"""Shared test fixtures."""

from __future__ import annotations

import os
import socket as _socket

import pytest


# litellm fetches its pricing table from raw.githubusercontent.com at import
# time (``litellm/__init__.py``) unless this is set, which makes importing
# litellm -- something half the suite does transitively -- depend on live
# network access. On a run where that fetch stalls (egress restrictions, a
# slow edge node, GitHub rate-limiting), every test file that imports litellm
# re-attempts the fetch at collection time, with no bound short enough to fit
# a CI job's timeout. Force the bundled local pricing table instead; it's
# the same data litellm falls back to anyway, just without the network round
# trip. Set unconditionally, not with setdefault: an inherited
# ``LITELLM_LOCAL_MODEL_COST_MAP=false`` from the caller's shell would
# otherwise silently re-enable the fetch this isolates against. Must be set
# before anything imports litellm, so it happens here at module scope rather
# than in a fixture.
os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "true"


class RealNetworkBlockedError(RuntimeError):
    """Raised when a test tries to open a connection the suite didn't isolate."""


_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1", "", None)


def _host_of(address: object) -> object:
    return address[0] if isinstance(address, tuple) else address


def _require_loopback(address: object) -> None:
    host = _host_of(address)
    if host not in _LOOPBACK_HOSTS:
        raise RealNetworkBlockedError(
            f"a test tried to reach {host!r}, off 127.0.0.1; "
            "the suite only talks to 127.0.0.1 fixtures/gateways. If this is a "
            "genuine new dependency, isolate it the way LITELLM_LOCAL_MODEL_COST_MAP "
            "isolates litellm's pricing fetch above, rather than loosening this guard."
        )


# A second, defense-in-depth layer behind LITELLM_LOCAL_MODEL_COST_MAP: any
# future accidental real network call (a new dependency, a misconfigured
# base_url, a cache TTL fetch) fails instantly and names the offending host,
# instead of hanging for minutes until something upstream times out.
# ``getaddrinfo`` is guarded too, not just ``connect``: a hostname (as
# opposed to an address literal) resolves via DNS first, and that lookup
# alone can hang before a socket ever gets opened.
_real_socket_connect = _socket.socket.connect
_real_socket_connect_ex = _socket.socket.connect_ex
_real_getaddrinfo = _socket.getaddrinfo


def _guarded_connect(self, address, *args, **kwargs):  # type: ignore[no-untyped-def]
    _require_loopback(address)
    return _real_socket_connect(self, address, *args, **kwargs)


def _guarded_connect_ex(self, address, *args, **kwargs):  # type: ignore[no-untyped-def]
    _require_loopback(address)
    return _real_socket_connect_ex(self, address, *args, **kwargs)


def _guarded_getaddrinfo(host, *args, **kwargs):  # type: ignore[no-untyped-def]
    _require_loopback(host)
    return _real_getaddrinfo(host, *args, **kwargs)


_socket.socket.connect = _guarded_connect  # type: ignore[method-assign]
_socket.socket.connect_ex = _guarded_connect_ex  # type: ignore[method-assign]
_socket.getaddrinfo = _guarded_getaddrinfo


@pytest.fixture(autouse=True)
def _isolate_mcp_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Keep the whole suite from reading the developer's real MCP config.

    ``run_strix_scan`` connects the MCP servers listed in
    ``~/.strix/mcp-servers.json`` and threads an inventory of them into the
    prompt context. Without isolation, any test that drives the runner on a
    machine that has a real config would do real network I/O and see MCP
    connections it never asked for. Point the loader at a path that does not
    exist so it resolves to "no connections", and clear the per-run selection
    env vars. Tests that exercise the loader itself set their own
    ``STRIX_MCP_CONFIG`` after this runs and so override it.
    """
    missing = tmp_path_factory.mktemp("mcp-isolation") / "no-servers.json"
    monkeypatch.setenv("STRIX_MCP_CONFIG", str(missing))
    monkeypatch.delenv("STRIX_MCP_ONLY", raising=False)
    monkeypatch.delenv("STRIX_MCP_EXCLUDE", raising=False)


@pytest.fixture(autouse=True)
def _plain_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make Rich output identical on every developer's machine.

    Many CLI tests force ``isatty()`` to ``True`` to exercise the human-readable
    code path and then assert on the plain text. Rich picks its color system
    from ``TERM``, ``COLORTERM``, and ``FORCE_COLOR``, so on a real terminal
    those assertions would meet ANSI escape codes instead of the words they
    look for. A dumb terminal renders the same text without any styling.
    """
    monkeypatch.setenv("TERM", "dumb")
    for name in ("COLORTERM", "FORCE_COLOR", "NO_COLOR", "TTY_COMPATIBLE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _isolate_wallet_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep a developer's real mppx wallet out of the top-up tests.

    ``strix cloud billing topup`` chooses the Stripe Link flow or the
    preconfigured mppx wallet from these variables, so leaving them set would
    silently switch which branch a test runs.
    """
    for name in ("MPPX_ACCOUNT", "MPPX_STRIPE_SECRET_KEY", "MPPX_STRIPE_PAYMENT_METHOD"):
        monkeypatch.delenv(name, raising=False)
