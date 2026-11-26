# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Host isolation for the contained backend's per-engagement Docker network.

An ``internal`` bridge blocks routing out, but Docker still gives the bridge a host-side gateway
address, and every host service bound to 0.0.0.0 (sshd, the API, Temporal) answers on it. Docker's
``isolated`` gateway mode removes that address. The Go helper in the Recon repo
(``control-plane/internal/netisolation``) defines the same option keys; keep the two in step.
"""

from __future__ import annotations

import contextlib
import ipaddress
import os
from typing import Any


GATEWAY_MODE_IPV4 = "com.docker.network.bridge.gateway_mode_ipv4"
GATEWAY_MODE_IPV6 = "com.docker.network.bridge.gateway_mode_ipv6"
MODE_ISOLATED = "isolated"
MIN_DOCKER_VERSION = (28, 0, 0)

# SSH, the API (two ports), Temporal and the dev database. A closed port proves nothing, so
# RECON_HOST_PROBE_PORTS adds the ports a given host really listens on.
DEFAULT_PROBE_PORTS = (22, 4000, 4001, 7233, 5434)

# Only a timeout or an unreachable error shows that nothing holds the address. A refusal is an RST
# from a host stack, which proves the address is there even when the probed port is closed.
_PROBE_SCRIPT = (
    "import errno,socket,sys\n"
    "try:\n"
    " socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=3).close()\n"
    " print('REACHABLE')\n"
    "except ConnectionRefusedError:\n"
    " print('REFUSED')\n"
    "except TimeoutError:\n"
    " print('CLOSED')\n"
    "except OSError as e:\n"
    " print('CLOSED' if e.errno in (errno.ENETUNREACH,errno.EHOSTUNREACH) else 'ERROR')\n"
)


def isolated_options() -> dict[str, str]:
    return {GATEWAY_MODE_IPV4: MODE_ISOLATED, GATEWAY_MODE_IPV6: MODE_ISOLATED}


def _parse_version(raw: str) -> tuple[int, ...]:
    parts = []
    for piece in raw.split("-", maxsplit=1)[0].split(".", 3)[:3]:
        digits = "".join(ch for ch in piece if ch.isdigit())
        if not digits:
            raise RuntimeError(f"unreadable Docker version {raw!r}")
        parts.append(int(digits))
    return tuple(parts)


def require_isolated_gateway_support(dc: Any) -> None:
    """Refuse to start on a daemon that may ignore the isolated gateway mode."""
    raw = str(dc.version().get("Version", ""))
    if _parse_version(raw) < MIN_DOCKER_VERSION:
        wanted = ".".join(str(n) for n in MIN_DOCKER_VERSION)
        raise RuntimeError(
            f"Docker {raw or 'unknown'} cannot isolate the contained network from the host; "
            f"{wanted} or newer is required"
        )


def require_isolated_network(attrs: dict[str, Any], name: str) -> None:
    """Fail unless the network is internal and isolated for both IP families."""
    if attrs.get("Driver") != "bridge":
        raise RuntimeError(
            f"network {name!r} uses driver {attrs.get('Driver')!r}, not bridge; refusing to start"
        )
    if attrs.get("Internal") is not True:
        raise RuntimeError(f"network {name!r} is not internal; refusing to start")
    options = attrs.get("Options") or {}
    for key in (GATEWAY_MODE_IPV4, GATEWAY_MODE_IPV6):
        if options.get(key) != MODE_ISOLATED:
            raise RuntimeError(
                f"contained network {name!r} is not isolated from the host "
                f"({key}={options.get(key)!r}); refusing to start"
            )


def probe_ports() -> tuple[int, ...]:
    ports = list(DEFAULT_PROBE_PORTS)
    for raw in os.environ.get("RECON_HOST_PROBE_PORTS", "").split(","):
        port = raw.strip()
        if port.isdigit() and int(port) not in ports:
            ports.append(int(port))
    return tuple(ports)


def _container_addresses(attrs: dict[str, Any]) -> set[str]:
    owned: set[str] = set()
    for endpoint in (attrs.get("Containers") or {}).values():
        for key in ("IPv4Address", "IPv6Address"):
            value = (endpoint.get(key) or "").split("/")[0]
            if value:
                owned.add(value)
    return owned


def _host_addresses(attrs: dict[str, Any]) -> list[str]:
    """Each configured gateway and the first usable address of each subnet.

    In isolated mode Docker reserves no gateway, so the first address may belong to a container.
    A container's own address is not the host, so it is left out of the probe.
    """
    configs = (attrs.get("IPAM") or {}).get("Config") or []
    if not configs:
        raise RuntimeError("contained network has no subnet to probe; refusing to start")
    owned = _container_addresses(attrs)
    seen: list[str] = []
    for cfg in configs:
        candidates = [cfg.get("Gateway")]
        with contextlib.suppress(ValueError, IndexError):
            candidates.append(str(ipaddress.ip_network(cfg.get("Subnet", ""), strict=False)[1]))
        for address in candidates:
            if address and address not in owned and address not in seen:
                seen.append(address)
    return seen


def check_host_unreachable(container: Any, attrs: dict[str, Any]) -> None:
    """Connect from inside the network to the host-side addresses and fail if any port answers.

    An exec that cannot run is an error, not a pass: an unrun probe proves nothing.
    """
    addresses = _host_addresses(attrs)
    if not addresses:
        # Isolated mode gives the host no address on the bridge, and a container holds the
        # first one, so there is nothing to connect to. The options must say so, or it is a fail.
        require_isolated_network(attrs, str(attrs.get("Name", "")))
        return
    reached: list[str] = []
    for address in addresses:
        for port in probe_ports():
            code, out = container.exec_run(["python3", "-c", _PROBE_SCRIPT, address, str(port)])
            text = out.decode(errors="replace").strip() if isinstance(out, bytes) else str(out)
            if code != 0 or text not in ("REACHABLE", "REFUSED", "CLOSED"):
                raise RuntimeError(
                    f"host exposure probe {address}:{port} could not run (exit {code}); "
                    "refusing to start"
                )
            if text in ("REACHABLE", "REFUSED"):
                reached.append(f"{address}:{port}")
    if reached:
        raise RuntimeError(
            "contained network reaches the host at " + ", ".join(reached) + "; refusing to start"
        )
