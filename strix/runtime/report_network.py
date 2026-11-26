# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Dedicated Docker network the contained gateway uses to reach the escalation reporter.

The gateway reports target-health and RoE-violation trips to the control plane's API on the host.
Allowing that port from the default Docker bridge would also open it to every other container on
that bridge, including practice targets. A dedicated bridge with a fixed subnet lets the host
allow the API port from that subnet alone, and only gateway containers join it.

The network is internal: it has no route out, so joining it never changes the gateway's default
route or bypasses the configured egress network. An internal bridge still exposes the host's own
address on it (see host_isolation.py), which is the one address the gateway needs.

The network is created on first use and reused afterwards. An existing network that is not an
internal bridge, has a different subnet or host address, or has a non-gateway container attached
is refused, so a start never reports over a network the host rule does not describe.
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any


DEFAULT_NAME = "recon-gw-report"
DEFAULT_SUBNET = "10.250.250.0/24"
ENV_NAME = "RECON_GATEWAY_REPORT_NETWORK"
ENV_SUBNET = "RECON_GATEWAY_REPORT_SUBNET"
ROLE_LABEL = {"recon.role": "gateway-report-network"}
GATEWAY_ROLE = "egress-gateway"

_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


def settings() -> tuple[str, str]:
    """Return (network name, canonical subnet) from the environment, or the defaults."""
    name = os.environ.get(ENV_NAME, "").strip() or DEFAULT_NAME
    raw = os.environ.get(ENV_SUBNET, "").strip() or DEFAULT_SUBNET
    if not _NAME_RE.fullmatch(name):
        raise ValueError(f"{ENV_NAME} {name!r} is not a valid Docker network name")
    try:
        network = ipaddress.ip_network(raw, strict=True)
    except ValueError as exc:
        raise ValueError(f"{ENV_SUBNET} {raw!r} is not a valid subnet: {exc}") from exc
    if network.version != 4 or network.prefixlen > 29:
        raise ValueError(f"{ENV_SUBNET} {raw!r} must be an IPv4 subnet of /29 or larger")
    return name, str(network)


def gateway_address(subnet: str) -> str:
    """The host's address on the network: the first usable address of the subnet."""
    return str(ipaddress.ip_network(subnet)[1])


def verify(dc: Any, attrs: dict[str, Any], name: str, subnet: str) -> None:
    """Refuse a network that does not match what the host rule describes."""
    if attrs.get("Driver") != "bridge":
        raise RuntimeError(
            f"gateway report network {name!r} uses driver {attrs.get('Driver')!r}, not bridge; "
            "refusing to start"
        )
    if attrs.get("Internal") is not True:
        raise RuntimeError(
            f"gateway report network {name!r} is not internal, so joining it could change the "
            "gateway's default route; refusing to start"
        )
    configs = (attrs.get("IPAM") or {}).get("Config") or []
    subnets = {str(cfg.get("Subnet", "")) for cfg in configs if cfg.get("Subnet")}
    if subnets != {subnet}:
        found = ", ".join(sorted(subnets)) or "none"
        raise RuntimeError(
            f"gateway report network {name!r} has subnet {found}, expected {subnet}; "
            "refusing to start (remove the network or set "
            f"{ENV_SUBNET} to match)"
        )
    expected_gateway = gateway_address(subnet)
    gateways = {str(cfg.get("Gateway") or "") for cfg in configs}
    if gateways != {expected_gateway}:
        found = ", ".join(sorted(g or "none" for g in gateways))
        raise RuntimeError(
            f"gateway report network {name!r} has host address {found}, expected "
            f"{expected_gateway}; refusing to start"
        )
    for container_id in attrs.get("Containers") or {}:
        labels = _container_labels(dc, container_id)
        if labels is not None and labels.get("recon.role") != GATEWAY_ROLE:
            raise RuntimeError(
                f"gateway report network {name!r} has a container that is not an egress gateway "
                f"({container_id[:12]}); refusing to start"
            )


def _container_labels(dc: Any, container_id: str) -> dict[str, str] | None:
    """Labels of an attached container, or None when it has already gone.

    Any other failure propagates: a container that cannot be inspected is not verified.
    """
    import docker  # noqa: PLC0415  (lazy, as backends.py does: docker is optional at import)

    try:
        return dc.containers.get(container_id).labels or {}
    except docker.errors.NotFound:
        return None


def _refuse_overlap(dc: Any, name: str, subnet: str) -> None:
    """Refuse to create the network over an address range another network already holds."""
    wanted = ipaddress.ip_network(subnet)
    for other in dc.networks.list():
        other_name = getattr(other, "name", "") or ""
        if other_name == name:
            continue
        configs = ((getattr(other, "attrs", None) or {}).get("IPAM") or {}).get("Config") or []
        for cfg in configs:
            raw = cfg.get("Subnet")
            if not raw:
                continue
            try:
                existing = ipaddress.ip_network(raw, strict=False)
            except ValueError:
                continue
            if existing.version == wanted.version and existing.overlaps(wanted):
                raise RuntimeError(
                    f"gateway report subnet {subnet} overlaps Docker network {other_name!r} "
                    f"({raw}); refusing to start (choose another {ENV_SUBNET})"
                )


def ensure_network(dc: Any, name: str, subnet: str) -> Any:
    """Return the verified report network, creating it when absent."""
    import docker  # noqa: PLC0415  (lazy, as backends.py does: docker is optional at import)

    try:
        network = dc.networks.get(name)
    except docker.errors.NotFound:
        _refuse_overlap(dc, name, subnet)
        pool = docker.types.IPAMPool(subnet=subnet, gateway=gateway_address(subnet))
        try:
            network = dc.networks.create(
                name,
                driver="bridge",
                internal=True,
                ipam=docker.types.IPAMConfig(pool_configs=[pool]),
                labels=dict(ROLE_LABEL),
                check_duplicate=True,
            )
        except docker.errors.APIError as exc:
            # Lost a creation race, or the subnet overlaps another network. A network that now
            # exists under the name is verified below; otherwise the start is refused.
            try:
                network = dc.networks.get(name)
            except docker.errors.NotFound:
                raise RuntimeError(
                    f"could not create gateway report network {name!r} ({subnet}): {exc}"
                ) from exc
    network.reload()
    verify(dc, network.attrs, name, subnet)
    return network
