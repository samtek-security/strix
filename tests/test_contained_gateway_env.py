# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""The contained Docker backend forwards the gateway's L7 host lists to its container."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import docker
import pytest

from strix.runtime import backends, gateway_staging


class _StopError(Exception):
    pass


def _gateway_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> dict[str, str]:
    spec = tmp_path / "gateway.json"
    spec.write_text("{}")
    spec.chmod(0o600)
    scan_id = "scan-1"
    boundary = {
        "recon.sandbox": "true",
        "recon.scan_id": scan_id,
        "recon.owner": "contained-egress",
    }
    net_name = f"recon-net-{scan_id}"

    net = MagicMock()
    net.attrs = {
        "Name": net_name,
        "Driver": "bridge",
        "Internal": True,
        "Labels": {**boundary, "recon.role": "agent-gateway-network"},
        "Containers": {},
        "Options": backends.host_isolation.isolated_options(),
    }
    volume = MagicMock()
    volume.attrs = {"Labels": {**boundary, "recon.role": "gateway-ca-volume"}}
    client = MagicMock()
    client.version.return_value = {"Version": "29.9.2"}
    client.networks.create.return_value = net
    client.volumes.create.return_value = volume
    client.containers.run.side_effect = _StopError
    monkeypatch.setattr(docker, "from_env", lambda: client)
    monkeypatch.setattr(gateway_staging, "needs_staging", lambda: False)
    monkeypatch.delenv("RECON_GATEWAY_CAPTURE", raising=False)
    # The backend refuses to start without the control-plane escalation reporter.
    token = tmp_path / "reporter-token"
    token.write_text("t" * 32)
    token.chmod(0o600)
    monkeypatch.setenv("RECON_TARGET_HEALTH_REPORTER_URL", "http://control-plane.test:4001")
    monkeypatch.setenv("RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE", str(token))

    with pytest.raises(_StopError):
        asyncio.run(
            backends._contained_docker_backend(
                image="agent:1",
                manifest=SimpleNamespace(),
                exposed_ports=(),
                scan_id=scan_id,
                gateway_spec_path=str(spec),
            )
        )
    env: dict[str, str] = client.containers.run.call_args.kwargs["environment"]
    return env


def test_gateway_container_gets_both_host_lists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    monkeypatch.setenv("RECON_MODEL_HOSTS", "models.example")
    monkeypatch.setenv("RECON_PENTEST_SUPPORT_HOSTS", "a.example,b.example")
    env = _gateway_environment(monkeypatch, tmp_path)
    assert env["RECON_MODEL_HOSTS"] == "models.example"
    assert env["RECON_PENTEST_SUPPORT_HOSTS"] == "a.example,b.example"


def test_unset_support_hosts_reach_the_gateway_as_empty(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    monkeypatch.delenv("RECON_PENTEST_SUPPORT_HOSTS", raising=False)
    env = _gateway_environment(monkeypatch, tmp_path)
    assert env["RECON_PENTEST_SUPPORT_HOSTS"] == ""
