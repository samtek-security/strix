"""The contained backend isolates its network from the host and proves it first."""

from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import docker
import pytest

from strix.runtime import backends, host_isolation


SCAN = "scan-1"
BOUNDARY = {"recon.sandbox": "true", "recon.scan_id": SCAN, "recon.owner": "contained-egress"}
IPAM = {"Config": [{"Subnet": "10.250.97.0/29"}]}


def _network(options: dict[str, str] | None = None) -> MagicMock:
    net = MagicMock()
    net.attrs = {
        "Name": f"recon-net-{SCAN}",
        "Driver": "bridge",
        "Internal": True,
        "Labels": {**BOUNDARY, "recon.role": "agent-gateway-network"},
        "Containers": {},
        "Options": host_isolation.isolated_options() if options is None else options,
        "IPAM": IPAM,
    }
    return net


def _run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    *,
    net: MagicMock,
    probe: Any,
    version: str = "29.9.2",
    client: MagicMock | None = None,
) -> MagicMock:
    spec = tmp_path / "gateway.json"
    spec.write_text("{}")
    spec.chmod(0o600)
    token = tmp_path / "reporter-token"
    token.write_text("t" * 32)
    token.chmod(0o600)
    monkeypatch.setenv("RECON_TARGET_HEALTH_REPORTER_URL", "http://control-plane.test:4001")
    monkeypatch.setenv("RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE", str(token))
    volume = MagicMock()
    volume.attrs = {"Labels": {**BOUNDARY, "recon.role": "gateway-ca-volume"}}
    gateway = MagicMock()
    gateway.status = "running"
    gateway.exec_run.side_effect = probe
    client = client or MagicMock()
    client.version.return_value = {"Version": version}
    client.networks.create.return_value = net
    client.volumes.create.return_value = volume
    client.containers.run.return_value = gateway
    monkeypatch.setattr(docker, "from_env", lambda: client)
    monkeypatch.setattr(backends, "_wait_gateway_ready", lambda *_args, **_kwargs: True)
    monkeypatch.delenv("RECON_GATEWAY_CAPTURE", raising=False)
    monkeypatch.delenv("RECON_HOST_PROBE_PORTS", raising=False)
    asyncio.run(
        backends._contained_docker_backend(
            image="agent:1",
            manifest=SimpleNamespace(),
            exposed_ports=(),
            scan_id=SCAN,
            gateway_spec_path=str(spec),
        )
    )
    return client


def _probe(results: dict[str, bytes]) -> Any:
    def run(cmd: list[str]) -> tuple[int, bytes]:
        return 0, results.get(f"{cmd[-2]}:{cmd[-1]}", b"CLOSED")

    return run


def test_network_is_created_isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    client = MagicMock()
    client.networks.get.side_effect = RuntimeError("no egress network")
    with pytest.raises(RuntimeError, match="could not attach"):
        _run(monkeypatch, tmp_path, net=_network(), probe=_probe({}), client=client)
    created = client.networks.create.call_args.kwargs
    assert created["internal"] is True
    assert created["options"] == host_isolation.isolated_options()


def test_old_docker_is_refused_before_anything_is_created(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    client = MagicMock()
    with pytest.raises(RuntimeError, match=r"28\.0\.0 or newer"):
        _run(
            monkeypatch, tmp_path, net=_network(), probe=_probe({}), version="27.5.1", client=client
        )
    client.networks.create.assert_not_called()


def test_network_without_isolated_mode_is_refused_and_removed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    net = _network(options={})
    client = MagicMock()
    with pytest.raises(RuntimeError, match="not isolated"):
        _run(monkeypatch, tmp_path, net=net, probe=_probe({}), client=client)
    net.remove.assert_called_once()
    client.containers.run.assert_not_called()


def test_reachable_host_port_aborts_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    net = _network()
    client = MagicMock()
    with pytest.raises(RuntimeError, match=r"reaches the host at 10\.250\.97\.1:22"):
        _run(
            monkeypatch,
            tmp_path,
            net=net,
            probe=_probe({"10.250.97.1:22": b"REACHABLE"}),
            client=client,
        )
    client.containers.run.return_value.remove.assert_called_once_with(force=True)
    net.remove.assert_called_once()
    client.networks.get.assert_not_called()


def test_probe_that_cannot_run_is_not_a_pass(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    net = _network()
    with pytest.raises(RuntimeError, match="could not run"):
        _run(
            monkeypatch,
            tmp_path,
            net=net,
            probe=lambda cmd: (0, b"") if cmd[0] == "head" else (127, b"not found"),
        )
    net.remove.assert_called_once()


def test_clean_probe_comes_before_the_outbound_network(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    client = MagicMock()
    client.networks.get.side_effect = RuntimeError("no egress network")
    with pytest.raises(RuntimeError, match="could not attach"):
        _run(monkeypatch, tmp_path, net=_network(), probe=_probe({}), client=client)
    gateway = client.containers.run.return_value
    probed = {f"{c.args[0][-2]}:{c.args[0][-1]}" for c in gateway.exec_run.call_args_list}
    assert {"10.250.97.1:22", "10.250.97.1:7233", "10.250.97.1:5434"} <= probed
    client.networks.get.assert_called_once()


def test_extra_probe_ports_come_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECON_HOST_PROBE_PORTS", "8080, 22, x")
    assert host_isolation.probe_ports()[-1] == 8080
    assert host_isolation.probe_ports().count(22) == 1


def _probe_locally(address: str, port: int) -> str:
    result = subprocess.run(  # noqa: S603 - fixed argv, interpreter and constant script
        [sys.executable, "-c", host_isolation._PROBE_SCRIPT, address, str(port)],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


@pytest.mark.parametrize(
    ("family", "address"), [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]
)
def test_probe_script_sees_open_and_closed_ports_in_both_families(
    family: int, address: str
) -> None:
    listener = socket.socket(family)
    try:
        listener.bind((address, 0))
    except OSError:
        pytest.skip(f"{address} is not available here")
    listener.listen(1)
    port = listener.getsockname()[1]
    assert _probe_locally(address, port) == "REACHABLE"
    listener.close()
    assert _probe_locally(address, port) == "REFUSED"


def test_probe_script_reports_a_bad_address_as_an_error() -> None:
    assert _probe_locally("not-an-address.invalid", 22) == "ERROR"


def _targets(options: dict[str, str] | None = None, internal: bool = True) -> MagicMock:
    net = MagicMock()
    net.attrs = {
        "Name": "recon-targets",
        "Driver": "bridge",
        "Internal": internal,
        "Options": host_isolation.isolated_options() if options is None else options,
        "IPAM": {"Config": [{"Subnet": "10.250.98.0/28"}]},
    }
    return net


def _with_targets(monkeypatch: pytest.MonkeyPatch, targets: MagicMock | Exception) -> MagicMock:
    monkeypatch.setenv("RECON_TARGETS_NETWORK", "recon-targets")
    client = MagicMock()
    if isinstance(targets, Exception):
        client.networks.get.side_effect = targets
    else:
        client.networks.get.return_value = targets
    return client


def test_targets_network_is_verified_joined_and_probed_before_egress(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    targets = _targets()
    client = _with_targets(monkeypatch, targets)
    # The egress attach reuses networks.get and returns the same mock; stop there.
    targets.connect.side_effect = [None, RuntimeError("stop")]
    with pytest.raises(RuntimeError, match="could not attach"):
        _run(monkeypatch, tmp_path, net=_network(), probe=_probe({}), client=client)
    gateway = client.containers.run.return_value
    probed = {f"{c.args[0][-2]}:{c.args[0][-1]}" for c in gateway.exec_run.call_args_list}
    assert "10.250.98.1:22" in probed
    assert targets.connect.call_args_list[0].args == (gateway,)


def test_targets_network_without_isolation_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    targets = _targets(options={})
    client = _with_targets(monkeypatch, targets)
    net = _network()
    with pytest.raises(RuntimeError, match="not isolated"):
        _run(monkeypatch, tmp_path, net=net, probe=_probe({}), client=client)
    targets.connect.assert_not_called()
    client.containers.run.return_value.remove.assert_called_once_with(force=True)
    net.remove.assert_called_once()


def test_targets_network_that_reaches_the_host_aborts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    client = _with_targets(monkeypatch, _targets())
    net = _network()
    with pytest.raises(RuntimeError, match=r"reaches the host at 10\.250\.98\.1:22"):
        _run(
            monkeypatch,
            tmp_path,
            net=net,
            probe=_probe({"10.250.98.1:22": b"REACHABLE"}),
            client=client,
        )
    net.remove.assert_called_once()


def test_missing_targets_network_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    client = _with_targets(monkeypatch, docker.errors.NotFound("gone"))
    net = _network()
    with pytest.raises(RuntimeError, match="could not be verified and joined"):
        _run(monkeypatch, tmp_path, net=net, probe=_probe({}), client=client)
    net.remove.assert_called_once()


def test_targets_network_with_another_driver_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    targets = _targets()
    targets.attrs["Driver"] = "macvlan"
    client = _with_targets(monkeypatch, targets)
    with pytest.raises(RuntimeError, match="not bridge"):
        _run(monkeypatch, tmp_path, net=_network(), probe=_probe({}), client=client)
    targets.connect.assert_not_called()


def test_a_containers_own_address_is_not_probed_as_the_host() -> None:
    attrs = {
        "IPAM": {"Config": [{"Subnet": "10.250.97.0/29"}]},
        "Containers": {"abc": {"IPv4Address": "10.250.97.1/29"}},
    }
    assert host_isolation._host_addresses(attrs) == []
    attrs["Containers"] = {}
    assert host_isolation._host_addresses(attrs) == ["10.250.97.1"]


def test_no_probe_address_passes_only_for_an_isolated_network() -> None:
    container = MagicMock()
    owned = {"10.250.97.1/29": {"IPv4Address": "10.250.97.1/29"}}
    attrs = {
        "Name": "n",
        "Driver": "bridge",
        "Internal": True,
        "Options": host_isolation.isolated_options(),
        "IPAM": {"Config": [{"Subnet": "10.250.97.0/29"}]},
        "Containers": owned,
    }
    host_isolation.check_host_unreachable(container, attrs)
    container.exec_run.assert_not_called()
    attrs["Options"] = {}
    with pytest.raises(RuntimeError, match="not isolated"):
        host_isolation.check_host_unreachable(container, attrs)


def test_a_refusal_means_the_address_answers_and_aborts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    client = MagicMock()
    with pytest.raises(RuntimeError, match=r"reaches the host at 10\.250\.97\.1:4000"):
        _run(
            monkeypatch,
            tmp_path,
            net=_network(),
            probe=_probe({"10.250.97.1:4000": b"REFUSED"}),
            client=client,
        )
    client.networks.get.assert_not_called()
