# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""The gateway reports over its own Docker network, so the host can allow one subnet."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import docker
import pytest

from strix.runtime import backends, docker_client, gateway_staging, host_isolation, report_network


@pytest.fixture(autouse=True)
def _mount_in_place(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway_staging, "needs_staging", lambda *_a, **_k: False)


pytestmark = pytest.mark.real_report_network

NAME = "recon-gw-report"
SUBNET = "10.250.250.0/24"
SCAN = "scan-1"
BOUNDARY = {"recon.sandbox": "true", "recon.scan_id": SCAN, "recon.owner": "contained-egress"}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (report_network.ENV_NAME, report_network.ENV_SUBNET):
        monkeypatch.delenv(name, raising=False)


def _attrs(
    subnets: list[str] | None = None,
    *,
    driver: str = "bridge",
    internal: bool = True,
    gateway: str | None = "10.250.250.1",
    labels: dict[str, str] | None = None,
    containers: dict[str, Any] | None = None,
) -> dict[str, Any]:
    configs = [
        {"Subnet": s, "Gateway": gateway} for s in (subnets if subnets is not None else [SUBNET])
    ]
    return {
        "Name": NAME,
        "Driver": driver,
        "Internal": internal,
        "Labels": {"recon.role": "gateway-report-network"} if labels is None else labels,
        "IPAM": {"Config": configs},
        "Containers": containers or {},
    }


def _network(**kwargs: Any) -> MagicMock:
    net = MagicMock()
    net.attrs = _attrs(**kwargs)
    return net


def _dc(
    existing: MagicMock | None = None, labels: dict[str, dict[str, str]] | None = None
) -> MagicMock:
    dc = MagicMock()
    if existing is None:
        dc.networks.get.side_effect = docker.errors.NotFound("no such network")
    else:
        dc.networks.get.return_value = existing
    by_id = labels or {}

    def get_container(container_id: str) -> Any:
        if container_id not in by_id:
            raise docker.errors.NotFound("gone")
        return SimpleNamespace(labels=by_id[container_id])

    dc.containers.get.side_effect = get_container
    return dc


# settings -------------------------------------------------------------------------------------


def test_defaults() -> None:
    assert report_network.settings() == (NAME, SUBNET)
    assert report_network.gateway_address(SUBNET) == "10.250.250.1"


def test_name_and_subnet_are_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(report_network.ENV_NAME, "gw-report-b")
    monkeypatch.setenv(report_network.ENV_SUBNET, "10.250.251.0/24")
    assert report_network.settings() == ("gw-report-b", "10.250.251.0/24")
    assert report_network.gateway_address("10.250.251.0/24") == "10.250.251.1"


@pytest.mark.parametrize("name", ["-bad", "has space", "a/b", "x" * 65])
def test_invalid_name_is_refused(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    monkeypatch.setenv(report_network.ENV_NAME, name)
    with pytest.raises(ValueError, match="network name"):
        report_network.settings()


@pytest.mark.parametrize(
    "subnet", ["172.31.250.5/24", "not-a-subnet", "fd00::/64", "172.31.250.0/30", "172.31.250.0"]
)
def test_invalid_subnet_is_refused(monkeypatch: pytest.MonkeyPatch, subnet: str) -> None:
    monkeypatch.setenv(report_network.ENV_SUBNET, subnet)
    with pytest.raises(ValueError, match=r"subnet|/29"):
        report_network.settings()


# ensure_network -------------------------------------------------------------------------------


def test_creates_the_network_when_absent() -> None:
    dc = _dc()
    dc.networks.create.return_value = _network()

    net = report_network.ensure_network(dc, NAME, SUBNET)

    assert net is dc.networks.create.return_value
    args, kwargs = dc.networks.create.call_args
    assert args == (NAME,)
    assert kwargs["driver"] == "bridge"
    assert kwargs["labels"] == {"recon.role": "gateway-report-network"}
    pool = kwargs["ipam"]["Config"][0]
    assert pool["Subnet"] == SUBNET
    assert pool["Gateway"] == "10.250.250.1"
    assert kwargs["internal"] is True


def test_reuses_a_matching_network_without_creating() -> None:
    existing = _network()
    dc = _dc(existing)

    assert report_network.ensure_network(dc, NAME, SUBNET) is existing
    dc.networks.create.assert_not_called()


def test_refuses_an_existing_network_with_a_different_subnet() -> None:
    dc = _dc(_network(subnets=["10.9.0.0/24"]))
    with pytest.raises(RuntimeError, match=r"subnet 10\.9\.0\.0/24, expected 10\.250\.250\.0/24"):
        report_network.ensure_network(dc, NAME, SUBNET)


@pytest.mark.parametrize("subnets", [[], [SUBNET, "10.9.0.0/24"]])
def test_refuses_no_subnet_or_an_extra_subnet(subnets: list[str]) -> None:
    with pytest.raises(RuntimeError, match="expected"):
        report_network.ensure_network(_dc(_network(subnets=subnets)), NAME, SUBNET)


def test_refuses_a_network_that_is_not_internal() -> None:
    with pytest.raises(RuntimeError, match="not internal"):
        report_network.ensure_network(_dc(_network(internal=False)), NAME, SUBNET)


@pytest.mark.parametrize("gateway", ["10.250.250.254", None])
def test_refuses_a_network_whose_host_address_is_not_the_first_address(
    gateway: str | None,
) -> None:
    dc = _dc(_network(gateway=gateway))
    with pytest.raises(RuntimeError, match=r"host address .*, expected 10\.250\.250\.1"):
        report_network.ensure_network(dc, NAME, SUBNET)


@pytest.mark.parametrize("labels", [{}, {"recon.role": "agent-gateway-network"}, {"other": "x"}])
def test_refuses_a_network_without_the_ownership_label(labels: dict[str, str]) -> None:
    dc = _dc(_network(labels=labels))
    with pytest.raises(RuntimeError, match="was not created for gateway reporting"):
        report_network.ensure_network(dc, NAME, SUBNET)


def test_refuses_a_network_that_is_not_a_bridge() -> None:
    with pytest.raises(RuntimeError, match="not bridge"):
        report_network.ensure_network(_dc(_network(driver="overlay")), NAME, SUBNET)


def test_refuses_a_network_with_a_container_that_is_not_a_gateway() -> None:
    net = _network(containers={"abc123def4567": {}, "gw0000000001": {}})
    dc = _dc(
        net,
        labels={
            "abc123def4567": {"recon.role": "agent"},
            "gw0000000001": {"recon.role": "egress-gateway"},
        },
    )
    with pytest.raises(RuntimeError, match="not an egress gateway"):
        report_network.ensure_network(dc, NAME, SUBNET)


def test_accepts_gateway_containers_and_ignores_vanished_ones() -> None:
    net = _network(containers={"gw0000000001": {}, "gone00000001": {}})
    dc = _dc(net, labels={"gw0000000001": {"recon.role": "egress-gateway"}})
    assert report_network.ensure_network(dc, NAME, SUBNET) is net


def test_an_inspection_error_is_not_treated_as_a_vanished_container() -> None:
    net = _network(containers={"abc123def4567": {}})
    dc = _dc(net)
    dc.containers.get.side_effect = docker.errors.APIError("permission denied")
    with pytest.raises(docker.errors.APIError, match="permission denied"):
        report_network.ensure_network(dc, NAME, SUBNET)


def _other_network(name: str, subnet: str) -> SimpleNamespace:
    return SimpleNamespace(name=name, attrs={"IPAM": {"Config": [{"Subnet": subnet}]}})


def test_creation_over_an_overlapping_network_is_refused_and_names_it() -> None:
    dc = _dc()
    dc.networks.list.return_value = [
        _other_network("bridge", "172.17.0.0/16"),
        _other_network("recon-net-eng-x", "10.250.0.0/16"),
    ]
    with pytest.raises(
        RuntimeError, match=r"overlaps Docker network 'recon-net-eng-x' \(10\.250\.0\.0/16\)"
    ):
        report_network.ensure_network(dc, NAME, SUBNET)
    dc.networks.create.assert_not_called()


def test_creation_ignores_networks_that_do_not_overlap() -> None:
    dc = _dc()
    dc.networks.list.return_value = [
        _other_network("bridge", "172.17.0.0/16"),
        _other_network("ipv6", "fd00::/64"),
        _other_network("empty", ""),
    ]
    dc.networks.create.return_value = _network()
    assert report_network.ensure_network(dc, NAME, SUBNET) is dc.networks.create.return_value


def test_a_lost_creation_race_is_resolved_by_verifying_the_winner() -> None:
    winner = _network()
    dc = MagicMock()
    dc.networks.get.side_effect = [docker.errors.NotFound("absent"), winner]
    dc.networks.create.side_effect = docker.errors.APIError("already exists")

    assert report_network.ensure_network(dc, NAME, SUBNET) is winner


def test_a_failed_creation_with_no_network_is_a_clear_refusal() -> None:
    dc = MagicMock()
    dc.networks.get.side_effect = docker.errors.NotFound("absent")
    dc.networks.create.side_effect = docker.errors.APIError("Pool overlaps with other one")
    with pytest.raises(RuntimeError, match="could not create gateway report network"):
        report_network.ensure_network(dc, NAME, SUBNET)


# the backend ----------------------------------------------------------------------------------


class _StopAtAgentError(Exception):
    """Raised when the backend reaches the agent step, after the gateway is fully attached."""


def _engagement_network() -> MagicMock:
    net = MagicMock()
    net.attrs = {
        "Name": f"recon-net-{SCAN}",
        "Driver": "bridge",
        "Internal": True,
        "Labels": {**BOUNDARY, "recon.role": "agent-gateway-network"},
        "Containers": {},
        "Options": host_isolation.isolated_options(),
        "IPAM": {"Config": [{"Subnet": "10.250.97.0/29"}]},
    }
    return net


def _start(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, *, report: MagicMock, egress: MagicMock
) -> tuple[MagicMock, MagicMock]:
    spec = tmp_path / "gateway.json"
    spec.write_text("{}")
    spec.chmod(0o600)
    token = tmp_path / "reporter-token"
    token.write_text("t" * 32)
    token.chmod(0o600)
    monkeypatch.setenv("RECON_TARGET_HEALTH_REPORTER_URL", "http://10.250.250.1:8090")
    monkeypatch.setenv("RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE", str(token))
    monkeypatch.setenv("RECON_EGRESS_NETWORK", "bridge")
    monkeypatch.delenv("RECON_GATEWAY_CAPTURE", raising=False)
    monkeypatch.delenv("RECON_TARGETS_NETWORK", raising=False)
    volume = MagicMock()
    volume.attrs = {"Labels": {**BOUNDARY, "recon.role": "gateway-ca-volume"}}
    gateway = MagicMock()
    gateway.exec_run.return_value = (0, b"CLOSED")
    client = MagicMock()
    client.version.return_value = {"Version": "29.9.2"}
    client.networks.create.return_value = _engagement_network()
    client.networks.get.side_effect = lambda name: report if name == NAME else egress
    client.volumes.create.return_value = volume
    client.containers.run.return_value = gateway
    monkeypatch.setattr(docker, "from_env", lambda: client)
    monkeypatch.setattr(backends, "_wait_gateway_ready", lambda *_a, **_k: True)

    def _stop(_dc: Any) -> None:
        raise _StopAtAgentError

    # Stop once the gateway is attached; the agent is out of scope here.
    monkeypatch.setattr(docker_client, "ReconDockerSandboxClient", _stop)
    return client, gateway


def _run_backend(tmp_path: Any) -> None:
    asyncio.run(
        backends._contained_docker_backend(
            image="agent:1",
            manifest=SimpleNamespace(),
            exposed_ports=(),
            scan_id=SCAN,
            gateway_spec_path=str(tmp_path / "gateway.json"),
        )
    )


def test_a_mismatched_report_network_is_refused_before_any_resource_exists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    egress = MagicMock()
    client, _gateway = _start(
        monkeypatch, tmp_path, report=_network(subnets=["10.9.0.0/24"]), egress=egress
    )

    with pytest.raises(RuntimeError, match=r"expected 10\.250\.250\.0/24"):
        _run_backend(tmp_path)

    client.networks.create.assert_not_called()
    client.volumes.create.assert_not_called()
    client.containers.run.assert_not_called()


def test_the_gateway_joins_the_report_network_after_the_egress_network(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    order: list[str] = []
    egress = MagicMock()
    egress.connect.side_effect = lambda _gw: order.append("egress")
    report = _network()
    report.connect.side_effect = lambda _gw: order.append("report")
    _client, gateway = _start(monkeypatch, tmp_path, report=report, egress=egress)

    with pytest.raises(_StopAtAgentError):
        _run_backend(tmp_path)

    assert order == ["egress", "report"]
    report.connect.assert_called_once_with(gateway)


def test_a_failed_report_attach_removes_the_gateway_and_refuses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    report = _network()
    report.connect.side_effect = docker.errors.APIError("no such network")
    _client, gateway = _start(monkeypatch, tmp_path, report=report, egress=MagicMock())

    with pytest.raises(RuntimeError, match="could not attach report network 'recon-gw-report'"):
        _run_backend(tmp_path)

    gateway.remove.assert_called_once_with(force=True)
