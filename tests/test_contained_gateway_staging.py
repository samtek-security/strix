# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""A worker whose UID is not the gateway's can still start the contained backend.

The worker-side checks stay strict (own the files, closed to group and other). The gateway reads
copies staged for its own UID in a per-launch volume that the agent never mounts.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import docker
import pytest
from agents.sandbox.sandboxes.docker import DockerSandboxClient

from strix.runtime import backends, gateway_staging, host_isolation
from strix.runtime.docker_client import StrixDockerSandboxClient


URL = "http://control-plane.test:4001"
OTHER_UID = os.geteuid() + 1


class _Volume:
    def __init__(self, name: str, labels: dict[str, str]) -> None:
        self.name = name
        self.attrs = {"Labels": labels}
        self.removed = False

    def reload(self) -> None:
        pass

    def remove(self, **_kw: Any) -> None:
        self.removed = True


class _Network:
    def __init__(self, name: str, labels: dict[str, str]) -> None:
        self.attrs = {
            "Name": name,
            "Driver": "bridge",
            "Internal": True,
            "Labels": labels,
            "Containers": {},
            "Options": host_isolation.isolated_options(),
            "IPAM": {"Config": [{"Subnet": "10.250.97.0/29"}]},
        }
        self.removed = False

    def reload(self) -> None:
        pass

    def remove(self) -> None:
        self.removed = True


class _FakeDocker:
    def __init__(self) -> None:
        self.helper_calls: list[dict[str, Any]] = []
        self.gateway_calls: list[dict[str, Any]] = []
        self.volumes_made: list[_Volume] = []
        self.networks_made: list[_Network] = []
        self.stale: list[_Volume] = []
        self.list_filters: list[dict[str, Any]] = []
        self.helper_error: Exception | None = None
        self.helper_status = 0
        self.version = lambda: {"Version": "29.9.2"}
        self.networks = SimpleNamespace(create=self._net)
        self.volumes = SimpleNamespace(create=self._vol, list=self._list)
        self.containers = SimpleNamespace(run=self._run, list=self._list_containers)
        self.stale_helpers: list[SimpleNamespace] = []
        self.container_filters: list[dict[str, Any]] = []
        self.helpers_removed = 0

    def _net(self, name: str, **kw: Any) -> _Network:
        net = _Network(name, kw["labels"])
        self.networks_made.append(net)
        return net

    def _vol(self, name: str, labels: dict[str, str] | None = None, **_kw: Any) -> _Volume:
        volume = _Volume(name, labels or {})
        self.volumes_made.append(volume)
        return volume

    def _list(self, filters: dict[str, Any] | None = None) -> list[_Volume]:
        self.list_filters.append(filters or {})
        return self.stale

    def _list_containers(self, filters: dict[str, Any] | None = None, **_kw: Any) -> list:
        self.container_filters.append(filters or {})
        return self.stale_helpers

    def _run(self, _image: str, **kw: Any) -> Any:
        if "entrypoint" in kw:
            self.helper_calls.append({"image": _image, **kw})
            if self.helper_error is not None:
                raise self.helper_error
            return SimpleNamespace(
                wait=lambda **_kw: {"StatusCode": self.helper_status},
                remove=lambda **_kw: setattr(self, "helpers_removed", self.helpers_removed + 1),
            )
        self.gateway_calls.append(kw)
        return SimpleNamespace(
            remove=lambda **_: None, exec_run=lambda _cmd: (0, b""), name=kw.get("name")
        )


@pytest.fixture
def fake_docker(monkeypatch: pytest.MonkeyPatch) -> _FakeDocker:
    fake = _FakeDocker()
    monkeypatch.setattr(docker, "from_env", lambda: fake)
    monkeypatch.setattr(backends, "_wait_gateway_ready", lambda *_a, **_k: False)
    monkeypatch.setattr(gateway_staging, "gateway_uid", lambda: OTHER_UID)
    monkeypatch.setenv("RECON_TARGET_HEALTH_REPORTER_URL", URL)
    monkeypatch.delenv("RECON_GATEWAY_CAPTURE", raising=False)
    monkeypatch.delenv("RECON_ENGAGEMENT_ID", raising=False)
    return fake


@pytest.fixture
def files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[str, str]:
    spec = tmp_path / "engagement.json"
    spec.write_text("{}")
    spec.chmod(0o600)
    token = tmp_path / "reporter-token"
    token.write_text("t" * 32)
    token.chmod(0o600)
    monkeypatch.setenv("RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE", str(token))
    return str(spec), str(token.resolve())


def _start(spec: str, scan_id: str = "s1") -> None:
    asyncio.run(
        backends._contained_docker_backend(
            image="agent:test",
            manifest=SimpleNamespace(),
            exposed_ports=(),
            scan_id=scan_id,
            gateway_spec_path=spec,
        )
    )


def test_staged_launch_gives_the_gateway_its_own_read_only_copies(
    fake_docker: _FakeDocker, files: tuple[str, str]
) -> None:
    spec, token = files
    with pytest.raises(RuntimeError, match="not ready"):
        _start(spec)

    (helper,) = fake_docker.helper_calls
    assert helper["user"] == "0"
    assert helper["network_mode"] == "none"
    assert helper["cap_drop"] == ["ALL"]
    assert set(helper["cap_add"]) == {"CHOWN", "DAC_OVERRIDE", "FOWNER"}
    assert helper["security_opt"] == ["no-new-privileges"]
    assert helper["read_only"] is True
    assert "auto_remove" not in helper
    assert fake_docker.helpers_removed == 1
    assert helper["detach"] is True
    assert helper["command"][-1] == str(OTHER_UID)
    script = helper["command"][0]
    assert "umask 0277" in script
    assert "chmod 0400" in script
    assert helper["volumes"][spec]["mode"] == "ro"
    assert helper["volumes"][token]["mode"] == "ro"

    (gateway,) = fake_docker.gateway_calls
    (stage,) = [v for v in fake_docker.volumes_made if v.name.startswith("recon-gwstage-")]
    assert gateway["volumes"][stage.name] == {"bind": gateway_staging.STAGE_MOUNT, "mode": "ro"}
    # Neither worker-owned file is mounted into the gateway directly.
    assert spec not in gateway["volumes"]
    assert token not in gateway["volumes"]
    env = gateway["environment"]
    assert env["RECON_ENGAGEMENT_SPEC"] == f"{gateway_staging.STAGE_MOUNT}/engagement.json"
    assert env["RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE"].startswith(gateway_staging.STAGE_MOUNT)


def test_stock_gateway_image_does_the_staging(
    fake_docker: _FakeDocker, files: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECON_EGRESS_GATEWAY_IMAGE", "recon/egress-gateway:stock")
    with pytest.raises(RuntimeError, match="not ready"):
        _start(files[0])
    assert fake_docker.helper_calls[0]["image"] == "recon/egress-gateway:stock"


def test_every_launch_stages_into_a_new_labelled_volume(
    fake_docker: _FakeDocker, files: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECON_ENGAGEMENT_ID", "eng-9")
    for _ in range(2):
        with pytest.raises(RuntimeError, match="not ready"):
            _start(files[0], scan_id="s7")

    staged = [v for v in fake_docker.volumes_made if v.name.startswith("recon-gwstage-")]
    assert len(staged) == 2
    assert staged[0].name != staged[1].name
    for volume in staged:
        labels = volume.attrs["Labels"]
        assert labels["recon.role"] == gateway_staging.STAGE_ROLE
        assert labels["recon.scan_id"] == "s7"
        assert labels["recon.engagement_id"] == "eng-9"
        assert labels["recon.run_id"] in volume.name
        assert labels["recon.sandbox"] == "true"
        assert volume.removed, "a failed launch must not leave staged secrets behind"


def test_stale_staging_volumes_of_this_engagement_are_swept_on_the_next_launch(
    fake_docker: _FakeDocker, files: tuple[str, str]
) -> None:
    leftover = _Volume("recon-gwstage-s1-dead", {"recon.scan_id": "s1"})
    fake_docker.stale = [leftover]
    dead_helper = SimpleNamespace(remove=lambda **_kw: setattr(leftover, "helper_gone", True))
    fake_docker.stale_helpers = [dead_helper]
    with pytest.raises(RuntimeError, match="not ready"):
        _start(files[0])

    assert leftover.removed
    assert getattr(leftover, "helper_gone", False)
    (helper_filters,) = fake_docker.container_filters
    assert sorted(helper_filters["label"]) == [
        f"recon.role={gateway_staging.HELPER_ROLE}",
        "recon.scan_id=s1",
    ]
    (filters,) = fake_docker.list_filters
    assert filters["label"] == [f"recon.role={gateway_staging.STAGE_ROLE}"]


def test_staging_failure_fails_closed_before_the_gateway_exists(
    fake_docker: _FakeDocker, files: tuple[str, str]
) -> None:
    fake_docker.helper_status = 1
    with pytest.raises(RuntimeError, match="could not stage"):
        _start(files[0])

    assert fake_docker.gateway_calls == []
    assert all(v.removed for v in fake_docker.volumes_made)
    assert all(n.removed for n in fake_docker.networks_made)


def test_helper_start_error_fails_closed_too(
    fake_docker: _FakeDocker, files: tuple[str, str]
) -> None:
    fake_docker.helper_error = docker.errors.APIError("daemon down")
    with pytest.raises(RuntimeError, match="could not stage"):
        _start(files[0])
    assert fake_docker.gateway_calls == []
    assert all(v.removed for v in fake_docker.volumes_made)


def test_capture_setup_error_leaves_no_staged_volume(
    fake_docker: _FakeDocker, files: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken_token(_secret: str, _scan_id: str) -> str:
        raise RuntimeError("token generation failed")

    package = types.ModuleType("recon_engine.backends.capture_token")
    package.capture_capability_token = broken_token  # type: ignore[attr-defined]
    for name in ("recon_engine", "recon_engine.backends"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, "recon_engine.backends.capture_token", package)
    monkeypatch.setenv("RECON_GATEWAY_CAPTURE", "1")
    monkeypatch.setenv("RECON_SESSION_SECRET", "s" * 32)

    with pytest.raises(RuntimeError, match="token generation failed"):
        _start(files[0])

    assert fake_docker.helper_calls == []
    assert fake_docker.gateway_calls == []
    assert not any(v.name.startswith("recon-gwstage-") for v in fake_docker.volumes_made)


def test_worker_side_checks_are_not_loosened(
    fake_docker: _FakeDocker, files: tuple[str, str]
) -> None:
    spec, _token = files
    Path(spec).chmod(0o640)
    with pytest.raises(ValueError, match="must not be accessible by group or other"):
        _start(spec)
    assert fake_docker.helper_calls == []
    assert fake_docker.gateway_calls == []


def test_a_worker_that_is_the_gateway_uid_mounts_in_place(
    fake_docker: _FakeDocker, files: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gateway_staging, "gateway_uid", os.geteuid)
    spec, token = files
    with pytest.raises(RuntimeError, match="not ready"):
        _start(spec)

    assert fake_docker.helper_calls == []
    (gateway,) = fake_docker.gateway_calls
    assert gateway["volumes"][spec] == {"bind": "/etc/recon/engagement.json", "mode": "ro"}
    assert gateway["volumes"][token]["mode"] == "ro"
    assert "RECON_ENGAGEMENT_SPEC" not in gateway["environment"]


@pytest.mark.parametrize("raw", ["abc", "0", "-5"])
def test_invalid_gateway_uid_is_rejected(raw: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECON_GATEWAY_UID", raw)
    with pytest.raises(ValueError, match="RECON_GATEWAY_UID"):
        gateway_staging.gateway_uid()


def test_gateway_uid_defaults_to_the_stock_image(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("RECON_GATEWAY_UID", raising=False)
    assert gateway_staging.gateway_uid() == 10001


def test_teardown_removes_the_staging_volume() -> None:
    client = StrixDockerSandboxClient.__new__(StrixDockerSandboxClient)
    client.docker_client = MagicMock()
    client.recon_gateway_stage_volume = MagicMock()
    session = SimpleNamespace(_inner=SimpleNamespace(state=SimpleNamespace(container_id=None)))

    with patch.object(DockerSandboxClient, "delete", new=AsyncMock(return_value=session)):
        asyncio.run(client.delete(session))  # type: ignore[arg-type]

    client.recon_gateway_stage_volume.remove.assert_called_once_with(force=True)


@pytest.mark.parametrize("raw", ["abc", "0", "-5"])
def test_bad_gateway_uid_fails_before_any_docker_resource(
    raw: str, fake_docker: _FakeDocker, files: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.undo()
    monkeypatch.setattr(docker, "from_env", lambda: fake_docker)
    monkeypatch.setenv("RECON_TARGET_HEALTH_REPORTER_URL", URL)
    monkeypatch.setenv("RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE", files[1])
    monkeypatch.setenv("RECON_GATEWAY_UID", raw)
    with pytest.raises(ValueError, match="RECON_GATEWAY_UID"):
        _start(files[0])
    assert fake_docker.networks_made == []
    assert fake_docker.volumes_made == []


def test_sweep_removes_expired_volumes_of_other_engagements_but_not_live_ones(
    fake_docker: _FakeDocker,
) -> None:
    now = time.time()
    expired = _Volume("old", {"recon.scan_id": "other", "recon.ttl_deadline": str(int(now - 5))})
    live = _Volume("live", {"recon.scan_id": "other2", "recon.ttl_deadline": str(int(now + 600))})
    fake_docker.stale = [expired, live]

    gateway_staging.sweep_stale(fake_docker, {"recon.scan_id": "s1"})

    assert expired.removed
    assert not live.removed


def test_staging_volume_carries_a_ttl_deadline(
    fake_docker: _FakeDocker, files: tuple[str, str]
) -> None:
    with pytest.raises(RuntimeError, match="not ready"):
        _start(files[0])
    (volume,) = [v for v in fake_docker.volumes_made if v.name.startswith("recon-gwstage-")]
    labels = volume.attrs["Labels"]
    assert int(labels["recon.ttl_deadline"]) > int(labels["recon.created_at"])
