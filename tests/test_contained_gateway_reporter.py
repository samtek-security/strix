"""The contained docker gateway must carry the control-plane escalation reporter."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import docker
import pytest

from strix.runtime import backends


URL = "http://control-plane.test:4001"
URL_VAR = "RECON_TARGET_HEALTH_REPORTER_URL"
TOKEN_VAR = "RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE"  # noqa: S105
USE_TOKEN_FILE = "use-token-file"  # noqa: S105


class _FakeNetwork:
    def __init__(self, name: str, labels: dict[str, str]) -> None:
        self.attrs = {
            "Name": name,
            "Driver": "bridge",
            "Internal": True,
            "Labels": labels,
            "Containers": {},
        }

    def reload(self) -> None:
        pass

    def remove(self) -> None:
        pass


class _FakeDocker:
    def __init__(self) -> None:
        self.run_calls: list[dict[str, Any]] = []
        self.networks = SimpleNamespace(create=self._create_network)
        self.volumes = SimpleNamespace(create=self._create_volume)
        self.containers = SimpleNamespace(run=self._run)

    def _create_network(self, name: str, **kw: Any) -> _FakeNetwork:
        return _FakeNetwork(name, kw["labels"])

    def _create_volume(self, labels: dict[str, str] | None = None, **_kw: Any) -> Any:
        labels = labels or {}
        return SimpleNamespace(
            attrs={"Labels": labels}, reload=lambda: None, remove=lambda **_: None
        )

    def _run(self, _image: str, **kw: Any) -> Any:
        self.run_calls.append(kw)
        return SimpleNamespace(remove=lambda **_: None)


@pytest.fixture
def fake_docker(monkeypatch: pytest.MonkeyPatch) -> _FakeDocker:
    fake = _FakeDocker()
    monkeypatch.setattr(docker, "from_env", lambda: fake)
    # Stop right after the gateway container is created; the agent is out of scope here.
    monkeypatch.setattr(backends, "_wait_gateway_ready", lambda *_a, **_k: False)
    for name in (
        "RECON_TARGET_HEALTH_REPORTER_URL",
        "RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE",
        "RECON_GATEWAY_CAPTURE",
    ):
        monkeypatch.delenv(name, raising=False)
    return fake


@pytest.fixture
def spec_file(tmp_path: Any) -> str:
    path = tmp_path / "engagement.json"
    path.write_text("{}")
    path.chmod(0o600)
    return str(path)


@pytest.fixture
def token_file(tmp_path: Any) -> str:
    path = tmp_path / "reporter-token"
    path.write_text("tok")
    path.chmod(0o600)
    return str(path)


def _start(spec_file: str) -> None:
    asyncio.run(
        backends._contained_docker_backend(
            image="agent:test",
            manifest=SimpleNamespace(),
            exposed_ports=(),
            scan_id="s1",
            gateway_spec_path=spec_file,
        )
    )


def test_gateway_gets_reporter_url_and_readonly_token_mount(
    fake_docker: _FakeDocker, spec_file: str, token_file: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECON_TARGET_HEALTH_REPORTER_URL", URL)
    monkeypatch.setenv("RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE", token_file)

    with pytest.raises(RuntimeError, match="not ready"):
        _start(spec_file)

    (call,) = fake_docker.run_calls
    env = call["environment"]
    assert env[URL_VAR] == URL
    mount_path = env[TOKEN_VAR]
    assert call["volumes"][str(Path(token_file).resolve())] == {"bind": mount_path, "mode": "ro"}


@pytest.mark.parametrize(
    ("url", "token", "missing"),
    [
        (None, None, [URL_VAR, TOKEN_VAR]),
        (URL, None, [TOKEN_VAR]),
        (None, USE_TOKEN_FILE, [URL_VAR]),
        ("  ", USE_TOKEN_FILE, [URL_VAR]),
        (URL, "  ", [TOKEN_VAR]),
    ],
)
def test_refuses_to_start_without_both_reporter_settings(
    fake_docker: _FakeDocker,
    spec_file: str,
    token_file: str,
    monkeypatch: pytest.MonkeyPatch,
    url: str | None,
    token: str | None,
    missing: list[str],
) -> None:
    if url is not None:
        monkeypatch.setenv("RECON_TARGET_HEALTH_REPORTER_URL", url)
    if token is not None:
        monkeypatch.setenv(
            "RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE",
            token_file if token == USE_TOKEN_FILE else token,
        )

    with pytest.raises(ValueError) as exc:
        _start(spec_file)

    for name in missing:
        assert name in str(exc.value)
    assert fake_docker.run_calls == []


def test_refuses_unreadable_token_file(
    fake_docker: _FakeDocker, spec_file: str, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECON_TARGET_HEALTH_REPORTER_URL", URL)
    monkeypatch.setenv("RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE", str(tmp_path / "absent"))

    with pytest.raises(ValueError, match="not a readable file"):
        _start(spec_file)
    assert fake_docker.run_calls == []
