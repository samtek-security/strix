# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""The contained docker gateway must carry the control-plane escalation reporter."""

from __future__ import annotations

import asyncio
import os
import random
import string
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import docker
import pytest

from strix.runtime import backends, gateway_staging, host_isolation


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
            "Options": host_isolation.isolated_options(),
            "IPAM": {"Config": [{"Subnet": "10.250.97.0/29"}]},
        }

    def reload(self) -> None:
        pass

    def remove(self) -> None:
        pass


class _FakeDocker:
    def __init__(self) -> None:
        self.run_calls: list[dict[str, Any]] = []
        self.exec_code = 0
        self.networks = SimpleNamespace(create=self._create_network, list=lambda **_: [])
        self.version = lambda: {"Version": "29.9.2"}
        self.volumes = SimpleNamespace(
            create=self._create_volume, get=self._no_volume, list=lambda **_: []
        )
        self.containers = SimpleNamespace(run=self._run, list=lambda **_: [])

    def _no_volume(self, _name: str) -> Any:
        raise docker.errors.NotFound("no such volume")

    def _create_network(self, name: str, **kw: Any) -> _FakeNetwork:
        return _FakeNetwork(name, kw["labels"])

    def _create_volume(self, labels: dict[str, str] | None = None, **_kw: Any) -> Any:
        labels = labels or {}
        return SimpleNamespace(
            attrs={"Labels": labels}, reload=lambda: None, remove=lambda **_: None
        )

    def exec_run(self, _cmd: list[str]) -> tuple[int, bytes]:
        return self.exec_code, b""

    def _run(self, _image: str, **kw: Any) -> Any:
        self.run_calls.append(kw)
        return SimpleNamespace(remove=lambda **_: None, exec_run=self.exec_run)


@pytest.fixture
def fake_docker(monkeypatch: pytest.MonkeyPatch) -> _FakeDocker:
    fake = _FakeDocker()
    monkeypatch.setattr(docker, "from_env", lambda: fake)
    # Stop right after the gateway container is created; the agent is out of scope here.
    monkeypatch.setattr(backends, "_wait_gateway_ready", lambda *_a, **_k: False)
    # These tests cover the in-place mount; staging has its own file.
    monkeypatch.setattr(gateway_staging, "needs_staging", lambda *_a, **_k: False)
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
    path.write_text("t" * 32)
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


@pytest.mark.parametrize("content", ["", "  \n", "short-token"])
def test_refuses_empty_or_short_token_file(
    fake_docker: _FakeDocker,
    spec_file: str,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    content: str,
) -> None:
    path = tmp_path / "weak-token"
    path.write_text(content)
    path.chmod(0o600)
    monkeypatch.setenv(URL_VAR, URL)
    monkeypatch.setenv(TOKEN_VAR, str(path))

    with pytest.raises(ValueError, match=r"fewer than 32 bytes|printable ASCII"):
        _start(spec_file)
    assert fake_docker.run_calls == []


@pytest.mark.parametrize(
    "url",
    [
        "control-plane:4001",
        "ftp://control-plane",
        "http://",
        "/api",
        "http://control-plane:abc",
        "http://control-plane:70000",
        "http://control-plane:4001/?x=1",
        "http://control-plane:4001/#frag",
        "http://control-plane:4001/?",
        "http://control-plane:4001/#",
        "http://control plane:4001",
        "http://user:pw@control-plane:4001",
        "http://control-plane:4001/a\tb",
    ],
)
def test_refuses_a_reporter_url_without_http_scheme_and_host(
    fake_docker: _FakeDocker,
    spec_file: str,
    token_file: str,
    monkeypatch: pytest.MonkeyPatch,
    url: str,
) -> None:
    monkeypatch.setenv(URL_VAR, url)
    monkeypatch.setenv(TOKEN_VAR, token_file)

    with pytest.raises(ValueError, match=r"http|valid URL"):
        _start(spec_file)
    assert fake_docker.run_calls == []


def test_refuses_a_token_file_open_to_group_or_other(
    fake_docker: _FakeDocker, spec_file: str, token_file: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    Path(token_file).chmod(0o640)
    monkeypatch.setenv(URL_VAR, URL)
    monkeypatch.setenv(TOKEN_VAR, token_file)

    with pytest.raises(ValueError, match="not accessible by group or other"):
        _start(spec_file)
    assert fake_docker.run_calls == []


def test_refuses_to_start_the_agent_when_the_gateway_cannot_read_the_token(
    fake_docker: _FakeDocker, spec_file: str, token_file: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(backends, "_wait_gateway_ready", lambda *_a, **_k: True)
    fake_docker.exec_code = 1
    monkeypatch.setenv(URL_VAR, URL)
    monkeypatch.setenv(TOKEN_VAR, token_file)

    with pytest.raises(RuntimeError, match="cannot read the escalation token"):
        _start(spec_file)


def test_refuses_a_token_path_that_is_not_a_regular_file(
    fake_docker: _FakeDocker, spec_file: str, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fifo = tmp_path / "token-fifo"
    os.mkfifo(fifo, 0o600)
    monkeypatch.setenv(URL_VAR, URL)
    monkeypatch.setenv(TOKEN_VAR, str(fifo))

    with pytest.raises(ValueError, match="not a regular file"):
        _start(spec_file)
    assert fake_docker.run_calls == []


@pytest.mark.parametrize(
    "content", ["a" * 20 + "\n" + "b" * 20, "a" * 20 + " " + "b" * 20, "é" * 20]
)
def test_refuses_a_token_that_is_not_a_single_header_safe_line(
    fake_docker: _FakeDocker,
    spec_file: str,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    content: str,
) -> None:
    path = tmp_path / "multiline-token"
    path.write_text(content)
    path.chmod(0o600)
    monkeypatch.setenv(URL_VAR, URL)
    monkeypatch.setenv(TOKEN_VAR, str(path))

    with pytest.raises(ValueError, match="printable ASCII"):
        _start(spec_file)
    assert fake_docker.run_calls == []


ACCEPTED_URLS = [
    "http://control-plane:4001",
    "https://recon-api.example.gov",
    "http://127.0.0.1:4001",
    "http://[::1]:4001",
    "http://" + "a" * 63 + ".example:4001",
    "http://a-b.c-d.e:4001",
    "http://control-plane:4001/",
    "http://control-plane:4001/api/v1",
    "http://cp.internal.example:80/a_b-c.d~e",
]

# Every shape the second reviewer raised in rounds 2-5, plus the neighbours the rebuild catches.
REJECTED_URLS = [
    "",
    "control-plane:4001",
    "ftp://control-plane",
    "http://",
    "/api",
    "http://control-plane:abc",
    "http://control-plane:70000",
    "http://control-plane:0",
    "http://control-plane:04001",
    "http://control-plane:4001/?x=1",
    "http://control-plane:4001/#frag",
    "http://control-plane:4001/?",
    "http://control-plane:4001/#",
    "http://control plane:4001",
    "http://control-plane:4001/a b",
    "http://control-plane:4001/a\tb",
    "http://control-plane:4001\n",
    " http://control-plane:4001",
    "http://control-plane:4001 ",
    "http://user:pw@control-plane:4001",
    "http://user@control-plane:4001",
    "http://Control-Plane:4001",
    "HTTP://control-plane:4001",
    "http://control-plane:4001/%2e%2e",
    "http://control-plane:4001/a;b",
    "http://control-plane:4001\\evil",
    "http://control-plane:4001//",
    "http://-bad:4001",
    "http://a..b:4001",
    "http://.a:4001",
    "http://a-.b:4001",
    "http://" + "a" * 64 + ":4001",
    "http://" + ".".join(["a" * 63] * 4) + ":4001",
    "http://control-plane.:4001/x?",
    "http://\u00e9.example:4001",
]


@pytest.mark.parametrize("url", ACCEPTED_URLS)
def test_canonical_reporter_url_accepts_the_allowlist(url: str) -> None:
    assert backends._canonical_reporter_url(url) == url


@pytest.mark.parametrize("url", REJECTED_URLS)
def test_canonical_reporter_url_rejects_everything_else(url: str) -> None:
    with pytest.raises(ValueError, match="REPORTER_URL"):
        backends._canonical_reporter_url(url)


def _random_url(rng: random.Random) -> str:
    label = string.ascii_lowercase + string.digits
    host = ".".join(
        "".join(rng.choice(label) for _ in range(rng.randint(1, 8)))
        for _ in range(rng.randint(1, 3))
    )
    port = f":{rng.randint(1, 65535)}" if rng.random() < 0.7 else ""
    path = "".join(
        "/" + "".join(rng.choice(string.ascii_letters + "._~-") for _ in range(rng.randint(1, 6)))
        for _ in range(rng.randint(0, 3))
    )
    return f"{rng.choice(['http', 'https'])}://{host}{port}{path}"


def test_round_trip_property_over_generated_and_mutated_urls() -> None:
    rng = random.Random(164)  # noqa: S311  (fixed seed, test data only)
    noise = list(" \t\n\r?#@%;\\:[]\x00\x7f\u00e9ABC.")
    for _ in range(2000):
        url = _random_url(rng)
        # Every generated URL on the allowlist round-trips to itself.
        assert backends._canonical_reporter_url(url) == url
        # A mutated one is either refused, or accepted only as its own canonical form.
        pos = rng.randint(0, len(url))
        mutated = url[:pos] + rng.choice(noise) + url[pos:]
        try:
            accepted = backends._canonical_reporter_url(mutated)
        except ValueError:
            continue
        assert accepted == mutated
        assert not any(ch in accepted for ch in " \t\n\r?#@\\\x00\x7f")


@pytest.mark.parametrize(
    "content",
    [
        " " + "a" * 40,
        "a" * 40 + " ",
        "\t" + "a" * 40,
        "a" * 40 + "\t\n",
        "a" * 40 + "\r\n",
        "a" * 40 + "\n\n",
    ],
)
def test_refuses_a_token_with_surrounding_whitespace(
    fake_docker: _FakeDocker,
    spec_file: str,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    content: str,
) -> None:
    path = tmp_path / "padded-token"
    path.write_text(content)
    path.chmod(0o600)
    monkeypatch.setenv(URL_VAR, URL)
    monkeypatch.setenv(TOKEN_VAR, str(path))

    with pytest.raises(ValueError, match="printable ASCII"):
        _start(spec_file)
    assert fake_docker.run_calls == []


@pytest.mark.parametrize("terminator", ["\n", ""])
def test_accepts_a_token_with_only_a_line_terminator(
    fake_docker: _FakeDocker,
    spec_file: str,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    terminator: str,
) -> None:
    path = tmp_path / "terminated-token"
    path.write_text("a" * 40 + terminator)
    path.chmod(0o600)
    monkeypatch.setenv(URL_VAR, URL)
    monkeypatch.setenv(TOKEN_VAR, str(path))

    with pytest.raises(RuntimeError, match="not ready"):
        _start(spec_file)
    assert len(fake_docker.run_calls) == 1


def test_a_transport_error_during_the_token_probe_cleans_up_the_boundary(
    fake_docker: _FakeDocker, spec_file: str, token_file: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    removed: list[str] = []
    monkeypatch.setattr(backends, "_wait_gateway_ready", lambda *_a, **_k: True)

    def _broken_exec(_cmd: list[str]) -> tuple[int, bytes]:
        raise ConnectionError("docker daemon went away")

    fake_docker.exec_run = _broken_exec  # type: ignore[method-assign]
    fake_docker.networks.get = None  # the run must not reach the network attach
    monkeypatch.setattr(
        fake_docker,
        "_run",
        lambda _i, **kw: (
            fake_docker.run_calls.append(kw)
            or SimpleNamespace(remove=lambda **_: removed.append("gateway"), exec_run=_broken_exec)
        ),
    )
    fake_docker.containers.run = fake_docker._run
    monkeypatch.setenv(URL_VAR, URL)
    monkeypatch.setenv(TOKEN_VAR, token_file)

    with pytest.raises(ConnectionError, match="went away"):
        _start(spec_file)
    assert removed == ["gateway"]
