# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
from __future__ import annotations

import io
import tarfile
from typing import TYPE_CHECKING, Any

import pytest

from strix.runtime import session_manager
from strix.runtime.backends import _BACKENDS, register_backend


if TYPE_CHECKING:
    from pathlib import Path


class _Session:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple[bytes, list[str]]] = []

    async def resolve_exposed_port(self, port: int) -> Any:
        return type("Endpoint", (), {"host": "127.0.0.1", "port": port, "tls": False})()

    async def hydrate_sources(self, data: io.IOBase, subdirs: list[str]) -> None:
        if self.fail:
            raise RuntimeError("tar stream refused")
        self.calls.append((data.read(), subdirs))


def _tree(tmp_path: Path, name: str = "app") -> dict[str, Any]:
    root = tmp_path / name
    root.mkdir()
    (root / "main.py").write_text("print('hi')\n")
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text("x")
    return {"workspace_subdir": name, "source_path": str(root), "mount": False}


@pytest.mark.asyncio
async def test_all_sources_travel_in_one_tar_stream(tmp_path: Path) -> None:
    session = _Session()
    await session_manager._hydrate_k8s_sources(
        session, [_tree(tmp_path, "app"), _tree(tmp_path, "lib")]
    )
    assert len(session.calls) == 1
    data, subdirs = session.calls[0]
    assert subdirs == ["app", "lib"]
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        names = tf.getnames()
    assert "app/main.py" in names and "lib/main.py" in names
    assert not any(".git" in n.split("/") for n in names)


@pytest.mark.asyncio
async def test_each_source_carries_its_own_hard_linked_files(tmp_path: Path) -> None:
    app, lib = _tree(tmp_path, "app"), _tree(tmp_path, "lib")
    (tmp_path / "lib" / "shared.py").hardlink_to(tmp_path / "app" / "main.py")
    session = _Session()
    await session_manager._hydrate_k8s_sources(session, [app, lib])
    with tarfile.open(fileobj=io.BytesIO(session.calls[0][0])) as tf:
        assert tf.getmember("lib/shared.py").isreg()


@pytest.mark.asyncio
async def test_links_inside_a_source_become_relative(tmp_path: Path) -> None:
    source = _tree(tmp_path, "checkout")
    source["workspace_subdir"] = "app"
    root = tmp_path / "checkout"
    (root / "pkg").mkdir()
    (root / "pkg" / "absolute").symlink_to(root / "main.py")
    (root / "pkg" / "round_trip").symlink_to("../../checkout/main.py")
    (root / "outside").symlink_to("/etc/hostname")
    session = _Session()
    await session_manager._hydrate_k8s_sources(session, [source])
    with tarfile.open(fileobj=io.BytesIO(session.calls[0][0])) as tf:
        assert tf.getmember("app/pkg/absolute").linkname == "../main.py"
        assert tf.getmember("app/pkg/round_trip").linkname == "../main.py"
        # Left for the backend to refuse.
        assert tf.getmember("app/outside").linkname == "/etc/hostname"


@pytest.mark.asyncio
async def test_hydration_error_is_raised(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="tar stream refused"):
        await session_manager._hydrate_k8s_sources(_Session(fail=True), [_tree(tmp_path)])


@pytest.mark.asyncio
async def test_missing_source_path_is_raised(tmp_path: Path) -> None:
    gone = {"workspace_subdir": "app", "source_path": str(tmp_path / "gone"), "mount": False}
    with pytest.raises(FileNotFoundError):
        await session_manager._hydrate_k8s_sources(_Session(), [gone])


@pytest.mark.asyncio
async def test_opt_out_skips_hydration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECON_MOUNT_SOURCE", "0")
    session = _Session()
    await session_manager._hydrate_k8s_sources(session, [_tree(tmp_path)])
    assert session.calls == []


class _Client:
    def __init__(self) -> None:
        self.deleted: list[Any] = []

    async def delete(self, session: Any) -> None:
        self.deleted.append(session)


class _Settings:
    class runtime:  # noqa: N801
        backend = ""


async def _no_caido(*_a: Any, **_k: Any) -> None:
    return None


def _fake_backend(session: _Session, client: _Client, seen: list[dict[str, Any]]) -> Any:
    async def backend(**kwargs: Any) -> tuple[Any, Any]:
        seen.append(kwargs)
        return client, session

    return backend


@pytest.mark.asyncio
@pytest.mark.parametrize(("is_k8s", "mount"), [(True, "1"), (False, "1"), (True, "0")])
async def test_only_a_mounting_k8s_backend_receives_local_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, is_k8s: bool, mount: str
) -> None:
    monkeypatch.setenv("RECON_MOUNT_SOURCE", mount)
    name = f"hydration-{is_k8s}-{mount}"
    seen: list[dict[str, Any]] = []
    register_backend(name, _fake_backend(_Session(), _Client(), seen), supports_bind_mounts=True)
    monkeypatch.setattr(session_manager, "bootstrap_caido", _no_caido)
    monkeypatch.setattr(session_manager, "_K8S_BACKENDS", frozenset({name} if is_k8s else ()))
    monkeypatch.setattr(session_manager, "_CONTAINED_BACKENDS", frozenset())
    settings = _Settings()
    settings.runtime.backend = name
    monkeypatch.setattr(session_manager, "load_settings", lambda: settings)
    scan_id = f"hydration-scan-{is_k8s}-{mount}"
    sources = [_tree(tmp_path)]
    try:
        await session_manager.create_or_reuse(scan_id, image="img", local_sources=sources)
    finally:
        await session_manager.cleanup(scan_id)
        _BACKENDS.pop(name, None)
    handed_over = is_k8s and mount == "1"
    assert ("local_sources" in seen[0]) is handed_over
    if handed_over:
        assert seen[0]["local_sources"] == sources


@pytest.mark.asyncio
async def test_hydration_failure_fails_session_bring_up_and_discards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = "hydration-fatal"
    client = _Client()
    session = _Session(fail=True)
    register_backend(name, _fake_backend(session, client, []))
    monkeypatch.setattr(session_manager, "bootstrap_caido", _no_caido)
    monkeypatch.setattr(session_manager, "_K8S_BACKENDS", frozenset({name}))
    monkeypatch.setattr(session_manager, "_CONTAINED_BACKENDS", frozenset())
    settings = _Settings()
    settings.runtime.backend = name
    monkeypatch.setattr(session_manager, "load_settings", lambda: settings)
    try:
        with pytest.raises(RuntimeError, match="tar stream refused"):
            await session_manager.create_or_reuse(
                "hydration-fatal-scan", image="img", local_sources=[_tree(tmp_path)]
            )
    finally:
        _BACKENDS.pop(name, None)
    assert client.deleted == [session]
