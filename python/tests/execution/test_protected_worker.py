"""The production worker refuses a sandbox config that is not the pinned bytes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from dynamisbench.adapters.mujoco.protected_worker import _load_config


def _write_config(path: Path, value: int) -> bytes:
    data = (
        json.dumps(
            {"schema": "dynamisbench.protected.sandbox/1", "value": value},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    path.write_bytes(data)
    return data


def test_the_worker_uses_only_the_pinned_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    raw = _write_config(tmp_path / "sandbox.json", 1)
    monkeypatch.setenv("DYNAMISBENCH_PROTECTED_CONFIG_SHA256", hashlib.sha256(raw).hexdigest())

    assert _load_config()["value"] == 1


def test_the_worker_refuses_a_changed_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    raw = _write_config(tmp_path / "sandbox.json", 1)
    monkeypatch.setenv("DYNAMISBENCH_PROTECTED_CONFIG_SHA256", hashlib.sha256(raw).hexdigest())
    _write_config(tmp_path / "sandbox.json", 2)

    with pytest.raises(ValueError, match="supervisor-pinned"):
        _load_config()


def test_the_worker_refuses_a_missing_config_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_config(tmp_path / "sandbox.json", 1)
    monkeypatch.delenv("DYNAMISBENCH_PROTECTED_CONFIG_SHA256", raising=False)

    with pytest.raises(ValueError, match="supervisor-pinned"):
        _load_config()
