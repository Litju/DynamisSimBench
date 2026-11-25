"""The protected bootstrap refuses a changed config, a changed self, or a non-isolated launch."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from dynamisbench.execution import protected_bootstrap
from dynamisbench.execution.protected_profile import protected_bootstrap_path


def _write_config(path: Path, *, value: dict[str, object] | None = None) -> bytes:
    import json

    payload = value or {
        "schema": "dynamisbench.protected.sandbox/1",
        "mechanism": "windows-appcontainer",
        "profile_sha256": "0" * 64,
        "runtime_closure_sha256": "0" * 64,
        "inputs": str(path.parent / "inputs"),
        "scratch": str(path.parent / "scratch"),
        "source_root": str(path.parent / "src"),
        "site_packages": str(path.parent / "site"),
        "base_prefix": str(path.parent / "base"),
        "landlock_module": str(path.parent / "src" / "landlock.py"),
        "seccomp_module": str(path.parent / "src" / "seccomp.py"),
        "read_execute": [],
        "read_only": [],
        "read_write": [],
        "memory_limit_bytes": 1,
        "cpu_time_seconds": 1,
        "max_file_bytes": 1,
        "max_open_files": 1,
    }
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    path.write_bytes(data)
    return data


def test_a_changed_config_is_refused_before_the_sandbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    raw = _write_config(tmp_path / "sandbox.json")
    digest = hashlib.sha256(raw).hexdigest()

    assert protected_bootstrap._read_config(digest)["schema"] == (
        "dynamisbench.protected.sandbox/1"
    )
    with pytest.raises(ValueError, match="supervisor-pinned"):
        protected_bootstrap._read_config("0" * 64)


def test_the_environment_is_reduced_to_the_launch_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RES555_REVIEW_SECRET", "must-not-survive")
    monkeypatch.setenv("DYNAMISBENCH_RES555_B2_PROBE", "1")
    monkeypatch.setenv("MUJOCO_GL", "egl")

    keys = protected_bootstrap._sanitize_environment(tmp_path)

    assert "RES555_REVIEW_SECRET" not in os.environ
    assert "DYNAMISBENCH_RES555_B2_PROBE" not in os.environ
    assert os.environ["MUJOCO_GL"] == "disable"
    assert os.environ["HOME"] == str(tmp_path)
    assert os.environ["TEMP"] == str(tmp_path)
    assert "MUJOCO_GL" in keys


def test_a_module_outside_the_measured_source_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("raise SystemExit('should not load')\n", encoding="utf-8")

    with pytest.raises(ValueError, match="outside"):
        protected_bootstrap._fixed_module(source, "../outside.py")


def test_the_bootstrap_refuses_without_isolated_site(tmp_path: Path) -> None:
    bootstrap = protected_bootstrap_path()
    completed = subprocess.run(
        [sys.executable, str(bootstrap), "0" * 64, "0" * 64],
        cwd=tmp_path,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 2
    assert b"isolated" in completed.stderr.lower()


def test_the_bootstrap_refuses_a_wrong_self_hash_before_reading_config(tmp_path: Path) -> None:
    bootstrap = protected_bootstrap_path()
    completed = subprocess.run(
        [sys.executable, "-I", "-S", str(bootstrap), "0" * 64, "0" * 64],
        cwd=tmp_path,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 2
    assert b"bootstrap is not the supervisor-pinned" in completed.stderr


def test_the_bootstrap_refuses_a_missing_config_before_the_sandbox(tmp_path: Path) -> None:
    bootstrap = protected_bootstrap_path()
    actual = hashlib.sha256(bootstrap.read_bytes()).hexdigest()
    completed = subprocess.run(
        [sys.executable, "-I", "-S", str(bootstrap), "0" * 64, actual],
        cwd=tmp_path,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 2
    assert completed.stderr
