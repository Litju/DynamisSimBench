"""The production runtime snapshot is measured, pinned and started isolated."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from dynamisbench.adapters.mujoco import reference
from dynamisbench.adapters.mujoco.protected_contracts import (
    measure_runtime_identity,
    sha256_file,
)
from dynamisbench.execution.protected_profile import build_protected_profile
from dynamisbench.execution.protected_runtime import (
    ProtectedRuntime,
    ProtectedRuntimeError,
    build_protected_sandbox_config,
    prepare_protected_runtime,
    protected_environment,
    protected_runtime_digest,
    protected_worker_command,
    write_protected_sandbox_config,
)
from tests.execution.mujoco.support import worker_python


def _tiny_identity(root: Path):
    executable = root / "base" / "python.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"interpreter")
    base = root / "base"
    site = root / "site"
    source = root / "source"
    site.mkdir()
    source.mkdir()
    (site / "package.py").write_text("VALUE = 1\n", encoding="utf-8")
    (source / "dynamisbench").mkdir()
    (source / "dynamisbench" / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    return measure_runtime_identity(
        executable=executable,
        base_prefix=base,
        site_packages=site,
        source_root=source,
    )


def test_the_protected_digest_binds_the_venv_config(tmp_path: Path) -> None:
    identity = _tiny_identity(tmp_path)

    without = protected_runtime_digest(identity, None)
    with_config = protected_runtime_digest(identity, "a" * 64)

    assert without != with_config


def test_the_worker_command_is_isolated_and_pinned(tmp_path: Path) -> None:
    command = protected_worker_command(
        interpreter=tmp_path / "python",
        bootstrap_path=tmp_path / "bootstrap.py",
        config_sha256="c" * 64,
        bootstrap_sha256="b" * 64,
    )

    assert command[1:3] == ("-I", "-S")
    assert command[3] == str(tmp_path / "bootstrap.py")
    assert command[4] == "c" * 64
    assert command[5] == "b" * 64


def test_the_supervisor_environment_is_minimal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RES555_RUNTIME_SECRET", "must-not-be-passed")
    monkeypatch.setenv("PYTHONPATH", "must-not-be-passed")

    environment = protected_environment(tmp_path)

    assert "RES555_RUNTIME_SECRET" not in environment
    assert "PYTHONPATH" not in environment
    assert environment["HOME"] == str(tmp_path)
    assert environment["TEMP"] == str(tmp_path)
    assert environment["TMP"] == str(tmp_path)
    assert environment["MUJOCO_GL"] == "disable"
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["TZ"] == "UTC"


def _fake_runtime(tmp_path: Path) -> ProtectedRuntime:
    source = tmp_path / "src"
    site = tmp_path / "site"
    source.mkdir()
    site.mkdir()
    environment = SimpleNamespace(site_packages=site, source_root=source)
    return cast(
        ProtectedRuntime,
        SimpleNamespace(
            source_root=source,
            site_packages=site,
            base_prefix=tmp_path / "base",
            environment=environment,
            protected_digest="d" * 64,
            venv_config_path=tmp_path / "pyvenv.cfg",
            venv_config_sha256="e" * 64,
        ),
    )


def test_the_config_is_canonical_and_pins_the_runtime_fields(tmp_path: Path) -> None:
    profile = build_protected_profile("windows-x86-64")
    runtime = _fake_runtime(tmp_path)
    config = build_protected_sandbox_config(
        profile=profile,
        runtime=runtime,
        inputs=tmp_path / "inputs",
        scratch=tmp_path / "scratch",
        binding_sha256="f" * 64,
        probe_targets=tmp_path / "scratch" / "probe-targets.json",
        read_execute=("/runtime",),
        read_only=("/inputs",),
        read_write=(str(tmp_path / "scratch"),),
    )

    path = tmp_path / "sandbox.json"
    digest = write_protected_sandbox_config(path, config)
    data = path.read_bytes()

    assert hashlib.sha256(data).hexdigest() == digest
    assert config["schema"] == "dynamisbench.protected.sandbox/1"
    assert config["profile_sha256"] == profile.digest()
    assert config["runtime_closure_sha256"] == runtime.protected_digest
    assert config["max_scratch_entries"] == profile.max_scratch_entries
    assert config["venv_config_sha256"] == runtime.venv_config_sha256
    with pytest.raises(ProtectedRuntimeError):
        write_protected_sandbox_config(path, config)


def test_a_changed_security_field_changes_the_config_digest(tmp_path: Path) -> None:
    profile = build_protected_profile("linux-x86-64")
    runtime = _fake_runtime(tmp_path)
    config = build_protected_sandbox_config(
        profile=profile,
        runtime=runtime,
        inputs=tmp_path / "inputs",
        scratch=tmp_path / "scratch",
        binding_sha256="f" * 64,
        probe_targets=tmp_path / "scratch" / "probe-targets.json",
        read_execute=("/runtime",),
        read_only=("/inputs",),
        read_write=(str(tmp_path / "scratch"),),
    )
    first = write_protected_sandbox_config(tmp_path / "one.json", config)
    changed = dict(config)
    changed["max_scratch_entries"] = 1
    second = write_protected_sandbox_config(tmp_path / "two.json", changed)

    assert first != second


@pytest.mark.skipif(
    os.environ.get("DYNAMISBENCH_REQUIRE_MUJOCO") != "1",
    reason="the full runtime snapshot needs the provisioned worker environment",
)
def test_the_full_runtime_snapshot_is_measured_and_mutation_is_visible(
    tmp_path: Path,
) -> None:
    platform = reference.platform_tag()
    profile = build_protected_profile(platform)
    runtime = prepare_protected_runtime(
        worker_python=worker_python(),
        root=tmp_path / "runtime",
        platform_tag=platform,
        profile=profile,
    )

    assert runtime.matches is True
    assert runtime.bootstrap_path.is_relative_to(runtime.source_root)
    assert runtime.bootstrap_sha256() == profile.bootstrap_sha256
    assert runtime.protected_digest == protected_runtime_digest(
        runtime.snapshot, runtime.venv_config_sha256
    )
    if platform == "linux-x86-64":
        assert runtime.venv_config_path is not None
        assert runtime.venv_config_sha256 is not None
        _, observed = sha256_file(runtime.venv_config_path, max_bytes=256 * 1024)
        assert observed == runtime.venv_config_sha256
        assert runtime.interpreter == runtime.environment.resolved_executable

    target = runtime.source_root / "dynamisbench" / "execution" / "protected_profile.py"
    target.write_bytes(target.read_bytes() + b"\n# mutation probe\n")
    remeasured = measure_runtime_identity(
        executable=runtime.interpreter,
        base_prefix=runtime.base_prefix,
        site_packages=runtime.site_packages,
        source_root=runtime.source_root,
        model_asset_relative="assets/reference_pendulum.xml",
    )

    assert remeasured.digest != runtime.snapshot.digest
