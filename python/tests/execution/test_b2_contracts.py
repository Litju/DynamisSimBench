"""Probe-only contract checks for RES-555 Gate B2.

These tests do not launch a worker. They pin the non-production boundary, the canonical
binding readability the worker depends on, the profile identity and the fail-closed gate.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
from tools.res555_gate_b2.launch import (
    ProtectedLaunchError,
    _scratch_usage,
    run_protected_probe,
)
from tools.res555_gate_b2.profile import build_profile

from dynamisbench.adapters.mujoco._b2_probe_common import (
    ProbePolicyError,
    assert_probe_authorized,
    measure_root_closure,
    read_bounded_regular,
)
from dynamisbench.domain.spec.sut import SUTInterface, SUTInterfaceKind
from dynamisbench.execution.input_binding import WorkerInputBinding
from dynamisbench.identity import canonical_semantic_bytes
from dynamisbench.workspace import initialize_workspace
from tests.domain import factories as domain
from tests.execution.support import (
    asset_realization,
    build_fixture,
    worker_manifest,
    write_source_asset,
)

MODEL_PATH = "models/reference/contract.json"
MODEL_BYTES = b'{"value":1}\n'


@pytest.fixture
def binding_fixture(tmp_path: Path):
    workspace = initialize_workspace(tmp_path / "source", tmp_path / "evidence")
    digest = write_source_asset(workspace, MODEL_PATH, MODEL_BYTES)
    fixture = build_fixture(
        tmp_path,
        workspace=workspace,
        realization=asset_realization(path=MODEL_PATH, sha256=digest),
        system_under_test=domain.sut_definition(
            interface=SUTInterface(kind=SUTInterfaceKind.IN_PROCESS)
        ),
    )
    selection = worker_manifest(fixture)
    from dynamisbench.execution import prepare_execution_inputs

    prepared = prepare_execution_inputs(
        fixture.run_id,
        fixture.run,
        benchmark=fixture.benchmark,
        scenario=fixture.benchmark.scenarios[0],
        realization=fixture.realization,
        system_under_test=fixture.system_under_test,
        environment=fixture.environment,
        manifest=selection,
        workspace=fixture.workspace,
    )
    return fixture, selection, prepared


def test_the_persisted_binding_is_readable_by_its_own_model(binding_fixture) -> None:
    """A1's binding must round-trip into the model a worker parses, without byte changes."""
    fixture, selection, prepared = binding_fixture
    from dynamisbench.execution.input_binding import build_worker_input_binding

    binding = build_worker_input_binding(
        prepared,
        selection,
        runtime_closure_sha256="a" * 64,
        isolation_profile_sha256="b" * 64,
    )
    raw = canonical_semantic_bytes(binding)
    assert WorkerInputBinding.model_validate_json(raw) == binding
    assert canonical_semantic_bytes(WorkerInputBinding.model_validate_json(raw)) == raw


def test_the_probe_gate_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DYNAMISBENCH_RES555_B2_PROBE", raising=False)
    with pytest.raises(ProbePolicyError):
        assert_probe_authorized()
    monkeypatch.setenv("DYNAMISBENCH_RES555_B2_PROBE", "1")
    assert_probe_authorized()


def test_the_isolation_profile_is_platform_explicit() -> None:
    windows = build_profile("windows-x86-64")
    linux = build_profile("linux-x86-64")
    assert windows.mechanism == "windows-appcontainer"
    assert linux.mechanism == "linux-landlock"
    assert windows.digest() == build_profile("windows-x86-64").digest()
    assert windows.digest() != linux.digest()
    assert windows.input_access == "read-only"
    assert windows.runtime_access == "read-execute-only"
    assert windows.scratch_access == "read-write"
    assert windows.scientific_source_access == "denied"
    assert windows.network_access == "restricted"
    assert windows.network_mechanism == "windows-appcontainer-firewall"
    assert windows.process_limit_mechanism == "windows-job-object-active-process"
    assert windows.max_processes == 8
    assert "canary received" in windows.network_scope
    assert "not proof" in windows.network_scope
    assert "universal no-socket or no-UDP" in windows.network_scope
    assert linux.network_access == "denied"
    assert linux.network_mechanism == "linux-landlock-tcp+seccomp"
    assert linux.process_limit_mechanism == "linux-cgroup-v2-pids"
    assert linux.process_limit_scope == "tasks-and-threads"
    assert linux.max_processes == 64
    assert "UDP" in linux.network_scope
    assert linux.scratch_limit_enforcement in {
        "sampled-watchdog",
        "dedicated-filesystem",
        "post-exit-acceptance-bound",
    }


def test_the_scratch_usage_measurement_counts_exact_bytes(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "receipt.json").write_bytes(b"12345")
    (scratch / "logs").mkdir()
    (scratch / "logs" / "worker.txt").write_bytes(b"abc")
    assert _scratch_usage(scratch) == (8, 2, 0, 0)


def test_a_materialized_probe_requires_a_qualified_trajectory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DYNAMISBENCH_RES555_B2_PROBE", "1")
    missing = cast(Any, None)
    with pytest.raises(ProtectedLaunchError, match="qualified trajectory"):
        run_protected_probe(
            workspace=missing,
            prepared=missing,
            selection=missing,
            runtime=missing,
            mode="materialized-mujoco",
        )
    with pytest.raises(ProtectedLaunchError, match="sha256"):
        run_protected_probe(
            workspace=missing,
            prepared=missing,
            selection=missing,
            runtime=missing,
            mode="materialized-mujoco",
            expected_trajectory_sha256="not-a-digest",
        )


def test_an_evidence_name_cannot_escape_the_evidence_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DYNAMISBENCH_RES555_B2_PROBE", "1")
    missing = cast(Any, None)
    with pytest.raises(ProtectedLaunchError, match="plain .json"):
        run_protected_probe(
            workspace=missing,
            prepared=missing,
            selection=missing,
            runtime=missing,
            mode="materialized-mujoco",
            expected_trajectory_sha256="0" * 64,
            evidence_dir=tmp_path,
            evidence_name="../escape.json",
        )


def test_a_denied_read_is_a_permission_error_not_a_shape_refusal(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX mode-bit denial fixture")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root can read a mode-000 file")
    path = tmp_path / "sentinel.txt"
    path.write_bytes(b"RES555\n")
    path.chmod(0)
    try:
        with pytest.raises(PermissionError):
            read_bounded_regular(path, limit=4096)
    finally:
        path.chmod(0o600)


def test_a_closure_refuses_a_link(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "file.txt").write_text("content", encoding="utf-8")
    link = root / "link.txt"
    try:
        link.symlink_to(root / "file.txt")
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip("host symlink privilege is unavailable")
        raise
    with pytest.raises(ProbePolicyError):
        measure_root_closure("test", root)


def test_a_closure_refuses_a_hardlink(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    original = root / "file.txt"
    original.write_text("content", encoding="utf-8")
    alias = root / "alias.txt"
    os.link(original, alias)
    assert alias.stat().st_nlink == 2
    with pytest.raises(ProbePolicyError):
        measure_root_closure("test", root)


def test_a_closure_resolves_an_in_root_file_link_only_when_allowed(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    real = root / "real.so"
    real.write_bytes(b"shared-library-bytes")
    link = root / "libname.so"
    try:
        link.symlink_to(real)
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip("host symlink privilege is unavailable")
        raise
    with pytest.raises(ProbePolicyError):
        measure_root_closure("base", root)
    closure = measure_root_closure("base", root, allow_symlinks=True)
    entries = {entry.path: entry for entry in closure.entries}
    assert entries["libname.so"].sha256 == entries["real.so"].sha256
    assert entries["libname.so"].size_bytes == len(b"shared-library-bytes")


def test_a_closure_refuses_a_junction(tmp_path: Path) -> None:
    if sys.platform != "win32":
        pytest.skip("NTFS junction fixture")
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "file.txt").write_text("content", encoding="utf-8")
    junction = root / "junction"
    subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/j", str(junction), str(outside)],
        check=True,
        capture_output=True,
    )
    assert junction.is_junction()
    with pytest.raises(ProbePolicyError):
        measure_root_closure("test", root)


def test_no_production_module_imports_the_probe_harness() -> None:
    root = Path(__file__).resolve().parents[2] / "src" / "dynamisbench"
    forbidden = ("_b2_probe", "res555_gate_b2", "_b2_landlock", "_b2_seccomp")
    probe_only = {
        "adapters/mujoco/_b2_probe_common.py",
        "adapters/mujoco/_b2_probe_worker.py",
        "execution/_b2_landlock.py",
        "execution/_b2_seccomp.py",
    }
    for path in sorted(root.rglob("*.py")):
        if path.relative_to(root).as_posix() in probe_only:
            continue
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in text, f"{path} references the probe-only {token}"
