"""Probe-only contract checks for RES-555 Gate B2.

These tests do not launch a worker. They pin the non-production boundary, the canonical
binding readability the worker depends on, the profile identity and the fail-closed gate.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from tools.res555_gate_b2.profile import build_profile

from dynamisbench.adapters.mujoco._b2_probe_common import (
    ProbePolicyError,
    assert_probe_authorized,
    measure_root_closure,
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
    assert windows.network_access == "denied"


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


def test_no_production_module_imports_the_probe_harness() -> None:
    root = Path(__file__).resolve().parents[2] / "src" / "dynamisbench"
    forbidden = ("_b2_probe", "res555_gate_b2", "_b2_landlock")
    scanned = [
        root / "execution" / "supervisor.py",
        root / "execution" / "preflight.py",
        root / "execution" / "contracts.py",
        root / "execution" / "environment.py",
        root / "cli.py",
        root / "api",
    ]
    for candidate in scanned:
        paths = [candidate] if candidate.is_file() else sorted(candidate.rglob("*.py"))
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for token in forbidden:
                assert token not in text, f"{path} references the probe-only {token}"
