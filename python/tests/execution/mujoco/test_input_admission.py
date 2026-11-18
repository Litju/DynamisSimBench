"""The real pendulum adapter's model closure uses the same input preparation."""

from __future__ import annotations

import sys
from pathlib import Path

from dynamisbench.adapters.mujoco import reference
from dynamisbench.execution import (
    WorkerCommand,
    WorkerEnvironmentManifest,
    prepare_execution_inputs,
)
from dynamisbench.execution.input_binding import build_worker_input_binding
from dynamisbench.execution.input_verification import verify_worker_input_view
from dynamisbench.materialization import MaterializationStore
from tests.execution.input_view_support import write_input_view
from tests.execution.mujoco.support import (
    MODEL_SOURCE_PATH,
    adapter_identity,
    build_mujoco_fixture,
    worker_manifest,
)
from tests.execution.support import ExecutionFixture


def test_prepare_exact_pendulum_inputs(
    mujoco_fixture: ExecutionFixture, mujoco_identity: dict
) -> None:
    fixture = mujoco_fixture
    selection = worker_manifest(fixture, mujoco_identity)
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
    store = MaterializationStore(fixture.workspace)
    verified = store.read_manifest(prepared.inputs.manifest_digest)
    (asset,) = verified.assets
    assert prepared.report.adapter == selection.adapter
    assert asset.logical_path == MODEL_SOURCE_PATH
    assert (
        store.object_path(asset.observed_sha256).read_bytes()
        == (fixture.workspace.source_root / MODEL_SOURCE_PATH).read_bytes()
    )


def test_verify_pinned_pendulum_view_offline(tmp_path: Path) -> None:
    identity = {
        "adapter_id": reference.ADAPTER_ID,
        "adapter_version": reference.ADAPTER_VERSION,
        "engine": reference.ENGINE,
        "engine_version": reference.ENGINE_VERSION,
        "python_version": reference.PYTHON_VERSION,
        "capabilities": [capability.value for capability in reference.CAPABILITIES],
        "implementation_digest": "a" * 64,
    }
    fixture = build_mujoco_fixture(tmp_path, identity=identity)
    # A fixed test-only candidate program suffices for preflight. Never launch it.
    selection = WorkerEnvironmentManifest(
        environment=fixture.run.spec.environment,
        adapter=adapter_identity(identity),
        command=WorkerCommand(program=sys.executable),
        timeout_seconds=30,
    )
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
    assert prepared.request is not None
    binding = build_worker_input_binding(
        prepared, selection, runtime_closure_sha256="b" * 64, isolation_profile_sha256="c" * 64
    )
    root = write_input_view(tmp_path / "inputs", fixture.workspace, prepared, binding)
    (fixture.workspace.source_root / MODEL_SOURCE_PATH).unlink()
    observation = verify_worker_input_view(root, expected=binding, request=prepared.request)
    assert observation.files[0].path == f"assets/{MODEL_SOURCE_PATH}"
    assert observation.files[0].sha256 == reference.MODEL_SHA256
