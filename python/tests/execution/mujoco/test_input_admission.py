"""The real pendulum adapter's model closure uses the same input preparation."""

from __future__ import annotations

from dynamisbench.execution import prepare_execution_inputs
from dynamisbench.materialization import MaterializationStore
from tests.execution.mujoco.support import MODEL_SOURCE_PATH, worker_manifest
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
