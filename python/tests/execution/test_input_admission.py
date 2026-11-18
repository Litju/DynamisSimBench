"""Qualification of the supervisor-side input preparation boundary."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from dynamisbench.domain.spec.sut import SUTInterface, SUTInterfaceKind
from dynamisbench.execution import (
    PreflightRefusedError,
    PreparedExecutionInputs,
    RefusalCode,
    WorkerEnvironmentManifest,
    preflight_run,
    prepare_execution_inputs,
)
from dynamisbench.identity import semantic_sha256
from dynamisbench.materialization import (
    MAX_ASSETS,
    AssetInput,
    MaterializationError,
    MaterializationRefusalCode,
    MaterializationStore,
)
from dynamisbench.workspace import PersistenceClass, initialize_workspace
from tests.domain import factories as domain
from tests.execution.support import (
    ExecutionFixture,
    asset_realization,
    build_fixture,
    worker_manifest,
    write_source_asset,
)

MODEL_PATH = "models/reference/decay.json"
MODEL_BYTES = b'{"initial_value":8,"multiplier":0.5,"steps":3}\n'


@pytest.fixture
def model_fixture(tmp_path: Path) -> ExecutionFixture:
    """A data-only scalar recurrence model for the simulator-free control adapter."""
    workspace = initialize_workspace(tmp_path / "source", tmp_path / "evidence")
    digest = write_source_asset(workspace, MODEL_PATH, MODEL_BYTES)
    return build_fixture(
        tmp_path,
        workspace=workspace,
        realization=asset_realization(path=MODEL_PATH, sha256=digest),
        system_under_test=domain.sut_definition(
            interface=SUTInterface(kind=SUTInterfaceKind.IN_PROCESS)
        ),
    )


def _prepare(
    fixture: ExecutionFixture, selection: WorkerEnvironmentManifest
) -> PreparedExecutionInputs:
    return prepare_execution_inputs(
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


def _assert_no_run(fixture: ExecutionFixture) -> None:
    for location in (PersistenceClass.STAGING, PersistenceClass.SEALED_EVIDENCE):
        assert not fixture.workspace.resolve(location, fixture.run_id).exists()


def test_incompatible_worker_is_refused_before_materialization(
    execution_fixture: ExecutionFixture, tmp_path: Path
) -> None:
    selection = worker_manifest(execution_fixture, program=str(tmp_path / "absent-worker"))
    with pytest.raises(PreflightRefusedError) as raised:
        _prepare(execution_fixture, selection)
    assert RefusalCode.WORKER_PROGRAM_UNRESOLVED in {r.code for r in raised.value.report.refusals}
    _assert_no_run(execution_fixture)


def test_substituted_environment_is_refused(execution_fixture: ExecutionFixture) -> None:
    selection = worker_manifest(execution_fixture)
    changed = execution_fixture.environment.model_copy(update={"description": "Different bytes"})
    with pytest.raises(PreflightRefusedError) as raised:
        _prepare(replace(execution_fixture, environment=changed), selection)
    codes = {item.code for item in raised.value.report.refusals}
    assert RefusalCode.ENVIRONMENT_IDENTITY_MISMATCH in codes
    _assert_no_run(execution_fixture)


def test_preparation_refuses_subprocess_sut(execution_fixture: ExecutionFixture) -> None:
    with pytest.raises(MaterializationError) as raised:
        _prepare(execution_fixture, worker_manifest(execution_fixture))
    assert raised.value.code is MaterializationRefusalCode.SUT_EXECUTABLE_CLOSURE_UNSUPPORTED
    _assert_no_run(execution_fixture)


def test_exact_inputs_are_reproducible_and_verifiable_after_source_edit(
    model_fixture: ExecutionFixture,
) -> None:
    selection = worker_manifest(model_fixture)
    first = _prepare(model_fixture, selection)
    assert _prepare(model_fixture, selection) == first
    legacy = preflight_run(
        model_fixture.run_id,
        model_fixture.run,
        realization=model_fixture.realization,
        environment=model_fixture.environment,
        manifest=selection,
        workspace=model_fixture.workspace,
    )
    assert first.report == legacy.report
    assert first.worker_environment_digest == semantic_sha256(selection)
    assert first.report.execution_fingerprint == model_fixture.run.fingerprint

    # Read and hash the persisted manifest independently of the prepare result.
    original_digest = hashlib.sha256(MODEL_BYTES).hexdigest()
    store = MaterializationStore(model_fixture.workspace)
    digest = first.inputs.manifest_digest
    assert hashlib.sha256(store.manifest_path(digest.hex).read_bytes()).hexdigest() == digest.hex
    assert write_source_asset(model_fixture.workspace, MODEL_PATH, b"revision 2") != original_digest
    restored = store.read_manifest(digest)
    assert restored == first.inputs.manifest
    assert restored.execution_refs.realization == model_fixture.run.spec.realization
    asset: AssetInput
    (asset,) = restored.assets
    assert asset.logical_path == MODEL_PATH
    assert asset.observed_sha256 == original_digest
    assert store.object_path(original_digest).read_bytes() == MODEL_BYTES
    _assert_no_run(model_fixture)


@pytest.mark.parametrize("source", [None, b"", b"revision 2"])
def test_original_plan_refuses_missing_or_edited_model(
    model_fixture: ExecutionFixture, source: bytes | None
) -> None:
    path = model_fixture.workspace.source_root / MODEL_PATH
    if source is None:
        path.unlink()
    else:
        path.write_bytes(source)
    with pytest.raises(MaterializationError) as raised:
        _prepare(model_fixture, worker_manifest(model_fixture))
    assert raised.value.code is (
        MaterializationRefusalCode.INPUT_SET_INCOMPLETE
        if source is None
        else MaterializationRefusalCode.INPUT_SOURCE_CHANGED
    )
    _assert_no_run(model_fixture)


def test_changed_benchmark_with_same_version_is_refused(model_fixture: ExecutionFixture) -> None:
    changed = model_fixture.benchmark.model_copy(update={"description": "Different benchmark"})
    with pytest.raises(MaterializationError) as raised:
        _prepare(replace(model_fixture, benchmark=changed), worker_manifest(model_fixture))
    assert raised.value.code is MaterializationRefusalCode.INPUT_DEFINITION_MISMATCH
    _assert_no_run(model_fixture)


def test_preparation_retains_materialization_asset_limit(model_fixture: ExecutionFixture) -> None:
    original = model_fixture.realization.assets[0]
    assets = tuple(
        original.model_copy(update={"asset_id": f"model-{i}", "path": f"models/model-{i}.json"})
        for i in range(MAX_ASSETS + 1)
    )
    fixture = build_fixture(
        model_fixture.workspace.source_root,
        workspace=model_fixture.workspace,
        realization=model_fixture.realization.model_copy(update={"assets": assets}),
        system_under_test=model_fixture.system_under_test,
    )
    with pytest.raises(MaterializationError) as raised:
        _prepare(fixture, worker_manifest(fixture))
    assert raised.value.code is MaterializationRefusalCode.INPUT_LIMIT_EXCEEDED
    _assert_no_run(fixture)
