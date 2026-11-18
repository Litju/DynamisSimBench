"""Qualification of the supervisor-side input preparation boundary."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from dynamisbench.execution import (
    PreflightRefusedError,
    PreparedExecutionInputs,
    RefusalCode,
    WorkerEnvironmentManifest,
    prepare_execution_inputs,
)
from dynamisbench.materialization import MaterializationError, MaterializationRefusalCode
from dynamisbench.workspace import PersistenceClass
from tests.execution.support import ExecutionFixture, worker_manifest


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
