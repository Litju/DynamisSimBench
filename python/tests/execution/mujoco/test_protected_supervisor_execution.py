"""RES-555: the protected route runs through the production supervisor lifecycle.

These tests are the integration gate between the qualified probe and
``execute_preflighted``. They launch the real pinned worker under AppContainer (Windows) or
Landlock + seccomp + cgroup v2 (Linux) *through the supervisor*, and require the same
model identity, the same 2,000-step trajectory, the same bounded IPC and the same terminal
diagnostic as the diagnostic route.

They are not a production activation: the route is only reachable by passing a
``ProtectedRun`` to ``execute_preflighted``, and nothing in the API, CLI or UI does that.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
from pathlib import Path
from typing import Any

import pytest

from dynamisbench.adapters.mujoco import reference
from dynamisbench.adapters.mujoco.protected_contracts import ConsumptionReceipt
from dynamisbench.evidence.bundle import RunOutcome
from dynamisbench.execution import (
    PreparedExecutionInputs,
    WorkerEnvironmentManifest,
    execute_preflighted,
    prepare_execution_inputs,
)
from dynamisbench.execution.contracts import RefusalCode, RunLifecycleState
from dynamisbench.execution.preflight import preflight_run
from dynamisbench.execution.protected_launch import (
    ProtectedConsumptionRecord,
    ProtectedExecutionRoute,
    ProtectedLaunchError,
    ProtectedRun,
    prepare_protected_route,
)
from dynamisbench.execution.protected_profile import PROTECTED_SUPERVISOR_RECORD_NAME
from dynamisbench.execution.protected_scratch import ScratchBudget
from dynamisbench.workspace import PersistenceClass
from tests.execution.mujoco.support import (
    ExecutionFixture,
    worker_manifest,
    worker_python,
)

_PROTECTED_RECORD = PROTECTED_SUPERVISOR_RECORD_NAME


def _prepare(
    fixture: ExecutionFixture,
    identity: dict[str, Any],
    *,
    run_id: str | None = None,
) -> tuple[WorkerEnvironmentManifest, PreparedExecutionInputs]:
    selection = worker_manifest(fixture, identity)
    prepared = prepare_execution_inputs(
        run_id or fixture.run_id,
        fixture.run,
        benchmark=fixture.benchmark,
        scenario=fixture.benchmark.scenarios[0],
        realization=fixture.realization,
        system_under_test=fixture.system_under_test,
        environment=fixture.environment,
        manifest=selection,
        workspace=fixture.workspace,
    )
    return selection, prepared


def _admission(
    fixture: ExecutionFixture,
    selection: WorkerEnvironmentManifest,
    *,
    run_id: str | None = None,
):
    return preflight_run(
        run_id or fixture.run_id,
        fixture.run,
        realization=fixture.realization,
        environment=fixture.environment,
        manifest=selection,
        workspace=fixture.workspace,
    )


def _record(fixture: ExecutionFixture, run_id: str | None = None) -> ProtectedConsumptionRecord:
    path = (
        fixture.workspace.location(PersistenceClass.STAGING).path
        / (run_id or fixture.run_id)
        / _PROTECTED_RECORD
    )
    return ProtectedConsumptionRecord.model_validate_json(path.read_bytes())


def _stderr(fixture: ExecutionFixture, run_id: str | None = None) -> str:
    path = (
        fixture.workspace.location(PersistenceClass.STAGING).path
        / (run_id or fixture.run_id)
        / "logs"
        / "worker.stderr.txt"
    )
    if not path.is_file():
        return "<no worker log>"
    return path.read_text(encoding="utf-8", errors="replace")[-4000:]


def _publish(record: ProtectedConsumptionRecord) -> Path | None:
    """Retain the demonstrated record when an evidence directory is requested.

    Only the demonstrated attempt publishes; a negative or verify-only run would otherwise be
    able to overwrite the acceptance observation.
    """
    configured = os.environ.get("DYNAMISBENCH_PROTECTED_EVIDENCE_DIR")
    if not configured or record.state is not RunLifecycleState.COMPLETED:
        return None
    from dynamisbench.identity import canonical_semantic_bytes

    directory = Path(configured)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{record.platform}.json"
    target.write_bytes(canonical_semantic_bytes(record))
    return target


def test_the_protected_route_completes_inside_the_supervisor(
    mujoco_fixture: ExecutionFixture,
    mujoco_identity: dict,
    mujoco_qualification: dict,
    protected_route: ProtectedExecutionRoute,
) -> None:
    fixture = mujoco_fixture
    selection, prepared = _prepare(fixture, mujoco_identity)
    admission = _admission(fixture, selection)

    supervised = execute_preflighted(
        admission, protected=ProtectedRun(route=protected_route, prepared=prepared)
    )
    result = supervised.result

    assert result.state is RunLifecycleState.COMPLETED, (
        result.refusals,
        _stderr(fixture),
    )
    assert result.refusals == ()
    assert result.worker_exit_code == 0
    assert result.stdin_delivered is True
    assert result.process_tree_cleaned is True
    assert result.worker_reaped is True
    assert result.diagnostic_reference == "diagnostics.json"
    assert result.seal_outcome is RunOutcome.SUCCEEDED

    record = _record(fixture)
    assert record.state is RunLifecycleState.COMPLETED
    assert record.refusals == ()
    assert record.receipt_present is True
    assert record.receipt_canonical is True
    assert record.receipt_completed is True
    assert record.post_runtime_digest == record.snapshot_runtime_digest
    assert record.worker_runtime_digest == record.runtime_closure_sha256
    assert record.view_after_digest == record.view_before_digest
    assert all(bool(check["passed"]) for check in record.checks), [
        check for check in record.checks if not check["passed"]
    ]
    check_names = {str(check["name"]) for check in record.checks}
    assert {
        "environment_keys",
        "receipt_source_manifest",
        "receipt_imports",
        "receipt_failure_absent",
        "receipt_final_time",
        "receipt_dependency_closure",
        "input_view_unchanged",
        "runtime_unchanged",
        "bootstrap_pinned",
        "scratch_within_limit",
        "external_isolation",
        "network_denied",
    } <= check_names
    assert record.process["tree_cleaned"] is True
    assert len(record.worker_entry_sha256) == 64
    # The persisted record carries the worker's full untrusted receipt, so its digest is
    # recomputable from the artifact rather than only asserted.
    assert record.receipt_document is not None
    from dynamisbench.identity import canonical_semantic_bytes as canonical

    receipt_bytes = canonical(ConsumptionReceipt.model_validate(record.receipt_document))
    assert hashlib.sha256(receipt_bytes).hexdigest() == record.receipt_sha256

    receipt = record.receipt
    assert receipt is not None
    trajectory = receipt["trajectory"]
    assert isinstance(trajectory, dict)
    assert trajectory["observed_trajectory_sha256"] == (
        protected_route.profile.reference_trajectory_sha256
    )
    diagnostic = mujoco_qualification["nominal"]["diagnostic"]
    assert trajectory["observed_trajectory_sha256"] == diagnostic["trajectory_sha256"]

    assert _publish(record) is not None or not os.environ.get("DYNAMISBENCH_PROTECTED_EVIDENCE_DIR")

    # The record is a diagnostic, never native evidence.
    assert not (fixture.workspace.location(PersistenceClass.SEALED_EVIDENCE).path).exists() or (
        not any(
            (fixture.workspace.location(PersistenceClass.SEALED_EVIDENCE).path / run).exists()
            for run in (fixture.run_id,)
        )
    )


def test_the_protected_attempt_is_single_use(
    mujoco_fixture: ExecutionFixture,
    mujoco_identity: dict,
    protected_route: ProtectedExecutionRoute,
) -> None:
    fixture = mujoco_fixture
    selection, prepared = _prepare(fixture, mujoco_identity)
    admission = _admission(fixture, selection)
    protected = ProtectedRun(route=protected_route, prepared=prepared)
    first = execute_preflighted(admission, protected=protected)
    assert first.result.state is RunLifecycleState.COMPLETED

    # One run id is one execution: a replay is refused before a second process exists.
    second = execute_preflighted(admission, protected=protected)
    assert second.result.state is RunLifecycleState.REFUSED
    assert second.result.worker_pid is None
    assert any(item.code is RefusalCode.DUPLICATE_EXECUTION for item in second.result.refusals)


def test_a_protected_timeout_is_terminal_and_correlated(
    mujoco_fixture: ExecutionFixture,
    mujoco_identity: dict,
    protected_route: ProtectedExecutionRoute,
) -> None:
    fixture = mujoco_fixture
    selection = worker_manifest(fixture, mujoco_identity, timeout_seconds=0.05)
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
    admission = _admission(fixture, selection)

    supervised = execute_preflighted(
        admission, protected=ProtectedRun(route=protected_route, prepared=prepared)
    )
    result = supervised.result

    assert result.state is RunLifecycleState.TIMED_OUT
    assert any(item.code is RefusalCode.WORKER_TIMEOUT for item in result.refusals)
    assert result.process_tree_cleaned is True
    assert result.worker_reaped is True
    assert result.seal_outcome is RunOutcome.FAILED
    record = _record(fixture)
    assert record.state is RunLifecycleState.TIMED_OUT
    assert record.receipt_present is False
    assert record.post_runtime_digest == record.snapshot_runtime_digest


def test_a_canceled_protected_run_never_reports_success(
    mujoco_fixture: ExecutionFixture,
    mujoco_identity: dict,
    protected_route: ProtectedExecutionRoute,
) -> None:
    import threading

    fixture = mujoco_fixture
    selection, prepared = _prepare(fixture, mujoco_identity)
    admission = _admission(fixture, selection)
    cancel = threading.Event()
    cancel.set()

    supervised = execute_preflighted(
        admission,
        protected=ProtectedRun(route=protected_route, prepared=prepared),
        cancel_event=cancel,
    )
    result = supervised.result

    assert result.state is RunLifecycleState.CANCELED
    assert any(item.code is RefusalCode.WORKER_CANCELED for item in result.refusals)
    assert result.seal_outcome is RunOutcome.FAILED


def test_a_resource_bound_violation_refuses_the_attempt(
    mujoco_fixture: ExecutionFixture,
    mujoco_identity: dict,
    protected_route: ProtectedExecutionRoute,
) -> None:
    fixture = mujoco_fixture
    squeezed = ProtectedExecutionRoute(
        profile=protected_route.profile.model_copy(update={"max_scratch_entries": 1}),
        runtime=protected_route.runtime,
        platform=protected_route.platform,
        scratch=protected_route.scratch,
        dependency_closure_digest=protected_route.dependency_closure_digest,
        workspace=protected_route.workspace,
    )
    selection, prepared = _prepare(fixture, mujoco_identity)
    admission = _admission(fixture, selection)

    supervised = execute_preflighted(
        admission, protected=ProtectedRun(route=squeezed, prepared=prepared)
    )
    result = supervised.result

    assert result.state is RunLifecycleState.FAILED
    record = _record(fixture)
    assert any(
        check["name"] == "scratch_within_limit" and check["passed"] is False
        for check in record.checks
    )
    assert "worker_failed" in record.refusals


def test_altered_input_bytes_refuse_before_any_process(
    mujoco_fixture: ExecutionFixture,
    mujoco_identity: dict,
    protected_route: ProtectedExecutionRoute,
) -> None:
    fixture = mujoco_fixture
    selection, prepared = _prepare(fixture, mujoco_identity)
    admission = _admission(fixture, selection)
    from dynamisbench.materialization import MaterializationStore

    store = MaterializationStore(fixture.workspace)
    asset = prepared.inputs.manifest.assets[0]
    object_path = store.object_path(asset.observed_sha256)
    original = object_path.read_bytes()
    object_path.write_bytes(original.replace(b"0.001", b"0.002", 1))
    try:
        supervised = execute_preflighted(
            admission, protected=ProtectedRun(route=protected_route, prepared=prepared)
        )
    finally:
        object_path.write_bytes(original)

    result = supervised.result
    assert result.state is RunLifecycleState.REFUSED
    assert result.refusals
    assert result.worker_pid is None
    assert result.worker_reaped is False


def test_a_changed_runtime_refuses_before_any_process(
    mujoco_fixture: ExecutionFixture,
    mujoco_identity: dict,
    protected_route: ProtectedExecutionRoute,
) -> None:
    fixture = mujoco_fixture
    selection, prepared = _prepare(fixture, mujoco_identity)
    admission = _admission(fixture, selection)
    target = (
        protected_route.runtime.source_root
        / "dynamisbench"
        / "adapters"
        / "mujoco"
        / ("reference.py")
    )
    if os.name == "nt":
        # A previous attempt reduced the supervisor user to RX,DE,DC on the runtime tree;
        # that is the adopted DACL. Re-grant write so this test can stage the substitution.
        from dynamisbench.host.protected_windows import restore_user_control

        restore_user_control(protected_route.runtime.root)
    original = target.read_bytes()
    target.write_bytes(original + b"\n# RES-555 supervisor runtime substitution probe\n")
    try:
        supervised = execute_preflighted(
            admission, protected=ProtectedRun(route=protected_route, prepared=prepared)
        )
    finally:
        target.write_bytes(original)

    result = supervised.result
    assert result.state is RunLifecycleState.REFUSED
    assert result.worker_pid is None
    assert any("runtime" in item.message for item in result.refusals)


def test_a_prepared_run_for_another_request_is_refused(
    mujoco_fixture: ExecutionFixture,
    mujoco_identity: dict,
    protected_route: ProtectedExecutionRoute,
) -> None:
    fixture = mujoco_fixture
    selection, prepared = _prepare(fixture, mujoco_identity)
    admission = _admission(fixture, selection)
    request = prepared.request
    assert request is not None
    other = dataclasses.replace(prepared, request=request.model_copy(update={"run_id": "run-2"}))

    supervised = execute_preflighted(
        admission, protected=ProtectedRun(route=protected_route, prepared=other)
    )

    # The attempt is refused because the prepared inputs do not describe the request the
    # admission carries; no process was started.
    assert supervised.result.state is RunLifecycleState.REFUSED
    assert supervised.result.worker_pid is None
    assert supervised.result.refusals


@pytest.mark.skipif(
    os.environ.get("DYNAMISBENCH_REQUIRE_MUJOCO") != "1",
    reason="the full protected route needs the provisioned worker environment",
)
def test_the_route_refuses_a_shared_scratch_volume_on_linux(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    if os.name == "nt":
        pytest.skip("a Linux production condition")
    from dynamisbench.execution import protected_launch

    monkeypatch.setattr(
        protected_launch,
        "resolve_scratch_budget",
        lambda **_: ScratchBudget(
            root=None,
            enforcement="sampled-watchdog",
            capacity_bytes=None,
            detail="test substitution",
        ),
    )
    with pytest.raises(ProtectedLaunchError, match="dedicated scratch"):
        prepare_protected_route(worker_python=worker_python(), sandbox_parent=tmp_path)


def test_the_worker_python_is_the_provisioned_interpreter() -> None:
    assert Path(worker_python()).is_file()


def test_the_pinned_trajectory_is_the_committed_reference() -> None:
    from dynamisbench.execution.protected_profile import build_protected_profile

    profile = build_protected_profile(reference.platform_tag())

    assert profile.reference_trajectory_sha256 == (
        "f585292dae08650de7980e5ff00256e1ca9a80bd28474f9357df9f6daf3278bf"
    )
    assert profile.model_sha256 == reference.MODEL_SHA256
