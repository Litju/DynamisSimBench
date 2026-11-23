"""RES-555 Gate B2: protected materialized MuJoCo consumption qualification.

These tests are probe-only. They launch the real isolated worker through the unadmitted
``tools.res555_gate_b2`` harness under AppContainer (Windows) or Landlock (Linux), feed it
the verified input view, and require the receipt and the existing qualified trajectory to
agree. They do not exercise or enable a production execution route.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from tools.res555_gate_b2.launch import (
    ProtectedLaunchError,
    consume_attempt,
    run_protected_probe,
)
from tools.res555_gate_b2.profile import build_profile
from tools.res555_gate_b2.runtime import ProtectedRuntime

from dynamisbench.adapters.mujoco import reference
from dynamisbench.execution import prepare_execution_inputs
from dynamisbench.execution.input_binding import build_worker_input_binding
from dynamisbench.workspace import PersistenceClass
from tests.execution.mujoco.support import (
    ExecutionFixture,
    worker_manifest,
)


def _evidence_dir() -> Path | None:
    configured = os.environ.get("DYNAMISBENCH_RES555_B2_EVIDENCE_DIR")
    return Path(configured) if configured else None


def _prepare(fixture: ExecutionFixture, identity: dict):
    selection = worker_manifest(fixture, identity)
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
    return selection, prepared


def _forbidden_roots(fixture: ExecutionFixture, runtime: ProtectedRuntime) -> tuple[Path, ...]:
    return (
        fixture.workspace.source_root,
        fixture.workspace.location(PersistenceClass.STAGING).path,
        fixture.workspace.location(PersistenceClass.SEALED_EVIDENCE).path,
        runtime.environment.source_root,
    )


def _run(
    fixture: ExecutionFixture,
    runtime: ProtectedRuntime,
    profile,
    mode: str = "materialized-mujoco",
    **kwargs,
):
    selection, prepared = _prepare(fixture, kwargs.pop("identity"))
    return run_protected_probe(
        workspace=fixture.workspace,
        prepared=prepared,
        selection=selection,
        runtime=runtime,
        mode=mode,
        profile=profile,
        forbidden_read_roots=_forbidden_roots(fixture, runtime),
        evidence_dir=_evidence_dir(),
        **kwargs,
    )


def test_the_real_pinned_worker_consumes_the_verified_materialized_model(
    mujoco_fixture: ExecutionFixture,
    mujoco_identity: dict,
    mujoco_qualification: dict,
    b2_runtime,
) -> None:
    profile, runtime = b2_runtime
    result = _run(mujoco_fixture, runtime, profile, identity=mujoco_identity)
    observation = result.observation

    assert observation.verdict == "demonstrated", [
        check for check in observation.checks if not check["passed"]
    ]
    assert observation.refusals == ()
    assert observation.runtime_matches is True
    assert observation.source_runtime.digest == observation.snapshot_runtime.digest
    assert observation.receipt is not None
    receipt = observation.receipt
    assert receipt.completed is True
    assert receipt.engine_imported is True
    assert receipt.model is not None
    assert receipt.model.sha256 == reference.MODEL_SHA256
    assert receipt.model.size_bytes == len(reference.model_bytes())
    assert receipt.model.source == "input_view"
    assert receipt.model.package_asset_present is False
    assert receipt.model.package_asset_probe == "denied"
    assert receipt.physics is not None
    assert receipt.physics.steps == 2000
    assert receipt.physics.timestep_s == reference.TIMESTEP_S
    assert receipt.physics.duration_s == reference.DURATION_S
    assert receipt.physics.all_finite is True
    assert receipt.physics.final_time_s == pytest.approx(reference.DURATION_S, abs=1e-9)

    # The existing independent qualification observation is the scientific reference.
    diagnostic = mujoco_qualification["nominal"]["diagnostic"]
    assert receipt.physics.trajectory_sha256 == diagnostic["trajectory_sha256"]
    assert receipt.physics.initial_time_s == diagnostic["initial"]["time_s"]
    assert receipt.physics.final_angle_rad == diagnostic["final"]["angle_rad"]
    assert (
        receipt.physics.final_angular_velocity_rad_s
        == diagnostic["final"]["angular_velocity_rad_s"]
    )
    assert receipt.physics.energy_initial_j == diagnostic["energy_initial_j"]
    assert receipt.physics.energy_final_j == diagnostic["energy_final_j"]

    probes = {probe.name: probe for probe in receipt.probes}
    assert probes["allowed_input_read"].observed == "allowed"
    assert probes["scratch_write"].observed == "allowed"
    for name, probe in probes.items():
        if name.startswith(
            ("forbidden_", "runtime_write", "package_model_asset", "network_connect")
        ):
            assert probe.observed == "denied", (name, probe)
    assert probes["package_model_asset"].detail == "the packaged XML is absent from the sandbox"

    imported = {module.module: module for module in receipt.imports}
    assert imported["dynamisbench"].under_runtime is True
    assert imported["mujoco"].under_runtime is True
    assert str(runtime.source_root) in imported["dynamisbench"].file
    assert str(runtime.site_packages) in imported["mujoco"].file

    # The exact model bytes are the verified view bytes, not a package resource.
    source_model = mujoco_fixture.workspace.source_root / reference.MODEL_SOURCE_PATH
    assert source_model.read_bytes() == reference.model_bytes()
    assert receipt.model.sha256 == reference.MODEL_SHA256

    if result.observation_path is not None:
        assert result.observation_path.is_file()
        assert result.observation_path.stat().st_size > 0


def test_a_substituted_runtime_refuses_before_physics(
    mujoco_fixture: ExecutionFixture,
    mujoco_identity: dict,
    b2_runtime,
) -> None:
    profile, runtime = b2_runtime
    target = runtime.source_root / "dynamisbench" / "adapters" / "mujoco" / "reference.py"
    original = target.read_bytes()

    def tamper(_runtime: ProtectedRuntime) -> None:
        target.write_bytes(original + b"\n# RES-555 runtime substitution probe\n")

    try:
        result = _run(
            mujoco_fixture,
            runtime,
            profile,
            identity=mujoco_identity,
            tamper=tamper,
        )
    finally:
        target.write_bytes(original)

    observation = result.observation
    assert observation.verdict == "refused"
    assert observation.receipt is not None
    assert observation.receipt.completed is False
    assert observation.receipt.physics is None
    assert observation.receipt.model is None
    assert "runtime_unchanged" in observation.refusals
    assert any(
        check["name"] == "receipt_probes" and not check["passed"] for check in observation.checks
    )


def test_a_tampered_input_view_refuses_before_launch(
    mujoco_fixture: ExecutionFixture,
    mujoco_identity: dict,
    b2_runtime,
) -> None:
    profile, runtime = b2_runtime

    def tamper(inputs: Path) -> None:
        model = inputs / "assets" / reference.MODEL_SOURCE_PATH
        model.write_bytes(model.read_bytes().replace(b"0.001", b"0.002", 1))

    with pytest.raises(Exception) as raised:
        _run(
            mujoco_fixture,
            runtime,
            profile,
            identity=mujoco_identity,
            view_tamper=tamper,
        )
    assert type(raised.value).__name__ in {
        "MaterializationError",
        "ValidationError",
        "ProbePolicyError",
    }


def test_a_replayed_binding_is_refused(
    mujoco_fixture: ExecutionFixture,
    mujoco_identity: dict,
    b2_runtime,
) -> None:
    _profile, runtime = b2_runtime
    selection, prepared = _prepare(mujoco_fixture, mujoco_identity)
    profile_value = build_profile(reference.platform_tag())
    binding = build_worker_input_binding(
        prepared,
        selection,
        runtime_closure_sha256=runtime.snapshot.digest,
        isolation_profile_sha256=profile_value.digest(),
    )
    consume_attempt(runtime, binding.launch_nonce, binding.request_sha256)
    with pytest.raises(ProtectedLaunchError):
        consume_attempt(runtime, binding.launch_nonce, binding.request_sha256)


def test_an_unavailable_mechanism_is_refused_not_downgraded(
    mujoco_fixture: ExecutionFixture,
    mujoco_identity: dict,
    b2_runtime,
) -> None:
    profile, runtime = b2_runtime
    with pytest.raises(ProtectedLaunchError):
        _run(
            mujoco_fixture,
            runtime,
            profile,
            identity=mujoco_identity,
            force_mechanism_unavailable=True,
        )
