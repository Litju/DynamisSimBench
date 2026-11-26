"""RES-555 Gate B2: the protected bootstrap is engine-independent.

The simulator-free JSON fixture exercises the same protected launch, exact view
verification, runtime closure and in-worker denial probes as the MuJoCo case, but the
worker never imports the engine. It is not a second solver adapter.
"""

from __future__ import annotations

from pathlib import Path

from tools.res555_gate_b2.launch import run_protected_probe

from dynamisbench.domain.spec.sut import SUTInterface, SUTInterfaceKind
from dynamisbench.execution import prepare_execution_inputs
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


def _control_fixture(tmp_path: Path) -> ExecutionFixture:
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


def test_the_protected_bootstrap_verifies_inputs_without_importing_the_engine(
    tmp_path: Path,
    b2_runtime,
) -> None:
    profile, runtime = b2_runtime
    fixture = _control_fixture(tmp_path)
    selection = worker_manifest(fixture)
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
    result = run_protected_probe(
        workspace=fixture.workspace,
        prepared=prepared,
        selection=selection,
        runtime=runtime,
        mode="verify-only",
        profile=profile,
        forbidden_read_roots=(
            fixture.workspace.source_root,
            fixture.workspace.location(PersistenceClass.STAGING).path,
            fixture.workspace.location(PersistenceClass.SEALED_EVIDENCE).path,
            runtime.environment.source_root,
            runtime.registry_root,
        ),
    )
    observation = result.observation
    assert observation.verdict == "demonstrated", (
        [check for check in observation.checks if not check["passed"]],
        observation.process.get("stderr_excerpt"),
        None if observation.receipt is None else observation.receipt.failure,
    )
    receipt = observation.receipt
    assert receipt is not None
    assert receipt.completed is True
    assert receipt.mode == "verify-only"
    assert receipt.engine_imported is False
    assert receipt.model is None
    assert receipt.physics is None
    assert observation.numerical_reference is None
    assert receipt.input_manifest_sha256 == prepared.inputs.manifest_digest.hex
    probes = {probe.name: probe for probe in receipt.probes}
    assert probes["allowed_input_read"].observed == "allowed"
    assert probes["scratch_write"].observed == "allowed"
    assert probes["package_model_asset"].observed == "denied"
    assert probes["network_connect"].observed == "denied"
    assert all(
        probe.observed == "denied"
        for name, probe in probes.items()
        if name.startswith(("forbidden_", "runtime_write"))
    )
    imported = {module.module for module in receipt.imports}
    assert "dynamisbench" in imported
    assert "mujoco" not in imported
