"""The protected launch boundary refuses unsafe inputs before any process exists."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from dynamisbench.adapters.mujoco import reference
from dynamisbench.adapters.mujoco.protected_contracts import (
    ConsumptionReceipt,
    ImportedModule,
    ModelConsumption,
    PhysicsObservation,
    ProbeObservation,
    RuntimeRootSummary,
    WorkerRuntimeSummary,
)
from dynamisbench.execution.input_binding import WorkerInputBinding
from dynamisbench.execution.protected_launch import (
    ProbeTargets,
    ProtectedExecutionRoute,
    ProtectedLaunchError,
    RuntimeExpectation,
    consume_binding,
    correlate_receipt,
    expected_probe_outcomes,
    prepare_protected_route,
)
from dynamisbench.execution.protected_profile import build_protected_profile
from dynamisbench.workspace import Workspace

_DIGEST = "a" * 64
_TARGETS = ProbeTargets(
    forbidden_reads=("/staging/sentinel.txt",),
    forbidden_writes=("/inputs/forbidden-write.txt",),
    forbidden_deletes=("/inputs/binding.json",),
    allowed_read="/inputs/binding.json",
    allowed_write="/scratch/probe-write.txt",
    runtime_write="/runtime/protected-write.txt",
    network_port=1234,
    network_udp_port=1235,
    write_token="token",
)
_DEPENDENCY_CLOSURE = "c" * 64
_SOURCE_MANIFEST = tuple(
    {
        "path": relative,
        "sha256": (reference.MODEL_SHA256 if relative == reference.MODEL_ASSET_PATH else _DIGEST),
    }
    for relative in sorted(reference.ADAPTER_SOURCE_FILES)
)


def _binding(**overrides: str) -> WorkerInputBinding:
    values = {
        "run_id": "run-1",
        "execution_fingerprint": _DIGEST,
        "request_sha256": "b" * 64,
        "preflight_sha256": "c" * 64,
        "input_manifest_sha256": "d" * 64,
        "environment_sha256": "e" * 64,
        "worker_selection_sha256": "f" * 64,
        "adapter_implementation_sha256": "1" * 64,
        "runtime_closure_sha256": "2" * 64,
        "isolation_profile_sha256": "3" * 64,
        "launch_nonce": "4" * 64,
    }
    values.update(overrides)
    return WorkerInputBinding.model_validate(values)


def _runtime_expectation(profile) -> RuntimeExpectation:
    return RuntimeExpectation(
        protected_digest="5" * 64,
        executable_sha256="6" * 64,
        base_digest="7" * 64,
        site_packages_digest="8" * 64,
        source_digest="9" * 64,
    )


def _receipt(profile, binding: WorkerInputBinding, expectation: RuntimeExpectation):
    def root(label: str, digest: str) -> RuntimeRootSummary:
        return RuntimeRootSummary(label=label, entry_count=1, digest=digest, content_digest=digest)

    return ConsumptionReceipt(
        mode="materialized-mujoco",
        completed=True,
        failure=None,
        attempt_nonce=binding.launch_nonce,
        run_id=binding.run_id,
        execution_fingerprint=binding.execution_fingerprint,
        request_sha256=binding.request_sha256,
        preflight_sha256=binding.preflight_sha256,
        input_manifest_sha256=binding.input_manifest_sha256,
        binding_sha256="b" * 64,
        environment_sha256=binding.environment_sha256,
        worker_selection_sha256=binding.worker_selection_sha256,
        adapter_implementation_sha256=binding.adapter_implementation_sha256,
        runtime_closure_sha256=expectation.protected_digest,
        isolation_profile_sha256=profile.digest(),
        source_manifest=_SOURCE_MANIFEST,
        dependency_closure_digest=_DEPENDENCY_CLOSURE,
        runtime_summary=WorkerRuntimeSummary(
            executable_sha256=expectation.executable_sha256,
            base_digest=expectation.base_digest,
            site_packages_digest=expectation.site_packages_digest,
            source_digest=expectation.source_digest,
            combined_digest=expectation.protected_digest,
        ),
        imports=(
            ImportedModule(
                module="dynamisbench",
                file="runtime/src/dynamisbench/__init__.py",
                under_runtime=True,
            ),
        ),
        probes=tuple(
            ProbeObservation(
                name=name,
                expectation=expectation,  # type: ignore[arg-type]
                observed=expectation,  # type: ignore[arg-type]
                detail="test observation",
            )
            for name, expectation in sorted(expected_probe_outcomes(_TARGETS).items())
        ),
        model=ModelConsumption(
            logical_path=reference.MODEL_SOURCE_PATH,
            size_bytes=len(reference.model_bytes()),
            sha256=profile.model_sha256,
            package_asset_present=False,
            package_asset_probe="denied",
            compiled={"nq": 1},
        ),
        physics=PhysicsObservation(
            diagnostic_sha256="d" * 64,
            steps=profile.steps,
            timestep_s=profile.timestep_s,
            duration_s=profile.duration_s,
            trajectory_sha256=profile.reference_trajectory_sha256,
            initial_time_s=0.0,
            final_time_s=profile.duration_s,
            final_angle_rad=profile.expected_final_angle_rad,
            final_angular_velocity_rad_s=profile.expected_final_angular_velocity_rad_s,
            energy_initial_j=profile.expected_energy_initial_j,
            energy_final_j=profile.expected_energy_final_j,
            max_relative_energy_drift=7.45e-14,
            all_finite=True,
        ),
        engine_imported=True,
    )


def _correlate(receipt, binding, profile, expectation, *, windows: bool = False):
    request = cast(
        object,
        SimpleNamespace(run_id=binding.run_id, execution_fingerprint=SimpleNamespace(hex="a" * 64)),
    )
    return correlate_receipt(
        receipt=receipt,
        receipt_error=None,
        binding=binding,
        binding_sha256="b" * 64,
        request=cast(object, request),  # type: ignore[arg-type]
        profile=profile,
        runtime=expectation,
        dependency_closure_digest=_DEPENDENCY_CLOSURE,
        model_size_bytes=len(reference.model_bytes()),
        expected_probes=expected_probe_outcomes(_TARGETS),
        windows=windows,
    )


def test_a_correlated_receipt_is_accepted_and_names_the_pinned_trajectory() -> None:
    profile = build_protected_profile(reference.platform_tag())
    binding = _binding()
    expectation = _runtime_expectation(profile)
    receipt = _receipt(profile, binding, expectation)

    checks, refusals, trajectory = _correlate(receipt, binding, profile, expectation)

    assert refusals == []
    assert trajectory["matches"] is True
    assert trajectory["observed_trajectory_sha256"] == profile.reference_trajectory_sha256
    assert all(bool(check["passed"]) for check in checks)


def test_a_receipt_with_the_wrong_nonce_is_refused() -> None:
    profile = build_protected_profile(reference.platform_tag())
    binding = _binding()
    expectation = _runtime_expectation(profile)
    receipt = _receipt(profile, binding, expectation)
    substituted = receipt.model_copy(update={"attempt_nonce": "0" * 64})

    checks, refusals, trajectory = _correlate(substituted, binding, profile, expectation)

    assert trajectory["matches"] is True
    assert [item.message for item in refusals] == [
        "the protected receipt disagrees with the supervisor: receipt_nonce"
    ]
    assert any(check["name"] == "receipt_nonce" and check["passed"] is False for check in checks)


def test_a_receipt_with_a_different_trajectory_is_refused() -> None:
    profile = build_protected_profile(reference.platform_tag())
    binding = _binding()
    expectation = _runtime_expectation(profile)
    receipt = _receipt(profile, binding, expectation)
    physics = receipt.physics
    assert physics is not None
    substituted = receipt.model_copy(
        update={"physics": physics.model_copy(update={"trajectory_sha256": "f" * 64})}
    )

    checks, refusals, trajectory = _correlate(substituted, binding, profile, expectation)

    assert trajectory["matches"] is False
    assert any("trajectory" in item.message for item in refusals)
    assert any(
        check["name"] == "receipt_trajectory_reference" and check["passed"] is False
        for check in checks
    )


def test_a_receipt_for_a_different_runtime_is_refused() -> None:
    profile = build_protected_profile(reference.platform_tag())
    binding = _binding()
    expectation = _runtime_expectation(profile)
    receipt = _receipt(profile, binding, expectation)
    summary = receipt.runtime_summary
    assert summary is not None
    substituted = receipt.model_copy(
        update={"runtime_summary": summary.model_copy(update={"base_digest": "0" * 64})}
    )

    _checks, refusals, _trajectory = _correlate(substituted, binding, profile, expectation)

    assert any("different runtime" in item.message for item in refusals)


def test_a_completed_receipt_with_a_failure_text_is_refused() -> None:
    profile = build_protected_profile(reference.platform_tag())
    binding = _binding()
    expectation = _runtime_expectation(profile)
    receipt = _receipt(profile, binding, expectation)
    substituted = receipt.model_copy(update={"failure": "a worker-side failure"})

    _checks, refusals, _trajectory = _correlate(substituted, binding, profile, expectation)

    assert [item.message for item in refusals] == [
        "the protected receipt disagrees with the supervisor: receipt_failure_absent"
    ]


def test_a_receipt_with_an_incomplete_source_manifest_is_refused() -> None:
    profile = build_protected_profile(reference.platform_tag())
    binding = _binding()
    expectation = _runtime_expectation(profile)
    receipt = _receipt(profile, binding, expectation)
    substituted = receipt.model_copy(update={"source_manifest": receipt.source_manifest[:-1]})

    _checks, refusals, _trajectory = _correlate(substituted, binding, profile, expectation)

    assert any("source manifest" in item.message for item in refusals)


def test_a_receipt_with_a_different_dependency_closure_is_refused() -> None:
    profile = build_protected_profile(reference.platform_tag())
    binding = _binding()
    expectation = _runtime_expectation(profile)
    receipt = _receipt(profile, binding, expectation)
    substituted = receipt.model_copy(update={"dependency_closure_digest": "0" * 64})

    _checks, refusals, _trajectory = _correlate(substituted, binding, profile, expectation)

    assert [item.message for item in refusals] == [
        "the protected receipt disagrees with the supervisor: receipt_dependency_closure"
    ]


def test_a_receipt_with_an_import_outside_the_runtime_is_refused() -> None:
    profile = build_protected_profile(reference.platform_tag())
    binding = _binding()
    expectation = _runtime_expectation(profile)
    receipt = _receipt(profile, binding, expectation)
    substituted = receipt.model_copy(
        update={
            "imports": (
                ImportedModule(
                    module="mujoco",
                    file="C:/host/site-packages/mujoco/__init__.py",
                    under_runtime=False,
                ),
            )
        }
    )

    _checks, refusals, _trajectory = _correlate(substituted, binding, profile, expectation)

    assert any("outside the worker's measured runtime" in item.message for item in refusals)


def test_a_receipt_that_does_not_reach_the_pinned_duration_is_refused() -> None:
    profile = build_protected_profile(reference.platform_tag())
    binding = _binding()
    expectation = _runtime_expectation(profile)
    receipt = _receipt(profile, binding, expectation)
    physics = receipt.physics
    assert physics is not None
    substituted = receipt.model_copy(
        update={"physics": physics.model_copy(update={"final_time_s": 1.5})}
    )

    _checks, refusals, _trajectory = _correlate(substituted, binding, profile, expectation)

    assert any("pinned duration" in item.message for item in refusals)


def test_a_non_canonical_receipt_is_refused() -> None:
    profile = build_protected_profile(reference.platform_tag())
    binding = _binding()
    expectation = _runtime_expectation(profile)
    receipt = _receipt(profile, binding, expectation)
    request = SimpleNamespace(
        run_id=binding.run_id, execution_fingerprint=SimpleNamespace(hex="a" * 64)
    )

    _checks, refusals, _trajectory = correlate_receipt(
        receipt=receipt,
        receipt_error="the receipt is not canonical",
        binding=binding,
        binding_sha256="b" * 64,
        request=cast(object, request),  # type: ignore[arg-type]
        profile=profile,
        runtime=expectation,
        dependency_closure_digest=_DEPENDENCY_CLOSURE,
        model_size_bytes=len(reference.model_bytes()),
        expected_probes=expected_probe_outcomes(_TARGETS),
        windows=False,
    )

    assert any("not canonical" in item.message for item in refusals)


def test_a_windows_udp_probe_is_informational_only() -> None:
    profile = build_protected_profile(reference.platform_tag())
    binding = _binding()
    expectation = _runtime_expectation(profile)
    receipt = _receipt(profile, binding, expectation)
    probes = tuple(
        probe.model_copy(update={"observed": "allowed"}) if probe.name == "network_udp" else probe
        for probe in receipt.probes
    )
    substituted = receipt.model_copy(update={"probes": probes})

    linux_checks, linux_refusals, _ = _correlate(substituted, binding, profile, expectation)
    windows_checks, windows_refusals, _ = _correlate(
        substituted, binding, profile, expectation, windows=True
    )

    assert any(check["name"] == "receipt_probes" and not check["passed"] for check in linux_checks)
    assert linux_refusals
    assert windows_refusals == []
    assert all(check["passed"] for check in windows_checks if check["name"] == "receipt_probes")


def test_a_receipt_that_omits_a_requested_probe_is_refused() -> None:
    profile = build_protected_profile(reference.platform_tag())
    binding = _binding()
    expectation = _runtime_expectation(profile)
    receipt = _receipt(profile, binding, expectation)
    substituted = receipt.model_copy(update={"probes": receipt.probes[1:]})

    _checks, refusals, _trajectory = _correlate(substituted, binding, profile, expectation)

    assert any("exactly the probes" in item.message for item in refusals)


def test_a_receipt_that_relabels_a_probe_expectation_is_refused() -> None:
    profile = build_protected_profile(reference.platform_tag())
    binding = _binding()
    expectation = _runtime_expectation(profile)
    receipt = _receipt(profile, binding, expectation)
    probes = tuple(
        probe.model_copy(update={"expectation": "allowed", "observed": "allowed"})
        if probe.name == "runtime_write"
        else probe
        for probe in receipt.probes
    )

    _checks, refusals, _trajectory = _correlate(
        receipt.model_copy(update={"probes": probes}), binding, profile, expectation
    )

    assert any("exactly the probes" in item.message for item in refusals)


def test_a_replayed_binding_is_refused(tmp_path: Path) -> None:
    route = cast(
        ProtectedExecutionRoute,
        SimpleNamespace(runtime=SimpleNamespace(registry_root=tmp_path / "registry")),
    )
    staging = tmp_path / "workspace" / ".staging"

    consume_binding(route, "e" * 64, staging, "f" * 64)

    with pytest.raises(ProtectedLaunchError, match="already used"):
        consume_binding(route, "e" * 64, staging, "f" * 64)

    # A different workspace is a different admission target, so the same request may run
    # again there; only the pair is single-use.
    consume_binding(route, "e" * 64, tmp_path / "other" / ".staging", "f" * 64)


def test_the_protected_route_is_not_reachable_from_the_application_surfaces() -> None:
    """No API, CLI, entry point or desktop-facing module may import the protected route.

    The route is an internal activation decision. A module that imports it would be a
    candidate for reaching it without the owner's activation requirements, so the guard is a
    source scan over the application surfaces rather than a promise in a document.
    """
    root = Path(__file__).resolve().parents[2] / "src" / "dynamisbench"
    surfaces = [
        root / "api",
        root / "cli.py",
        root / "__main__.py",
        root / "query",
        root / "workspace",
    ]
    offenders: dict[str, list[str]] = {}
    for surface in surfaces:
        candidates = surface.rglob("*.py") if surface.is_dir() else [surface]
        for path in candidates:
            text = path.read_text(encoding="utf-8")
            hits = [
                name
                for name in ("protected_launch", "protected_worker", "protected_runtime")
                if name in text
            ]
            if hits:
                offenders[path.relative_to(root).as_posix()] = hits

    assert offenders == {}


def test_the_protected_route_is_not_enabled_by_an_environment_variable() -> None:
    """The activation is the passed route, not an environment switch."""
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "dynamisbench"
        / "execution"
        / "protected_launch.py"
    ).read_text(encoding="utf-8")

    for marker in ("os.environ[", "os.getenv(", "getenv("):
        assert marker not in source, marker


def test_the_tree_owns_and_closes_the_platform_primitive() -> None:
    from dynamisbench.execution.protected_launch import ProtectedTree, _ProcessLike

    class FakeProcess:
        pid = 1234
        returncode = None

        def __init__(self) -> None:
            self.killed = False
            self.closed = False

        def poll(self) -> int | None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            return 0

        def kill(self) -> None:
            self.killed = True

        def close(self) -> None:
            self.closed = True

        def job_accounting(self) -> dict[str, int]:
            return {"active_processes": 0}

    process = FakeProcess()
    tree = ProtectedTree(
        platform="windows-x86-64",
        process=cast("_ProcessLike", process),
        windows_process=process,
    )

    assert tree.wait_empty(0.1) is True
    tree.request_termination()
    tree.close()

    assert process.killed is True
    assert process.closed is True
    assert tree.cleanup_failed is False


def test_a_missing_mechanism_refuses_to_build_a_route(monkeypatch: pytest.MonkeyPatch) -> None:
    if os.name == "nt":
        from dynamisbench.host import protected_windows

        monkeypatch.setattr(protected_windows, "is_available", lambda: False)
    else:
        from dynamisbench.execution import landlock

        monkeypatch.setattr(landlock, "abi_version", lambda: 1)

    with pytest.raises(ProtectedLaunchError):
        prepare_protected_route(
            workspace=cast(Workspace, SimpleNamespace(source_root=Path("."))),
            worker_python=Path("python"),
        )


def test_a_non_linux_dedicated_scratch_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    if os.name == "nt":
        pytest.skip("the dedicated-scratch requirement is a Linux production condition")

    from dynamisbench.execution import protected_launch

    monkeypatch.setattr(
        protected_launch,
        "resolve_scratch_budget",
        lambda **_: SimpleNamespace(enforcement="sampled-watchdog", root=None),
    )
    platform = protected_launch.ProtectedPlatform(
        profile=build_protected_profile(reference.platform_tag()),
        sandbox_parent=None,
        scratch_root=None,
        cgroup_root=None,
        accept_elevated_windows_residual=False,
    )

    with pytest.raises(ProtectedLaunchError, match="dedicated scratch"):
        platform.open()


def test_the_profile_matches_the_committed_reference() -> None:
    """The frozen profile must reproduce the committed reference file exactly.

    The profile hard-codes the reference so a worker cannot choose it. This test is the other
    half: the hard-coded values are the ones the repository committed.
    """
    import json

    repository = Path(__file__).resolve().parents[3]
    committed = json.loads(
        (repository / "evidence" / "RES-555" / "gate-b2" / "reference-observation.json").read_text(
            encoding="utf-8"
        )
    )
    profile = build_protected_profile(reference.platform_tag())

    assert profile.model_sha256 == committed["model_sha256"]
    assert profile.steps == committed["steps"]
    assert profile.timestep_s == committed["timestep_s"]
    assert profile.duration_s == committed["duration_s"]
    assert profile.reference_trajectory_sha256 == committed["trajectory_sha256"]
    assert profile.expected_final_angle_rad == committed["expected_final_angle_rad"]
    assert (
        profile.expected_final_angular_velocity_rad_s
        == committed["expected_final_angular_velocity_rad_s"]
    )
    assert profile.expected_energy_initial_j == committed["expected_energy_initial_j"]
    assert profile.expected_energy_final_j == committed["expected_energy_final_j"]


def test_the_pinned_profile_refuses_a_different_admitted_request(tmp_path: Path) -> None:
    from tests.execution.support import build_fixture, preflight

    fixture = build_fixture(tmp_path)
    admission = preflight(fixture)
    assert admission.request is not None
    profile = build_protected_profile(reference.platform_tag())

    differences = profile.authority_refusals(admission.request)

    assert "adapter id" in differences
    assert "adapter implementation digest" in differences
    assert "environment semantic digest" in differences
    assert profile.matches_request(admission.request) is False


def test_the_windows_launch_environment_copies_only_named_system_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    if os.name != "nt":
        pytest.skip("the AppContainer environment constraint is Windows-specific")
    from dynamisbench.execution.protected_runtime import protected_environment

    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\qualification\AppData\Local")
    monkeypatch.setenv("USERPROFILE", r"C:\Users\qualification")
    monkeypatch.setenv("SUPERVISOR_SECRET", "must-not-be-passed")

    environment = protected_environment(tmp_path)

    assert environment["LOCALAPPDATA"] == r"C:\Users\qualification\AppData\Local"
    assert environment["PROCESSOR_ARCHITECTURE"] == os.environ["PROCESSOR_ARCHITECTURE"]
    assert "USERPROFILE" not in environment
    assert "SUPERVISOR_SECRET" not in environment
    assert environment["TEMP"] == str(tmp_path)
    assert environment["MUJOCO_GL"] == "disable"


def test_a_missing_local_app_data_is_a_refusal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    if os.name != "nt":
        pytest.skip("the AppContainer environment constraint is Windows-specific")
    from dynamisbench.execution.protected_runtime import (
        ProtectedRuntimeError,
        protected_environment,
    )

    monkeypatch.delenv("LOCALAPPDATA", raising=False)

    with pytest.raises(ProtectedRuntimeError, match="LOCALAPPDATA"):
        protected_environment(tmp_path)
