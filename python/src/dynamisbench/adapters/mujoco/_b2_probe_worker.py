"""Probe-only worker entry point for the RES-555 Gate B2 qualification.

This module is **not** a production worker. It is launched only by
``python/tools/res555_gate_b2`` behind ``DYNAMISBENCH_RES555_B2_PROBE=1``, after the
platform sandbox has been applied. It consumes the exact verified input view, proves the
packaged model is unavailable, compiles the view bytes with the pinned MuJoCo release,
runs the existing 2,000-step reference integration, and writes a bounded consumption
receipt into its scratch directory.

It does not write staging, sealed evidence, ``native/``, canonical quantities or an
assessment. The receipt is an observation for the authority decision, not evidence.

The production supervisor, preflight, API and CLI never import this module.
"""

from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path
from typing import Any, Final, Literal

_MAX_CONFIG_BYTES: Final = 64 * 1024
_MAX_FAILURE: Final = 240


def _bounded_text(error: BaseException) -> str:
    text = f"{type(error).__name__}: {error}"
    return text[:_MAX_FAILURE]


def _load_config() -> dict[str, Any]:
    path = Path.cwd() / "sandbox.json"
    from dynamisbench.adapters.mujoco._b2_probe_common import read_bounded_regular

    raw = read_bounded_regular(path, limit=_MAX_CONFIG_BYTES)
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("sandbox.json is not an object")
    if value.get("schema") != "dynamisbench.res555.sandbox/1":
        raise ValueError("sandbox.json is not the probe configuration")
    return value


def _read_request():
    from dynamisbench.execution.contracts import (
        MAX_WORKER_MESSAGE_BYTES,
        WorkerProtocolError,
        parse_worker_request,
    )

    raw = sys.stdin.buffer.read(MAX_WORKER_MESSAGE_BYTES + 1)
    if len(raw) > MAX_WORKER_MESSAGE_BYTES:
        raise WorkerProtocolError("the request exceeds the worker protocol message bound")
    return parse_worker_request(raw)


def _write_stdout(payload: bytes) -> None:
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def _write_stderr(line: str) -> None:
    sys.stderr.write(line.rstrip("\n") + "\n")
    sys.stderr.flush()


def _response(request, status: str, message: str | None):
    from dynamisbench.execution.contracts import WorkerResponse, WorkerStatus

    return WorkerResponse(
        run_id=request.run_id,
        execution_fingerprint=request.execution_fingerprint,
        environment=request.environment,
        adapter=request.adapter,
        status=WorkerStatus.COMPLETED if status == "completed" else WorkerStatus.FAILED,
        message=message,
    )


def _write_response(request, status: str, message: str | None) -> None:
    from dynamisbench.identity import canonical_semantic_bytes

    _write_stdout(canonical_semantic_bytes(_response(request, status, message)) + b"\n")


def _probe_read(path: str, name: str, *, expectation: Literal["allowed", "denied"] = "denied"):
    from dynamisbench.adapters.mujoco._b2_probe_common import ProbeObservation, read_bounded_regular

    try:
        read_bounded_regular(Path(path), limit=4096)
    except PermissionError:
        return ProbeObservation(
            name=name,
            expectation=expectation,
            observed="denied",
            detail="PermissionError",
        )
    except OSError as error:
        return ProbeObservation(
            name=name,
            expectation=expectation,
            observed="error",
            detail=type(error).__name__,
        )
    except Exception as error:  # noqa: BLE001 - a probe records a bounded observation
        return ProbeObservation(
            name=name,
            expectation=expectation,
            observed="error",
            detail=type(error).__name__,
        )
    return ProbeObservation(
        name=name,
        expectation=expectation,
        observed="allowed",
        detail="read succeeded",
    )


def _probe_write(path: str, name: str):
    from dynamisbench.adapters.mujoco._b2_probe_common import ProbeObservation

    try:
        with open(path, "xb") as handle:
            handle.write(b"res555-forbidden-write")
    except PermissionError:
        return ProbeObservation(
            name=name, expectation="denied", observed="denied", detail="PermissionError"
        )
    except OSError as error:
        return ProbeObservation(
            name=name, expectation="denied", observed="denied", detail=type(error).__name__
        )
    return ProbeObservation(
        name=name, expectation="denied", observed="allowed", detail="write succeeded"
    )


def _probe_delete(path: str, name: str):
    from dynamisbench.adapters.mujoco._b2_probe_common import ProbeObservation

    try:
        os.unlink(path)
    except PermissionError:
        return ProbeObservation(
            name=name, expectation="denied", observed="denied", detail="PermissionError"
        )
    except OSError as error:
        return ProbeObservation(
            name=name, expectation="denied", observed="denied", detail=type(error).__name__
        )
    return ProbeObservation(
        name=name, expectation="denied", observed="allowed", detail="unlink succeeded"
    )


def _probe_network(port: int):
    from dynamisbench.adapters.mujoco._b2_probe_common import ProbeObservation

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3.0)
    try:
        sock.connect(("127.0.0.1", port))
    except PermissionError:
        return ProbeObservation(
            name="network_connect",
            expectation="denied",
            observed="denied",
            detail="PermissionError",
        )
    except OSError as error:
        winerror = getattr(error, "winerror", None)
        # A failed connect is the denial observation. The supervisor's localhost canary
        # independently proves that no connection arrived; a closed port alone would not.
        return ProbeObservation(
            name="network_connect",
            expectation="denied",
            observed="denied",
            detail=f"{type(error).__name__}:{error.errno or winerror}",
        )
    finally:
        sock.close()
    return ProbeObservation(
        name="network_connect", expectation="denied", observed="allowed", detail="connect succeeded"
    )


def _probe_allowed_write(target: str, token: str):
    from dynamisbench.adapters.mujoco._b2_probe_common import (
        ProbeObservation,
        read_bounded_regular,
    )

    try:
        with open(target, "xb") as handle:
            handle.write(token.encode("utf-8"))
        observed = read_bounded_regular(Path(target), limit=4096).decode("utf-8")
    except Exception as error:  # noqa: BLE001 - a probe records a bounded observation
        return ProbeObservation(
            name="scratch_write",
            expectation="allowed",
            observed="error",
            detail=type(error).__name__,
        )
    if observed != token:
        return ProbeObservation(
            name="scratch_write", expectation="allowed", observed="error", detail="content mismatch"
        )
    return ProbeObservation(
        name="scratch_write", expectation="allowed", observed="allowed", detail="exact bytes"
    )


def _probes(config: dict[str, Any], targets, inputs_root: Path):
    from dynamisbench.adapters.mujoco import reference
    from dynamisbench.adapters.mujoco._b2_probe_common import ProbeObservation

    observations = [
        _probe_read(targets.allowed_read, "allowed_input_read", expectation="allowed"),
        _probe_allowed_write(targets.allowed_write, targets.write_token),
        _probe_network(targets.network_port),
        _probe_write(targets.runtime_write, "runtime_write"),
    ]
    observations.extend(
        _probe_read(path, f"forbidden_read_{index}")
        for index, path in enumerate(targets.forbidden_reads)
    )
    observations.extend(
        _probe_write(path, f"forbidden_write_{index}")
        for index, path in enumerate(targets.forbidden_writes)
    )
    observations.extend(
        _probe_delete(path, f"forbidden_delete_{index}")
        for index, path in enumerate(targets.forbidden_deletes)
    )
    try:
        reference.model_bytes()
    except reference.ReferenceModelError:
        observations.append(
            ProbeObservation(
                name="package_model_asset",
                expectation="denied",
                observed="denied",
                detail="the packaged XML is absent from the sandbox",
            )
        )
    except Exception as error:  # noqa: BLE001
        observations.append(
            ProbeObservation(
                name="package_model_asset",
                expectation="denied",
                observed="error",
                detail=type(error).__name__,
            )
        )
    else:
        observations.append(
            ProbeObservation(
                name="package_model_asset",
                expectation="denied",
                observed="allowed",
                detail="the packaged XML was readable",
            )
        )
    return tuple(observations)


def _import_audit(*, site_packages: Path, source_root: Path, base_prefix: Path):
    from dynamisbench.adapters.mujoco._b2_probe_common import ImportedModule

    audited: list[ImportedModule] = []
    for name in ("dynamisbench", "pydantic", "mujoco", "numpy"):
        module = sys.modules.get(name)
        if module is None:
            continue
        filename = getattr(module, "__file__", None)
        if not filename:
            continue
        resolved = Path(filename).resolve()
        under = any(
            resolved.is_relative_to(root.resolve())
            for root in (site_packages, source_root, base_prefix)
        )
        audited.append(ImportedModule(module=name, file=str(resolved), under_runtime=bool(under)))
    return tuple(audited)


def _run_materialized(
    config: dict[str, Any],
    request,
    view,
    identity,
):
    from dynamisbench.adapters.mujoco import reference
    from dynamisbench.adapters.mujoco._b2_probe_common import ProbePolicyError

    if view.asset_sha256 != reference.MODEL_SHA256:
        raise ProbePolicyError("the input-view model is not the reviewed reference XML")
    from dynamisbench.adapters.mujoco._b2_probe_common import reconstruct_implementation_digest

    digest, source_manifest = reconstruct_implementation_digest(
        model_sha256=view.asset_sha256,
        source_root=Path(config["source_root"]),
        engine_version=request.adapter.engine_version,
        python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        platform_tag=reference.platform_tag(),
    )
    if digest != request.adapter.implementation_digest:
        raise ProbePolicyError(
            "the sandbox adapter source does not reproduce the request implementation digest"
        )

    from dynamisbench.adapters.mujoco import physics

    if physics.engine_version() != request.adapter.engine_version:
        raise ProbePolicyError("the installed MuJoCo version is not the requested engine version")
    try:
        model = physics.compile_model(view.model_bytes)
    except reference.ReferenceAdapterError as error:
        raise ProbePolicyError(
            f"the pinned compiler refused the input-view XML: {error}"
        ) from error

    original_model_bytes = reference.model_bytes
    original_load_model = physics.load_model

    def forbidden(*_args: object, **_kwargs: object):
        raise reference.ReferenceModelError(
            "the packaged model is forbidden during materialized execution"
        )

    def from_view():
        return model

    context = physics.RunContext(
        run_id=str(request.run_id),
        execution_fingerprint=request.execution_fingerprint.hex,
        benchmark=str(request.run_spec.benchmark.identifier),
        scenario=str(request.run_spec.scenario.identifier),
        realization=str(request.run_spec.realization.identifier),
        environment_id=str(request.run_spec.environment.identifier),
        seed=request.run_spec.seed,
        outcomes=tuple(str(outcome) for outcome in request.run_spec.outcomes),
        adapter_version=str(request.adapter.adapter_version),
        engine_version=str(request.adapter.engine_version),
        implementation_digest=str(request.adapter.implementation_digest),
    )
    try:
        reference.model_bytes = forbidden
        physics.load_model = from_view
        run = physics.run_reference(context)
    finally:
        reference.model_bytes = original_model_bytes
        physics.load_model = original_load_model

    diagnostic = run.diagnostic
    if diagnostic.steps != reference.STEPS:
        raise ProbePolicyError("the reference run did not execute the pinned 2,000 steps")
    from dynamisbench.adapters.mujoco._b2_probe_common import ModelConsumption, PhysicsObservation

    mass, distance, inertia = physics.hinge_parameters(model)
    model_consumption = ModelConsumption(
        logical_path=view.asset_path,
        size_bytes=view.asset_size_bytes,
        sha256=view.asset_sha256,
        package_asset_present=False,
        package_asset_probe="denied",
        compiled={
            "nq": int(model.nq),
            "nv": int(model.nv),
            "nu": int(model.nu),
            "njnt": int(model.njnt),
            "ngeom": int(model.ngeom),
            "nbody": int(model.nbody),
            "mass_kg": mass,
            "com_distance_m": distance,
            "hinge_inertia_kg_m2": inertia,
            "timestep_s": float(model.opt.timestep),
            "solver_tolerance": float(model.opt.tolerance),
        },
    )
    from dynamisbench.identity import semantic_sha256

    diagnostic_digest = semantic_sha256(diagnostic.model_dump(mode="json")).hex
    physics_observation = PhysicsObservation(
        diagnostic_sha256=diagnostic_digest,
        steps=diagnostic.steps,
        timestep_s=diagnostic.timestep_s,
        duration_s=diagnostic.duration_s,
        trajectory_sha256=diagnostic.trajectory_sha256,
        initial_time_s=diagnostic.initial.time_s,
        final_time_s=diagnostic.final.time_s,
        final_angle_rad=diagnostic.final.angle_rad,
        final_angular_velocity_rad_s=diagnostic.final.angular_velocity_rad_s,
        energy_initial_j=diagnostic.energy_initial_j,
        energy_final_j=diagnostic.energy_final_j,
        max_relative_energy_drift=diagnostic.max_relative_energy_drift,
        all_finite=diagnostic.all_finite,
    )
    return model_consumption, physics_observation, source_manifest


def _run(config: dict[str, Any], request):
    from dynamisbench.adapters.mujoco import dependencies
    from dynamisbench.adapters.mujoco._b2_probe_common import (
        MAX_RECEIPT_BYTES,
        ConsumptionReceipt,
        ProbeTargets,
        WorkerRuntimeSummary,
        measure_runtime_identity,
        read_bounded_regular,
        sha256_bytes,
        verify_view,
        write_canonical_atomic,
    )

    inputs_root = Path(config["inputs"])
    scratch = Path(config["scratch"])
    binding_bytes = read_bounded_regular(inputs_root / "binding.json", limit=4096)
    view = verify_view(inputs_root, request)
    target_bytes = read_bounded_regular(scratch / "probe-targets.json", limit=64 * 1024)
    targets = ProbeTargets.model_validate_json(target_bytes)

    identity = measure_runtime_identity(
        executable=Path(sys.executable),
        base_prefix=Path(config["base_prefix"]),
        site_packages=Path(config["site_packages"]),
        source_root=Path(config["source_root"]),
        model_asset_relative="assets/reference_pendulum.xml",
    )
    if identity.digest != config["runtime_closure_sha256"]:
        raise ValueError("the worker runtime does not match the supervisor-measured closure")
    if view.binding.runtime_closure_sha256 != identity.digest:
        raise ValueError("the input binding does not commit to this worker runtime")
    if view.binding.isolation_profile_sha256 != config["profile_sha256"]:
        raise ValueError("the input binding does not commit to this isolation profile")

    probes = _probes(config, targets, inputs_root)
    if any(not probe.passed for probe in probes):
        failed = ", ".join(probe.name for probe in probes if not probe.passed)
        raise ValueError(f"an inside-worker isolation probe did not hold: {failed}")

    mode = config["mode"]
    if mode == "materialized-mujoco":
        model, physics_observation, source_manifest = _run_materialized(
            config, request, view, identity
        )
        engine_imported = "mujoco" in sys.modules
    elif mode == "verify-only":
        model = None
        physics_observation = None
        source_manifest = ()
        engine_imported = bool(sys.modules.get("mujoco"))
    else:
        raise ValueError("sandbox.json declares an unknown probe mode")

    imports = _import_audit(
        site_packages=Path(config["site_packages"]),
        source_root=Path(config["source_root"]),
        base_prefix=Path(config["base_prefix"]),
    )
    if any(not module.under_runtime for module in imports):
        raise ValueError("a scientific import resolved outside the measured runtime")
    if mode == "verify-only":
        if engine_imported:
            raise ValueError("the verify-only probe imported the engine")
        if not any(module.module == "dynamisbench" for module in imports):
            raise ValueError("the verify-only probe did not import the package under test")

    receipt = ConsumptionReceipt(
        mode=mode,
        completed=True,
        failure=None,
        attempt_nonce=view.binding.launch_nonce,
        run_id=str(request.run_id),
        execution_fingerprint=request.execution_fingerprint.hex,
        request_sha256=view.binding.request_sha256,
        preflight_sha256=view.binding.preflight_sha256,
        input_manifest_sha256=view.binding.input_manifest_sha256,
        binding_sha256=sha256_bytes(binding_bytes),
        environment_sha256=view.binding.environment_sha256,
        worker_selection_sha256=view.binding.worker_selection_sha256,
        adapter_implementation_sha256=view.binding.adapter_implementation_sha256,
        runtime_closure_sha256=identity.digest,
        isolation_profile_sha256=view.binding.isolation_profile_sha256,
        source_manifest=source_manifest,
        dependency_closure_digest=dependencies.installed_closure().digest,
        runtime_summary=WorkerRuntimeSummary(
            executable_sha256=identity.executable_sha256,
            base_digest=identity.base.digest,
            site_packages_digest=identity.site_packages_closure.digest,
            source_digest=identity.source.digest,
            combined_digest=identity.digest,
        ),
        imports=imports,
        probes=probes,
        model=model,
        physics=physics_observation,
        engine_imported=engine_imported,
    )
    write_canonical_atomic(scratch / "consumption.json", receipt, limit=MAX_RECEIPT_BYTES)
    return receipt


def _write_failure_receipt(config: dict[str, Any], request, error: BaseException) -> None:
    """Best-effort bounded failure observation; never claim completion."""
    try:
        from dynamisbench.adapters.mujoco._b2_probe_common import (
            MAX_RECEIPT_BYTES,
            ConsumptionReceipt,
            sha256_bytes,
            write_canonical_atomic,
        )

        inputs_root = Path(config["inputs"])
        scratch = Path(config["scratch"])
        binding_bytes = (inputs_root / "binding.json").read_bytes()
        from dynamisbench.execution.input_binding import WorkerInputBinding

        binding = WorkerInputBinding.model_validate_json(binding_bytes)
        receipt = ConsumptionReceipt(
            mode=config["mode"],
            completed=False,
            failure=_bounded_text(error),
            attempt_nonce=binding.launch_nonce,
            run_id=str(request.run_id),
            execution_fingerprint=request.execution_fingerprint.hex,
            request_sha256=binding.request_sha256,
            preflight_sha256=binding.preflight_sha256,
            input_manifest_sha256=binding.input_manifest_sha256,
            binding_sha256=sha256_bytes(binding_bytes),
            environment_sha256=binding.environment_sha256,
            worker_selection_sha256=binding.worker_selection_sha256,
            adapter_implementation_sha256=binding.adapter_implementation_sha256,
            runtime_closure_sha256=binding.runtime_closure_sha256,
            isolation_profile_sha256=binding.isolation_profile_sha256,
            source_manifest=(),
            dependency_closure_digest="0" * 64,
            imports=(),
            probes=(),
            model=None,
            physics=None,
            engine_imported="mujoco" in sys.modules,
        )
        write_canonical_atomic(scratch / "consumption.json", receipt, limit=MAX_RECEIPT_BYTES)
    except Exception:  # noqa: BLE001 - a failure receipt is best effort
        return


def main(argv: list[str] | None = None) -> int:
    """Run exactly one probe mode, or refuse without claiming a successful response."""
    from dynamisbench.adapters.mujoco._b2_probe_common import assert_probe_authorized

    arguments = sys.argv[1:] if argv is None else argv
    if arguments:
        _write_stderr("dynamisbench protected probe: the probe accepts no arguments")
        return 2
    try:
        assert_probe_authorized()
        config = _load_config()
        request = _read_request()
    except Exception as error:  # noqa: BLE001 - no valid request to answer
        _write_stderr(f"dynamisbench protected probe: {_bounded_text(error)}")
        return 2

    try:
        _run(config, request)
    except BaseException as error:  # noqa: BLE001 - fail closed, never a false success
        _write_failure_receipt(config, request, error)
        message = f"protected probe refused: {type(error).__name__}"
        _write_stderr(f"dynamisbench protected probe: {_bounded_text(error)}")
        _write_response(request, "failed", message)
        return 0

    _write_response(
        request,
        "completed",
        "protected materialized probe completed; consumption receipt written",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
