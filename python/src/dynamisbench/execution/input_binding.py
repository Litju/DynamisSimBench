"""Offline commitments for prepared inputs. These values carry no launch capability."""

from __future__ import annotations

from hashlib import sha256
from secrets import token_hex
from typing import Final, Literal

from pydantic import ConfigDict, Field

from dynamisbench.domain.spec.base import DomainModel
from dynamisbench.domain.spec.identifiers import Sha256Hex
from dynamisbench.evidence.bundle import RunId
from dynamisbench.execution.contracts import (
    MAX_WORKER_MESSAGE_BYTES,
    PreflightDecision,
    WorkerRequest,
    canonical_worker_request_bytes,
    preflight_digest,
)
from dynamisbench.execution.environment import WorkerEnvironmentManifest
from dynamisbench.execution.preflight import PreparedExecutionInputs
from dynamisbench.identity import canonical_semantic_bytes, semantic_sha256
from dynamisbench.materialization import (
    ExecutionInputRefs,
    MaterializationError,
    MaterializationRefusalCode,
    input_manifest_digest,
)
from dynamisbench.planning.runspec import run_spec_fingerprint

MAX_BINDING_BYTES: Final = 4096


class WorkerInputBinding(DomainModel):
    """A commitment retained by the trusted offline caller before view verification."""

    model_config = ConfigDict(serialize_by_alias=True)

    schema_version: Literal["dynamisbench.worker-input-binding/1"] = Field(
        default="dynamisbench.worker-input-binding/1", serialization_alias="schema"
    )
    run_id: RunId
    execution_fingerprint: Sha256Hex
    request_sha256: Sha256Hex
    preflight_sha256: Sha256Hex
    input_manifest_sha256: Sha256Hex
    environment_sha256: Sha256Hex
    worker_selection_sha256: Sha256Hex
    adapter_implementation_sha256: Sha256Hex
    runtime_closure_sha256: Sha256Hex
    isolation_profile_sha256: Sha256Hex
    launch_nonce: Sha256Hex


def _input_refs(request: WorkerRequest) -> ExecutionInputRefs:
    spec = request.run_spec
    return ExecutionInputRefs(
        benchmark=spec.benchmark,
        scenario=spec.scenario,
        realization=spec.realization,
        system_under_test=spec.system_under_test,
        environment=spec.environment,
    )


def _request_sha256(request: WorkerRequest) -> str:
    if request.execution_fingerprint != run_spec_fingerprint(request.run_spec):
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_MANIFEST_MISMATCH,
            "the worker request fingerprint does not match its RunSpec",
        )
    raw = canonical_worker_request_bytes(request)
    if len(raw) + 1 > MAX_WORKER_MESSAGE_BYTES:
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_LIMIT_EXCEEDED, "worker request exceeds its bound"
        )
    return sha256(raw).hexdigest()


def build_worker_input_binding(
    prepared: PreparedExecutionInputs,
    selection: WorkerEnvironmentManifest,
    *,
    runtime_closure_sha256: Sha256Hex,
    isolation_profile_sha256: Sha256Hex,
) -> WorkerInputBinding:
    """Commit to a trusted preparation result, its selection and a fresh attempt.

    The closure and isolation digests are expected identities supplied by the
    offline caller. This function does not inspect the installed worker or host.
    """
    report = prepared.report
    request = prepared.request
    if request is None or report.decision != PreflightDecision.READY:
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_MANIFEST_MISMATCH,
            "the preparation did not retain an admitted request",
        )
    request_sha256 = _request_sha256(request)
    selection_digest = semantic_sha256(selection)
    implementation = request.adapter.implementation_digest
    if (
        report.run_id != request.run_id
        or report.execution_fingerprint != request.execution_fingerprint
        or report.environment != request.environment
        or report.adapter != request.adapter
        or report.required_capabilities != request.required_capabilities
        or report.supported_capabilities != request.supported_capabilities
        or report.staging_locator != request.staging_locator
        or report.request_digest is None
        or report.request_digest.hex != request_sha256
        or report.refusals
        or selection.adapter != request.adapter
        or selection_digest != prepared.worker_environment_digest
        or implementation is None
    ):
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_MANIFEST_MISMATCH,
            "the prepared request, report and worker selection disagree",
        )

    manifest = prepared.inputs.manifest
    manifest_digest = input_manifest_digest(manifest)
    if (
        manifest.execution_refs != _input_refs(request)
        or manifest_digest != prepared.inputs.manifest_digest
    ):
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_MANIFEST_MISMATCH,
            "the input manifest does not match the prepared request and digest",
        )

    return WorkerInputBinding(
        run_id=request.run_id,
        execution_fingerprint=request.execution_fingerprint.hex,
        request_sha256=request_sha256,
        preflight_sha256=preflight_digest(report).hex,
        input_manifest_sha256=manifest_digest.hex,
        environment_sha256=request.environment.semantic_digest.hex,
        worker_selection_sha256=selection_digest.hex,
        adapter_implementation_sha256=implementation,
        runtime_closure_sha256=runtime_closure_sha256,
        isolation_profile_sha256=isolation_profile_sha256,
        launch_nonce=token_hex(32),
    )


def verify_worker_input_binding(
    data: bytes, *, expected: WorkerInputBinding, request: WorkerRequest
) -> None:
    """Verify exact binding bytes against independent trusted expectations."""
    if len(data) > MAX_BINDING_BYTES:
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_LIMIT_EXCEEDED, "input binding exceeds its bound"
        )
    if (
        data != canonical_semantic_bytes(expected)
        or expected.request_sha256 != _request_sha256(request)
        or expected.run_id != request.run_id
        or expected.execution_fingerprint != request.execution_fingerprint.hex
        or expected.environment_sha256 != request.environment.semantic_digest.hex
        or expected.adapter_implementation_sha256 != request.adapter.implementation_digest
    ):
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_MANIFEST_MISMATCH,
            "the input binding does not match the trusted attempt and request",
        )
