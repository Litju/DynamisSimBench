"""Probe-only contracts for the RES-555 Gate B2 protected-consumption qualification.

This module is **not** part of the accepted execution route. The supervisor, preflight,
API, CLI and worker protocol never import it. It exists only for the unadmitted
qualification harness in ``python/tools/res555_gate_b2`` and its tests, so that the
authority decision can be made against executable evidence rather than a design document.

It deliberately contains no launch capability: measuring a closure, verifying a view or
parsing a receipt does not start a process, and none of these values can be handed to
``execute_preflighted``.

The receipt is a bounded *observation*, not native evidence. It is not written to
``native/``, not canonicalized, not assessed and not sealed.
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Final, Literal

from pydantic import ConfigDict, Field

from dynamisbench.adapters.mujoco import dependencies, reference
from dynamisbench.domain.spec.base import DomainModel
from dynamisbench.domain.spec.benchmark import BenchmarkRelease
from dynamisbench.domain.spec.environment import EnvironmentDefinition
from dynamisbench.domain.spec.identifiers import Sha256Hex
from dynamisbench.domain.spec.realizations import RealizationDefinition
from dynamisbench.domain.spec.scenarios import ScenarioDefinition
from dynamisbench.domain.spec.sut import SUTDefinition, SUTInterfaceKind
from dynamisbench.evidence.bundle import is_link_or_reparse_point
from dynamisbench.execution.contracts import (
    WORKER_PROTOCOL_VERSION,
    WorkerRequest,
    canonical_worker_request_bytes,
)
from dynamisbench.execution.input_binding import (
    MAX_BINDING_BYTES,
    WorkerInputBinding,
    _input_refs,
)
from dynamisbench.identity import canonical_semantic_bytes
from dynamisbench.materialization import (
    DefinitionInput,
    DefinitionKind,
    InputManifest,
    MaterializationError,
    MaterializationRefusalCode,
    parse_input_manifest,
)

__all__ = [
    "CLOSURE_SCHEMA",
    "CONSUMPTION_RECEIPT_SCHEMA",
    "ISOLATION_PROFILE_SCHEMA",
    "MAX_CLOSURE_FILE_BYTES",
    "MAX_RECEIPT_BYTES",
    "MAX_VIEW_FILE_BYTES",
    "OBSERVATION_SCHEMA",
    "PROBE_ENV_VAR",
    "PROBE_SCHEMA",
    "ClosureEntry",
    "ConsumptionReceipt",
    "ImportedModule",
    "IsolationProfile",
    "ModelConsumption",
    "PhysicsObservation",
    "ProbeObservation",
    "ProbePolicyError",
    "ProbeTargets",
    "RootClosure",
    "RuntimeIdentity",
    "RuntimeRootSummary",
    "RuntimeSummary",
    "SupervisorObservation",
    "VerifiedView",
    "WorkerRuntimeSummary",
    "assert_probe_authorized",
    "combined_runtime_digest",
    "measure_root_closure",
    "measure_runtime_identity",
    "read_bounded_regular",
    "reconstruct_implementation_digest",
    "sha256_bytes",
    "sha256_file",
    "verify_view",
    "write_canonical_atomic",
]

PROBE_ENV_VAR: Final = "DYNAMISBENCH_RES555_B2_PROBE"
"""The explicit probe gate. Production execution has no such environment variable."""

ISOLATION_PROFILE_SCHEMA: Final = "dynamisbench.res555.isolation-profile/1"
CLOSURE_SCHEMA: Final = "dynamisbench.res555.runtime-closure/1"
CONSUMPTION_RECEIPT_SCHEMA: Final = "dynamisbench.res555.consumption-receipt/1"
OBSERVATION_SCHEMA: Final = "dynamisbench.res555.supervisor-observation/1"
PROBE_SCHEMA: Final = "dynamisbench.res555.probe-targets/1"

MAX_RECEIPT_BYTES: Final = 512 * 1024
MAX_VIEW_FILE_BYTES: Final = 1024 * 1024
MAX_CLOSURE_FILE_BYTES: Final = 256 * 1024 * 1024
_CLOSURE_EXCLUDED_NAMES: Final = frozenset({"__pycache__"})
_CLOSURE_POLICY: Final = (
    "regular single-link files only; __pycache__ excluded and absent from the sandbox; "
    "relative paths are portable and sorted; file bytes are SHA-256; no directory entry "
    "or symlink is treated as a runtime file"
)


class ProbePolicyError(RuntimeError):
    """The probe harness or a probe-only value refused the requested operation."""


def assert_probe_authorized() -> None:
    """Refuse to run outside the explicit probe gate.

    The environment variable is not a security boundary. It is a deliberate circuit
    breaker: an operator or test must state that this is a probe, and an accidental
    production path cannot silently reach the harness.
    """
    if os.environ.get(PROBE_ENV_VAR) != "1":
        raise ProbePolicyError(
            "the RES-555 Gate B2 harness is probe-only and requires "
            f"{PROBE_ENV_VAR}=1; no production materialized-worker route is authorized"
        )


class _Model(DomainModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
        populate_by_name=True,
        serialize_by_alias=True,
    )


class IsolationProfile(_Model):
    """The exact OS-enforcement profile a probe attempt is launched under."""

    schema_id: Literal["dynamisbench.res555.isolation-profile/1"] = Field(
        default=ISOLATION_PROFILE_SCHEMA, alias="schema"
    )
    platform: Literal["windows-x86-64", "linux-x86-64"]
    mechanism: Literal["windows-appcontainer", "linux-landlock"]
    worker_principal: str
    input_access: Literal["read-only"] = "read-only"
    runtime_access: Literal["read-execute-only"] = "read-execute-only"
    scratch_access: Literal["read-write"] = "read-write"
    scientific_source_access: Literal["denied"] = "denied"
    staging_access: Literal["denied"] = "denied"
    sealed_access: Literal["denied"] = "denied"
    network_access: Literal["denied"] = "denied"
    memory_limit_bytes: int = Field(gt=0)
    cpu_time_seconds: int = Field(gt=0)
    wall_time_seconds: float = Field(gt=0)
    max_stdout_bytes: int = Field(gt=0)
    max_stderr_bytes: int = Field(gt=0)
    max_scratch_bytes: int = Field(gt=0)
    max_processes: int = Field(gt=0)

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
        populate_by_name=True,
        serialize_by_alias=True,
    )

    def digest(self) -> str:
        return sha256_bytes(canonical_semantic_bytes(self))


class ClosureEntry(_Model):
    path: str
    size_bytes: int = Field(ge=0)
    sha256: Sha256Hex


class RootClosure(_Model):
    label: str
    entries: tuple[ClosureEntry, ...]
    digest: Sha256Hex
    content_digest: Sha256Hex


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(
    path: Path, *, max_bytes: int = MAX_CLOSURE_FILE_BYTES, allow_hardlinks: bool = False
) -> tuple[int, str]:
    """Hash one regular file, refusing anything a closure cannot name."""
    info = path.lstat()
    if (
        is_link_or_reparse_point(path)
        or not stat.S_ISREG(info.st_mode)
        or (not allow_hardlinks and info.st_nlink != 1)
    ):
        raise ProbePolicyError("a closure entry is not one regular single-link file")
    if info.st_size > max_bytes:
        raise ProbePolicyError("a closure entry exceeds the per-file bound")
    hasher = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ProbePolicyError("a closure entry grew past its per-file bound")
            hasher.update(chunk)
    if total != info.st_size:
        raise ProbePolicyError("a closure entry changed size while it was hashed")
    return total, hasher.hexdigest()


def measure_root_closure(
    label: str,
    root: Path,
    *,
    exclude_relative_prefixes: Sequence[str] = (),
    exclude_names: Iterable[str] = _CLOSURE_EXCLUDED_NAMES,
    allow_hardlinks: bool = False,
) -> RootClosure:
    """Measure one root as portable relative paths, refusing links and special files.

    The root must be an absolute, non-linked directory. Directory traversal is sorted so
    two measurements of identical bytes produce identical canonical output. A symlink,
    junction, reparse point, FIFO, device or socket is a refusal, not an entry: a closure
    is a claim about exact bytes, and an alias is not one.

    ``allow_hardlinks`` exists only for measuring the *installed* source tree, where a
    package installer may deduplicate files with hard links. The executed snapshot is
    copied and is always measured with hard links refused; the source/snapshot comparison
    uses :attr:`RootClosure.content_digest`, which excludes the hard-link policy.
    """
    if not root.is_absolute() or not root.is_dir():
        raise ProbePolicyError(f"closure root {label!r} is not an absolute directory")
    if is_link_or_reparse_point(root):
        raise ProbePolicyError(f"closure root {label!r} is a link or reparse point")
    excluded_prefixes = tuple(prefix.strip("/") for prefix in exclude_relative_prefixes)
    excluded_names = frozenset(exclude_names)
    entries: list[ClosureEntry] = []

    def visit(directory: Path, relative: str) -> None:
        try:
            children = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError as error:
            raise ProbePolicyError(f"closure root {label!r} could not be enumerated") from error
        for child in children:
            name = child.name
            if name in excluded_names:
                continue
            child_relative = f"{relative}/{name}" if relative else name
            if child_relative in excluded_prefixes or any(
                child_relative.startswith(prefix + "/") for prefix in excluded_prefixes
            ):
                continue
            info = child.lstat()
            if is_link_or_reparse_point(child):
                raise ProbePolicyError(
                    f"closure {label!r} contains a link or reparse point at {child_relative!r}"
                )
            if stat.S_ISDIR(info.st_mode):
                visit(child, child_relative)
            elif stat.S_ISREG(info.st_mode):
                if not allow_hardlinks and info.st_nlink != 1:
                    raise ProbePolicyError(
                        f"closure {label!r} contains a hard link at {child_relative!r}"
                    )
                if info.st_size > MAX_CLOSURE_FILE_BYTES:
                    raise ProbePolicyError(
                        f"closure {label!r} contains an oversized file at {child_relative!r}"
                    )
                size, digest = sha256_file(child, allow_hardlinks=allow_hardlinks)
                entries.append(ClosureEntry(path=child_relative, size_bytes=size, sha256=digest))
            else:
                raise ProbePolicyError(
                    f"closure {label!r} contains a non-regular object at {child_relative!r}"
                )

    visit(root, "")
    ordered = tuple(sorted(entries, key=lambda entry: entry.path))
    policy = _CLOSURE_POLICY + (
        "; hard links are followed by path in the installed-source measurement"
        if allow_hardlinks
        else "; every measured object is a single-link file"
    )
    payload = {
        "schema": CLOSURE_SCHEMA,
        "label": label,
        "policy": policy,
        "entries": [entry.model_dump(mode="json") for entry in ordered],
    }
    content_payload = {
        "schema": CLOSURE_SCHEMA,
        "label": label,
        "entries": [entry.model_dump(mode="json") for entry in ordered],
    }
    return RootClosure(
        label=label,
        entries=ordered,
        digest=sha256_bytes(canonical_semantic_bytes(payload)),
        content_digest=sha256_bytes(canonical_semantic_bytes(content_payload)),
    )


class RuntimeIdentity(_Model):
    """One measured runtime, from three independently named roots."""

    schema_id: Literal["dynamisbench.res555.runtime-identity/1"] = Field(
        default="dynamisbench.res555.runtime-identity/1", alias="schema"
    )
    executable: str
    executable_sha256: Sha256Hex
    base_prefix: str
    site_packages_path: str
    source_root: str
    base: RootClosure
    site_packages_closure: RootClosure
    source: RootClosure
    digest: Sha256Hex

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
        populate_by_name=True,
        serialize_by_alias=True,
    )


def combined_runtime_digest(identity: RuntimeIdentity) -> str:
    payload = {
        "schema": "dynamisbench.res555.runtime-identity-digest/1",
        "executable_sha256": identity.executable_sha256,
        "base": identity.base.content_digest,
        "site_packages": identity.site_packages_closure.content_digest,
        "source": identity.source.content_digest,
    }
    return sha256_bytes(canonical_semantic_bytes(payload))


def _base_site_packages_prefixes(base_prefix: Path) -> tuple[str, ...]:
    prefixes = ["Lib/site-packages"]
    lib = base_prefix / "lib"
    if lib.is_dir():
        for child in sorted(lib.iterdir(), key=lambda item: item.name):
            if child.is_dir() and child.name.startswith("python"):
                prefixes.append(f"lib/{child.name}/site-packages")
    return tuple(prefixes)


def measure_runtime_identity(
    *,
    executable: Path,
    base_prefix: Path,
    site_packages: Path,
    source_root: Path,
    model_asset_relative: str | None = None,
    allow_hardlinks: bool = False,
) -> RuntimeIdentity:
    """Measure the interpreter, base installation, site-packages and adapter source.

    ``model_asset_relative`` names the packaged model inside the adapter source tree. When
    given, it is excluded from the source closure because the materialized route removes it
    from the sandbox: its bytes must arrive through the verified input view instead. The
    same exclusion is applied on the trusted source side, so the comparison is about the
    bytes that actually execute.
    """
    resolved_executable = executable.resolve()
    executable_size, executable_digest = sha256_file(resolved_executable, allow_hardlinks=True)
    del executable_size
    exclude = (
        (f"dynamisbench/adapters/mujoco/{model_asset_relative}",) if model_asset_relative else ()
    )
    base_exclusions = (*_base_site_packages_prefixes(base_prefix), "bin", "Scripts")
    base = measure_root_closure(
        "base",
        base_prefix,
        exclude_relative_prefixes=base_exclusions,
        allow_hardlinks=True,
    )
    site = measure_root_closure("site-packages", site_packages, allow_hardlinks=allow_hardlinks)
    source = measure_root_closure(
        "source",
        source_root,
        exclude_relative_prefixes=exclude,
        allow_hardlinks=allow_hardlinks,
    )
    provisional = RuntimeIdentity(
        executable=str(resolved_executable),
        executable_sha256=executable_digest,
        base_prefix=str(base_prefix),
        site_packages_path=str(site_packages),
        source_root=str(source_root),
        base=base,
        site_packages_closure=site,
        source=source,
        digest="0" * 64,
    )
    return provisional.model_copy(update={"digest": combined_runtime_digest(provisional)})


def read_bounded_regular(path: Path, *, limit: int) -> bytes:
    """Read one regular single-link file without following a link, bounded in size."""
    info = path.lstat()
    if is_link_or_reparse_point(path) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ProbePolicyError("a view entry is not one regular single-link file")
    if info.st_size > limit:
        raise ProbePolicyError("a view entry exceeds its byte bound")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ProbePolicyError(
            "a view entry could not be opened without following a link"
        ) from error
    try:
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or after.st_size != info.st_size
            or (after.st_dev, after.st_ino) != (info.st_dev, info.st_ino)
        ):
            raise ProbePolicyError("a view entry changed between inspection and open")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > limit:
            raise ProbePolicyError("a view entry grew past its byte bound")
        return data
    finally:
        os.close(descriptor)


def write_canonical_atomic(path: Path, model: DomainModel, *, limit: int) -> bytes:
    """Write canonical bytes through a create-exclusive temporary file and atomic rename."""
    data = canonical_semantic_bytes(model)
    if len(data) > limit:
        raise ProbePolicyError("the canonical payload exceeds its byte bound")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return data


class RuntimeRootSummary(_Model):
    label: str
    entry_count: int = Field(ge=0)
    digest: Sha256Hex
    content_digest: Sha256Hex


class RuntimeSummary(_Model):
    executable: str
    executable_sha256: Sha256Hex
    base_prefix: str
    site_packages_path: str
    source_root: str
    base: RuntimeRootSummary
    site_packages_closure: RuntimeRootSummary
    source: RuntimeRootSummary
    digest: Sha256Hex


def summarize_runtime(identity: RuntimeIdentity) -> RuntimeSummary:
    """The compact observation form: roots, counts and digests, not every entry."""

    def root(value: RootClosure) -> RuntimeRootSummary:
        return RuntimeRootSummary(
            label=value.label,
            entry_count=len(value.entries),
            digest=value.digest,
            content_digest=value.content_digest,
        )

    return RuntimeSummary(
        executable=identity.executable,
        executable_sha256=identity.executable_sha256,
        base_prefix=identity.base_prefix,
        site_packages_path=identity.site_packages_path,
        source_root=identity.source_root,
        base=root(identity.base),
        site_packages_closure=root(identity.site_packages_closure),
        source=root(identity.source),
        digest=identity.digest,
    )


class VerifiedView(DomainModel):
    """The worker's own verification of the exact input view before any physics."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
        arbitrary_types_allowed=True,
    )

    binding: WorkerInputBinding
    manifest_digest: Sha256Hex
    manifest: InputManifest
    realization: RealizationDefinition
    asset_path: str
    asset_sha256: Sha256Hex
    asset_size_bytes: int
    model_bytes: bytes
    observed_files: tuple[ClosureEntry, ...]


def _definition_identity(value: object, kind: DefinitionKind) -> tuple[str, str]:
    match kind:
        case DefinitionKind.BENCHMARK:
            assert isinstance(value, BenchmarkRelease)
            return str(value.benchmark_id), value.version
        case DefinitionKind.SCENARIO:
            assert isinstance(value, ScenarioDefinition)
            return str(value.scenario_id), value.version
        case DefinitionKind.REALIZATION:
            assert isinstance(value, RealizationDefinition)
            return str(value.realization_id), value.version
        case DefinitionKind.SYSTEM_UNDER_TEST:
            assert isinstance(value, SUTDefinition)
            return str(value.sut_id), value.version
        case DefinitionKind.ENVIRONMENT:
            assert isinstance(value, EnvironmentDefinition)
            return str(value.environment_id), value.version


_DEFINITION_MODELS: Final = {
    DefinitionKind.BENCHMARK: BenchmarkRelease,
    DefinitionKind.SCENARIO: ScenarioDefinition,
    DefinitionKind.REALIZATION: RealizationDefinition,
    DefinitionKind.SYSTEM_UNDER_TEST: SUTDefinition,
    DefinitionKind.ENVIRONMENT: EnvironmentDefinition,
}


def _verify_definition(
    root: Path, record: DefinitionInput, observations: list[ClosureEntry]
) -> object:
    path = root / f"{record.kind.value}.json"
    data = read_bounded_regular(path, limit=MAX_VIEW_FILE_BYTES)
    observed = sha256_bytes(data)
    if len(data) != record.size_bytes or observed != record.semantic_digest.hex:
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_OBJECT_CORRUPT,
            "a worker view definition does not match the manifest",
        )
    model = _DEFINITION_MODELS[record.kind]
    value = model.model_validate_json(data)
    if canonical_semantic_bytes(value) != data or _definition_identity(value, record.kind) != (
        record.identifier,
        record.version,
    ):
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_DEFINITION_MISMATCH,
            "a worker view definition is not its canonical resolved definition",
        )
    observations.append(
        ClosureEntry(path=f"definitions/{path.name}", size_bytes=len(data), sha256=observed)
    )
    return value


def verify_view(inputs_root: Path, request: WorkerRequest) -> VerifiedView:
    """Verify the exact view the worker is allowed to consume.

    This is the worker-side counterpart of the A1 offline verifier, not a replacement for
    it: the supervisor still verifies the same view before launch and after exit. The
    worker check is intentionally narrower and accepts exactly one asset, which is the
    fixed reference profile's shape and not a general model loader.
    """
    observations: list[ClosureEntry] = []
    binding_bytes = read_bounded_regular(inputs_root / "binding.json", limit=MAX_BINDING_BYTES)
    binding = WorkerInputBinding.model_validate_json(binding_bytes)
    if canonical_semantic_bytes(binding) != binding_bytes:
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_MANIFEST_MISMATCH,
            "the worker view binding is not canonical",
        )
    request_sha256 = sha256_bytes(canonical_worker_request_bytes(request))
    if (
        binding.request_sha256 != request_sha256
        or binding.run_id != request.run_id
        or binding.execution_fingerprint != request.execution_fingerprint.hex
        or binding.environment_sha256 != request.environment.semantic_digest.hex
        or binding.adapter_implementation_sha256 != request.adapter.implementation_digest
    ):
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_MANIFEST_MISMATCH,
            "the worker view binding does not describe the request it was launched for",
        )
    manifest_bytes = read_bounded_regular(inputs_root / "manifest.json", limit=MAX_VIEW_FILE_BYTES)
    manifest_digest = sha256_bytes(manifest_bytes)
    if manifest_digest != binding.input_manifest_sha256:
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_MANIFEST_MISMATCH,
            "the worker view manifest bytes do not match the binding",
        )
    manifest = parse_input_manifest(manifest_bytes)
    if manifest.execution_refs != _input_refs(request):
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_MANIFEST_MISMATCH,
            "the worker view manifest references do not match the request",
        )
    observations.append(
        ClosureEntry(path="manifest.json", size_bytes=len(manifest_bytes), sha256=manifest_digest)
    )

    definitions_dir = inputs_root / "definitions"
    expected_names = {f"{kind.value}.json" for kind in DefinitionKind}
    observed_names = {entry.name for entry in definitions_dir.iterdir()}
    if observed_names != expected_names:
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_SET_UNEXPECTED,
            "the worker view definitions do not contain exactly the five resolved kinds",
        )
    records = {record.kind: record for record in manifest.definitions}
    if set(records) != set(DefinitionKind):
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_SET_INCOMPLETE,
            "the worker view manifest does not declare exactly five definitions",
        )
    values = {
        kind: _verify_definition(definitions_dir, records[kind], observations)
        for kind in DefinitionKind
    }
    benchmark = values[DefinitionKind.BENCHMARK]
    scenario = values[DefinitionKind.SCENARIO]
    realization = values[DefinitionKind.REALIZATION]
    sut = values[DefinitionKind.SYSTEM_UNDER_TEST]
    assert isinstance(benchmark, BenchmarkRelease)
    assert isinstance(scenario, ScenarioDefinition)
    assert isinstance(realization, RealizationDefinition)
    assert isinstance(sut, SUTDefinition)
    if (
        realization.benchmark.identifier != benchmark.benchmark_id
        or realization.benchmark.version != benchmark.version
        or not any(item == scenario for item in benchmark.scenarios)
    ):
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_DEFINITION_MISMATCH,
            "the worker view benchmark, scenario and realization disagree",
        )
    if sut.interface.kind is not SUTInterfaceKind.IN_PROCESS:
        raise MaterializationError(
            MaterializationRefusalCode.SUT_EXECUTABLE_CLOSURE_UNSUPPORTED,
            "the probe accepts only the fixed in-process reference SUT",
        )
    declared = {(asset.asset_id, asset.path, asset.sha256) for asset in realization.assets}
    listed = {
        (asset.asset_id, asset.logical_path, asset.observed_sha256) for asset in manifest.assets
    }
    if declared != listed or len(manifest.assets) != 1:
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_MANIFEST_MISMATCH,
            "the worker view must contain exactly the realization's single declared asset",
        )
    asset = manifest.assets[0]
    asset_path = inputs_root / "assets"
    for segment in asset.logical_path.split("/"):
        asset_path = asset_path / segment
    data = read_bounded_regular(asset_path, limit=MAX_VIEW_FILE_BYTES)
    observed = sha256_bytes(data)
    if len(data) != asset.size_bytes or observed != asset.observed_sha256:
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_OBJECT_CORRUPT,
            "the worker view asset bytes do not match the manifest",
        )
    observations.append(
        ClosureEntry(
            path=f"assets/{asset.logical_path}",
            size_bytes=len(data),
            sha256=observed,
        )
    )

    expected_dirs = {"definitions", "assets"}
    extra = {entry.name for entry in inputs_root.iterdir()} - {
        "binding.json",
        "manifest.json",
        *expected_dirs,
    }
    if extra:
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_SET_UNEXPECTED,
            "the worker view contains an unexpected top-level entry",
        )
    return VerifiedView(
        binding=binding,
        manifest_digest=manifest_digest,
        manifest=manifest,
        realization=realization,
        asset_path=asset.logical_path,
        asset_sha256=observed,
        asset_size_bytes=len(data),
        model_bytes=data,
        observed_files=tuple(sorted(observations, key=lambda entry: entry.path)),
    )


def reconstruct_implementation_digest(
    *,
    model_sha256: str,
    source_root: Path,
    engine_version: str,
    python_version: str,
    platform_tag: str,
) -> tuple[str, tuple[dict[str, str], ...]]:
    """Recompute the adapter identity from the sandbox source, without the package XML.

    The packaged model is a production adapter source file, but the materialized route
    removes it from the sandbox and supplies the same pinned bytes through the verified
    input view. Its entry in the source manifest is therefore the verified view digest.
    Every other adapter file is read from the sandbox source and hashed. The payload is
    identical to :func:`dynamisbench.adapters.mujoco.identity.build_implementation_identity`
    with the same model digest, so a test can compare the two.
    """
    adapter_root = source_root / "dynamisbench" / "adapters" / "mujoco"
    manifest: list[dict[str, str]] = []
    for relative in sorted(reference.ADAPTER_SOURCE_FILES):
        if relative == reference.MODEL_ASSET_PATH:
            digest = model_sha256
        else:
            data = read_bounded_regular(adapter_root / relative, limit=MAX_VIEW_FILE_BYTES)
            digest = sha256_bytes(data)
        manifest.append({"path": relative, "sha256": digest})
    payload = {
        "schema": reference.IMPLEMENTATION_IDENTITY_SCHEMA,
        "adapter_id": reference.ADAPTER_ID,
        "adapter_version": reference.ADAPTER_VERSION,
        "engine": reference.ENGINE,
        "engine_version": engine_version,
        "protocol_version": WORKER_PROTOCOL_VERSION,
        "capabilities": sorted(capability.value for capability in reference.CAPABILITIES),
        "platform": platform_tag,
        "python_version": python_version,
        "model_sha256": model_sha256,
        "source_manifest": manifest,
        "dependency_closure": dependencies.installed_closure().as_json_object(),
    }
    digest = sha256_bytes(canonical_semantic_bytes(payload))
    return digest, tuple(manifest)


class ProbeObservation(_Model):
    name: str
    expectation: Literal["allowed", "denied"]
    observed: Literal["allowed", "denied", "error"]
    detail: str

    @property
    def passed(self) -> bool:
        return self.observed == self.expectation


class ProbeTargets(_Model):
    schema_id: Literal["dynamisbench.res555.probe-targets/1"] = Field(
        default=PROBE_SCHEMA, alias="schema"
    )
    forbidden_reads: tuple[str, ...]
    forbidden_writes: tuple[str, ...]
    forbidden_deletes: tuple[str, ...]
    allowed_read: str
    allowed_write: str
    runtime_write: str
    network_port: int = Field(ge=1, le=65535)
    write_token: str

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
        populate_by_name=True,
        serialize_by_alias=True,
    )


class ImportedModule(_Model):
    module: str
    file: str
    under_runtime: bool


class WorkerRuntimeSummary(_Model):
    executable_sha256: Sha256Hex
    base_digest: Sha256Hex
    site_packages_digest: Sha256Hex
    source_digest: Sha256Hex
    combined_digest: Sha256Hex


class ModelConsumption(_Model):
    logical_path: str
    size_bytes: int = Field(ge=0)
    sha256: Sha256Hex
    source: Literal["input_view"] = "input_view"
    package_asset_present: bool
    package_asset_probe: Literal["allowed", "denied"]
    compiled: dict[str, float | int | str]


class PhysicsObservation(_Model):
    diagnostic_sha256: Sha256Hex
    steps: int = Field(gt=0)
    timestep_s: float = Field(gt=0, allow_inf_nan=False)
    duration_s: float = Field(gt=0, allow_inf_nan=False)
    trajectory_sha256: Sha256Hex
    initial_time_s: float = Field(ge=0, allow_inf_nan=False)
    final_time_s: float = Field(ge=0, allow_inf_nan=False)
    final_angle_rad: float = Field(allow_inf_nan=False)
    final_angular_velocity_rad_s: float = Field(allow_inf_nan=False)
    energy_initial_j: float = Field(allow_inf_nan=False)
    energy_final_j: float = Field(allow_inf_nan=False)
    max_relative_energy_drift: float = Field(ge=0, allow_inf_nan=False)
    all_finite: bool


class ConsumptionReceipt(_Model):
    schema_id: Literal["dynamisbench.res555.consumption-receipt/1"] = Field(
        default=CONSUMPTION_RECEIPT_SCHEMA, alias="schema"
    )
    mode: Literal["materialized-mujoco", "verify-only"]
    completed: bool
    failure: str | None = None
    attempt_nonce: Sha256Hex
    run_id: str
    execution_fingerprint: Sha256Hex
    request_sha256: Sha256Hex
    preflight_sha256: Sha256Hex
    input_manifest_sha256: Sha256Hex
    binding_sha256: Sha256Hex
    environment_sha256: Sha256Hex
    worker_selection_sha256: Sha256Hex
    adapter_implementation_sha256: Sha256Hex
    runtime_closure_sha256: Sha256Hex
    isolation_profile_sha256: Sha256Hex
    source_manifest: tuple[dict[str, str], ...]
    dependency_closure_digest: Sha256Hex
    runtime_summary: WorkerRuntimeSummary | None = None
    imports: tuple[ImportedModule, ...]
    probes: tuple[ProbeObservation, ...]
    model: ModelConsumption | None = None
    physics: PhysicsObservation | None = None
    engine_imported: bool

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
        populate_by_name=True,
        serialize_by_alias=True,
    )

    def digest(self) -> str:
        return sha256_bytes(canonical_semantic_bytes(self))


class SupervisorObservation(_Model):
    schema_id: Literal["dynamisbench.res555.supervisor-observation/1"] = Field(
        default=OBSERVATION_SCHEMA, alias="schema"
    )
    verdict: Literal["demonstrated", "refused"]
    refusals: tuple[str, ...]
    profile: IsolationProfile
    attempt_nonce: Sha256Hex
    binding_sha256: Sha256Hex
    request_sha256: Sha256Hex
    input_manifest_sha256: Sha256Hex
    execution_fingerprint: Sha256Hex
    source_runtime: RuntimeSummary
    snapshot_runtime: RuntimeSummary
    worker_runtime: dict[str, object] | None
    runtime_matches: bool
    external_isolation: dict[str, object]
    receipt_sha256: Sha256Hex | None
    receipt: ConsumptionReceipt | None
    process: dict[str, object]
    response: dict[str, object]
    checks: tuple[dict[str, object], ...]

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
        populate_by_name=True,
        serialize_by_alias=True,
    )

    def digest(self) -> str:
        return sha256_bytes(canonical_semantic_bytes(self))
