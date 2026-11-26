"""The frozen protected-execution profile for the pinned MuJoCo reference.

This module is the trusted, engine-independent pin for the one production route the owner
conditionally approved: ``dynamisbench.mujoco.reference`` 0.1.0 running its fixed
planar-pendulum reference on MuJoCo 3.17.0 / CPython 3.12.13 on Windows x86-64 or Linux
x86-64. It contains no simulator import and no launch capability. Selecting a profile is an
explicit operational decision; a request field can never select or widen it.

The profile hashes the protected bootstrap source file. The runtime closure measured by the
supervisor covers the rest of the executed source tree (including the protected worker entry),
so a bootstrap change is visible in the profile digest and a worker entry change is visible in
the runtime-closure digest. Neither digest is a vendor signature; see the owner adoption
record for the accepted residuals.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Final, Literal, cast

from pydantic import Field

from dynamisbench.adapters.mujoco import reference
from dynamisbench.domain.spec.base import DomainModel
from dynamisbench.domain.spec.capability import Capability
from dynamisbench.domain.spec.identifiers import Sha256Hex
from dynamisbench.execution.contracts import WORKER_PROTOCOL_VERSION, WorkerRequest
from dynamisbench.identity import SemanticDigest, semantic_sha256

__all__ = [
    "ADAPTER_IMPLEMENTATION_DIGESTS",
    "PROTECTED_IMPLEMENTATION_DIGESTS",
    "PROTECTED_PROFILE_SCHEMA",
    "PinnedReferenceProfile",
    "build_protected_profile",
    "protected_bootstrap_path",
]

PROTECTED_PROFILE_SCHEMA: Final = "dynamisbench.protected-execution-profile/1"
PROTECTED_BOOTSTRAP_RELATIVE_PATH: Final = "dynamisbench/execution/protected_bootstrap.py"
PROTECTED_WORKER_RELATIVE_PATH: Final = "dynamisbench/adapters/mujoco/protected_worker.py"
PROTECTED_RECEIPT_SCHEMA: Final = "dynamisbench.res555.consumption-receipt/1"
PROTECTED_SUPERVISOR_RECORD_SCHEMA: Final = "dynamisbench.protected-consumption/1"
PROTECTED_SUPERVISOR_RECORD_NAME: Final = "protected-consumption.json"

ADAPTER_IMPLEMENTATION_DIGESTS: Final[dict[str, str]] = {
    "windows-x86-64": "4a907d4262ceca66588188ddcc37894ec488a55f0756886864c89bc5f99827b8",
    "linux-x86-64": "7993ac96c91de71a7b5f8770d444c318d6c1283de5b8f0f0d1c615d7c6afe097",
}
"""The exact-head B2 adapter implementation digests accepted by the owner on 2026-11-25.

They include ``physics.compile_model``, the platform tag and the Python patch version. The
protected worker entry and bootstrap are execution-integration files covered by the runtime
source closure, not additions to ``reference.ADAPTER_SOURCE_FILES``; adding an adapter source
file would change these digests and require another owner decision.
"""


# RES-555 owner-selected 13-file schema-2 production execution identities. The v1
# WorkerRequest adapter digest remains unchanged for wire/worker compatibility. The
# supervisor independently binds the complete executed production entry to this second,
# owner-adopted identity; both checks are mandatory for the protected reference route.
PROTECTED_IMPLEMENTATION_DIGESTS: Final[dict[str, str]] = {
    "windows-x86-64": "86d5e912fa876208e156bfe13f91be6a5cfde7f0aefcc9e0bbf3aedbc7051f20",
    "linux-x86-64": "9ea31547f2246e2a8eedcaefcac8ae767086711c96ad79d5da835f72e5bc2ea1",
}
"""`dynamisbench.mujoco.implementation-identity/2` accepted conditionally on 2026-11-26.

This identity includes the 10 historical adapter files, the exact materialized model
hash, and protected_contracts.py, protected_worker.py and protected_bootstrap.py. No
mutation of a bound file may silently change these accepted identities. The model and
solver remain the pinned reference; the native-output ADR-027 gate remains separate.
"""


def protected_bootstrap_path() -> Path:
    """The source-file bootstrap that applies the sandbox before importing the worker."""
    return Path(__file__).with_name("protected_bootstrap.py")


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


class PinnedReferenceProfile(DomainModel):
    """One platform's frozen reference and resource profile.

    This is a trusted value, not a request. ``authority_refusals`` compares a request with
    the profile and returns field labels, never request content. The production supervisor
    refuses before staging or launch when the tuple is non-empty.
    """

    schema_version: Literal["dynamisbench.protected-execution-profile/1"] = PROTECTED_PROFILE_SCHEMA
    platform: Literal["windows-x86-64", "linux-x86-64"]
    adapter_id: str
    adapter_version: str
    engine: str
    engine_version: str
    python_version: str
    protocol_version: int
    capabilities: tuple[Capability, ...]
    adapter_implementation_digest: Sha256Hex
    production_implementation_digest: Sha256Hex
    model_source_path: str
    model_sha256: Sha256Hex
    benchmark_identifier: str
    benchmark_version: str
    benchmark_semantic_digest: SemanticDigest
    scenario_identifier: str
    scenario_version: str
    scenario_semantic_digest: SemanticDigest
    realization_identifier: str
    realization_version: str
    realization_semantic_digest: SemanticDigest
    system_under_test_identifier: str
    system_under_test_version: str
    system_under_test_semantic_digest: SemanticDigest
    environment_identifier: str
    environment_version: str
    environment_semantic_digest: SemanticDigest
    seed: int
    outcomes: tuple[str, ...]
    duration_s: float = Field(gt=0, allow_inf_nan=False)
    timestep_s: float = Field(gt=0, allow_inf_nan=False)
    steps: int = Field(gt=0)
    gravity_m_s2: float = Field(allow_inf_nan=False)
    gravity_factor_id: str
    gravity_quantity: str
    gravity_unit: str
    integrator: str
    solver: str
    tolerance: float = Field(gt=0, allow_inf_nan=False)
    reference_trajectory_sha256: Sha256Hex
    expected_final_angle_rad: float = Field(allow_inf_nan=False)
    expected_final_angular_velocity_rad_s: float = Field(allow_inf_nan=False)
    expected_energy_initial_j: float = Field(allow_inf_nan=False)
    expected_energy_final_j: float = Field(allow_inf_nan=False)
    bootstrap_relative_path: str
    bootstrap_sha256: Sha256Hex
    worker_relative_path: str
    receipt_schema: str
    supervisor_record_schema: str
    supervisor_record_name: str
    max_scratch_bytes: int = Field(gt=0)
    max_scratch_entries: int = Field(gt=0)
    max_memory_bytes: int = Field(gt=0)
    max_cpu_seconds: int = Field(gt=0)
    max_wall_seconds: float = Field(gt=0)
    max_stdout_bytes: int = Field(gt=0)
    max_stderr_bytes: int = Field(gt=0)
    max_processes: int = Field(gt=0)
    require_dedicated_scratch_linux: bool
    require_non_elevated_windows: bool

    def digest(self) -> str:
        """The canonical profile digest committed by the supervisor."""
        return semantic_sha256(self.model_dump(mode="json")).hex

    def authority_refusals(self, request: WorkerRequest) -> tuple[str, ...]:
        """Return the field labels in which ``request`` differs from this profile.

        This is deliberately a pure, engine-independent comparison. The MuJoCo worker also
        calls its own accepted ``worker._verify_reference_authority``; the two checks are
        compared by the qualification tests so a divergence is visible.
        """
        refusals: list[str] = []

        def check(label: str, observed: object, expected: object) -> None:
            if observed != expected:
                refusals.append(label)

        adapter = request.adapter
        check("adapter id", adapter.adapter_id, self.adapter_id)
        check("adapter version", adapter.adapter_version, self.adapter_version)
        check("engine", adapter.engine, self.engine)
        check("engine version", adapter.engine_version, self.engine_version)
        check("protocol version", adapter.protocol_version, self.protocol_version)
        check("capabilities", tuple(adapter.capabilities), self.capabilities)
        check("required capabilities", tuple(request.required_capabilities), self.capabilities)
        check(
            "adapter implementation digest",
            adapter.implementation_digest,
            self.adapter_implementation_digest,
        )
        check("request protocol version", request.protocol_version, WORKER_PROTOCOL_VERSION)

        spec = request.run_spec
        check("benchmark", str(spec.benchmark.identifier), self.benchmark_identifier)
        check("benchmark version", spec.benchmark.version, self.benchmark_version)
        check(
            "benchmark semantic digest",
            spec.benchmark.semantic_digest,
            self.benchmark_semantic_digest,
        )
        check("scenario", str(spec.scenario.identifier), self.scenario_identifier)
        check("scenario version", spec.scenario.version, self.scenario_version)
        check(
            "scenario semantic digest",
            spec.scenario.semantic_digest,
            self.scenario_semantic_digest,
        )
        check("realization", str(spec.realization.identifier), self.realization_identifier)
        check("realization version", spec.realization.version, self.realization_version)
        check(
            "realization semantic digest",
            spec.realization.semantic_digest,
            self.realization_semantic_digest,
        )
        check(
            "system under test",
            str(spec.system_under_test.identifier),
            self.system_under_test_identifier,
        )
        check(
            "system under test version",
            spec.system_under_test.version,
            self.system_under_test_version,
        )
        check(
            "system under test semantic digest",
            spec.system_under_test.semantic_digest,
            self.system_under_test_semantic_digest,
        )
        check("environment", str(spec.environment.identifier), self.environment_identifier)
        check("environment version", spec.environment.version, self.environment_version)
        check(
            "environment semantic digest",
            spec.environment.semantic_digest,
            self.environment_semantic_digest,
        )
        check("environment identity", request.environment, spec.environment)
        check("seed", spec.seed, self.seed)
        check("outcomes", tuple(str(item) for item in spec.outcomes), self.outcomes)

        if len(spec.factors) != 1:
            refusals.append("factor count")
        else:
            factor = spec.factors[0]
            check("factor id", str(factor.factor_id), self.gravity_factor_id)
            check("factor quantity", str(factor.quantity), self.gravity_quantity)
            check("factor unit", factor.unit.expression, self.gravity_unit)
            check("factor target kind", factor.target.kind.value, "realization")
            check("factor target", str(factor.target.identifier), self.realization_identifier)
            check("factor parameter", factor.target.parameter, "gravity")
            check("factor value", factor.value, self.gravity_m_s2)

        return tuple(refusals)

    def matches_request(self, request: WorkerRequest) -> bool:
        return not self.authority_refusals(request)


def build_protected_profile(
    platform_tag: str,
    *,
    bootstrap_path: Path | None = None,
) -> PinnedReferenceProfile:
    """Build the frozen profile for one qualified platform.

    The bootstrap hash is a measurement of the source file that will execute before the
    sandbox. A changed bootstrap changes the profile digest and must be re-accepted.
    """
    if platform_tag not in ADAPTER_IMPLEMENTATION_DIGESTS:
        raise ValueError(f"no protected reference profile for platform {platform_tag!r}")
    bootstrap = (bootstrap_path or protected_bootstrap_path()).resolve()
    if not bootstrap.is_file():
        raise ValueError("the protected bootstrap source file is absent")
    max_processes = 8 if platform_tag == "windows-x86-64" else 64
    return PinnedReferenceProfile(
        platform=cast('Literal["windows-x86-64", "linux-x86-64"]', platform_tag),
        adapter_id=reference.ADAPTER_ID,
        adapter_version=reference.ADAPTER_VERSION,
        engine=reference.ENGINE,
        engine_version=reference.ENGINE_VERSION,
        python_version=reference.PYTHON_VERSION,
        protocol_version=WORKER_PROTOCOL_VERSION,
        capabilities=tuple(reference.CAPABILITIES),
        adapter_implementation_digest=ADAPTER_IMPLEMENTATION_DIGESTS[platform_tag],
        production_implementation_digest=PROTECTED_IMPLEMENTATION_DIGESTS[platform_tag],
        model_source_path=reference.MODEL_SOURCE_PATH,
        model_sha256=reference.MODEL_SHA256,
        benchmark_identifier=reference.BENCHMARK_ID,
        benchmark_version=reference.BENCHMARK_VERSION,
        benchmark_semantic_digest=reference.BENCHMARK_SEMANTIC_DIGEST,
        scenario_identifier=reference.SCENARIO_ID,
        scenario_version=reference.SCENARIO_VERSION,
        scenario_semantic_digest=reference.SCENARIO_SEMANTIC_DIGEST,
        realization_identifier=reference.REALIZATION_ID,
        realization_version=reference.REALIZATION_VERSION,
        realization_semantic_digest=reference.REALIZATION_SEMANTIC_DIGEST,
        system_under_test_identifier=reference.SUT_ID,
        system_under_test_version=reference.SUT_VERSION,
        system_under_test_semantic_digest=reference.SUT_SEMANTIC_DIGEST,
        environment_identifier=reference.expected_environment_id_for(platform_tag),
        environment_version=reference.ENVIRONMENT_VERSION,
        environment_semantic_digest=reference.environment_semantic_digest_for(platform_tag),
        seed=reference.SEED,
        outcomes=(reference.OUTCOME,),
        duration_s=reference.DURATION_S,
        timestep_s=reference.TIMESTEP_S,
        steps=reference.STEPS,
        gravity_m_s2=reference.GRAVITY_M_S2,
        gravity_factor_id="f.reference.gravity",
        gravity_quantity="q.pendulum.gravity",
        gravity_unit=reference.GRAVITY_UNIT,
        integrator=reference.INTEGRATOR,
        solver=reference.SOLVER,
        tolerance=reference.TOLERANCE,
        reference_trajectory_sha256=(
            "f585292dae08650de7980e5ff00256e1ca9a80bd28474f9357df9f6daf3278bf"
        ),
        expected_final_angle_rad=0.5192097890514507,
        expected_final_angular_velocity_rad_s=0.2069654165048836,
        expected_energy_initial_j=1.3138419739773342,
        expected_energy_final_j=1.3138419739773048,
        bootstrap_relative_path=PROTECTED_BOOTSTRAP_RELATIVE_PATH,
        bootstrap_sha256=_sha256_file(bootstrap),
        worker_relative_path=PROTECTED_WORKER_RELATIVE_PATH,
        receipt_schema=PROTECTED_RECEIPT_SCHEMA,
        supervisor_record_schema=PROTECTED_SUPERVISOR_RECORD_SCHEMA,
        supervisor_record_name=PROTECTED_SUPERVISOR_RECORD_NAME,
        max_scratch_bytes=64 * 1024 * 1024,
        max_scratch_entries=256,
        max_memory_bytes=2 * 1024 * 1024 * 1024,
        max_cpu_seconds=120,
        max_wall_seconds=180.0,
        max_stdout_bytes=1024 * 1024,
        max_stderr_bytes=256 * 1024,
        max_processes=max_processes,
        require_dedicated_scratch_linux=True,
        require_non_elevated_windows=True,
    )
