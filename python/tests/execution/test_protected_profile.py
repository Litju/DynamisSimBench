"""The protected reference profile is the only eligible request shape."""

from __future__ import annotations

from pathlib import Path

import pytest

from dynamisbench.adapters.mujoco import reference, reference_case
from dynamisbench.execution.contracts import (
    WorkerAdapterIdentity,
    WorkerRequest,
    staging_locator_for,
)
from dynamisbench.execution.protected_profile import (
    ADAPTER_IMPLEMENTATION_DIGESTS,
    build_protected_profile,
)
from dynamisbench.identity import SemanticDigest
from dynamisbench.planning.runspec import run_spec_fingerprint

_PLATFORMS = ("windows-x86-64", "linux-x86-64")
_RUN_ID = "run.reference.0001"


def _request(platform: str) -> WorkerRequest:
    profile = build_protected_profile(platform)
    spec = reference_case.run_spec(platform_tag=platform)
    adapter = WorkerAdapterIdentity(
        adapter_id=reference.ADAPTER_ID,
        adapter_version=reference.ADAPTER_VERSION,
        engine=reference.ENGINE,
        engine_version=reference.ENGINE_VERSION,
        capabilities=reference.CAPABILITIES,
        implementation_digest=profile.adapter_implementation_digest,
    )
    return WorkerRequest(
        run_id=_RUN_ID,
        run_spec=spec,
        execution_fingerprint=run_spec_fingerprint(spec),
        environment=spec.environment,
        adapter=adapter,
        required_capabilities=reference.CAPABILITIES,
        supported_capabilities=reference.CAPABILITIES,
        staging_locator=staging_locator_for(_RUN_ID),
    )


@pytest.mark.parametrize("platform", _PLATFORMS)
def test_the_canonical_reference_request_matches_the_profile(platform: str) -> None:
    profile = build_protected_profile(platform)
    request = _request(platform)

    assert profile.authority_refusals(request) == ()
    assert profile.matches_request(request) is True
    assert profile.adapter_implementation_digest == ADAPTER_IMPLEMENTATION_DIGESTS[platform]
    assert profile.model_source_path == reference.MODEL_SOURCE_PATH
    assert profile.model_sha256 == reference.MODEL_SHA256
    assert profile.reference_trajectory_sha256 == (
        "f585292dae08650de7980e5ff00256e1ca9a80bd28474f9357df9f6daf3278bf"
    )
    assert profile.steps == 2000
    assert profile.duration_s == 2.0
    assert profile.timestep_s == 0.001
    assert profile.require_non_elevated_windows is True
    assert profile.require_dedicated_scratch_linux is True


@pytest.mark.parametrize("platform", _PLATFORMS)
def test_every_pinned_identity_is_separate_per_platform(platform: str) -> None:
    profile = build_protected_profile(platform)

    assert (
        profile.digest()
        != build_protected_profile(
            "linux-x86-64" if platform == "windows-x86-64" else "windows-x86-64"
        ).digest()
    )


def test_a_changed_seed_is_refused() -> None:
    profile = build_protected_profile("windows-x86-64")
    request = _request("windows-x86-64")
    spec = request.run_spec.model_copy(update={"seed": 1})
    changed = request.model_copy(
        update={"run_spec": spec, "execution_fingerprint": run_spec_fingerprint(spec)}
    )

    assert profile.authority_refusals(changed) == ("seed",)


def test_a_changed_scenario_digest_is_refused() -> None:
    profile = build_protected_profile("windows-x86-64")
    request = _request("windows-x86-64")
    scenario = request.run_spec.scenario.model_copy(
        update={"semantic_digest": SemanticDigest(hex="0" * 64)}
    )
    spec = request.run_spec.model_copy(update={"scenario": scenario})
    changed = request.model_copy(
        update={"run_spec": spec, "execution_fingerprint": run_spec_fingerprint(spec)}
    )

    assert profile.authority_refusals(changed) == ("scenario semantic digest",)


def test_a_changed_implementation_digest_is_refused() -> None:
    profile = build_protected_profile("windows-x86-64")
    request = _request("windows-x86-64")
    adapter = request.adapter.model_copy(update={"implementation_digest": "0" * 64})
    changed = request.model_copy(update={"adapter": adapter})

    assert profile.authority_refusals(changed) == ("adapter implementation digest",)


def test_a_changed_gravity_factor_is_refused() -> None:
    profile = build_protected_profile("windows-x86-64")
    request = _request("windows-x86-64")
    factor = request.run_spec.factors[0].model_copy(update={"value": 9.0})
    spec = request.run_spec.model_copy(update={"factors": (factor,)})
    changed = request.model_copy(
        update={"run_spec": spec, "execution_fingerprint": run_spec_fingerprint(spec)}
    )

    assert "factor value" in profile.authority_refusals(changed)


def test_a_changed_adapter_id_is_refused() -> None:
    profile = build_protected_profile("windows-x86-64")
    request = _request("windows-x86-64")
    adapter = request.adapter.model_copy(update={"adapter_id": "dynamisbench.other"})
    changed = request.model_copy(update={"adapter": adapter})

    assert "adapter id" in profile.authority_refusals(changed)


def test_a_changed_bootstrap_changes_the_profile(tmp_path: Path) -> None:
    from dynamisbench.execution.protected_profile import protected_bootstrap_path

    original = protected_bootstrap_path().read_bytes()
    copy = tmp_path / "protected_bootstrap.py"
    copy.write_bytes(original + b"\n# profile digest probe\n")

    original_profile = build_protected_profile("windows-x86-64")
    changed_profile = build_protected_profile("windows-x86-64", bootstrap_path=copy)

    assert original_profile.bootstrap_sha256 != changed_profile.bootstrap_sha256
    assert original_profile.digest() != changed_profile.digest()
