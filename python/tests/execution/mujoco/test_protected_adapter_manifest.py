"""The expanded adapter-manifest acceptance request must reproduce exactly.

The candidate identity is a request, not authority. These tests keep it honest: the
committed JSON must be derivable from the current source, it must bind the same worker and
bootstrap bytes the qualified observations recorded, it must differ from the accepted
10-file identity, and the protected profile must still pin the accepted identity until the
owner signs the replacement.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import dynamisbench
from dynamisbench.adapters.mujoco import reference
from dynamisbench.adapters.mujoco.protected_contracts import (
    CANDIDATE_IDENTITY_SCHEMA,
    CANDIDATE_PRODUCTION_ENTRY_FILES,
    expanded_implementation_identity,
)
from dynamisbench.execution.protected_launch import ProtectedLaunchError, _verify_production_identity
from dynamisbench.execution.protected_profile import (
    ADAPTER_IMPLEMENTATION_DIGESTS,
    PROTECTED_IMPLEMENTATION_DIGESTS,
    build_protected_profile,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
CANDIDATE_PATH = REPO_ROOT / "evidence" / "RES-555" / "gate-b2" / "adapter-manifest-candidate.json"
OBSERVATION_DIR = REPO_ROOT / "evidence" / "RES-555" / "gate-b2" / "protected-supervisor"
PLATFORMS = ("windows-x86-64", "linux-x86-64")


def _candidate() -> dict:
    return json.loads(CANDIDATE_PATH.read_text(encoding="utf-8"))


def test_the_committed_candidate_reproduces_from_the_current_source() -> None:
    candidate = _candidate()
    source_root = Path(dynamisbench.__file__).resolve().parent.parent
    assert candidate["status"] == "requested-not-accepted"
    assert candidate["candidate_identity"]["schema"] == CANDIDATE_IDENTITY_SCHEMA
    assert candidate["candidate_identity"]["file_count"] == (
        len(reference.ADAPTER_SOURCE_FILES) + len(CANDIDATE_PRODUCTION_ENTRY_FILES)
    )

    for platform in PLATFORMS:
        digest, payload = expanded_implementation_identity(
            source_root=source_root,
            model_sha256=reference.MODEL_SHA256,
            engine_version=reference.ENGINE_VERSION,
            python_version=reference.PYTHON_VERSION,
            platform_tag=platform,
        )
        recorded = candidate["candidate_identity"]["platforms"][platform]
        assert digest == recorded["implementation_digest"]
        assert payload == recorded["payload"]


def test_the_candidate_is_a_new_identity_not_the_accepted_10_file_digest() -> None:
    candidate = _candidate()
    accepted = candidate["accepted_identity"]
    assert accepted["source_file_count"] == 10
    assert accepted["schema"] == reference.IMPLEMENTATION_IDENTITY_SCHEMA

    for platform in PLATFORMS:
        digest = candidate["candidate_identity"]["platforms"][platform]["implementation_digest"]
        assert digest != accepted["digests"][platform]
        assert digest != ADAPTER_IMPLEMENTATION_DIGESTS[platform]
        # The route still pins the accepted identity until the owner signs.
        assert ADAPTER_IMPLEMENTATION_DIGESTS[platform] == accepted["digests"][platform]
        assert PROTECTED_IMPLEMENTATION_DIGESTS[platform] == digest


def test_the_candidate_binds_the_exact_executed_worker_and_bootstrap_bytes() -> None:
    candidate = _candidate()
    for platform in PLATFORMS:
        manifest = {
            entry["path"]: entry["sha256"]
            for entry in candidate["candidate_identity"]["platforms"][platform]["payload"][
                "production_entry_manifest"
            ]
        }
        observation = json.loads((OBSERVATION_DIR / f"{platform}.json").read_text(encoding="utf-8"))
        assert (
            manifest["dynamisbench/adapters/mujoco/protected_worker.py"]
            == (observation["worker_entry_sha256"])
        )
        assert (
            manifest["dynamisbench/execution/protected_bootstrap.py"]
            == (observation["bootstrap_sha256"])
        )


def _copy_the_exact_bound_source(tmp_path: Path) -> Path:
    """Copy only the 12 executable source files; the packaged XML is intentionally absent."""
    installed = Path(dynamisbench.__file__).resolve().parent.parent
    snapshot = tmp_path / "src"
    adapter_root = snapshot / "dynamisbench" / "adapters" / "mujoco"
    for relative in reference.ADAPTER_SOURCE_FILES:
        if relative == reference.MODEL_ASSET_PATH:
            continue
        target = adapter_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(installed / "dynamisbench" / "adapters" / "mujoco" / relative, target)
    for relative in CANDIDATE_PRODUCTION_ENTRY_FILES:
        target = snapshot / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(installed / relative, target)
    assert not (adapter_root / reference.MODEL_ASSET_PATH).exists()
    return snapshot


@pytest.mark.parametrize("platform", PLATFORMS)
def test_the_supervisor_reconstructs_the_accepted_13_file_identity(
    tmp_path: Path, platform: str
) -> None:
    """The owner-approved schema-2 digest is a strict launch check, not metadata."""
    snapshot = _copy_the_exact_bound_source(tmp_path)
    profile = build_protected_profile(platform)
    assert _verify_production_identity(profile, snapshot) == PROTECTED_IMPLEMENTATION_DIGESTS[
        platform
    ]


@pytest.mark.parametrize(
    "changed",
    (
        "dynamisbench/adapters/mujoco/physics.py",
        "dynamisbench/adapters/mujoco/protected_contracts.py",
        "dynamisbench/adapters/mujoco/protected_worker.py",
        "dynamisbench/execution/protected_bootstrap.py",
    ),
)
def test_any_mutated_bound_file_refuses_the_protected_identity(
    tmp_path: Path, changed: str
) -> None:
    snapshot = _copy_the_exact_bound_source(tmp_path)
    target = snapshot / changed
    target.write_bytes(target.read_bytes() + b"\\n# tampered after owner adoption\\n")
    with pytest.raises(ProtectedLaunchError, match="13-file protected implementation"):
        _verify_production_identity(build_protected_profile("linux-x86-64"), snapshot)


def test_a_missing_protected_worker_refuses_before_launch(tmp_path: Path) -> None:
    snapshot = _copy_the_exact_bound_source(tmp_path)
    (snapshot / "dynamisbench/adapters/mujoco/protected_worker.py").unlink()
    with pytest.raises(ProtectedLaunchError, match="cannot be reconstructed"):
        _verify_production_identity(build_protected_profile("windows-x86-64"), snapshot)
