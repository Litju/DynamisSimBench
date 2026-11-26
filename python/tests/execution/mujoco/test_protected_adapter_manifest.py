"""The expanded adapter-manifest acceptance request must reproduce exactly.

The candidate identity is a request, not authority. These tests keep it honest: the
committed JSON must be derivable from the current source, it must bind the same worker and
bootstrap bytes the qualified observations recorded, it must differ from the accepted
10-file identity, and the protected profile must still pin the accepted identity until the
owner signs the replacement.
"""

from __future__ import annotations

import json
from pathlib import Path

import dynamisbench
from dynamisbench.adapters.mujoco import reference
from dynamisbench.adapters.mujoco.protected_contracts import (
    CANDIDATE_IDENTITY_SCHEMA,
    CANDIDATE_PRODUCTION_ENTRY_FILES,
    expanded_implementation_identity,
)
from dynamisbench.execution.protected_profile import ADAPTER_IMPLEMENTATION_DIGESTS

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
