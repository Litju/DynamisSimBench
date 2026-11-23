"""Shared real-MuJoCo fixtures for RES-550 and RES-555 Gate B2 qualification."""

from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from pathlib import Path

import pytest

from dynamisbench.adapters.mujoco import reference
from tests.execution.mujoco.support import (
    ExecutionFixture,
    assert_identity_is_the_reviewed_environment,
    build_mujoco_fixture,
    run_nonfinite_probe,
    run_qualification,
    run_worker_identity,
    worker_python,
)


@pytest.fixture(scope="session")
def mujoco_identity() -> dict:
    """One installed-worker identity for this qualification session."""
    with tempfile.TemporaryDirectory(prefix="dynamisbench-mujoco-identity-") as scratch:
        identity = run_worker_identity(Path(scratch))
    assert_identity_is_the_reviewed_environment(identity)
    return identity


@pytest.fixture(scope="session")
def mujoco_qualification() -> dict:
    """One full fixed-reference qualification observation for the session."""
    with tempfile.TemporaryDirectory(prefix="dynamisbench-mujoco-qualification-") as scratch:
        return run_qualification(Path(scratch))


@pytest.fixture(scope="session")
def mujoco_nonfinite_probe() -> dict:
    """One real-MuJoCo non-finite guard probe for the session."""
    with tempfile.TemporaryDirectory(prefix="dynamisbench-mujoco-nonfinite-") as scratch:
        return run_nonfinite_probe(Path(scratch))


@pytest.fixture
def mujoco_fixture(tmp_path: Path, mujoco_identity: dict) -> ExecutionFixture:
    """A fresh workspace and planned reference run for one test."""
    return build_mujoco_fixture(tmp_path, identity=mujoco_identity)


@pytest.fixture(scope="session")
def b2_runtime():
    """One measured probe runtime snapshot for the whole B2 qualification session.

    The fixture is explicitly probe-only. If the platform mechanism is unavailable and
    the environment does not require MuJoCo qualification, the tests skip with the
    reason; CI sets ``DYNAMISBENCH_REQUIRE_MUJOCO=1`` and a missing mechanism is a
    failure, never a weaker fallback.
    """
    from tools.res555_gate_b2.profile import mechanism_available
    from tools.res555_gate_b2.runtime import prepare_runtime

    # The test module is itself an explicit probe caller. The production supervisor never
    # imports this harness, so this is a circuit breaker for accidental invocation, not an
    # authorization boundary.
    os.environ.setdefault("DYNAMISBENCH_RES555_B2_PROBE", "1")
    if not mechanism_available():
        message = "the required RES-555 Gate B2 isolation mechanism is unavailable on this host"
        if os.environ.get("DYNAMISBENCH_REQUIRE_MUJOCO") == "1":
            pytest.fail(message)
        pytest.skip(message)
    platform_tag = reference.platform_tag()
    registry = Path(tempfile.mkdtemp(prefix="res555-b2-registry-"))
    try:
        if os.name == "nt":
            from tools.res555_gate_b2.windows import AppContainerProfile

            profile = AppContainerProfile.create(f"DynamisBench.RES555.{uuid.uuid4().hex[:16]}")
            try:
                runtime = prepare_runtime(
                    worker_python=worker_python(),
                    root=profile.folder / "runtime",
                    platform_tag=platform_tag,
                    registry_root=registry,
                )
                yield profile, runtime
            finally:
                profile.delete()
        else:
            with tempfile.TemporaryDirectory(prefix="res555-gate-b2-runtime-") as temporary:
                runtime = prepare_runtime(
                    worker_python=worker_python(),
                    root=Path(temporary) / "runtime",
                    platform_tag=platform_tag,
                    registry_root=registry,
                )
                yield None, runtime
    finally:
        shutil.rmtree(registry, ignore_errors=True)
