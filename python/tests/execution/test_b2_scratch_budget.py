"""RES-555 Gate B2: scratch-budget mechanism qualifications."""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest
from tools.res555_gate_b2.scratch import (
    ScratchBudgetError,
    ScratchWatchdog,
    measure_scratch,
    resolve_scratch_budget,
)


def test_measure_scratch_counts_exact_bytes_and_files(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "receipt.json").write_bytes(b"12345")
    (scratch / "nested").mkdir()
    (scratch / "nested" / "worker.txt").write_bytes(b"abc")
    usage = measure_scratch(scratch)
    assert (usage.bytes, usage.files, usage.links) == (8, 2, 0)
    assert usage.acceptable


def test_an_explicit_shared_directory_is_not_a_dedicated_scratch_bound(tmp_path: Path) -> None:
    with pytest.raises(ScratchBudgetError):
        resolve_scratch_budget(explicit_root=tmp_path, max_bytes=64 * 1024 * 1024)


def test_the_default_is_a_sampled_watchdog_and_is_not_called_a_quota() -> None:
    budget = resolve_scratch_budget(explicit_root=None, max_bytes=64 * 1024 * 1024)
    assert budget.enforcement == "sampled-watchdog"
    assert budget.capacity_bytes is None
    assert "can exceed the bound" in budget.detail


def test_the_watchdog_reports_an_over_budget_write(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "large.bin").write_bytes(b"x" * 4096)
    triggered = threading.Event()

    def overrun(_usage) -> None:
        triggered.set()

    watchdog = ScratchWatchdog(
        root=scratch,
        limit_bytes=1024,
        interval_seconds=0.01,
        on_overrun=overrun,
    )
    watchdog.start()
    try:
        assert triggered.wait(2.0)
    finally:
        watchdog.stop()
    assert watchdog.triggered
    assert watchdog.peak_bytes >= 4096


def test_a_dedicated_tmpfs_refuses_an_over_capacity_write() -> None:
    configured = os.environ.get("DYNAMISBENCH_RES555_B2_SCRATCH_ROOT")
    if not configured:
        pytest.skip("no dedicated scratch root is provisioned")
    root = Path(configured)
    try:
        budget = resolve_scratch_budget(explicit_root=root, max_bytes=64 * 1024 * 1024)
    except ScratchBudgetError as error:
        if os.environ.get("DYNAMISBENCH_REQUIRE_MUJOCO") == "1":
            pytest.fail(str(error))
        pytest.skip(str(error))
    assert budget.enforcement == "dedicated-filesystem"
    assert budget.capacity_bytes is not None
    target = root / f"capacity-probe-{os.getpid()}.bin"
    written = 0
    try:
        with target.open("wb") as handle:
            while written <= budget.capacity_bytes:
                handle.write(b"x" * (1024 * 1024))
                written += 1024 * 1024
    except OSError as error:
        assert error.errno in {28, 122}  # ENOSPC / ERROR_DISK_FULL
    else:
        raise AssertionError("the dedicated filesystem accepted more than its capacity")
    finally:
        target.unlink(missing_ok=True)
