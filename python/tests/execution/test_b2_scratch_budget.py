"""RES-555 Gate B2: scratch-budget mechanism qualifications."""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest
import tools.res555_gate_b2.scratch as scratch_module
from tools.res555_gate_b2.scratch import (
    ScratchBudgetError,
    ScratchWatchdog,
    measure_scratch,
    resolve_scratch_budget,
    scratch_headroom,
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


def test_the_watchdog_reports_an_over_file_budget(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    for index in range(5):
        (scratch / f"empty-{index}").write_bytes(b"")
    triggered = threading.Event()

    def overrun(_usage) -> None:
        triggered.set()

    watchdog = ScratchWatchdog(
        root=scratch,
        limit_bytes=1024 * 1024,
        interval_seconds=0.01,
        on_overrun=overrun,
        max_files=4,
    )
    watchdog.start()
    try:
        assert triggered.wait(2.0)
    finally:
        watchdog.stop()
    assert watchdog.triggered


def test_a_transient_unmeasurable_entry_is_not_a_link_in_a_live_sample(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file atomically renamed during a scan must not kill a healthy worker.

    The live watchdog samples every 20 ms. Windows can briefly refuse a stat while a file is
    being replaced or scanned by antivirus. The final post-exit measurement stays
    fail-closed, but a single transient sample is not evidence of a link or an over-budget
    write.
    """
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    target = scratch / "receipt.json"
    target.write_bytes(b"payload")
    real_stat = os.stat

    def selective(path, *args, **kwargs):
        if str(path) == str(target):
            raise FileNotFoundError("the entry was renamed during the scan")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(scratch_module.os, "stat", selective)
    live = measure_scratch(scratch, fail_closed=False)
    assert (live.links, live.unmeasured) == (0, 1)
    strict = measure_scratch(scratch)
    assert strict.links == 1
    assert strict.unmeasured == 0


def test_scratch_headroom_is_the_writable_free_space(tmp_path: Path) -> None:
    assert scratch_headroom(tmp_path) > 0


@pytest.mark.skipif(os.name != "nt", reason="NTFS alternate data streams are Windows-only")
def test_windows_alternate_data_streams_are_counted(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    target = scratch / "receipt.json"
    target.write_bytes(b"1")
    stream = f"{target}:res555-ads"
    try:
        with open(stream, "wb") as handle:
            handle.write(b"x" * 4096)
    except OSError:
        pytest.skip("this filesystem does not support alternate data streams")
    try:
        usage = measure_scratch(scratch)
        assert usage.bytes >= 4097
        assert usage.links == 0
    finally:
        try:
            os.unlink(stream)
        except OSError:
            pass


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
