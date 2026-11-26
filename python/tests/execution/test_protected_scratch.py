"""The protected scratch measurement counts directories, not only regular files."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from dynamisbench.execution.protected_scratch import (
    ScratchWatchdog,
    measure_scratch,
)


def test_empty_directories_are_counted(tmp_path: Path) -> None:
    for index in range(100):
        (tmp_path / f"d{index:03d}").mkdir()

    usage = measure_scratch(tmp_path)

    assert usage.bytes == 0
    assert usage.files == 0
    assert usage.directories == 100
    assert usage.entries == 100
    assert usage.links == 0


def test_nested_directories_and_files_are_counted_together(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b").mkdir()
    (tmp_path / "a" / "b" / "file").write_bytes(b"x" * 17)

    usage = measure_scratch(tmp_path)

    assert usage.bytes == 17
    assert usage.files == 1
    assert usage.directories == 2
    assert usage.entries == 3


def test_the_watchdog_triggers_on_the_entry_budget(tmp_path: Path) -> None:
    for index in range(20):
        (tmp_path / f"d{index:03d}").mkdir()
    triggered: list[int] = []

    watchdog = ScratchWatchdog(
        root=tmp_path,
        limit_bytes=1024 * 1024,
        interval_seconds=0.01,
        on_overrun=lambda usage: triggered.append(usage.entries),
        max_entries=5,
    )
    watchdog.start()
    try:
        deadline = time.monotonic() + 1.0
        while not watchdog.triggered and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        watchdog.stop()

    assert watchdog.triggered is True
    assert triggered and triggered[0] >= 20


@pytest.mark.skipif(os.name != "nt", reason="NTFS directory streams are Windows-only")
def test_a_directory_alternate_stream_is_counted(tmp_path: Path) -> None:
    directory = tmp_path / "dir"
    directory.mkdir()
    stream = Path(str(directory) + ":hidden")
    with stream.open("wb") as handle:
        handle.write(b"x" * (1024 * 1024))

    usage = measure_scratch(tmp_path)

    assert usage.directories == 1
    assert usage.bytes >= 1024 * 1024
    assert usage.links == 0
