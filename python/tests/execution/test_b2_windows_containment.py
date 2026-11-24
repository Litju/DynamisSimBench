"""RES-555 Gate B2: Windows AppContainer and Job Object containment qualifications."""

from __future__ import annotations

import contextlib
import ctypes
import json
import os
import shutil
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator
from ctypes import wintypes
from pathlib import Path
from typing import Any, cast

import pytest
from tools.res555_gate_b2.scratch import ScratchWatchdog, measure_scratch
from tools.res555_gate_b2.windows import (
    AppContainerProcess,
    AppContainerProfile,
    grant_tree,
)

pytestmark = pytest.mark.skipif(os.name != "nt", reason="AppContainer is Windows-only")

_WAIT_FAILED = 0xFFFFFFFF
_ERROR_INVALID_HANDLE = 6


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wintypes.BOOL),
    ]


def _win32():
    return cast(Any, ctypes).WinDLL("kernel32", use_last_error=True)


def _last_error() -> int:
    getter = getattr(ctypes, "get_last_error", None)
    return int(getter()) if getter is not None else 0


def _kernel32():
    api = _win32()
    api.CreateEventW.argtypes = [
        ctypes.POINTER(_SecurityAttributes),
        wintypes.BOOL,
        wintypes.BOOL,
        wintypes.LPCWSTR,
    ]
    api.CreateEventW.restype = wintypes.HANDLE
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    return api


@contextlib.contextmanager
def _appcontainer(
    script: str, arguments: tuple[str, ...] = ()
) -> Iterator[tuple[AppContainerProfile, Path, AppContainerProcess]]:
    root = Path(tempfile.mkdtemp(prefix="res555-win-contain-"))
    scratch = root / "scratch"
    scratch.mkdir()
    (scratch / "worker.py").write_text(script, encoding="utf-8")
    profile = AppContainerProfile.create(f"DynamisBench.RES555.Contain.{uuid.uuid4().hex[:12]}")
    try:
        python = Path(sys.executable)
        grant_tree(Path(sys.base_prefix), profile.sid_string, "(OI)(CI)(RX)")
        grant_tree(python.parent.parent, profile.sid_string, "(OI)(CI)(RX)")
        grant_tree(scratch, profile.sid_string, "(OI)(CI)(F)")
        process = AppContainerProcess.launch(
            profile=profile,
            application=python,
            arguments=("-I", str(scratch / "worker.py"), *arguments),
            working_directory=scratch,
            environment=None,
            memory_bytes=512 * 1024 * 1024,
            cpu_seconds=30,
            max_processes=8,
        )
        try:
            yield profile, scratch, process
        finally:
            process.close()
    finally:
        profile.delete()
        shutil.rmtree(root, ignore_errors=True)


def _create_inheritable_file(path: Path) -> tuple[int, str]:
    api = _win32()
    api.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SecurityAttributes),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    api.CreateFileW.restype = wintypes.HANDLE
    attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), None, True)
    handle = api.CreateFileW(
        str(path),
        0x80000000,  # GENERIC_READ
        0x00000001,  # FILE_SHARE_READ
        ctypes.byref(attributes),
        3,  # OPEN_EXISTING
        0x00000080,  # FILE_ATTRIBUTE_NORMAL
        None,
    )
    if not handle:
        raise OSError(_last_error(), "CreateFileW failed")
    return int(handle.value) if hasattr(handle, "value") else int(handle), str(path)


def test_only_the_stdio_pipe_handles_are_inherited(tmp_path: Path) -> None:
    secret = tmp_path / "res555-handle-secret.txt"
    secret.write_text("RES555-HANDLE-SECRET", encoding="utf-8")
    api = _win32()
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    handle_value, secret_path = _create_inheritable_file(secret)
    script = r"""
import ctypes, json, sys
api = ctypes.WinDLL("kernel32", use_last_error=True)
api.GetFinalPathNameByHandleW.argtypes = [
    ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32
]
api.GetFinalPathNameByHandleW.restype = ctypes.c_uint32
buffer = ctypes.create_unicode_buffer(1024)
try:
    result = api.GetFinalPathNameByHandleW(
        ctypes.c_void_p(int(sys.argv[1])), buffer, len(buffer), 0
    )
except OSError as error:
    print(json.dumps({"result": "invalid", "path": "",
                      "error": getattr(error, "winerror", None)}))
else:
    print(json.dumps({"result": int(result), "path": buffer.value,
                      "error": ctypes.get_last_error()}))
"""
    try:
        with _appcontainer(script, (str(handle_value),)) as (_profile, _scratch, process):
            stdout = process.stdout.read()
            stderr = process.stderr.read()
            process.wait(10.0)
            assert process.returncode == 0, stderr.decode("utf-8", "replace")
            observed = json.loads(stdout.decode("utf-8"))
            inherited = (
                isinstance(observed["result"], int)
                and int(observed["result"]) > 0
                and observed["path"].casefold() == secret_path.casefold()
            )
            assert not inherited, observed
    finally:
        api.CloseHandle(ctypes.c_void_p(handle_value))


def test_a_descendant_that_outlives_its_direct_parent_stays_in_the_job() -> None:
    script = r"""
import subprocess, sys
child = subprocess.Popen(
    [sys.executable, "-I", "-c", "import time; time.sleep(30)"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
print(child.pid, flush=True)
"""
    with _appcontainer(script) as (_profile, _scratch, process):
        stdout = process.stdout.read()
        process.wait(10.0)
        assert process.returncode == 0
        assert int(stdout.strip()) > 0
        deadline = time.monotonic() + 5.0
        active = 0
        while active < 1 and time.monotonic() < deadline:
            active = int(process.job_accounting()["active_processes"])
            time.sleep(0.02)
        assert active >= 1
        process.kill()
        assert process.wait(10.0) is not None
        assert int(process.job_accounting()["active_processes"]) == 0


def test_cancellation_terminates_the_job_and_the_direct_worker() -> None:
    script = "import time; time.sleep(30)"
    with _appcontainer(script) as (_profile, _scratch, process):
        time.sleep(0.2)
        process.kill()
        process.wait(10.0)
        assert int(process.job_accounting()["active_processes"]) == 0


def test_repeated_launches_leave_no_active_processes() -> None:
    script = "import time; time.sleep(30)"
    root = Path(tempfile.mkdtemp(prefix="res555-win-repeat-"))
    scratch = root / "scratch"
    scratch.mkdir()
    (scratch / "worker.py").write_text(script, encoding="utf-8")
    profile = AppContainerProfile.create(f"DynamisBench.RES555.Repeat.{uuid.uuid4().hex[:12]}")
    try:
        python = Path(sys.executable)
        grant_tree(Path(sys.base_prefix), profile.sid_string, "(OI)(CI)(RX)")
        grant_tree(python.parent.parent, profile.sid_string, "(OI)(CI)(RX)")
        grant_tree(scratch, profile.sid_string, "(OI)(CI)(F)")
        for _ in range(3):
            process = AppContainerProcess.launch(
                profile=profile,
                application=python,
                arguments=("-I", str(scratch / "worker.py")),
                working_directory=scratch,
                environment=None,
                memory_bytes=512 * 1024 * 1024,
                cpu_seconds=30,
                max_processes=8,
            )
            try:
                time.sleep(0.1)
                process.kill()
                process.wait(10.0)
                assert int(process.job_accounting()["active_processes"]) == 0
            finally:
                process.close()
    finally:
        profile.delete()
        shutil.rmtree(root, ignore_errors=True)


def test_the_sampled_watchdog_kills_an_over_budget_writer() -> None:
    script = r"""
import os, sys
path = os.path.join(sys.argv[1], "grow.bin")
with open(path, "wb") as handle:
    while True:
        handle.write(b"x" * (1024 * 1024))
        handle.flush()
"""
    root = Path(tempfile.mkdtemp(prefix="res555-win-watchdog-"))
    scratch = root / "scratch"
    scratch.mkdir()
    (scratch / "worker.py").write_text(script, encoding="utf-8")
    profile = AppContainerProfile.create(f"DynamisBench.RES555.Watch.{uuid.uuid4().hex[:12]}")
    try:
        python = Path(sys.executable)
        grant_tree(Path(sys.base_prefix), profile.sid_string, "(OI)(CI)(RX)")
        grant_tree(python.parent.parent, profile.sid_string, "(OI)(CI)(RX)")
        grant_tree(scratch, profile.sid_string, "(OI)(CI)(F)")
        process = AppContainerProcess.launch(
            profile=profile,
            application=python,
            arguments=("-I", str(scratch / "worker.py"), str(scratch)),
            working_directory=scratch,
            environment=None,
            memory_bytes=512 * 1024 * 1024,
            cpu_seconds=30,
            max_processes=8,
        )
        watchdog = ScratchWatchdog(
            root=scratch,
            limit_bytes=1024 * 1024,
            interval_seconds=0.01,
            on_overrun=lambda _usage: process.kill(),
        )
        watchdog.start()
        try:
            deadline = time.monotonic() + 10.0
            while not watchdog.triggered and time.monotonic() < deadline:
                time.sleep(0.02)
            if not watchdog.triggered and process.poll() is not None:
                raise AssertionError(
                    f"the writer exited before the watchdog: {process.returncode} "
                    f"{process.stderr.read().decode('utf-8', 'replace')}"
                )
            assert watchdog.triggered
            process.wait(10.0)
            assert int(process.job_accounting()["active_processes"]) == 0
        finally:
            watchdog.stop()
            process.close()
        # The watchdog is sampled, not a hard quota: the point is that it reacted and the
        # job is empty, not that the worker wrote exactly the configured number of bytes.
        assert measure_scratch(scratch).bytes >= 1024 * 1024
    finally:
        profile.delete()
        shutil.rmtree(root, ignore_errors=True)
