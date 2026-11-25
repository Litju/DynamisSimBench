"""Scratch-budget mechanisms for the protected pinned-reference worker.

The existing 64 MiB bound was evaluated after the worker exited. That is an acceptance
check, not prevention: the worker could fill the host filesystem first. This module adds two
truthfully different mechanisms and keeps their names distinct. Unlike the probe-only
measurement, the production entry budget counts every directory and file entry and every
NTFS stream on both, so an empty-directory tree or a directory alternate stream cannot hide
behind a zero-byte total.

``dedicated-filesystem``
    The attempt directory is a mount/volume whose total capacity is at most the configured
    scratch bound. A write beyond the capacity is refused by the kernel/filesystem while the
    worker is still running. This is a real aggregate allocation bound, not a per-file limit.
    It requires the host to provide the dedicated mount; the probe refuses an explicitly
    named root that is not one.

``sampled-watchdog``
    The supervisor samples the scratch tree while the worker runs and kills it when the
    sampled usage exceeds the bound. This bounds the damage after a sampling interval, but a
    fast writer can exceed the bound before the next sample. It is not a hard quota and is
    never described as one.

``post-exit-acceptance-bound``
    The historical behaviour: measure after exit and refuse the run if it is over budget.
    This neither prevents nor interrupts an over-budget write; it only refuses to accept the
    result.

A per-file limit (Linux ``RLIMIT_FSIZE``) is not an aggregate limit: many files can each be
below it. Memory limits (``RLIMIT_AS``, cgroup ``memory.max``, Job Object memory limits) are
not disk limits. None of those is used to claim an aggregate scratch bound here.
"""

from __future__ import annotations

import ctypes
import os
import stat
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal, cast

__all__ = [
    "DEFAULT_MAX_ENTRIES",
    "DEFAULT_MAX_FILES",
    "ScratchBudget",
    "ScratchBudgetError",
    "ScratchEnforcement",
    "ScratchUsage",
    "ScratchWatchdog",
    "measure_scratch",
    "resolve_scratch_budget",
    "scratch_headroom",
]

ScratchEnforcement = Literal[
    "dedicated-filesystem",
    "sampled-watchdog",
    "post-exit-acceptance-bound",
]

_DEFAULT_WATCHDOG_SECONDS: Final = 0.02
DEFAULT_MAX_FILES: Final = 256
DEFAULT_MAX_ENTRIES: Final = 256
"""A metadata/inode bound for scratch. The pinned worker needs four files; 256 is generous
and far below an inode-exhaustion attempt. Empty files *and empty directories* consume
metadata even when bytes stay small, and NTFS directories can carry alternate streams, so the
byte bound alone is not an aggregate scratch-exhaustion bound. The production watchdog uses
``max_entries`` for the combined directory/file/stream count."""
_SYSTEM_VOLUME_NAMES: Final = frozenset({"System Volume Information", "$RECYCLE.BIN"})


class ScratchBudgetError(RuntimeError):
    """An explicitly requested scratch root cannot provide the claimed bound."""


@dataclass(frozen=True, slots=True)
class ScratchUsage:
    """One measurement of a scratch tree.

    ``links`` counts objects that are not one regular single-link file. ``unmeasured``
    counts entries that could not be inspected during a live, best-effort watchdog sample.
    The post-exit acceptance measurement is fail-closed: an unmeasurable entry is a refusal,
    never an undercount.
    """

    bytes: int
    files: int
    links: int
    unmeasured: int = 0
    directories: int = 0
    entries: int = 0

    @property
    def acceptable(self) -> bool:
        return self.links == 0 and self.unmeasured == 0


@dataclass(frozen=True, slots=True)
class ScratchBudget:
    """The mechanism that actually bounds one attempt's scratch."""

    root: Path | None
    enforcement: ScratchEnforcement
    capacity_bytes: int | None
    detail: str
    watchdog_interval_seconds: float | None = None
    available_bytes: int | None = None


def _mount_for(path: Path) -> tuple[Path, str] | None:
    """Return ``(mount_point, fstype)`` for the longest mount containing ``path``."""
    if not sys_platform_linux():
        return None
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    target = path.resolve()
    candidates: list[tuple[Path, str]] = []
    for line in lines:
        try:
            before, after = line.split(" - ", 1)
            fields = before.split()
            mount_point = Path(fields[4])
            fstype = after.split()[0]
        except (IndexError, ValueError):
            continue
        if target.is_relative_to(mount_point.resolve()):
            candidates.append((mount_point, fstype))
    if not candidates:
        return None
    return max(candidates, key=lambda item: len(item[0].parts))


def sys_platform_linux() -> bool:
    import sys

    return sys.platform.startswith("linux")


def _linux_budget(root: Path, max_bytes: int) -> ScratchBudget:
    mount = _mount_for(root)
    if mount is None:
        raise ScratchBudgetError("the requested scratch root is not on a readable mount")
    mount_point, fstype = mount
    if mount_point.resolve() != root.resolve():
        raise ScratchBudgetError(
            "the requested scratch root is not a dedicated mount point; a directory on a "
            "shared filesystem cannot claim an aggregate allocation bound"
        )
    statvfs = getattr(os, "statvfs", None)
    if statvfs is None:
        raise ScratchBudgetError("the scratch mount capacity is not readable")
    try:
        info = statvfs(root)
    except OSError as error:
        raise ScratchBudgetError("the scratch mount capacity is not readable") from error
    total = int(info.f_blocks) * int(info.f_frsize)
    if total <= 0 or total > max_bytes:
        raise ScratchBudgetError(
            f"the scratch mount capacity {total} is not a positive bound at or below "
            f"{max_bytes} bytes"
        )
    if not os.access(root, os.W_OK | os.X_OK):
        raise ScratchBudgetError("the dedicated scratch mount is not writable")
    available = int(info.f_bavail) * int(info.f_frsize)
    return ScratchBudget(
        root=root,
        enforcement="dedicated-filesystem",
        capacity_bytes=total,
        detail=f"{mount_point} is a {fstype} mount with a {total}-byte capacity",
        available_bytes=available,
    )


def _windows_volume(path: Path) -> tuple[str, int, int, str]:
    """Return ``(volume_path, total_bytes, available_bytes, filesystem_name)``."""
    kernel32: Any = cast(Any, ctypes).windll.kernel32
    volume = ctypes.create_unicode_buffer(261)
    if not kernel32.GetVolumePathNameW(str(path), volume, len(volume)):
        raise ScratchBudgetError("the scratch path has no readable Windows volume")
    free = ctypes.c_ulonglong(0)
    total = ctypes.c_ulonglong(0)
    available = ctypes.c_ulonglong(0)
    if not kernel32.GetDiskFreeSpaceExW(
        str(path), ctypes.byref(available), ctypes.byref(total), ctypes.byref(free)
    ):
        raise ScratchBudgetError("the scratch volume capacity is not readable")
    name = ctypes.create_unicode_buffer(261)
    filesystem = ctypes.create_unicode_buffer(261)
    serial = ctypes.c_ulong(0)
    maximum = ctypes.c_ulong(0)
    flags = ctypes.c_ulong(0)
    if not kernel32.GetVolumeInformationW(
        volume.value,
        name,
        len(name),
        ctypes.byref(serial),
        ctypes.byref(maximum),
        ctypes.byref(flags),
        filesystem,
        len(filesystem),
    ):
        filesystem.value = "unknown"
    return volume.value, int(total.value), int(available.value), filesystem.value


def _windows_budget(root: Path, max_bytes: int) -> ScratchBudget:
    volume_path, total, available, filesystem = _windows_volume(root)
    if os.path.normcase(os.path.abspath(str(root))) != os.path.normcase(volume_path):
        raise ScratchBudgetError(
            "the requested Windows scratch root is not a dedicated volume root; a directory "
            "on a shared volume cannot claim an aggregate allocation bound"
        )
    if total <= 0 or total > max_bytes:
        raise ScratchBudgetError(
            f"the scratch volume capacity {total} is not a positive bound at or below "
            f"{max_bytes} bytes"
        )
    unexpected = [
        name
        for name in os.listdir(root)
        if name not in _SYSTEM_VOLUME_NAMES and not name.startswith("attempt-")
    ]
    if unexpected:
        raise ScratchBudgetError(
            "the dedicated scratch volume contains unexpected entries; it must be reserved "
            "for this supervisor"
        )
    return ScratchBudget(
        root=root,
        enforcement="dedicated-filesystem",
        capacity_bytes=total,
        detail=f"{volume_path} is a {filesystem} volume with a {total}-byte capacity",
        available_bytes=available,
    )


def resolve_scratch_budget(
    *,
    explicit_root: Path | None,
    max_bytes: int,
    watchdog_interval_seconds: float = _DEFAULT_WATCHDOG_SECONDS,
) -> ScratchBudget:
    """Resolve the strongest truthful scratch mechanism available on this host.

    An explicit root is a claim that the host provides a dedicated filesystem. If it is not
    one, the probe refuses rather than silently downgrading the claim. Without an explicit
    root, a sampled watchdog is used on both platforms; it is explicitly not a hard quota.
    """
    if max_bytes <= 0:
        raise ScratchBudgetError("a scratch bound must be positive")
    if explicit_root is not None:
        try:
            root = explicit_root.resolve(strict=True)
        except OSError as error:
            raise ScratchBudgetError("the requested scratch root does not exist") from error
        if root.is_symlink() or not root.is_dir():
            raise ScratchBudgetError("the requested scratch root is not a real directory")
        if os.name == "nt":
            return _windows_budget(root, max_bytes)
        if sys_platform_linux():
            return _linux_budget(root, max_bytes)
        raise ScratchBudgetError("this platform has no supported dedicated scratch mechanism")
    if os.name == "nt":
        detail = (
            "a supervisor thread samples the scratch tree every "
            f"{watchdog_interval_seconds * 1000:.0f} ms and kills an over-budget worker; "
            "a fast writer can exceed the bound before the next sample"
        )
    elif sys_platform_linux():
        detail = (
            "a supervisor thread samples the scratch tree every "
            f"{watchdog_interval_seconds * 1000:.0f} ms and kills an over-budget worker; "
            "a fast writer can exceed the bound before the next sample, and RLIMIT_FSIZE is "
            "only a per-file limit, not an aggregate bound"
        )
    else:
        detail = "only the post-exit acceptance bound is available on this platform"
        return ScratchBudget(
            root=None,
            enforcement="post-exit-acceptance-bound",
            capacity_bytes=None,
            detail=detail,
        )
    return ScratchBudget(
        root=None,
        enforcement="sampled-watchdog",
        capacity_bytes=None,
        detail=detail,
        watchdog_interval_seconds=watchdog_interval_seconds,
    )


class _Win32FindStreamData(ctypes.Structure):
    _fields_ = [
        ("stream_size", ctypes.c_longlong),
        ("stream_name", ctypes.c_wchar * 296),
    ]


_INVALID_HANDLE: Final = (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1


def _windows_stream_bytes(path: Path, logical_size: int) -> int:
    """Return the total logical size of every NTFS stream on one file.

    ``os.stat().st_size`` names only the unnamed ``:$DATA`` stream. A worker can write an
    arbitrarily large alternate data stream to a small-looking file, so the scratch
    measurement must enumerate the streams instead of trusting the default-stream size.
    A host or filesystem that does not support stream enumeration falls back to the
    ordinary size; the post-exit check remains fail-closed for links and unmeasured entries.
    """
    kernel32: Any = cast(Any, ctypes).windll.kernel32
    kernel32.FindFirstStreamW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.POINTER(_Win32FindStreamData),
        ctypes.c_uint32,
    ]
    kernel32.FindFirstStreamW.restype = ctypes.c_void_p
    kernel32.FindNextStreamW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_Win32FindStreamData),
    ]
    kernel32.FindNextStreamW.restype = ctypes.c_int
    kernel32.FindClose.argtypes = [ctypes.c_void_p]
    kernel32.FindClose.restype = ctypes.c_int
    data = _Win32FindStreamData()
    handle = kernel32.FindFirstStreamW(str(path), 0, ctypes.byref(data), 0)
    handle_value = int(handle) if handle is not None else 0
    if handle_value == 0 or handle_value == int(_INVALID_HANDLE):
        return logical_size
    total = 0
    try:
        while True:
            total += max(0, int(data.stream_size))
            if not kernel32.FindNextStreamW(handle, ctypes.byref(data)):
                break
    finally:
        kernel32.FindClose(handle)
    return max(logical_size, total)


def scratch_headroom(path: Path) -> int:
    """Return the writable free bytes of the volume containing ``path``.

    This is a pre-launch capacity observation, not a quota. It prevents a probe from
    starting when the host cannot absorb the configured scratch bound even once.
    """
    if os.name == "nt":
        _volume, _total, available, _filesystem = _windows_volume(path)
        return available
    statvfs = getattr(os, "statvfs", None)
    if statvfs is None:
        raise ScratchBudgetError("the scratch volume free space is not readable")
    try:
        info = statvfs(path)
    except OSError as error:
        raise ScratchBudgetError("the scratch volume free space is not readable") from error
    return int(info.f_bavail) * int(info.f_frsize)


def measure_scratch(scratch: Path, *, fail_closed: bool = True) -> ScratchUsage:
    """Measure exact bytes, regular files and unmeasurable link objects.

    ``fail_closed`` is the post-exit acceptance rule: an entry the supervisor cannot measure
    is counted as a link object, so ``links == 0`` refuses instead of silently undercounting
    unreadable bytes. The live watchdog uses ``fail_closed=False`` because a file being
    created or atomically renamed can disappear between the directory scan and the stat; a
    transient observation must not kill a healthy worker. Actual links, reparse
    points, hard links, special files and oversized content still fail in both modes, and
    the final post-exit measurement is always fail-closed.
    """
    total = 0
    files = 0
    directories = 0
    entries_count = 0
    links = 0
    unmeasured = 0
    pending = [scratch]
    while pending:
        current = pending.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            if fail_closed:
                links += 1
            else:
                unmeasured += 1
            continue
        for entry in entries:
            entries_count += 1
            path = Path(entry.path)
            try:
                # Query the object directly rather than trusting the directory entry's
                # cached size. On Windows, a DirEntry for a file another process is still
                # writing can report a stale (often zero) size, which would make a sampled
                # watchdog miss a rapidly growing file entirely.
                info = os.stat(path, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode) or (
                    os.name == "nt"
                    and getattr(info, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                ):
                    links += 1
                elif stat.S_ISDIR(info.st_mode):
                    directories += 1
                    if os.name == "nt":
                        # A directory is metadata, and NTFS directories can carry alternate
                        # streams too. Count both, not only the children's default streams.
                        total += _windows_stream_bytes(path, 0)
                    pending.append(path)
                elif stat.S_ISREG(info.st_mode):
                    if info.st_nlink != 1:
                        links += 1
                        continue
                    size = info.st_size
                    if os.name == "nt":
                        size = _windows_stream_bytes(path, size)
                    total += size
                    files += 1
                else:
                    links += 1
            except OSError:
                if fail_closed:
                    links += 1
                else:
                    unmeasured += 1
    return ScratchUsage(
        bytes=total,
        files=files,
        links=links,
        unmeasured=unmeasured,
        directories=directories,
        entries=entries_count,
    )


@dataclass
class ScratchWatchdog:
    """A sampled, best-effort over-budget detector; never a hard quota.

    An entry that cannot be sampled is counted in ``unmeasured_samples`` and does not trigger
    by itself; the post-exit acceptance measurement is fail-closed and refuses it. This keeps
    a transient atomic-rename or scanner lock from killing a healthy worker without turning
    an unmeasurable entry into an accepted result.
    """

    root: Path
    limit_bytes: int
    interval_seconds: float
    on_overrun: Callable[[ScratchUsage], None]
    max_files: int = DEFAULT_MAX_FILES
    max_entries: int = DEFAULT_MAX_ENTRIES
    triggered: bool = False
    peak_bytes: int = 0
    samples: int = 0
    unmeasured_samples: int = 0
    peak_unmeasured: int = 0
    last_usage: ScratchUsage | None = None
    _stop: threading.Event = field(default_factory=threading.Event, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("the scratch watchdog has already started")
        self._thread = threading.Thread(
            target=self._run, name="dynamisbench-scratch-watchdog", daemon=True
        )
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            usage = measure_scratch(self.root, fail_closed=False)
            self.samples += 1
            self.last_usage = usage
            self.peak_bytes = max(self.peak_bytes, usage.bytes)
            self.peak_unmeasured = max(self.peak_unmeasured, usage.unmeasured)
            if usage.unmeasured:
                self.unmeasured_samples += 1
            if (
                usage.bytes > self.limit_bytes
                or usage.files > self.max_files
                or usage.entries > self.max_entries
                or usage.links > 0
            ):
                self.triggered = True
                try:
                    self.on_overrun(usage)
                except Exception:  # noqa: BLE001 - the supervisor callback must not die here
                    pass
                return
            self._stop.wait(self.interval_seconds)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(5.0)
            self._thread = None
