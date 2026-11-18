"""Linux handle operations for the offline worker-input verifier."""

from __future__ import annotations

import os
import stat
import sys
from collections.abc import Iterator
from contextlib import ExitStack
from pathlib import Path

from dynamisbench.materialization import MaterializationError, MaterializationRefusalCode

if sys.platform != "linux":
    raise ImportError("Linux handle operations require Linux")


def open_root(path: Path) -> int:
    # Walk every component. A no-follow open on only the last component would
    # still follow links in the caller's root path.
    mode = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    with ExitStack() as parents:
        parent = os.open(path.anchor, mode)
        parents.callback(os.close, parent)
        for component in path.parts[1:]:
            child = os.open(component, mode, dir_fd=parent)
            parents.callback(os.close, child)
            parent = child
        return os.dup(parent)


def _mount_id(handle: int) -> str:
    with open(f"/proc/self/fdinfo/{handle}", "rb") as info:
        for line in info.read(4096).decode("ascii").splitlines():
            key, _, value = line.partition(":")
            if key == "mnt_id" and value.strip().isdigit():
                return value.strip()
    raise OSError("mount identity unavailable")


def open_child(parent: int, name: str, *, directory: bool, inode: int) -> int:
    if directory:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    else:
        # O_PATH pins the object without opening a device or blocking on a FIFO.
        flags = os.O_PATH | os.O_NOFOLLOW
    handle = os.open(name, flags, dir_fd=parent)
    try:
        info = os.fstat(handle)
        kind_matches = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not kind_matches or (not directory and info.st_nlink != 1):
            raise MaterializationError(
                MaterializationRefusalCode.INPUT_LINK_REFUSED,
                "the input view contains a link or non-regular object",
            )
        if info.st_ino != inode or _mount_id(handle) != _mount_id(parent):
            raise MaterializationError(
                MaterializationRefusalCode.INPUT_PATH_REFUSED,
                "the input view entry changed identity or crossed a mount",
            )
        return os.dup(handle)
    finally:
        os.close(handle)


def entries(directory: int) -> Iterator[tuple[str, int]]:
    handle = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        with os.scandir(handle) as children:
            for entry in children:
                yield entry.name, entry.inode()
    finally:
        os.close(handle)


def read(handle: int, max_bytes: int) -> bytes:
    pinned = os.fstat(handle)
    if pinned.st_size > max_bytes:
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_LIMIT_EXCEEDED,
            "an input view file exceeds its read bound",
        )
    # This procfs name addresses our pinned inode, independent of candidate names.
    with open(f"/proc/self/fd/{handle}", "rb") as stream:
        before = os.fstat(stream.fileno())
        if before != pinned or before.st_nlink != 1:
            raise MaterializationError(
                MaterializationRefusalCode.INPUT_SOURCE_CHANGED,
                "the pinned input file changed before reading",
            )
        data = stream.read(max_bytes + 1)
        after = os.fstat(stream.fileno())
        if (
            len(data) != before.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise MaterializationError(
                MaterializationRefusalCode.INPUT_SOURCE_CHANGED,
                "the pinned input file changed while reading",
            )
        return data


close = os.close
