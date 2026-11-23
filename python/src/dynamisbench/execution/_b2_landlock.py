"""Probe-only Linux Landlock domain for the RES-555 Gate B2 qualification.

This module is deliberately importable with the standard library only. The probe
bootstrap loads it by path, applies an allowlist filesystem domain and a TCP deny domain,
and only then imports the scientific worker. Landlock is irreversible for the process and
is inherited across ``exec``; the supervisor also verifies ``NoNewPrivs`` and zero
capabilities from outside.

It is not imported by the production supervisor, preflight, API or CLI. No production
execution route uses it. The profile requires ABI 4, because ABI 4 is the first release
that can deny TCP bind/connect globally; a host without it is a refusal, not a weaker
fallback.
"""

from __future__ import annotations

import ctypes
import importlib
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

try:
    resource_module = importlib.import_module("resource")
except ImportError:  # pragma: no cover - Windows has no resource module
    resource_module = None
resource: Any = resource_module

__all__ = ["LandlockError", "abi_version", "apply", "apply_limits"]

_SYS_LANDLOCK_CREATE_RULESET: Final = 444
_SYS_LANDLOCK_ADD_RULE: Final = 445
_SYS_LANDLOCK_RESTRICT_SELF: Final = 446
_LANDLOCK_CREATE_RULESET_VERSION: Final = 1
_LANDLOCK_RULE_PATH_BENEATH: Final = 1
_LANDLOCK_RULE_NET_PORT: Final = 2
_PR_SET_NO_NEW_PRIVS: Final = 38
_PR_GET_NO_NEW_PRIVS: Final = 39

_ACCESS_FS_EXECUTE: Final = 1 << 0
_ACCESS_FS_WRITE_FILE: Final = 1 << 1
_ACCESS_FS_READ_FILE: Final = 1 << 2
_ACCESS_FS_READ_DIR: Final = 1 << 3
_ACCESS_FS_REMOVE_DIR: Final = 1 << 4
_ACCESS_FS_REMOVE_FILE: Final = 1 << 5
_ACCESS_FS_MAKE_CHAR: Final = 1 << 6
_ACCESS_FS_MAKE_DIR: Final = 1 << 7
_ACCESS_FS_MAKE_REG: Final = 1 << 8
_ACCESS_FS_MAKE_SOCK: Final = 1 << 9
_ACCESS_FS_MAKE_FIFO: Final = 1 << 10
_ACCESS_FS_MAKE_BLOCK: Final = 1 << 11
_ACCESS_FS_MAKE_SYM: Final = 1 << 12
_ACCESS_FS_REFER: Final = 1 << 13
_ACCESS_FS_TRUNCATE: Final = 1 << 14
_ACCESS_FS_IOCTL_DEV: Final = 1 << 15

_ACCESS_NET_BIND_TCP: Final = 1 << 0
_ACCESS_NET_CONNECT_TCP: Final = 1 << 1

_REQUIRED_ABI: Final = 4
_FS_BASE = (
    _ACCESS_FS_EXECUTE
    | _ACCESS_FS_WRITE_FILE
    | _ACCESS_FS_READ_FILE
    | _ACCESS_FS_READ_DIR
    | _ACCESS_FS_REMOVE_DIR
    | _ACCESS_FS_REMOVE_FILE
    | _ACCESS_FS_MAKE_CHAR
    | _ACCESS_FS_MAKE_DIR
    | _ACCESS_FS_MAKE_REG
    | _ACCESS_FS_MAKE_SOCK
    | _ACCESS_FS_MAKE_FIFO
    | _ACCESS_FS_MAKE_BLOCK
    | _ACCESS_FS_MAKE_SYM
)
_READ_EXECUTE = _ACCESS_FS_EXECUTE | _ACCESS_FS_READ_FILE | _ACCESS_FS_READ_DIR
_READ_ONLY = _ACCESS_FS_READ_FILE | _ACCESS_FS_READ_DIR
_READ_WRITE = (_FS_BASE & ~_ACCESS_FS_EXECUTE) | _ACCESS_FS_REFER | _ACCESS_FS_TRUNCATE


class LandlockError(RuntimeError):
    """The required Linux isolation domain could not be established."""


class _RulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
    ]


class _PathBeneathAttr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


class _NetPortAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("port", ctypes.c_uint64),
    ]


def _libc():
    return ctypes.CDLL(None, use_errno=True)


def _check(result: int, what: str) -> int:
    if result < 0:
        error = ctypes.get_errno()
        raise LandlockError(f"{what} failed: {os.strerror(error)} (errno {error})")
    return result


def abi_version() -> int:
    """Return the kernel Landlock ABI, or refuse on a non-Linux host."""
    if not sys.platform.startswith("linux"):
        raise LandlockError("Landlock is only available on Linux")
    libc = _libc()
    result = libc.syscall(
        _SYS_LANDLOCK_CREATE_RULESET,
        ctypes.c_void_p(0),
        ctypes.c_size_t(0),
        ctypes.c_uint32(_LANDLOCK_CREATE_RULESET_VERSION),
    )
    return _check(int(result), "landlock_create_ruleset(VERSION)")


def _fs_access_for_abi(abi: int) -> int:
    access = _FS_BASE
    if abi >= 2:
        access |= _ACCESS_FS_REFER
    if abi >= 3:
        access |= _ACCESS_FS_TRUNCATE
    if abi >= 5:
        access |= _ACCESS_FS_IOCTL_DEV
    return access


def _add_path_rule_checked(libc, ruleset_fd: int, path: Path, allowed: int) -> None:
    if not path.exists():
        raise LandlockError(f"Landlock allowlist path is missing: {path.name}")
    resolved = path.resolve()
    if resolved.is_symlink():
        raise LandlockError("a resolved Landlock path is a symlink")
    if not resolved.is_dir():
        # File rules cannot carry directory-only or execute rights.
        allowed &= ~(_ACCESS_FS_READ_DIR | _ACCESS_FS_EXECUTE)
        if not allowed:
            return
    descriptor = os.open(resolved, getattr(os, "O_PATH", 0o10000000) | getattr(os, "O_CLOEXEC", 0))
    try:
        attribute = _PathBeneathAttr(allowed_access=allowed, parent_fd=descriptor)
        result = libc.syscall(
            _SYS_LANDLOCK_ADD_RULE,
            ctypes.c_int(ruleset_fd),
            ctypes.c_int(_LANDLOCK_RULE_PATH_BENEATH),
            ctypes.byref(attribute),
            ctypes.c_uint32(0),
        )
        _check(int(result), f"landlock_add_rule({path.name})")
    finally:
        os.close(descriptor)


def apply_limits(
    *,
    memory_bytes: int,
    cpu_seconds: int,
    file_bytes: int,
    open_files: int,
) -> None:
    """Apply bounded resource limits before the scientific worker is imported."""
    if memory_bytes <= 0 or cpu_seconds <= 0 or file_bytes <= 0 or open_files <= 0:
        raise LandlockError("resource limits must be positive")
    if resource is None:
        raise LandlockError("resource limits are unavailable on this platform")
    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))
    resource.setrlimit(resource.RLIMIT_NOFILE, (open_files, open_files))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)


def apply(
    *,
    read_execute: Sequence[Path],
    read_only: Sequence[Path],
    read_write: Sequence[Path],
) -> int:
    """Apply an irreversible Landlock filesystem and TCP domain.

    The allowlist is exhaustive for the handled access bits: a path not beneath one of the
    rules is denied. TCP bind and connect are handled with no allow rules, so both are
    denied. ABI 4 is required; an older kernel refuses the probe.
    """
    abi = abi_version()
    if abi < _REQUIRED_ABI:
        raise LandlockError(
            f"Landlock ABI {abi} is older than the required ABI {_REQUIRED_ABI}; "
            "the network-deny domain cannot be established"
        )
    libc = _libc()
    handled_fs = _fs_access_for_abi(abi)
    handled_net = _ACCESS_NET_BIND_TCP | _ACCESS_NET_CONNECT_TCP
    ruleset = _RulesetAttr(handled_access_fs=handled_fs, handled_access_net=handled_net)
    result = libc.syscall(
        _SYS_LANDLOCK_CREATE_RULESET,
        ctypes.byref(ruleset),
        ctypes.c_size_t(ctypes.sizeof(ruleset)),
        ctypes.c_uint32(0),
    )
    ruleset_fd = _check(int(result), "landlock_create_ruleset")
    try:
        seen: set[tuple[str, int]] = set()
        for path, access in (
            *((path, _READ_EXECUTE) for path in read_execute),
            *((path, _READ_ONLY) for path in read_only),
            *((path, _READ_WRITE & handled_fs) for path in read_write),
        ):
            resolved = Path(path).resolve()
            key = (str(resolved), access)
            if key in seen:
                continue
            seen.add(key)
            _add_path_rule_checked(libc, ruleset_fd, resolved, access)
        prctl = libc.prctl
        prctl.argtypes = [
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]
        prctl.restype = ctypes.c_int
        _check(prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "prctl(PR_SET_NO_NEW_PRIVS)")
        _check(
            int(
                libc.syscall(
                    _SYS_LANDLOCK_RESTRICT_SELF,
                    ctypes.c_int(ruleset_fd),
                    ctypes.c_uint32(0),
                )
            ),
            "landlock_restrict_self",
        )
        if prctl(_PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1:
            raise LandlockError("NoNewPrivs is not set after the Landlock domain")
    finally:
        os.close(ruleset_fd)
    return abi
