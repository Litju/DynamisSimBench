"""Restrictive seccomp policy for the RES-555 Gate B2 Linux worker.

Landlock ABI 4 denies TCP bind/connect, but it does not handle UDP, raw sockets,
Unix-domain sockets or an inherited socket descriptor. That is a narrower fact than "no
network". This module installs a second, independent kernel control: a seccomp-BPF filter
that denies socket creation and the socket data paths, before the scientific worker is
imported. An inherited socket descriptor is prevented by the supervisor's close_fds and
verified through /proc; the filter also blocks sendfile/splice/tee/vmsplice/copy_file_range
so a future inherited socket cannot be used through those paths. The policy denies the
syscalls that would let a worker observe or signal the
supervisor, create a new namespace or mount, use io_uring to bypass the socket filter, or
escape through a pidfd.

The policy is deliberately not a general-purpose sandbox. It allows ``fork``/``clone`` for
ordinary processes and threads; the protected supervisor's cgroup pids limit and subtree
kill are the containment primitive for those. It blocks
``clone3`` with ``ENOSYS`` so glibc falls back to ``clone``, whose namespace flags this filter
can inspect; a direct ``clone3`` caller is refused rather than silently trusted.

The filter is inherited across ``execve`` and cannot be removed. A host without seccomp
filter support refuses: the probe does not fall back to the Landlock TCP-only claim.
"""

from __future__ import annotations

import ctypes
import errno
import os
import sys
from pathlib import Path
from typing import Final

__all__ = [
    "BLOCKED_NETWORK_SYSCALLS",
    "SeccompError",
    "SeccompUnavailableError",
    "apply_network_policy",
    "build_network_filter",
    "seccomp_available",
    "seccomp_status",
]

_PR_SET_NO_NEW_PRIVS: Final = 38
_PR_GET_NO_NEW_PRIVS: Final = 39
_PR_SET_SECCOMP: Final = 22
_PR_GET_SECCOMP: Final = 21
_SECCOMP_MODE_FILTER: Final = 2

_SECCOMP_RET_KILL_PROCESS: Final = 0x80000000
_SECCOMP_RET_ERRNO: Final = 0x00050000
_SECCOMP_RET_ALLOW: Final = 0x7FFF0000

_AUDIT_ARCH_X86_64: Final = 0xC000003E
_X32_SYSCALL_BIT: Final = 0x40000000
_CLONE3_SYSCALL: Final = 435
_CLONE_SYSCALL: Final = 56
_CLONE_NAMESPACE_FLAGS: Final = (
    0x00000080  # CLONE_NEWTIME
    | 0x00020000  # CLONE_NEWNS
    | 0x02000000  # CLONE_NEWCGROUP
    | 0x04000000  # CLONE_NEWUTS
    | 0x08000000  # CLONE_NEWIPC
    | 0x10000000  # CLONE_NEWUSER
    | 0x20000000  # CLONE_NEWPID
    | 0x40000000  # CLONE_NEWNET
)

# Socket creation, every socket data path, and the io_uring interface that could create a
# socket without calling socket(2). Names are kept for the observation document.
BLOCKED_NETWORK_SYSCALLS: Final[dict[int, str]] = {
    41: "socket",
    42: "connect",
    43: "accept",
    44: "sendto",
    45: "recvfrom",
    46: "sendmsg",
    47: "recvmsg",
    48: "shutdown",
    49: "bind",
    50: "listen",
    51: "getsockname",
    52: "getpeername",
    53: "socketpair",
    54: "setsockopt",
    55: "getsockopt",
    40: "sendfile",
    275: "splice",
    276: "tee",
    278: "vmsplice",
    288: "accept4",
    299: "recvmmsg",
    307: "sendmmsg",
    326: "copy_file_range",
    425: "io_uring_setup",
    426: "io_uring_enter",
    427: "io_uring_register",
}

# Observation, signalling and namespace interfaces a pinned scientific worker does not need.
# They are not file or network access; they are escape/observation paths that should not be
# reachable from a process that is supposed to be contained by the supervisor.
BLOCKED_PROCESS_SYSCALLS: Final[dict[int, str]] = {
    62: "kill",
    101: "ptrace",
    155: "pivot_root",
    161: "chroot",
    165: "mount",
    166: "umount2",
    200: "tkill",
    234: "tgkill",
    272: "unshare",
    298: "perf_event_open",
    303: "name_to_handle_at",
    304: "open_by_handle_at",
    308: "setns",
    310: "process_vm_readv",
    311: "process_vm_writev",
    312: "kcmp",
    321: "bpf",
    323: "userfaultfd",
    424: "pidfd_send_signal",
    434: "pidfd_open",
    438: "pidfd_getfd",
    129: "rt_sigqueueinfo",
    297: "rt_tgsigqueueinfo",
}


class SeccompError(RuntimeError):
    """The seccomp policy could not be installed or verified."""


class SeccompUnavailableError(SeccompError):
    """The host does not expose the seccomp filter mechanism this profile requires."""


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_uint16),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


_BPF_LD: Final = 0x00
_BPF_W: Final = 0x00
_BPF_ABS: Final = 0x20
_BPF_JMP: Final = 0x05
_BPF_JEQ: Final = 0x10
_BPF_JSET: Final = 0x40
_BPF_RET: Final = 0x06
_BPF_K: Final = 0x00


def _statement(code: int, k: int) -> _SockFilter:
    return _SockFilter(code=code, jt=0, jf=0, k=k)


def _jump(code: int, k: int, jt: int, jf: int) -> _SockFilter:
    return _SockFilter(code=code, jt=jt, jf=jf, k=k)


def _deny(errno_value: int) -> _SockFilter:
    return _statement(_BPF_RET | _BPF_K, _SECCOMP_RET_ERRNO | errno_value)


def build_network_filter() -> list[_SockFilter]:
    """Build the fixed BPF program; exposed for the policy unit tests."""
    program: list[_SockFilter] = [
        # The architecture is checked before any syscall number. A process that reaches this
        # filter through a different ABI is killed, not evaluated against x86-64 numbers.
        _statement(_BPF_LD | _BPF_W | _BPF_ABS, 4),
        _jump(_BPF_JMP | _BPF_JEQ | _BPF_K, _AUDIT_ARCH_X86_64, 1, 0),
        _statement(_BPF_RET | _BPF_K, _SECCOMP_RET_KILL_PROCESS),
        _statement(_BPF_LD | _BPF_W | _BPF_ABS, 0),
        # The x32 ABI shares the x86-64 audit arch but not the syscall table. A pinned
        # x86-64 worker never needs it, so the bit is refused rather than allowed through.
        _jump(_BPF_JMP | _BPF_JSET | _BPF_K, _X32_SYSCALL_BIT, 0, 1),
        _deny(errno.EPERM),
    ]
    for number in sorted(BLOCKED_NETWORK_SYSCALLS):
        program.append(_jump(_BPF_JMP | _BPF_JEQ | _BPF_K, number, 0, 1))
        program.append(_deny(errno.EPERM))
    for number in sorted(BLOCKED_PROCESS_SYSCALLS):
        program.append(_jump(_BPF_JMP | _BPF_JEQ | _BPF_K, number, 0, 1))
        program.append(_deny(errno.EPERM))
    # clone3 carries its flags in a pointed-to structure, which a classic seccomp filter
    # cannot dereference. Refusing it with ENOSYS makes glibc use clone(2), whose flags this
    # filter can inspect. The alternative, allowing clone3 blindly, would let a direct
    # caller create a user or mount namespace without the flag check below.
    program.append(_jump(_BPF_JMP | _BPF_JEQ | _BPF_K, _CLONE3_SYSCALL, 0, 1))
    program.append(_deny(errno.ENOSYS))
    # clone is allowed for fork and pthread_create, but never for a new namespace. The
    # namespace flags are the only escape from the cgroup/Landlock view that clone can
    # request; process creation itself remains owned by the cgroup.
    program.append(_jump(_BPF_JMP | _BPF_JEQ | _BPF_K, _CLONE_SYSCALL, 0, 3))
    program.append(_statement(_BPF_LD | _BPF_W | _BPF_ABS, 16))
    program.append(_jump(_BPF_JMP | _BPF_JSET | _BPF_K, _CLONE_NAMESPACE_FLAGS, 0, 1))
    program.append(_deny(errno.EPERM))
    program.append(_statement(_BPF_RET | _BPF_K, _SECCOMP_RET_ALLOW))
    return program


def _program() -> tuple[ctypes.Array[_SockFilter], _SockFprog]:
    instructions = build_network_filter()
    array = (_SockFilter * len(instructions))(*instructions)
    fprog = _SockFprog(len=len(instructions), filter=array)
    return array, fprog


def _prctl(
    option: int,
    argument_2: int = 0,
    argument_3: int = 0,
    argument_4: int = 0,
    argument_5: int = 0,
) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    result = int(prctl(option, argument_2, argument_3, argument_4, argument_5))
    if result < 0:
        error = ctypes.get_errno()
        raise SeccompError(f"prctl({option}) failed: {os.strerror(error)} (errno {error})")
    return result


def seccomp_available() -> bool:
    """Whether the host exposes seccomp filter mode, checked without installing a filter."""
    if not sys.platform.startswith("linux"):
        return False
    try:
        actions = Path("/proc/sys/kernel/seccomp/actions_avail").read_text(encoding="ascii")
    except OSError:
        return False
    return "errno" in actions and "kill_process" in actions


def _single_threaded() -> bool:
    try:
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
            name, _, value = line.partition(":")
            if name == "Threads":
                return int(value.strip()) == 1
    except (OSError, ValueError):
        return False
    return False


def apply_network_policy() -> None:
    """Install the fixed filter and verify it is active.

    The caller must have set ``PR_SET_NO_NEW_PRIVS`` already (Landlock does). This function
    sets it again because the filter must never be installed on a process that could gain
    privileges afterwards.
    """
    if not sys.platform.startswith("linux"):
        raise SeccompUnavailableError("seccomp is only available on Linux")
    if not seccomp_available():
        raise SeccompUnavailableError("this kernel does not expose seccomp filter mode")
    if not _single_threaded():
        raise SeccompError(
            "the seccomp policy must be installed from a single-threaded process; "
            "prctl(PR_SET_SECCOMP) filters only the calling thread"
        )
    array, fprog = _program()
    try:
        # ``array`` owns the instruction storage; ``fprog`` holds only a pointer to it, so
        # the local reference must stay alive until prctl has copied the program.
        _ = array
        _prctl(_PR_SET_NO_NEW_PRIVS, 1)
        _prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.addressof(fprog))
    except SeccompError as error:
        raise SeccompUnavailableError(
            f"the seccomp network policy could not be installed: {error}"
        ) from error
    mode = _prctl(_PR_GET_SECCOMP)
    if mode != _SECCOMP_MODE_FILTER:
        raise SeccompError("the seccomp filter mode is not active after installation")


def seccomp_status() -> dict[str, object]:
    """Return the kernel-reported filter status for the current process, for tests."""
    status: dict[str, object] = {}
    try:
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
            name, _, value = line.partition(":")
            if name in {"Seccomp", "Seccomp_filters", "NoNewPrivs"}:
                status[name] = value.strip()
    except OSError:
        return {}
    return status
