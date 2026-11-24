"""Probe-only isolation profile values for RES-555 Gate B2."""

from __future__ import annotations

import os
import sys
from typing import Final

from tools.res555_gate_b2.scratch import (
    ScratchBudget,
    ScratchEnforcement,
    resolve_scratch_budget,
)

from dynamisbench.adapters.mujoco._b2_probe_common import IsolationProfile

__all__ = ["build_profile", "mechanism_available"]

_MEMORY_LIMIT_BYTES: Final = 2 * 1024 * 1024 * 1024
_CPU_TIME_SECONDS: Final = 120
_WALL_TIME_SECONDS: Final = 180.0
_MAX_STDOUT_BYTES: Final = 1024 * 1024
_MAX_STDERR_BYTES: Final = 256 * 1024
_MAX_SCRATCH_BYTES: Final = 64 * 1024 * 1024
_WINDOWS_MAX_PROCESSES: Final = 8
# cgroup v2 pids.max counts every task, including NumPy/OpenBLAS threads. The real MuJoCo
# reference run records pids.peak; 64 is deliberately above the observed four-vCPU worker
# and below any value that would make a fork bomb cheap.
_LINUX_MAX_TASKS: Final = 64


def _linux_mechanisms_available() -> bool:
    if not sys.platform.startswith("linux"):
        return False
    try:
        from tools.res555_gate_b2.linux_cgroup import cgroup_available

        from dynamisbench.execution._b2_landlock import abi_version
        from dynamisbench.execution._b2_seccomp import seccomp_available
    except ImportError:
        return False
    try:
        if abi_version() < 4:
            return False
    except Exception:  # noqa: BLE001 - availability is a probe, not an assertion
        return False
    return bool(seccomp_available() and cgroup_available())


def mechanism_available() -> bool:
    """Whether the platform's required isolation mechanism can be established here."""
    if os.name == "nt":
        from tools.res555_gate_b2 import windows

        return windows.is_available()
    if sys.platform.startswith("linux"):
        return _linux_mechanisms_available()
    return False


def _window_network_scope() -> str:
    return (
        "AppContainer without an internetClient/privateNetwork capability: outbound TCP "
        "connects time out and no connection reaches a localhost canary; UDP sendto returns "
        "success but no datagram reaches a localhost canary; raw send is denied; the "
        "Unix-domain attempt is denied and no connection reaches the canary. socketpair "
        "remains available as local in-process IPC, so this is 'restricted', not a universal "
        "no-socket claim."
    )


def _linux_network_scope() -> str:
    return (
        "Landlock ABI >= 4 denies TCP bind/connect; seccomp additionally denies socket, "
        "socketpair, connect, bind, listen, accept, sendto/sendmsg/sendmmsg, "
        "recvfrom/recvmsg/recvmmsg, shutdown, getsockname/getpeername, getsockopt/setsockopt, "
        "sendfile/splice/tee/vmsplice/copy_file_range and io_uring. No IP (TCP or UDP), raw or "
        "Unix-domain socket communication remains; inherited sockets are prevented by "
        "close_fds and verified through /proc. stdio pipes and Landlock-bounded file access "
        "are the remaining channels."
    )


def _linux_process_scope() -> str:
    return (
        "cgroup v2 pids.max counts tasks, including threads; cgroup.kill terminates the "
        "whole subtree, including setsid() children and descendants whose direct parent "
        "exited. The supervisor must run in a child of the delegated root."
    )


def _scratch_fields(scratch: ScratchBudget | None) -> tuple[ScratchEnforcement, str]:
    if scratch is None:
        default = resolve_scratch_budget(explicit_root=None, max_bytes=_MAX_SCRATCH_BYTES)
        return default.enforcement, default.detail
    return scratch.enforcement, scratch.detail


def build_profile(
    platform_tag: str,
    *,
    scratch: ScratchBudget | None = None,
) -> IsolationProfile:
    enforcement, detail = _scratch_fields(scratch)
    if platform_tag == "windows-x86-64":
        return IsolationProfile(
            platform=platform_tag,
            mechanism="windows-appcontainer",
            worker_principal="appcontainer-package-sid",
            network_access="restricted",
            network_mechanism="windows-appcontainer-firewall",
            network_scope=_window_network_scope(),
            process_limit_mechanism="windows-job-object-active-process",
            process_limit_scope="processes",
            process_limit_detail=(
                "Job Object ActiveProcessLimit counts processes; threads are not counted by "
                "this limit and are not claimed to be bounded by it."
            ),
            memory_limit_bytes=_MEMORY_LIMIT_BYTES,
            cpu_time_seconds=_CPU_TIME_SECONDS,
            wall_time_seconds=_WALL_TIME_SECONDS,
            max_stdout_bytes=_MAX_STDOUT_BYTES,
            max_stderr_bytes=_MAX_STDERR_BYTES,
            max_scratch_bytes=_MAX_SCRATCH_BYTES,
            scratch_limit_enforcement=enforcement,
            scratch_backend_detail=detail,
            max_processes=_WINDOWS_MAX_PROCESSES,
        )
    if platform_tag == "linux-x86-64":
        return IsolationProfile(
            platform=platform_tag,
            mechanism="linux-landlock",
            worker_principal="same-uid-irreversible-landlock-domain",
            network_access="denied",
            network_mechanism="linux-landlock-tcp+seccomp",
            network_scope=_linux_network_scope(),
            process_limit_mechanism="linux-cgroup-v2-pids",
            process_limit_scope="tasks-and-threads",
            process_limit_detail=_linux_process_scope(),
            memory_limit_bytes=_MEMORY_LIMIT_BYTES,
            cpu_time_seconds=_CPU_TIME_SECONDS,
            wall_time_seconds=_WALL_TIME_SECONDS,
            max_stdout_bytes=_MAX_STDOUT_BYTES,
            max_stderr_bytes=_MAX_STDERR_BYTES,
            max_scratch_bytes=_MAX_SCRATCH_BYTES,
            scratch_limit_enforcement=enforcement,
            scratch_backend_detail=detail,
            max_processes=_LINUX_MAX_TASKS,
        )
    raise ValueError(f"the probe has no isolation profile for {platform_tag!r}")
