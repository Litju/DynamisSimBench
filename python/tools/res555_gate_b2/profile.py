"""Probe-only isolation profile values for RES-555 Gate B2."""

from __future__ import annotations

import os
import sys
from typing import Final

from dynamisbench.adapters.mujoco._b2_probe_common import IsolationProfile

__all__ = ["build_profile", "mechanism_available"]

_MEMORY_LIMIT_BYTES: Final = 2 * 1024 * 1024 * 1024
_CPU_TIME_SECONDS: Final = 120
_WALL_TIME_SECONDS: Final = 180.0
_MAX_STDOUT_BYTES: Final = 1024 * 1024
_MAX_STDERR_BYTES: Final = 256 * 1024
_MAX_SCRATCH_BYTES: Final = 64 * 1024 * 1024
_MAX_PROCESSES: Final = 8


def mechanism_available() -> bool:
    """Whether the platform's required isolation mechanism can be established here."""
    if os.name == "nt":
        from tools.res555_gate_b2 import windows

        return windows.is_available()
    if sys.platform.startswith("linux"):
        try:
            from dynamisbench.execution._b2_landlock import abi_version

            return abi_version() >= 4
        except Exception:  # noqa: BLE001 - availability is a probe, not an assertion
            return False
    return False


def build_profile(platform_tag: str) -> IsolationProfile:
    if platform_tag == "windows-x86-64":
        return IsolationProfile(
            platform=platform_tag,
            mechanism="windows-appcontainer",
            worker_principal="appcontainer-package-sid",
            memory_limit_bytes=_MEMORY_LIMIT_BYTES,
            cpu_time_seconds=_CPU_TIME_SECONDS,
            wall_time_seconds=_WALL_TIME_SECONDS,
            max_stdout_bytes=_MAX_STDOUT_BYTES,
            max_stderr_bytes=_MAX_STDERR_BYTES,
            max_scratch_bytes=_MAX_SCRATCH_BYTES,
            max_processes=_MAX_PROCESSES,
        )
    if platform_tag == "linux-x86-64":
        return IsolationProfile(
            platform=platform_tag,
            mechanism="linux-landlock",
            worker_principal="same-uid-irreversible-landlock-domain",
            memory_limit_bytes=_MEMORY_LIMIT_BYTES,
            cpu_time_seconds=_CPU_TIME_SECONDS,
            wall_time_seconds=_WALL_TIME_SECONDS,
            max_stdout_bytes=_MAX_STDOUT_BYTES,
            max_stderr_bytes=_MAX_STDERR_BYTES,
            max_scratch_bytes=_MAX_SCRATCH_BYTES,
            max_processes=_MAX_PROCESSES,
        )
    raise ValueError(f"the probe has no isolation profile for {platform_tag!r}")
