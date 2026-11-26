"""Compatibility re-export of the production Linux cgroup v2 boundary.

The mechanism moved to :mod:`dynamisbench.host.protected_cgroup` when the protected route
became a production host primitive. The probe harness keeps importing this name so its
qualified observations continue to exercise the exact code the production launcher uses.
"""

from __future__ import annotations

from dynamisbench.host.protected_cgroup import (
    CgroupError,
    CgroupLimits,
    CgroupObservation,
    CgroupUnavailableError,
    CgroupV2,
    attach_code,
    cgroup2_mount_for,
    cgroup_available,
    delegated_root,
    verify_supervisor_placement,
)

__all__ = [
    "CgroupError",
    "CgroupLimits",
    "CgroupObservation",
    "CgroupUnavailableError",
    "CgroupV2",
    "attach_code",
    "cgroup2_mount_for",
    "cgroup_available",
    "delegated_root",
    "verify_supervisor_placement",
]
