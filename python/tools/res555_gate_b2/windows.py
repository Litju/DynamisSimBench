"""Compatibility re-export of the production Windows AppContainer launch boundary.

The mechanism moved to :mod:`dynamisbench.host.protected_windows` when the protected route
became a production host primitive. The probe harness keeps importing this name so its
qualified observations continue to exercise the exact code the production launcher uses.
"""

from __future__ import annotations

from dynamisbench.host.protected_windows import (
    AppContainerError,
    AppContainerProcess,
    AppContainerProfile,
    PrincipalError,
    current_user_sid,
    grant_tree,
    is_available,
    require_non_elevated_supervisor,
    restore_user_control,
    supervisor_principal,
)

__all__ = [
    "AppContainerError",
    "AppContainerProcess",
    "AppContainerProfile",
    "PrincipalError",
    "current_user_sid",
    "grant_tree",
    "is_available",
    "require_non_elevated_supervisor",
    "restore_user_control",
    "supervisor_principal",
]
