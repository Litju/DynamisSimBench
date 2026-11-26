"""The pinned RES-550 reference observation used by the Gate B2 comparison.

The B2 test may regenerate a packaged-path diagnostic in the same environment as the
materialized worker. That parity check alone would move with a changed adapter. This loader
reads a reviewed, committed observation so the fresh diagnostic and both materialized
receipts must also equal the historical trajectory and model identity.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

__all__ = ["REFERENCE_OBSERVATION_PATH", "load_reference_observation"]

_SCHEMA: Final = "dynamisbench.res555.reference-observation/1"
REFERENCE_OBSERVATION_PATH: Final = (
    Path(__file__).resolve().parents[3]
    / "evidence"
    / "RES-555"
    / "gate-b2"
    / "reference-observation.json"
)
_REQUIRED = (
    "model_sha256",
    "steps",
    "timestep_s",
    "duration_s",
    "trajectory_sha256",
    "expected_final_angle_rad",
    "expected_final_angular_velocity_rad_s",
    "expected_energy_initial_j",
    "expected_energy_final_j",
)


def load_reference_observation() -> dict[str, Any]:
    """Read the committed reference observation, refusing a malformed or moved record."""
    try:
        value = json.loads(REFERENCE_OBSERVATION_PATH.read_text(encoding="utf-8"))
    except OSError as error:
        raise RuntimeError("the committed RES-555 reference observation is unreadable") from error
    if not isinstance(value, dict) or value.get("schema") != _SCHEMA:
        raise RuntimeError("the committed RES-555 reference observation has an unknown schema")
    for field in _REQUIRED:
        if field not in value:
            raise RuntimeError(f"the committed RES-555 reference observation lacks {field!r}")
    for field in ("model_sha256", "trajectory_sha256"):
        digest = value[field]
        if not isinstance(digest, str) or len(digest) != 64:
            raise RuntimeError(f"the committed RES-555 reference {field} is not a sha256")
    if value["steps"] != 2000:
        raise RuntimeError("the committed RES-555 reference trajectory is not the 2,000-step run")
    return value
