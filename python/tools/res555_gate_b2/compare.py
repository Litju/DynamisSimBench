"""Compare the Windows and Linux RES-555 Gate B2 probe observations.

This is a qualification artifact comparator, not an execution route. It requires both
platforms to demonstrate the same materialized model identity and the same qualified
trajectory, while deliberately not requiring the full ExecutionFingerprint or
InputManifestDigest to be equal: those include the platform-specific environment definition
and are expected to differ.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Final

from tools.res555_gate_b2.reference import load_reference_observation

from dynamisbench.adapters.mujoco import reference
from dynamisbench.adapters.mujoco._b2_probe_common import SupervisorObservation

__all__ = ["compare", "main"]

_SCHEMA: Final = "dynamisbench.res555.gate-b2-comparison/1"


class ComparisonError(RuntimeError):
    """The two observations cannot be compared as the intended pair."""


def _check(name: str, passed: bool, observed: object, expected: object) -> dict[str, object]:
    return {
        "name": name,
        "passed": bool(passed),
        "observed": observed,
        "expected": expected,
    }


def _named_checks(observation: SupervisorObservation) -> dict[str, bool]:
    return {str(check["name"]): bool(check["passed"]) for check in observation.checks}


def compare(windows_path: Path, linux_path: Path) -> dict[str, Any]:
    windows = SupervisorObservation.model_validate_json(windows_path.read_bytes())
    linux = SupervisorObservation.model_validate_json(linux_path.read_bytes())
    windows_checks = _named_checks(windows)
    linux_checks = _named_checks(linux)
    windows_model = windows.receipt.model if windows.receipt is not None else None
    linux_model = linux.receipt.model if linux.receipt is not None else None
    windows_physics = windows.receipt.physics if windows.receipt is not None else None
    linux_physics = linux.receipt.physics if linux.receipt is not None else None
    pinned = load_reference_observation()
    pinned_trajectory = str(pinned["trajectory_sha256"])
    pinned_model = str(pinned["model_sha256"])
    windows_token = windows.external_isolation.get("token")
    windows_token_fields: dict[str, object] = (
        windows_token if isinstance(windows_token, dict) else {}
    )
    windows_capability_count = windows_token_fields.get("capability_count")

    def qualified(observation: SupervisorObservation) -> bool:
        value = observation.numerical_reference
        return bool(
            value is not None
            and value.get("matches") is True
            and value.get("expected_trajectory_sha256") == pinned_trajectory
            and value.get("observed_trajectory_sha256") == pinned_trajectory
        )

    checks = [
        _check(
            "windows_verdict",
            windows.verdict == "demonstrated",
            windows.verdict,
            "demonstrated",
        ),
        _check(
            "linux_verdict",
            linux.verdict == "demonstrated",
            linux.verdict,
            "demonstrated",
        ),
        _check(
            "windows_receipt_completed",
            windows.receipt is not None and windows.receipt.completed,
            None if windows.receipt is None else windows.receipt.completed,
            True,
        ),
        _check(
            "linux_receipt_completed",
            linux.receipt is not None and linux.receipt.completed,
            None if linux.receipt is None else linux.receipt.completed,
            True,
        ),
        _check(
            "same_model",
            windows_model is not None
            and linux_model is not None
            and windows_model.sha256 == reference.MODEL_SHA256
            and linux_model.sha256 == reference.MODEL_SHA256,
            [
                None if windows_model is None else windows_model.sha256,
                None if linux_model is None else linux_model.sha256,
            ],
            reference.MODEL_SHA256,
        ),
        _check(
            "model_pinned",
            windows_model is not None
            and linux_model is not None
            and windows_model.sha256 == pinned_model
            and linux_model.sha256 == pinned_model,
            [
                None if windows_model is None else windows_model.sha256,
                None if linux_model is None else linux_model.sha256,
            ],
            pinned_model,
        ),
        _check(
            "model_from_input_view",
            windows_model is not None
            and linux_model is not None
            and windows_model.source == "input_view"
            and linux_model.source == "input_view"
            and not windows_model.package_asset_present
            and not linux_model.package_asset_present,
            [
                None if windows_model is None else windows_model.source,
                None if linux_model is None else linux_model.source,
            ],
            "input_view with no packaged model",
        ),
        _check(
            "same_trajectory",
            windows_physics is not None
            and linux_physics is not None
            and windows_physics.trajectory_sha256 == linux_physics.trajectory_sha256,
            [
                None if windows_physics is None else windows_physics.trajectory_sha256,
                None if linux_physics is None else linux_physics.trajectory_sha256,
            ],
            "one equal SHA-256",
        ),
        _check(
            "windows_qualified_trajectory",
            qualified(windows),
            None if windows.numerical_reference is None else windows.numerical_reference,
            "the supervisor's comparison with the committed qualified reference",
        ),
        _check(
            "linux_qualified_trajectory",
            qualified(linux),
            None if linux.numerical_reference is None else linux.numerical_reference,
            "the supervisor's comparison with the committed qualified reference",
        ),
        _check(
            "steps",
            windows_physics is not None
            and linux_physics is not None
            and windows_physics.steps == pinned["steps"]
            and linux_physics.steps == pinned["steps"],
            [
                None if windows_physics is None else windows_physics.steps,
                None if linux_physics is None else linux_physics.steps,
            ],
            pinned["steps"],
        ),
        _check(
            "runtime_matches",
            windows.runtime_matches and linux.runtime_matches,
            [windows.runtime_matches, linux.runtime_matches],
            True,
        ),
        _check(
            "windows_appcontainer",
            windows.profile.mechanism == "windows-appcontainer"
            and windows_checks.get("external_appcontainer", False),
            [windows.profile.mechanism, windows_checks.get("external_appcontainer")],
            ["windows-appcontainer", True],
        ),
        _check(
            "windows_token_no_capabilities",
            isinstance(windows_capability_count, int) and windows_capability_count == 0,
            windows_token,
            "an AppContainer token with zero package capabilities",
        ),
        _check(
            "linux_landlock",
            linux.profile.mechanism == "linux-landlock"
            and linux_checks.get("external_proc_facts", False),
            [linux.profile.mechanism, linux_checks.get("external_proc_facts")],
            ["linux-landlock", True],
        ),
        _check(
            "linux_seccomp",
            linux.profile.network_mechanism == "linux-landlock-tcp+seccomp"
            and linux_checks.get("network_udp_not_delivered", False)
            and linux_checks.get("network_unix_denied", False)
            and linux_checks.get("network_raw_denied", False)
            and linux_checks.get("network_socketpair_denied", False)
            and linux_checks.get("seccomp_io_uring_denied", False),
            [
                linux.profile.network_mechanism,
                linux_checks.get("network_udp_not_delivered"),
                linux_checks.get("network_unix_denied"),
                linux_checks.get("network_raw_denied"),
                linux_checks.get("network_socketpair_denied"),
                linux_checks.get("seccomp_io_uring_denied"),
            ],
            ["linux-landlock-tcp+seccomp", True, True, True, True, True],
        ),
        _check(
            "linux_cgroup",
            linux.profile.process_limit_mechanism == "linux-cgroup-v2-pids"
            and linux.profile.process_limit_scope == "tasks-and-threads"
            and linux_checks.get("external_cgroup", False)
            and linux_checks.get("cgroup_process_limit", False)
            and linux_checks.get("cgroup_tree_cleaned", False),
            [
                linux.profile.process_limit_mechanism,
                linux.profile.process_limit_scope,
                linux_checks.get("external_cgroup"),
                linux_checks.get("cgroup_process_limit"),
                linux_checks.get("cgroup_tree_cleaned"),
            ],
            ["linux-cgroup-v2-pids", "tasks-and-threads", True, True, True],
        ),
        _check(
            "windows_scratch_bounded",
            windows.profile.scratch_limit_enforcement
            in {"dedicated-filesystem", "sampled-watchdog"}
            and windows_checks.get("scratch_headroom", False)
            and windows_checks.get("scratch_within_limit", False),
            [
                windows.profile.scratch_limit_enforcement,
                windows_checks.get("scratch_headroom"),
                windows_checks.get("scratch_within_limit"),
            ],
            "a dedicated filesystem or a sampled watchdog, never post-exit only",
        ),
        _check(
            "linux_scratch_dedicated",
            linux.profile.scratch_limit_enforcement == "dedicated-filesystem"
            and linux_checks.get("scratch_headroom", False)
            and linux_checks.get("scratch_within_limit", False),
            [
                linux.profile.scratch_limit_enforcement,
                linux_checks.get("scratch_headroom"),
                linux_checks.get("scratch_within_limit"),
            ],
            "the host-provisioned dedicated 64 MiB filesystem used by the qualified run",
        ),
        _check(
            "input_view_stable",
            windows_checks.get("input_view_unchanged", False)
            and linux_checks.get("input_view_unchanged", False),
            [
                windows_checks.get("input_view_unchanged"),
                linux_checks.get("input_view_unchanged"),
            ],
            [True, True],
        ),
        _check(
            "headless_gl",
            windows_checks.get("headless_gl", False)
            and linux_checks.get("headless_gl", False),
            [windows_checks.get("headless_gl"), linux_checks.get("headless_gl")],
            [True, True],
        ),
        _check(
            "network_canary_control",
            windows_checks.get("network_canary_control", False)
            and linux_checks.get("network_canary_control", False),
            [
                windows_checks.get("network_canary_control"),
                linux_checks.get("network_canary_control"),
            ],
            [True, True],
        ),
        _check(
            "network_denied",
            windows_checks.get("network_denied", False)
            and linux_checks.get("network_denied", False),
            [windows_checks.get("network_denied"), linux_checks.get("network_denied")],
            [True, True],
        ),
        _check(
            "environment_sanitized",
            windows_checks.get("environment_sanitized", False)
            and linux_checks.get("environment_sanitized", False),
            [
                windows_checks.get("environment_sanitized"),
                linux_checks.get("environment_sanitized"),
            ],
            [True, True],
        ),
        _check(
            "distinct_platform_fingerprints",
            windows.execution_fingerprint != linux.execution_fingerprint,
            [windows.execution_fingerprint, linux.execution_fingerprint],
            "two distinct platform execution fingerprints",
        ),
    ]
    failed = [str(check["name"]) for check in checks if not bool(check["passed"])]
    return {
        "schema": _SCHEMA,
        "kind": "res555-gate-b2-cross-platform-probe-comparison",
        "windows": str(windows_path),
        "linux": str(linux_path),
        "model_sha256": reference.MODEL_SHA256,
        "trajectory_sha256": (
            None if windows_physics is None else windows_physics.trajectory_sha256
        ),
        "windows_mechanism": windows.profile.mechanism,
        "linux_mechanism": linux.profile.mechanism,
        "checks": checks,
        "failed_checks": failed,
        "verdict": "pass" if not failed else "fail",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--windows", required=True, type=Path)
    parser.add_argument("--linux", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args(argv)
    comparison = compare(arguments.windows, arguments.linux)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(comparison, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    sys.stdout.write(
        json.dumps(
            {
                "schema": comparison["schema"],
                "verdict": comparison["verdict"],
                "failed_checks": comparison["failed_checks"],
                "output": str(arguments.output),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    return 0 if comparison["verdict"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
