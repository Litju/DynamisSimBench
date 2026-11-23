# RES-555 Gate B2 — protected-consumption probe (not a production route)

Status: **PROBE-ONLY.** This package is not imported by `dynamisbench.execution.supervisor`,
preflight, the CLI, the API, or any production route. It exists to test, on real Windows and
Linux hosts, whether the mechanisms proposed in
`evidence/RES-555/gate-b2/authority-decision.md` can be established and whether the real
pinned MuJoCo worker can consume the exact verified materialized model bytes under them.

The authority packet is a **proposal**, not an accepted decision. ADR-027 remains proposed.
Native extraction, sealing and a production materialized-worker route remain unavailable.

## What the probe does

1. Measures the installed interpreter, base installation, site-packages and adapter source.
2. Copies a runtime snapshot, removes every packaged copy of the reference XML, and
   re-measures the snapshot. Source and snapshot must have identical per-path bytes.
3. Builds the exact `inputs/` view from the A1 `WorkerInputBinding` and materialized CAS
   objects, verifies it with the existing A1 verifier, and writes bounded probe targets.
4. Launches the pinned worker:
   - **Windows:** a per-attempt AppContainer profile with a suspended `CreateProcessW`,
     `SECURITY_CAPABILITIES`, a bounded Job Object, and explicit read-only/runtime and
     read-write/scratch DACLs. The supervisor reads the worker token from outside.
   - **Linux:** the installed venv interpreter with a fixed bootstrap that applies an
     irreversible Landlock ABI ≥ 4 filesystem allowlist and TCP deny, `PR_SET_NO_NEW_PRIVS`,
     zero capabilities and rlimits. The supervisor verifies `/proc/<pid>/status`.
5. The worker verifies the binding, manifest, definitions and asset bytes again, measures its
   own runtime, runs inside-worker read/write/delete/network/package-model probes, compiles
   the view XML with the pinned MuJoCo release, runs the existing 2,000-step reference, and
   writes a bounded consumption receipt.
6. The supervisor correlates the receipt with its fresh nonce, binding, request, manifest,
   runtime and profile, re-verifies the input view and runtime after exit, checks the
   localhost canary, and writes a supervisor observation to
   `evidence/res555-gate-b2/<platform>.json`.

The simulator-free JSON fixture runs the same bootstrap in `verify-only` mode and proves that
the launch, closure, view and denial mechanisms are engine-independent. It is not a second
solver adapter.

## Run locally

```bash
cd python
uv sync --frozen --project worker-mujoco
DYNAMISBENCH_RES555_B2_PROBE=1 \
DYNAMISBENCH_RES555_B2_EVIDENCE_DIR=evidence/res555-gate-b2 \
uv run pytest -q \
  tests/execution/mujoco/test_b2_protected_consumption.py \
  tests/execution/mujoco/test_b2_protected_verify_only.py
```

A host without the required mechanism skips only when `DYNAMISBENCH_REQUIRE_MUJOCO` is unset;
CI sets it and treats an unavailable mechanism as a failure. There is no A1 fallback.

## What is not claimed

- No production launch, no native capture, no canonicalization, no assessment, no seal.
- No aggregate kernel-enforced scratch quota (Windows uses Job memory limits and post-exit
  checks; Linux uses `RLIMIT_FSIZE`/`RLIMIT_AS` and post-exit checks).
- No vendor-authenticated wheels or interpreter binary. The closure is a measured snapshot,
  not a signature.
- On an elevated CI runner the AppContainer token can report `elevated=true`; the probe records that fact but does not treat it as isolation. The package-SID/restricted-token file access, the explicit DACLs and the in-worker denial probes are the evidence. A non-elevated local run records `elevated=false` and the same denials.
- On Windows the AppContainer's inherited environment is sanitized by the measured bootstrap
  because `CreateProcessW` in an AppContainer rejected explicit environment blocks on the
  qualified host. `-I` ignores Python environment overrides and the AppContainer denies the
  inherited paths; the production contract still needs a rebuilt environment and must be
  re-qualified if that differs.
- The probe does not authorize any decision in the authority packet. It provides evidence
  for the owner's review.
