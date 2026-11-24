# RES-555 Gate B2 — independent review packet

Status: **REVIEW REQUEST — NO HUMAN SIGN-OFF RECORDED.** This document is a request for the
independent human security, runtime and scientific/architecture review required by RES-555's
acceptance record. It is not a review, not an approval and not owner adoption. Automated
tests and an automated review are listed separately and must not be counted as human review.

## Exact material to review

- Base: protected `main` at the branch's merge base; the hardening head is the exact commit
  named in `evidence/RES-555/gate-b2/authority-decision.md` and the PR #35 head.
- Historical B2 feature head: `47ca8d3`.
- Historical qualified integration head: `911d2e6` (workflow_dispatch `45270650148`, 10/10
  jobs). That result is **not** a qualification of the new hardening head.
- Diff under review: the commits with `RES-555` in their subject added after `47ca8d3`, plus
  the protected-main merge. Read the exact head, not this paragraph.

## Reviewer brief by discipline

### Security

1. Is the Windows AppContainer + Job Object + stdio-only handle list a defensible boundary for
   the stated scientific worker? Check the token observation, DACL expressions
   (`RX,DE,DC` for runtime/input/attempt during an attempt), scratch DACL, handle-list
   construction and cleanup. What remains possible for the same host user, including
   deletion and post-exit races?
2. Is the Linux Landlock ABI >= 4 + seccomp + cgroup v2 composition defensible? Check:
   - the seccomp filter's syscall list and the `clone3`/`clone` handling;
   - the `socket`/`socketpair`/UDP/raw/Unix coverage and `io_uring` denial;
   - the cgroup placement, `pids.max` task semantics, `cgroup.kill`, `cgroup.events`;
   - the supervisor's `/proc` checks and the in-worker probes;
   - whether the same-UID external-write residual is stated truthfully.
3. Does the scratch mechanism match its name? `dedicated-filesystem` must be a real
   aggregate capacity bound; `sampled-watchdog` must not be described as a quota;
   `post-exit-acceptance-bound` must not be described as prevention.
4. Is the receipt treated as untrusted? Does any check accidentally promote a
   worker-authored value to supervisor authority?
5. Are there refusal paths that silently fall back to A1, a process group, a TCP-only
   Landlock claim, or an unprotected launch? Search for `mechanism_available`,
   `CgroupV2.create`, `resolve_scratch_budget`, `_launch`, and Windows `launch`.

### Runtime

1. Reproduce the Linux cgroup placement requirement (`Delegate=yes` / supervisor child),
   the `pids.peak` and `pids.events.max` observations, and the `fork`/`setsid`/orphan and
   repeated-launch cleanup tests.
2. Reproduce the Windows handle-list test, descendant Job Object test, cancellation cleanup
   and watchdog behaviour.
3. Verify the runtime closure and dependency closure on both platforms, including the
   packaged-XML removal and the adapter source digest reconstruction.
4. Check the mutation windows: supervisor measurement → launch, execution, exit →
   post-measurement, and the Windows DACL restore between attempts. Is any window
   unmeasured or misdescribed?

### Scientific / architecture

1. Confirm the 2,000-step reference trajectory, model SHA-256 and numerical criteria are
   unchanged from the existing qualification. This review must not re-accept a changed
   adapter identity implicitly.
2. Confirm the probe remains outside the production supervisor/API/CLI, protocol v1 is
   unchanged, and no native evidence, canonicalization, assessment or seal is produced.
3. Confirm the adapter implementation digest change is attributed to
   `physics.compile_model()` and requires explicit owner re-acceptance.
4. Confirm D4's sidecar receipt is not presented as authenticated evidence and ADR-027 is
   still proposed / outside this increment.

## Reviewer findings

| ID | Discipline | Severity | Finding | Evidence / reproduction | Disposition |
|---|---|---|---|---|---|
| | | | | | |

Reviewer name / role:

Exact head reviewed (SHA):

Date:

Signature / disposition (approve, approve with conditions, reject):

## Automated evidence (supporting only)

- `python/tests/execution/mujoco/test_b2_protected_consumption.py` — 7 tests, including the
  real pinned MuJoCo consumption, trajectory reference, replay, substitution, late hardlink,
  tampered view and unavailable mechanism. Local Windows: 7 passed.
- `python/tests/execution/mujoco/test_b2_protected_verify_only.py` — engine-independent
  bootstrap. Local Windows: 1 passed.
- `python/tests/execution/test_b2_windows_containment.py` — stdio-only handle inheritance,
  descendant Job containment, cancellation, repeated launches, sampled watchdog. Local
  Windows: 5 passed.
- `python/tests/execution/test_b2_linux_containment.py` — cgroup availability/refusal,
  fork/`setsid`/orphan containment, cancellation, repeated launches, failed setup, task
  counting and the real NumPy/MuJoCo task bound. Local WSL Linux: 12 passed (the dedicated
  path is a separate test).
- `python/tests/execution/test_b2_seccomp_policy.py` — filter construction and installed
  denial of TCP/UDP/Unix/socketpair, `kill`, `clone3` fallback, fork and threads. Local WSL
  Linux: passed.
- `python/tests/execution/test_b2_scratch_budget.py` — exact measurement, explicit
  non-dedicated refusal, sampled-watchdog truthfulness, dedicated tmpfs ENOSPC. Local WSL
  Linux with a 64 MiB tmpfs: passed; local Windows: passed with the dedicated test skipped.
- Hosted `workflow_dispatch` `45409652528` on code head `d2aa5ca`: all 10 jobs succeeded.
  `python (linux-x64)` was 2871 passed / 17 skipped with 23 passed in the dedicated B2
  step; the Linux B2 observation was `demonstrated` with 36/36 checks. `python
  (windows-x64)` full suite and B2 step succeeded; the cross-platform comparison passed
  with identical model and trajectory digests. The exact PR head adds the final
  review-driven hardening; its rerun is the authoritative exact-head result. The local WSL
  kernel exposes Landlock ABI 3, so its full B2 integration run is a mechanism diagnostic,
  not a qualification of the ABI >= 4 profile.

## Automated review (not human review)

An independent automated review of the diff is recorded in the final report if one was run.
It is explicitly **not** substituted for the human review above and must not be marked as a
security, runtime or scientific sign-off.
