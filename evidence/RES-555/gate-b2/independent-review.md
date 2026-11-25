# RES-555 Gate B2 — independent review packet

Status: **REVIEW REQUEST — NO HUMAN SIGN-OFF RECORDED.** This document requests the
independent human security, runtime and scientific/architecture review required by RES-555's
acceptance record. It is not a review, not an approval and not owner adoption. Automated
tests and automated reviews are listed separately and must not be counted as human review.

## Exact material to review

- Base: protected `main` at the branch's merge base.
- Exact head: the PR #35 head named in `evidence/RES-555/gate-b2/authority-decision.md` and
  the `res555-gate-b2-comparison` artifact for that head. A result on an earlier head is not
  a qualification of this head.
- A1 stack: PR #31 `bfd5e6a` → PR #32 `e705841` → PR #34 `5860904`.
- Historical B2 feature head: `47ca8d3`.
- Historical qualified integration head: `911d2e6` (workflow_dispatch `45270650148`, 10/10
  jobs). It is not a qualification of the current head.
- Prior hardening code head: `cc72f91` (workflow_dispatch `45431738452` attempt 3, 10/10
  jobs). It is retained as historical evidence, not as the current exact head.
- Diff under review: the commits with `RES-555` in their subject added after `47ca8d3`, plus
  the protected-main merge and this increment's fixes.

## Reviewer brief by discipline

### Security

1. Is the Windows AppContainer + Job Object + stdio-only handle list a defensible boundary for
   the stated scientific worker? Check the token observation (package SID, zero capabilities,
   privileges, integrity, elevation), DACL expressions (`RX,DE,DC` for runtime/input/attempt
   during an attempt), scratch DACL, handle-list construction and cleanup. What remains
   possible for the same host user, including DACL rewrite, deletion and post-exit races?
2. Is the Linux Landlock ABI >= 4 + seccomp + cgroup v2 composition defensible? Check the
   seccomp syscall list and `clone3`/`clone` handling; the `socket`/`socketpair`/UDP/raw/Unix
   coverage and `io_uring` denial; cgroup placement, `pids.max`, `cgroup.kill`,
   `cgroup.events`; the supervisor's `/proc` checks and in-worker probes; and whether the
   same-UID external-write residual is stated truthfully.
3. Does the scratch mechanism match its name? `dedicated-filesystem` must be a real aggregate
   capacity bound; `sampled-watchdog` must not be described as a quota; the transient-sampling
   tolerance must not hide actual links or persistent unmeasurable entries; Windows alternate
   data streams and pre-launch headroom must be counted.
4. Is the receipt treated as untrusted? Does any check accidentally promote a worker-authored
   value to supervisor authority? Are run id, completion/failure, preflight, environment,
   worker selection, runtime, profile, adapter and trajectory all correlated?
5. Are there refusal paths that silently fall back to A1, a process group, a TCP-only
   Landlock claim, or an unprotected launch? Search for `mechanism_available`,
   `CgroupV2.create`, `resolve_scratch_budget`, `_launch`, and Windows `launch`.
6. Is the canary evidence meaningful? Each active TCP/UDP/Unix canary must receive a
   supervisor control before a zero worker count is accepted; the Windows UDP observation is
   one measured path, not a universal denial.

### Runtime

1. Reproduce the Linux cgroup placement requirement (`Delegate=yes` / supervisor child), the
   `pids.peak` and `pids.events.max` observations, and the `fork`/`setsid`/orphan and
   repeated-launch cleanup tests.
2. Reproduce the Windows handle-list test, descendant Job Object test, cancellation cleanup
   and watchdog behaviour, including a transient unmeasurable entry that must not kill a
   healthy worker.
3. Verify the runtime closure and dependency closure on both platforms, including the
   packaged-XML removal and the adapter source digest reconstruction.
4. Check the mutation windows: supervisor measurement → launch, execution, exit →
   post-measurement, and the Windows DACL restore between attempts. Is any window unmeasured
   or misdescribed?
5. Verify `MUJOCO_GL=disable` is set before any scientific import and that no GLFW helper is
   spawned; confirm the 2,000-step trajectory is unchanged.

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
5. Confirm the proposed production increment is limited to the pinned reference profile, not
   a general arbitrary-model loader, and is not activated by this packet.
6. Confirm the packet does not claim an independent physics oracle: the trajectory digest is
   worker-authored and the supervisor only correlates it with the committed reference. The
   pinned adapter is trusted code, not an independently validated solver.

## Reviewer findings

| ID | Discipline | Severity | Finding | Evidence / reproduction | Disposition |
|---|---|---|---|---|---|
| | | | | | |

Reviewer name / role:

Exact head reviewed (SHA):

Date:

Signature / disposition (approve, approve with conditions, reject):

## Automated evidence (supporting only)

- `python/tests/execution/mujoco/test_b2_protected_consumption.py` — real pinned MuJoCo
  consumption, trajectory reference, replay, substitution, late hardlink, tampered view,
  unavailable mechanism and headless-GL check.
- `python/tests/execution/mujoco/test_b2_protected_verify_only.py` — engine-independent
  bootstrap.
- `python/tests/execution/mujoco/test_b2_windows_containment.py` — stdio-only handle
  inheritance, descendant Job containment, cancellation, repeated launches, sampled
  watchdog, and the external token capability observation.
- `python/tests/execution/test_b2_linux_containment.py` — cgroup availability/refusal,
  fork/`setsid`/orphan containment, cancellation, repeated launches, failed setup, task
  counting and the real NumPy/MuJoCo task bound.
- `python/tests/execution/test_b2_seccomp_policy.py` — filter construction and installed
  denial of TCP/UDP/Unix/socketpair, `kill`, `clone3` fallback, fork and threads.
- `python/tests/execution/test_b2_scratch_budget.py` — exact measurement, transient sampling
  tolerance, explicit non-dedicated refusal, sampled-watchdog truthfulness, dedicated tmpfs
  ENOSPC, Windows alternate data streams and scratch headroom.
- Hosted `workflow_dispatch` `45680046080` on code head `9206648`: all 10 jobs passed,
  including the Windows B2 step (51/51 checks, zero capabilities, low integrity, sampled
  watchdog with zero unmeasured entries), the Linux B2 step (57/57 checks, ABI 8, cgroup
  `pids.peak=4`, dedicated tmpfs), the B2 comparison and the MuJoCo receipt comparison. The
  final code head adds only the probe-presence strictness and fsynced marker; its exact-head
  result is recorded in the PR and committed observations. A local WSL ABI 3 run is not a
  qualification of the ABI >= 4 profile.

## Automated review dispositions (not human review)

The engineering corrections below are supported by the probe tests. They are not a human
review and are not a security, runtime or scientific sign-off.

| Automated finding | Disposition |
|---|---|
| Windows AC folder writable by package SID | Fixed: attempt moved outside AC, AC reduced to `RX`, `..`/AC escape probes added |
| Same-user DACL can be rewritten by owner | Corrected claim: worker-token-only; owner DACL rewrite is detection-only residual |
| Windows UDP result conflated with denial | Fixed: canary control added, check renamed `network_udp_not_delivered`, profile narrowed to the measured path |
| Elevated AppContainer token | Fixed observation: capabilities/privileges/integrity/elevation read from outside; demonstrated check requires zero capabilities; production principal still requires a non-elevated run or explicit acceptance |
| Linux memory controller silently optional | Fixed: `memory` controller and limit readback required |
| Linux sampled watchdog accepted as qualified scratch | Fixed: materialized Linux test and comparator require dedicated filesystem |
| Inherited socket data paths not covered by seccomp | Fixed: `sendfile`/`splice`/`tee`/`vmsplice`/`copy_file_range` denied; inherited fds externally verified |
| Windows containment tests rewrite host Python DACLs | Fixed: tests use the measured snapshot and never re-DACL `sys.base_prefix` |
| Seccomp installs only on the calling thread | Fixed: installer refuses unless `/proc/self/status` reports one thread |
| UDP check did not gate the worker result | Fixed: Linux requires the in-worker denial; both platforms require zero canary delivery after a control |
| `/usr` system Python could receive broad execute grant | Fixed: Linux probe refuses `/`, `/usr` and `/usr/local` base prefixes |
| `external_landlock` included worker-authored fields | Split into supervisor `/proc` facts and a labelled worker echo |
| Failed-setup test depended on optional cpu controller | Fixed: skips when the controller is absent |
| `pids.peak` not checked at availability | Fixed: required in delegation validation |
| Tautological scratch/backend and Job-limit comparator checks | Removed or replaced with the dedicated-backend/observed checks |
| Dead watchdog flag, unchecked cgroup kill, handle leak, unchecked `ResumeThread` | Fixed |
| Fast worker could lose `/proc` facts after reaping | Fixed: facts captured before termination, plus a final pre-reap capture |
| “No user SID” AppContainer claim | Corrected: lowbox/restricted token intersection, not absence of the user SID |
| Reference trajectory regenerated by the code under test | Fixed: committed `reference-observation.json` and pinned checks |
| No committed observation artifact | Final exact-head observations are added after the exact-head CI run; see the final report |
| Comparator trusted a stored boolean | Fixed: both observations must equal the committed reference digest |
| Environment sanitisation was self-asserted | Supervisor checks the echoed key set against the launch policy, and `MUJOCO_GL=disable` is required |
| AF_UNIX absence conflated with denial | Observed separately; Linux denial and Windows “unavailable or denied” are distinct |
| Package asset probe hard-coded | Derived from the recorded in-worker probe |
| Seccomp/scratch claims broader than named checks | Added socketpair/`io_uring` checks; sampled-watchdog overshoot stated |
| Evidence modules outside adapter digest | Documented as covered by the runtime source closure, not the adapter manifest |
| Transient Windows watchdog kill | Fixed: live sampling tolerates a single disappeared/unmeasurable entry; post-exit remains fail-closed |
| Windows scratch exhaustion via alternate streams | Fixed: NTFS stream enumeration, hard-link/reparse refusal and pre-launch headroom |
| Linux GLFW helper pyvenv error | Fixed: headless `MUJOCO_GL=disable`; helper no longer spawned; `headless_gl` check added |

These dispositions are engineering corrections, not a human review. The remaining
unverified items are the kernel-exploit surface, the elevated Windows runner's token/group
composition as a production principal, a production cgroup delegation/scratch provisioning
outside CI, and the native output contract reserved to ADR-027.
