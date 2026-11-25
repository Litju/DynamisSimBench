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
4. Resolves the strongest truthful scratch mechanism the host provides:
   - a dedicated 64 MiB tmpfs/volume root when the host provisions one
     (`DYNAMISBENCH_RES555_B2_SCRATCH_ROOT`), which is a real aggregate allocation bound;
   - otherwise a sampled supervisor watchdog, which is explicitly **not** a hard quota and
     which tolerates a single transient stat race (for example an atomic rename or a scanner
     briefly holding a file) without killing a healthy worker; the post-exit measurement
     remains fail-closed;
   - otherwise the historical post-exit acceptance bound.
   Before launch the supervisor also requires enough free space on the scratch volume for
   the declared bound (2× the bound when only the sampled watchdog is available). On Windows
   the byte count includes every NTFS alternate data stream, not only the unnamed stream that
   `os.stat().st_size` reports.
5. Launches the pinned worker:
   - **Windows:** a per-attempt AppContainer profile with a suspended `CreateProcessW`,
     `SECURITY_CAPABILITIES`, a bounded Job Object, an explicit
     `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` containing only the three stdio pipes, and
     explicit DACLs. The worker's runtime/input/attempt trees are `RX`; the profile's AC
     folder is reduced to `RX` for the package SID so `..` cannot create files outside the
     measured attempt. During the attempt the interactive user has `RX,DE,DC` on those
     trees, so the **worker token** cannot rewrite the measured bytes. The user owns the
     tree and can change its DACL, so this is not a same-user immutability barrier; the
     post-exit closures detect a change. The supervisor reads the worker token from outside,
     including its package SID, `TokenCapabilities` (the check requires zero capabilities),
     privileges, integrity level and elevation facts. A high-integrity CI runner is recorded
     as elevated; that is not treated as an isolation grant, and production must not use the
     elevated CI principal as its security argument.
   - **Linux:** the installed venv interpreter with a fixed bootstrap that applies
     `PR_SET_NO_NEW_PRIVS`, zero capabilities, rlimits, an irreversible Landlock ABI >= 4
     filesystem allowlist and TCP deny, and then a seccomp-BPF policy that denies socket
     creation/use for every family, `io_uring`, namespace/mount changes, ptrace/pidfd and
     process-signalling paths. The supervisor also creates a per-attempt cgroup v2 subtree,
     writes `pids.max`, `memory.max` and `memory.oom.group`, and moves the worker into it
     before it executes. `cgroup.kill` and `cgroup.events` are the termination and
     emptiness facts.
6. The worker verifies the binding, manifest, definitions and asset bytes again, measures
   its own runtime, runs inside-worker read/write/delete/network/descriptor/package-model
   probes, compiles the view XML with the pinned MuJoCo release, runs the existing
   2,000-step reference, and writes a bounded consumption receipt.
7. The supervisor correlates the receipt with its fresh nonce, binding, request, preflight,
   manifest, environment, worker selection, runtime and profile; re-verifies the input view
   and runtime after exit; first proves each active localhost TCP/UDP/Unix canary receives a
   supervisor control connection/datagram and then requires zero worker traffic; reads
   `/proc/<pid>/status`, `/proc/<pid>/cgroup` and `/proc/<pid>/fd` on Linux; checks cgroup
   `pids.peak`/`pids.events`/`cgroup.events`; compares the receipt trajectory with the
   separately qualified `mujoco_qualification` reference digest; and writes a supervisor
   observation to `evidence/res555-gate-b2/<platform>.json`. The exact-head CI observations
   are committed under `evidence/RES-555/gate-b2/observations/`.

Only the positive materialized test names an evidence file. Every negative and verify-only
test passes no evidence name, so it cannot overwrite the acceptance observation; the positive
test reads its own file back and requires a demonstrated materialized observation.

The simulator-free JSON fixture runs the same bootstrap in `verify-only` mode and proves that
the launch, closure, view and denial mechanisms are engine-independent. It is not a second
solver adapter.

## Host provisioning

Linux needs a delegated cgroup v2 root with the supervisor running in a child of it, and
(for a real aggregate scratch bound) a dedicated mount. The hosted CI provisions both and
runs the tests through `exec_in_cgroup.sh`. That wrapper is **test-host provisioning**, not
the production mechanism: it uses the runner's passwordless sudo once to move the test shell
into the supervisor cgroup and then keeps the original user and environment. A production
supervisor must receive the same delegation from its service manager (`Delegate=yes`) and a
provisioned scratch mount. The cgroup delegation is a hard requirement and its absence is a
failure; without the scratch mount the probe records the sampled-watchdog fallback, which is
truthful but **not production-eligible** for an aggregate-bound claim.

Run locally:

```bash
cd python
uv sync --frozen --project worker-mujoco
DYNAMISBENCH_RES555_B2_PROBE=1 \
DYNAMISBENCH_RES555_B2_EVIDENCE_DIR=evidence/res555-gate-b2 \
DYNAMISBENCH_MUJOCO_PYTHON="$PWD/worker-mujoco/.venv/bin/python" \
DYNAMISBENCH_CGROUP_ROOT=/sys/fs/cgroup/dynamisbench \
DYNAMISBENCH_RES555_B2_SCRATCH_ROOT=/mnt/res555-scratch \
  bash tools/res555_gate_b2/exec_in_cgroup.sh uv run --frozen pytest -q \
    tests/execution/mujoco/test_b2_protected_consumption.py \
    tests/execution/mujoco/test_b2_protected_verify_only.py \
    tests/execution/test_b2_linux_containment.py \
    tests/execution/test_b2_seccomp_policy.py \
    tests/execution/test_b2_scratch_budget.py
```

A host without the required mechanism skips only when `DYNAMISBENCH_REQUIRE_MUJOCO` is unset;
CI sets it and treats an unavailable mechanism as a failure. There is no A1 fallback.

## What is not claimed

- No production launch, no native capture, no canonicalization, no assessment, no seal.
- **Linux process containment is cgroup v2 only.** A host that cannot delegate a writable
  leaf cgroup is refused; the session/process-group primitive is not accepted as a fallback.
  `pids.max` counts tasks, including threads; 64 is qualified against the real
  NumPy/OpenBLAS/MuJoCo worker and recorded as `pids.peak`. The supervisor must run in a
  child of the delegated root; the root itself stays empty.
- **Linux scratch prevention depends on host provisioning.** A dedicated tmpfs/volume whose
  total capacity is at most 64 MiB is a real aggregate bound and an over-budget write fails
  while the worker runs. Without one, the probe uses a sampled watchdog: it reacts after a
  sampling interval and a fast writer can exceed the bound before the next sample. The
  post-exit acceptance check is never described as prevention. `RLIMIT_FSIZE` is a per-file
  limit, not an aggregate one.
- **Windows scratch is a sampled watchdog, not a hard quota.** A host-provisioned dedicated
  volume root is accepted when present; the standard desktop host has none. The watchdog
  counts alternate data streams and requires pre-launch free-space headroom, but a fast
  writer can still exceed the bound before the next sample. Job Object memory limits are
  memory limits, not disk limits. The final post-exit measurement is fail-closed.
- **Windows network is restricted, not universal no-socket or no-UDP.** The probe measured
  one outbound path per family to a supervisor localhost canary, after proving the canary
  could receive control traffic: the TCP connect did not complete, one UDP `sendto` returned
  success but zero datagrams arrived, raw send was denied, and AF_UNIX was unavailable in
  that interpreter. `socketpair` remains available as local in-process IPC. This is a
  delivery observation for the measured paths, not a proof that every destination or every
  socket family is denied; the profile says `restricted`, not `denied`.
- **Linux network is denied through two controls, not one.** Landlock ABI 4 denies TCP
  bind/connect; seccomp denies the socket families and data paths Landlock does not cover,
  plus `io_uring`, so no IP, raw or Unix-domain socket communication remains. The kernel
  facts are read from `/proc` by the supervisor; the worker receipt is only corroboration.
- **Same-user external modification is not universally prevented.** On Linux the worker runs
  as the same UID; a process outside the sandbox can still write a runtime or input file
  between measurements, including between the worker's own source measurement and the
  import/execution of those bytes. The supervisor re-measures before process creation and
  after exit, and the worker measures again at start, but that is detection, not an immutable
  store. On Windows the attempt DACL stops the worker token from rewriting and the AC
  folder from package-SID writes, but a same-user owner can change the DACL and rewrite;
  deletion is also possible. Both are detected by the post-exit closure, not prevented. A
  read-only volume or a different principal remains the stronger production answer.
- **The headless worker disables the GL backend.** `MUJOCO_GL=disable` is set in the
  sanitized bootstrap environment before any scientific import, so MuJoCo does not import
  PyGLFW and does not spawn its version-check helper. This removes the previous
  `pyvenv.cfg` denial and keeps the worker a single Python process. The supervisor records a
  `headless_gl` check and refuses a demonstrated attempt if the helper signature reappears.
  Physics is unchanged; the 2,000-step trajectory is identical.
- **Runtime provenance is measured bytes, not a vendor signature.** The dependency closure
  and interpreter are hashed; the wheel/builder identity is not authenticated.
- **Adapter identity changed.** `physics.compile_model()` is part of
  `ADAPTER_SOURCE_FILES`, so the MuJoCo adapter implementation digest differs from the
  pre-B2 acceptance. The probe recomputes the digest from the sandbox source and refuses a
  mismatch; this packet does not re-accept the new digest.
- **The worker receipt is untrusted.** It is a bounded self-report; the supervisor authors
  the correlation and the external observations. It is not signed and not native evidence.
- No vendor-authenticated wheels or interpreter binary.
- On an elevated CI runner the AppContainer token reports `elevated=true` and a high
  integrity level; the probe records both and also enumerates `TokenCapabilities` and
  privileges. The demonstrated check requires the expected package SID and **zero
  capabilities**. It does not claim that elevation or every privilege is absent, and the
  elevated CI principal is not the production principal: a production adoption must run the
  supervisor non-elevated or explicitly accept that residual. A non-elevated local run
  records `elevated=false` and the same package-SID denials.
- On Windows the AppContainer's inherited environment is sanitized by the measured bootstrap
  because `CreateProcessW` in an AppContainer rejected explicit environment blocks on the
  qualified host. `-I` ignores Python environment overrides and the AppContainer denies the
  inherited paths; the production contract still needs a rebuilt environment and must be
  re-qualified if that differs.
- The `sandbox-ready.json` payload is written by the worker-side bootstrap. It is a
  synchronization and configuration echo, not independent proof: the supervisor checks it
  against its own profile/runtime digests, but the isolation claim rests on the external
  AppContainer token, `/proc` facts and the in-worker denial probes.
- The probe does not authorize any decision in the authority packet. It provides evidence
  for the owner's review.
