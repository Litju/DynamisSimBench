# RES-555 — smallest production increment: protected pinned-reference execution

Status: **DESIGN ONLY. NOT AUTHORIZED. NO PRODUCTION ROUTE IS ACTIVATED.** This document
identifies the smallest next increment that could connect the B2 bootstrap to
`execute_preflighted`. It does not edit an accepted ADR, does not add a production gate, and
does not authorize native output, canonicalization, assessment or sealing.

## 1. Existing production boundary

`execute_preflighted` in `python/src/dynamisbench/execution/supervisor.py` currently:

- re-derives admission immediately before staging and launch;
- launches the selected diagnostic worker from `WorkerEnvironmentManifest.command`;
- delivers one protocol-v1 request on stdin and reads one bounded response;
- enforces one deadline, cancellation, bounded stdout/stderr, process-tree cleanup and
  reaping;
- writes only `diagnostics.json` and `logs/worker.stderr.txt`;
- returns a `SupervisedExecution` whose `finalize()` verifies the persisted diagnostic and
  derives the only admissible seal outcome.

It does **not** create a per-run input view, build a `WorkerInputBinding`, measure or
snapshot a runtime closure, apply AppContainer/Landlock/seccomp/cgroup, or consume a
supervision-correlated receipt. `physics.load_model()` still reads the packaged XML. There is
no production caller of `prepare_execution_inputs`.

## 2. The one route worth building

The increment is a **trusted, pinned-reference execution profile**, not a general
arbitrary-model loader:

| Element | Pinned value |
|---|---|
| Adapter | `dynamisbench.mujoco.reference`, adapter version `0.1.0` |
| Engine | MuJoCo `3.17.0`, Python `3.12.13`, qualified Windows x86-64 / Linux x86-64 |
| Model | logical path `models/reference/pendulum.xml`, SHA-256 `eac679a723ccfebb48ea5ee40692fa6ee38f965772b484b94b827be6b9dbfdfd` |
| Benchmark / scenario / realization | `db.reference.pendulum` / `sc.reference.pendulum` / `rl.mujoco.reference-pendulum`, versions `1.0.0` |
| SUT | `sut.reference.pendulum` `1.0.0`, IN_PROCESS, forward-dynamics only |
| Run | seed `0`, outcome `reference-state`, 2.0 s, 1 ms timestep, exactly 2,000 steps |
| Physics | one body, one hinge, no contacts, no actuators, RK4/Newton, tolerance `1e-12` |
| Inputs | exactly the five resolved definitions plus the one declared asset, in a verified read-only view |
| Protocol | WorkerRequest/WorkerResponse v1 unchanged |
| Reference | committed `evidence/RES-555/gate-b2/reference-observation.json`; trajectory `f585292dae08650de7980e5ff00256e1ca9a80bd28474f9357df9f6daf3278bf` |

Any request that differs in adapter, implementation digest, model digest, scenario,
environment identity, seed, outcome, step count, timestep or duration is refused. A
different scientific model is a new authority decision and a new adapter identity, not a
parameter to this route.

## 3. Implementation shape (smallest honest change)

1. **Profile value.** Add a frozen `ProtectedExecutionProfile` (schema/version, pinned
   constants above, platform mechanism, scratch/network/process bounds, receipt schema,
   profile digest). It is selected by trusted operational configuration, never by the
   RunSpec or a request field. Constructing it is an explicit activation gate.
2. **Admission binding.** After the existing `execute_preflighted` revalidation, call
   `prepare_execution_inputs` for the already-admitted definitions; build the existing
   `WorkerInputBinding` with a fresh nonce, the measured runtime-snapshot digest and the
   profile digest; create the per-run `inputs/` view from the A1 materialized objects; verify
   it with `verify_worker_input_view` before and after launch.
3. **Runtime snapshot.** Reuse the probe's `prepare_runtime` measurement semantics: copy the
   selected interpreter/base/site-packages/adapter source into a per-attempt snapshot, remove
   the packaged XML from that snapshot, and re-measure. The expected digest is a measurement,
   never caller-supplied proof.
4. **Launch.** Reuse the existing supervisor's bounded writer/readers, deadline,
   cancellation, reaping and staging lifecycle, but launch the fixed bootstrap under the
   platform sandbox:
   - Windows: per-attempt AppContainer, Job Object, stdio-only handle list, explicit DACLs;
   - Linux: Landlock ABI >= 4, seccomp, delegated cgroup v2, rlimits, dedicated scratch or an
     explicit refusal when the host cannot provide the adopted profile.
   No unavailable mechanism is replaced by the current process-tree launch.
5. **Consumption.** The worker verifies the view, compiles the view bytes with
   `physics.compile_model`, runs the pinned 2,000-step reference, and writes the bounded
   receipt. The supervisor compares nonce, binding, request, preflight, manifest,
   environment, worker-selection, adapter, runtime, profile, run id, completion/failure and
   trajectory with its own observations; it re-verifies the view and runtime after exit and
   checks the network canaries, scratch, token/`proc`/cgroup facts and single-use marker.
6. **Persisted evidence.** On success, persist the supervisor-authored correlated receipt in
   staging (a versioned `protected-consumption.json` or the owner-approved D4 name), then
   `diagnostics.json`. On any refusal, cancellation, timeout, scratch overrun, receipt
   mismatch, input/runtime change or cleanup failure, write a complete FAILED/REFUSED
   diagnostic and do not report success. No native/ directory is produced.
7. **Activation.** The route remains unreachable from the API/CLI/UI and defaults off. It is
   enabled only by an explicit owner-adopted profile plus a feature gate; the existing
   diagnostic path remains the default.

## 4. Guarantees that must survive

- **Refusal:** a missing mechanism, mismatched binding, changed input, changed runtime,
  replayed nonce, wrong adapter/model/scenario/steps, missing receipt, receipt mismatch,
  scratch/headroom failure or sandbox setup failure is a refusal before physics or a failed
  terminal observation, never a fallback to `execute_preflighted`'s current launch.
- **Cancellation/timeout:** the existing single cancellation path must terminate the
  sandbox-owned tree (Job Object on Windows; the delegated cgroup on Linux), verify it empty,
  reap the direct child, and return CANCELED/TIMED_OUT; no success seal is possible.
- **Resource bounds:** the adopted memory, CPU, wall, stdout/stderr, process/task, scratch,
  canary and no-network limits apply to the protected launch; a host that cannot enforce a
  claimed bound is refused, not silently downgraded.
- **Consumption evidence:** the receipt is worker-authored and untrusted; only the
  supervisor's correlation and external observations make it admissible. Its nonce is
  single-use and fsynced before process creation; a consumed binding is never reusable.
- **Protocol:** no field is added to WorkerRequest/WorkerResponse; the receipt is a sidecar
  whose schema requires owner adoption. ADR-027 native output remains separate.

## 5. Tests required before activation

- pinned profile accepts exactly the reference request and refuses a different adapter,
  model digest, scenario, environment, seed, steps, duration or implementation digest;
- missing/extra/changed/truncated input view, symlink/hardlink/reparse or alternate-stream
  substitution, and a changed model after the pre-launch check;
- runtime substitution between supervisor measurement and worker import, late hardlink, and
  packaged-XML reintroduction;
- replayed binding, nonce reuse, stale request/preflight/manifest/environment/selection;
- unavailable AppContainer/Landlock/seccomp/cgroup/scratch: refusal, no process;
- cancellation and timeout at each lifecycle transition, descendant `setsid`/orphan cleanup,
  repeated launches, scratch overrun, canary traffic, token capability failure;
- receipt nonce/binding/request/preflight/manifest/fingerprint/runtime/profile/adapter/
  trajectory mismatch, incomplete record, missing receipt, non-canonical receipt;
- a completed reference run writes the pinned trajectory and does not write native/canonical/
  assessment; protocol-v1 regression tests remain green;
- full exact-head Windows/Linux CI, B2 comparison and MuJoCo receipt comparison, plus an
  independent security/runtime/scientific review of the exact head.

## 6. Explicit non-goals

No general arbitrary-model execution, no RunSpec schema change, no new worker protocol, no
native extraction, no canonicalization, no assessment, no seal of native output, no UI
activation, and no weakening of the existing eight ADR-025 gates. ADR-027 remains proposed and
separate.

## 7. Owner decisions needed to activate

1. Adopt the pinned-reference execution profile above (or replace it and require
   re-qualification).
2. Adopt D3 (per-platform mechanism, principal, allowlists and residual model) and D4
   (binding/receipt sidecar, protocol v1 preserved), including the exact persisted receipt
   name.
3. Accept measured-snapshot runtime semantics and name the artifact-trust and same-user
   mutation residuals.
4. Re-accept the MuJoCo adapter implementation digest produced by `physics.compile_model()`.
5. Require delegated cgroup v2 and a dedicated scratch filesystem (or a non-elevated
   AppContainer profile) for production; the CI sampled-watchdog result is mechanism
   evidence, not a production quota.
6. Obtain the independent security/runtime/scientific review of the exact head.

Until each is recorded, only the probe-only qualification described in
`python/tools/res555_gate_b2/README.md` is executable.
