# RES-555 Gate B2 — Authority Decision Packet (proposal, not acceptance)

Status: **PROPOSED FOR OWNER ADOPTION. NOT ACCEPTED AUTHORITY. NOT A PRODUCTION ACTIVATION.**
This packet records the minimum decisions that must exist before a materialized model may be
executed by a production worker. It does not edit an accepted ADR, does not change the worker
protocol, and does not enable native extraction or sealing. RES-555 remains In Review.
ADR-027 remains proposed and separate.

The executable qualification in `python/tools/res555_gate_b2/` is deliberately probe-only. It
runs behind `DYNAMISBENCH_RES555_B2_PROBE=1` and is not reachable from the supervisor, API,
CLI, or any production route. Its purpose is to demonstrate or refute the mechanisms below so
the owner can decide with evidence rather than a design document.

## 0. The pinned-reference execution profile (the only proposed route)

This packet does **not** propose general arbitrary-model execution. The only route it makes
eligible for a later owner decision is the existing pinned MuJoCo reference case:

| Element | Pinned value |
|---|---|
| Adapter | `dynamisbench.mujoco.reference` `0.1.0`; `physics.compile_model()` is part of the implementation identity |
| Engine / interpreter | MuJoCo `3.17.0`; CPython `3.12.13`; qualified Windows x86-64 and Linux x86-64 |
| Model | `models/reference/pendulum.xml`; SHA-256 `eac679a723ccfebb48ea5ee40692fa6ee38f965772b484b94b827be6b9dbfdfd` |
| Definitions | `db.reference.pendulum` / `sc.reference.pendulum` / `rl.mujoco.reference-pendulum` / `sut.reference.pendulum`, all `1.0.0`, IN_PROCESS |
| Run | seed `0`, outcome `reference-state`, 2.0 s, 0.001 s timestep, exactly 2,000 steps |
| Physics | one body, one frictionless hinge, no contacts, no actuators, RK4 / Newton, tolerance `1e-12` |
| Inputs | exactly the five resolved definitions plus the one declared realization asset in a verified read-only view |
| Protocol | WorkerRequest/WorkerResponse v1 exactly; no new wire field |
| Reference trajectory | `f585292dae08650de7980e5ff00256e1ca9a80bd28474f9357df9f6daf3278bf` |

Any request that differs in adapter, implementation digest, model digest, scenario,
environment identity, seed, outcome, step count, timestep or duration is refused. A new model
or adapter is a new authority decision and a new implementation identity, never a parameter
to this route. Native output, canonicalization, assessment and sealing remain outside it.

## 1. Baseline and exact heads

- Protected main at the start of this increment: `16adf8a` (RES-742 Gate 3 merged).
- A1 stack: PR #31 `bfd5e6a` → PR #32 `e705841` → PR #34 `5860904`.
- B2 historical feature head: `47ca8d3` (PR #35).
- Pre-hardening qualified integration head: `911d2e6` (`res-555-b2-main-qualification`),
  workflow_dispatch `45270650148`: 10/10 jobs.
- Prior hardening code head: `cc72f91`; hosted `45431738452` attempt 3: 10/10 jobs, Linux
  full suite 2,872 passed / 17 skipped, 24 B2 tests, Windows full suite and B2 step, both
  comparison jobs. The committed observations on that head are
  `evidence/RES-555/gate-b2/observations/`.
- This increment's exact head and hosted result are recorded in
  `evidence/RES-555/gate-b2/observations/` and in the PR #35 body after the exact-head run.
  A result on an earlier head is not a qualification of a later head.
- Accepted: ADR-026 (InputManifest v1, disposable CACHE, admission binding, self-contained
  inputs) and ADR-028. Proposed: ADR-027. ADR-028 does not accept ADR-027 by numbering.
- Existing production boundary: `execute_preflighted` launches the selected diagnostic worker
  with protocol v1 and writes only `diagnostics.json` / `logs/`. `physics.load_model()` still
  reads the packaged XML. `PrepareExecutionInputs` has no production execution caller.
- Adapter identity change: the probe needs the `physics.compile_model()` entry point to
  compile verified input bytes. `physics.py` is part of `ADAPTER_SOURCE_FILES`, so the adapter
  implementation digest changes. No existing acceptance is silently re-used: the owner must
  re-accept the adapter identity (and therefore its implementation digest) before any
  production materialized route. `load_model()` and the packaged path are unchanged.
- Existing A1 boundary: `WorkerInputBinding`, `verify_worker_input_view`, anchored Windows and
  Linux readers. A1 proves sequential content identity on mutable storage; it is not OS
  immutability or read containment.

## 2. Observed engineering results

These are observations from the probe on the named hosts. A result on one host is not a
cross-platform result; the matrix in §5 names the unverified assumptions.

### 2.1 Windows x86-64

- **Mechanism:** per-attempt AppContainer profile, suspended `CreateProcessW` with
  `SECURITY_CAPABILITIES`, Job Object with `ActiveProcessLimit=8`, `KILL_ON_JOB_CLOSE`,
  process/job memory limits, and an explicit `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` containing
  only the three stdio pipe ends.
- **Token:** the supervisor reads the worker token from outside. The demonstrated check
  requires the expected package SID and zero `TokenCapabilities`; the observation also records
  `TokenPrivileges`, integrity level, elevation and elevation type. On the hosted elevated CI
  runner the worker token reports `elevated=true` but integrity `S-1-16-4096` (low), zero
  capabilities, and two privileges (`SeChangeNotifyPrivilege` enabled,
  `SeIncreaseWorkingSetPrivilege` disabled). That is recorded as a host fact, not used as an
  isolation grant; production must run non-elevated or explicitly accept the residual.
  `TokenIsRestricted` is not used as the AppContainer claim.
- **Network:** after proving each active localhost canary received a supervisor control
  connection/datagram, the worker's measured paths produced: TCP connect did not complete and
  zero connections arrived; one 10-byte UDP `sendto` returned success but zero datagrams
  arrived; raw send was denied; AF_UNIX was unavailable in that interpreter. `socketpair`
  remains local IPC. The profile therefore declares `network_access: restricted`, not a
  universal no-socket or no-UDP denial. The comparison requires zero worker canary traffic and
  a successful canary control on both platforms.
- **Handles:** a deliberately inheritable non-stdio file handle is not inherited; the handle
  list is the mechanism.
- **Process tree:** a descendant that outlives its direct parent remains in the Job Object and
  is terminated by `TerminateJobObject`; cancellation leaves zero active processes; repeated
  launches leave none.
- **DACLs:** during an attempt the runtime, input and attempt trees grant the worker `RX` and
  the interactive user `RX,DE,DC`; the profile's AC folder is reduced from package-SID full
  control to `RX`. A worker writing `..\` outside the measured scratch is refused. The
  **worker token** cannot rewrite the measured bytes. The interactive user owns the tree and
  can change its DACL, so this is not a same-user immutability barrier; the pre/post closures
  and the user's post-attempt restore are detection and staging, not prevention. Deletion is
  a denial-of-service residual and is detected post-exit.
- **Scratch:** the standard desktop host has no dedicated volume. The probe uses a sampled
  supervisor watchdog (20 ms) plus a pre-launch free-space headroom check and a post-exit
  exact measurement. The measurement enumerates NTFS alternate data streams, so a large ADS
  cannot hide behind a small default stream. The watchdog treats a transient unmeasurable
  entry (an atomic rename or scanner lock) as a sampling miss, not as a link;
  actual links, reparse points, hard links and special files still trigger, and the post-exit
  check is fail-closed. A fast writer can still exceed the bound before the next sample. This
  is not a hard quota.
- **Runtime:** the probe re-measures the installed interpreter, base installation,
  site-packages, native extension files and adapter source before launch and after exit; the
  worker re-measures the snapshot. The dependency closure must equal the locked worker
  environment; a mismatch is a refusal before physics.
- **Headless:** `MUJOCO_GL=disable` is set in the sanitized bootstrap before any scientific
  import. MuJoCo therefore does not import PyGLFW and spawn its version-check helper. The
  supervisor records a `headless_gl` check; the 2,000-step trajectory is unchanged.
- **Scientific:** the real pinned MuJoCo 3.17.0 run executes exactly 2,000 steps and its
  trajectory SHA-256 equals the existing qualified reference digest. The model bytes come
  from the verified input view and the packaged XML is absent.

### 2.2 Linux x86-64

- **Mechanism:** Landlock ABI >= 4 filesystem allowlist and TCP deny, `PR_SET_NO_NEW_PRIVS`,
  zero effective capabilities, rlimits, seccomp-BPF, and a supervisor-owned cgroup v2 subtree
  with `pids.max`, `memory.max`, `memory.swap.max=0`, `memory.oom.group=1` and `cgroup.kill`.
- **Placement:** the supervisor must run in a child of the delegated root; the root stays
  empty so its controllers can be enabled. A writable leaf root with the supervisor outside
  it, or no root at all, is a refusal; the session/process-group primitive is not used as a
  fallback.
- **Process tree:** a forked child that calls `setsid()` remains in the attempt cgroup; a
  child that outlives its direct parent remains and is killed; cancellation and timeout use
  the same `cgroup.kill`; repeated launches leave no attempt subtrees; failed setup removes
  its partial subtree.
- **Task bound:** `pids.max` counts tasks, including threads. With `pids.max=4`, a 12-thread
  probe is partly refused and `pids.events.max` increments. With `pids.max=64`, the real
  NumPy/MuJoCo import fits and `pids.peak <= 64`; the materialized run records its actual
  peak. A process that calls `setsid()` is still owned by the cgroup.
- **Seccomp:** the policy denies socket creation and use for every family, including UDP, raw
  and Unix-domain sockets, plus `socketpair`, `io_uring`, namespace/mount changes,
  ptrace/process-vm/pidfd and process-signalling paths. The supervisor reads `Seccomp: 2`, at
  least one filter, `NoNewPrivs: 1`, zero effective capabilities, the worker's cgroup path and
  a descriptor table with no socket descriptors from `/proc`. `clone3` is refused with
  `ENOSYS` so glibc falls back to `clone(2)`, whose namespace flags the filter can inspect;
  ordinary `fork` and threads remain available to the cgroup.
- **Scratch:** on a host that provisions a dedicated 64 MiB tmpfs scratch root, an
  over-capacity write fails while the worker is alive (ENOSPC); the probe declares
  `dedicated-filesystem`. Without one, it uses the sampled watchdog and says so. The
  post-exit acceptance check is separate and is never called prevention.
- **Headless:** the prior `pyvenv.cfg` stderr from MuJoCo's GLFW helper is removed by
  `MUJOCO_GL=disable`; the worker spawns no helper and the cgroup records only its own tasks.
- **Local diagnostic limit:** the WSL development kernel exposes Landlock ABI 3. The full
  Linux materialized/verify-only B2 integration can be exercised there for mechanism
  debugging only, but the authority profile requires ABI >= 4 and the qualifying Linux result
  is the hosted `ubuntu-24.04` job. A local ABI 3 run is not a qualification of this profile.

### 2.3 Cross-platform

- The Windows and Linux observations are compared by `tools.res555_gate_b2.compare`, which
  requires the same model SHA-256, the same 2,000-step trajectory, the qualified reference
  match, the platform mechanisms, the cgroup/seccomp checks, a successful canary control and
  zero worker TCP/UDP/Unix canary traffic. It does not require equal ExecutionFingerprints or
  InputManifestDigests: those include platform-specific environment definitions and are
  expected to differ.
- The comparison job is additional RES-555 evidence, not one of the eight ADR-025 gates.

### 2.4 Hosted exact-head evidence

Hosted `workflow_dispatch` run `45680046080` on code head `9206648` completed all 10 jobs
successfully, including both `python` jobs, `res555-gate-b2-comparison` and
`mujoco-receipt-comparison`.

- **Windows:** the observation is `demonstrated` with 51/51 checks. The AppContainer token has
  the expected package SID, zero capabilities, low integrity `S-1-16-4096`, and two recorded
  privileges. The canary control received TCP, UDP and Unix control traffic and the worker
  delivered zero canary traffic; UDP `sendto` was recorded as allowed with zero delivery.
  Scratch used the sampled watchdog with 28,670,119,936 bytes free (headroom 134,217,728),
  9,794 bytes used and zero unmeasured entries; the watchdog took 430 samples. Stderr was
  empty (`headless_gl` passed). The model SHA-256 and 2,000-step trajectory match the
  committed reference.
- **Linux:** the observation is `demonstrated` with 57/57 checks. Landlock ABI 8, seccomp
  filter mode 2, `NoNewPrivs=1`, zero effective capabilities, delegated cgroup
  `pids.max=64`, `pids.peak=4`, zero `pids.events.max`, empty subtree, dedicated 64 MiB tmpfs
  with 67,072,000 bytes available, zero canary traffic after successful controls, empty
  stderr (`headless_gl` passed), and the same model/trajectory. The receipt's run id,
  preflight, environment, worker-selection, adapter, runtime, profile and reference trajectory
  all correlate with the supervisor's observation.
- **Comparison:** `res555-gate-b2-comparison` passed with the same model and trajectory
  digests. `mujoco-receipt-comparison` passed unchanged.

This run qualifies code head `9206648`. The final code head `ae4957f` adds only the
probe-presence strictness and the fsynced single-use marker; its exact-head run is recorded
in the PR and in the committed observation set. A green run on an earlier head is not a
qualification of a later head.

## 3. Decisions requested

### D3 — OS enforcement (hard)

Adopt a per-platform, fail-closed profile. A Windows Job Object alone is not a filesystem
sandbox; re-running A1 hashes is not A2 isolation. If the named mechanism is unavailable,
admission refuses and no weaker fallback is attempted.

| Platform | Mechanism | Worker principal | Input | Runtime | Scratch | Scientific sources / staging / sealed | Network |
|---|---|---|---|---|---|---|---|
| Windows x86-64 | AppContainer profile per attempt (`CreateAppContainerProfile` + `SECURITY_CAPABILITIES`), Job Object with `ActiveProcessLimit=8`, stdio-only handle list, explicit DACLs | AppContainer package SID / lowbox token; zero package capabilities; elevation/privileges recorded, not claimed absent | read-only | read/execute-only | read/write | denied by the intersection of the normal and restricted checks (package SID); no capability | restricted: measured TCP/UDP/raw/AF_UNIX paths did not deliver to canaries; `socketpair` local IPC remains; not a universal no-UDP claim |
| Linux x86-64 | Landlock ABI ≥ 4 + seccomp-BPF + supervisor-owned cgroup v2 subtree + `PR_SET_NO_NEW_PRIVS`, zero capabilities, rlimits | same UID in an irreversible Landlock/seccomp domain, in a supervisor cgroup | read-only | read/execute-only | read/write | denied by Landlock allowlist | denied through Landlock TCP deny **and** seccomp socket/`io_uring` policy; stdio pipes remain |

Residual threat model, stated so it is not mistaken for a stronger claim:

- **Same-user modification and TOCTOU.** On Linux the worker is the same UID; a process
  outside the sandbox can modify a runtime or input file between measurements, including
  between the worker's own source measurement and the import/execution of those bytes. The
  exact unmeasured windows are pre-measure → launch, launch → worker measure/import, worker
  measure → import, and exit → post-measure. The supervisor measures before process creation
  and after exit, the worker measures again at start, and a mismatch is refused, but that is
  detection, not an immutable store. On Windows the attempt DACL stops the worker token from
  rewriting; a same-user owner can change the DACL and rewrite, and deletion is possible. Both
  are detected post-exit, not prevented. A read-only volume, a different principal or an
  immutable artifact store remains the stronger production answer.
- **Elevated Windows supervisor.** The qualified CI observation ran elevated and recorded a
  high-integrity AppContainer token. The lowbox/package-SID check and zero capabilities are
  the isolation facts; the probe does not claim that elevation or every privilege is absent.
  Production adoption requires a non-elevated supervisor or an explicit owner acceptance of
  this residual, and a re-qualification if the principal changes.
- **Runtime authenticity.** File hashes identify bytes, not a vendor signature. The file-level
  closure does not prove the wheel was published by an approved builder; the lockfile and
  distribution provenance are inputs to, not a substitute for, an artifact-trust decision.
- **The trajectory is worker-authored.** The supervisor compares the receipt's 2,000-step
  trajectory digest with the committed reference, but it does not independently re-execute
  the physics in the supervisor process. The admission argument is that the measured sandbox
  source is the pinned adapter; a worker that fabricates the expected digest, or a same-user
  writer that substitutes the adapter inside a mutation window, is not detected by digest
  comparison alone. The production increment must treat the pinned adapter as trusted code
  and must not claim an independent scientific oracle.
- **Landlock has no externally readable marker.** The supervisor verifies `/proc` `Seccomp`,
  `NoNewPrivs`, capabilities and cgroup membership, and the in-worker probes; a substituted
  bootstrap could decline to apply Landlock. The supervisor measures and hashes the bootstrap
  and the whole runtime, denies the worker write access to the runtime, and refuses a closure
  mismatch. The worker-written `sandbox-ready.json` is a configuration echo, not independent
  proof.
- **Process containment requires host delegation.** A Linux host without a writable delegated
  cgroup v2 root and a supervisor child is refused; the probe does not inherit
  `max_processes: null`. `pids.max` counts tasks/threads; 64 is a qualified bound, not a
  universal one. Windows `ActiveProcessLimit` counts processes, not threads.
- **Scratch.** A dedicated filesystem whose capacity is at most 64 MiB is a real aggregate
  bound; it is host-provisioned. The sampled watchdog is not a hard quota. The post-exit
  measurement is an acceptance check only. `RLIMIT_FSIZE` is per-file, not aggregate. On
  Windows the measurement includes NTFS alternate data streams and requires pre-launch
  free-space headroom, but a fast writer can still overshoot between samples.
- **Network.** Linux denies the socket families through two independent controls. Windows
  AppContainer drops the measured outbound paths and leaves `socketpair` as local IPC; the
  probe does not claim universal no-socket or no-UDP isolation. A different destination,
  family, inherited handle or host firewall policy is not covered by the canary evidence.
- **Kernel exploit surface.** Neither mechanism makes the process kernel-exploit-proof, and
  neither authenticates the host kernel.

### D4 — Request/receipt binding (hard)

Preserve WorkerRequest/WorkerResponse v1 exactly. Do **not** add an input path, manifest,
nonce, or receipt field to the wire protocol. The probe route instead uses:

1. The trusted supervisor builds `WorkerInputBinding` (already present in A1) with a fresh
   `launch_nonce`, the measured runtime-closure digest, and the isolation-profile digest.
2. The supervisor writes the exact admitted manifest, definitions and asset bytes into a
   per-attempt `inputs/` view. The worker reads that fixed relative view; it receives no
   caller-supplied path.
3. The worker reads the binding from the verified view, checks its `request_sha256` against
   the canonical v1 request on stdin, re-verifies the manifest/definitions/assets, and echoes
   the nonce only in a bounded sidecar receipt in its writable scratch.
4. The supervisor refuses a reused binding or nonce before process creation (single-use
   marker, fsynced before launch), and refuses a receipt whose run id, completion/failure,
   nonce, binding, request, preflight, manifest, environment, worker selection, fingerprint,
   runtime closure, profile, adapter digest or trajectory does not match its own trusted
   observation.
5. A production adoption would version this sidecar as
   `dynamisbench.consumption-receipt/1` and name it in ADR-027. That version is **not**
   accepted by this packet.

The receipt remains a worker-authored, unauthenticated observation. The supervisor's
correlation and external canaries are the admissibility evidence; the receipt alone is not.

### Runtime closure (hard for the immutability claim)

The expected digest is not supplied as proof. The supervisor measures the installed
interpreter, base installation, site-packages, native extension files (MuJoCo, NumPy), and the
adapter source tree before launch. The snapshot the worker will execute is derived from those
measured bytes; the supervisor re-measures it immediately before launch and after exit. The
worker re-measures its own roots and the dependency closure and reports the result. The
supervisor compares all three and refuses any mismatch. The probe removes the packaged
reference XML from the worker's source snapshot and records that `reference.model_bytes()`
refuses inside the worker.

Residual: measured hashes are not vendor signatures; the same-user mutation windows in D3
remain; the installed interpreter/dependency provenance is the lockfile plus measured
distribution closure, not an authenticated builder chain.

### Adapter implementation identity (hard)

`physics.compile_model()` is now part of the adapter source manifest. The probe reconstructs
the implementation digest from the sandbox source (using the verified input-view model digest
for the removed packaged XML) and refuses if it differs from the request's digest. The
existing packaged `load_model()` path and the qualified 2,000-step reference trajectory are
unchanged. The probe harness modules themselves (`_b2_probe_common`, `_b2_probe_worker`,
`_b2_landlock`, `_b2_seccomp`) are covered by the measured runtime source closure, not by the
adapter `ADAPTER_SOURCE_FILES` digest; that separation is explicit. The owner must explicitly
re-accept the new adapter implementation digest; this packet does not do so and does not alter
historical reference evidence.

## 4. Remaining review findings and dispositions

| Finding | Disposition in this increment | Residual |
|---|---|---|
| Windows UDP claim precision | Added supervisor canary positive controls; renamed the check to `network_udp_not_delivered`; the profile states one measured path, successful `sendto`, zero delivery and **not** a universal UDP denial | Other destinations/families and host firewall policy are not measured |
| Elevated AppContainer token privileges | Read `TokenCapabilities`, `TokenPrivileges`, integrity and elevation from outside; the demonstrated check requires the expected package SID and zero capabilities | Elevation is recorded, not removed; production must be non-elevated or owner-accepted |
| Same-user mutation / TOCTOU | Stated the exact unmeasured windows and that detection is not prevention; kept the substitution and late-hardlink refusals | A same-user writer or deletion can still win a window; a read-only volume/different principal is the production answer |
| Windows scratch exhaustion | Count NTFS alternate data streams, reject hard links/reparse points, require pre-launch free-space headroom, and keep the sampled watchdog truthful | The watchdog can still overshoot between samples; no hard per-directory Windows quota is claimed |
| Intermittent Windows worker exit | The live watchdog no longer treats a transient unmeasurable entry (atomic rename/scanner lock) as a link; the post-exit check remains fail-closed | A persistent unmeasurable entry is refused only at post-exit; the watchdog is best-effort |
| Linux GLFW helper failure | `MUJOCO_GL=disable` before any scientific import; the helper is not spawned; a `headless_gl` check refuses the old stderr signature | A different MuJoCo release or rendering path would need re-qualification |

These are engineering corrections supported by the probe tests. They are not a human review
and do not accept any decision.

## 5. Decision matrix

| Decision | Status | Proven control | Evidence | Unverified assumption / residual | Owner action |
|---|---|---|---|---|---|
| D1 (input materialization) | **Approved** 2026-10-31 | ADR-026 A1 | A1 stack, hosted run `45170458764` | — | None in this increment |
| D2 (materialization boundary) | **Approved** 2026-10-31 | ADR-026 | A1 stack | — | None in this increment |
| D9 (disposable cache) | **Approved** 2026-10-31 | ADR-026 | A1 stack | — | None in this increment |
| D3 Windows isolation | **Proposed** | AppContainer token with package SID and zero capabilities, Job Object, stdio handle list, DACLs, canary controls, sampled watchdog + ADS/headroom | B2 Windows observation; containment/scratch tests | No hard Windows scratch quota; same-user deletion/DACL rewrite; elevated CI principal; kernel exploits | Accept mechanism + residual, or replace and re-qualify |
| D3 Linux isolation | **Proposed** | cgroup v2 pids/kill, seccomp, Landlock ABI 4, rlimits, dedicated tmpfs scratch | B2 Linux observation; cgroup/seccomp/scratch tests | Production cgroup delegation; same-UID external writes; ABI 4 target; host-provisioned scratch | Accept mechanism + residual, or replace and re-qualify |
| D4 binding/receipt | **Proposed** | Single-use fsynced nonce, binding/view re-verification, supervisor correlation, canary controls | B2 observations; replay/mutation tests | Receipt authenticity; registry garbage collection; sidecar schema acceptance | Accept/version v1 sidecar or reject |
| Runtime closure | **Proposed** | Three-point closure, dependency closure, packaged-XML removal | B2 observations; substitution tests | No vendor signature; Linux same-UID mutation; Windows deletion | Accept measured-snapshot semantics and name artifact-trust gap |
| Adapter identity | **Proposed** | Recomputed digest from sandbox source | B2 observations; identity tests | New digest not yet re-accepted | Re-accept the MuJoCo adapter identity/digest |
| ADR-027 native evidence | **Outside this increment** | None | — | Native output contract, canonicalization, assessment, sealing | Adopt ADR-027 separately before native extraction |

No row marked **Proposed** is an approval. No owner adoption is recorded by this packet.

## 6. What the probe demonstrates, and what it does not

The probe is designed to demonstrate, on an exact commit and both qualified platforms:

- platform denial of input writes, staging/sealed/source reads, runtime writes and network,
  with the probes executed inside the launched worker and the external canaries read by the
  supervisor after a positive canary control;
- measured runtime identity at three independent points and refusal on substitution;
- exact materialized XML bytes handed to `mujoco.MjModel.from_xml_string`, with the packaged
  XML absent from the worker's importable package;
- the existing pinned 2,000-step reference integration and its trajectory, compared against
  the existing qualified observation without changing tolerances;
- refusal before the first physics step on stale/replayed bindings, binding/view mutation,
  runtime substitution, and unavailable isolation;
- Linux cgroup containment of `fork`/`setsid`/orphan descendants and a qualified task limit;
- Windows stdio-only handle inheritance and Job Object descendant cleanup;
- an over-budget scratch write either failing against a dedicated filesystem (Linux when
  provisioned) or being interrupted by a sampled watchdog (Windows/Linux without one; a fast
  writer can exceed the bound before the next sample, so this is not a hard quota);
- a headless worker that imports the pinned MuJoCo release without spawning the GLFW helper.

It does **not** demonstrate owner approval, a production launch route, native output capture,
sealing, canonicalization, assessment, cross-platform numerical equivalence, a universal hard
disk quota on every host, a Linux same-UID immutable store, Windows `socketpair` elimination,
universal Windows UDP denial, vendor-authenticated wheels, or kernel-exploit resistance. A
successful probe run is evidence for the exact tree, not acceptance of any decision above.

## 7. Owner action

The smallest explicit owner-adoption record that would unblock a production increment is:

> For the pinned-reference profile in §0 only, adopt D3 (the per-platform mechanisms,
> principals, allowlists and stated residuals, including the elevated Windows principal and
> the sampled-watchdog/ADS limitation) and D4 (the v1-preserving binding and
> supervisor-correlated receipt sidecar, with the persisted receipt name recorded). Accept the
> measured-snapshot runtime closure and name the artifact-trust and same-user mutation gaps.
> Re-accept the MuJoCo adapter implementation digest produced by `physics.compile_model()`.
> Require a delegated cgroup v2 root plus dedicated scratch on Linux and a non-elevated
> AppContainer principal on Windows for production. This adoption does not accept ADR-027,
> native output, sealing, canonicalization or assessment, and does not mark RES-555 Done.
> Independent human security/runtime/scientific review of the exact head remains a merge gate.

The detailed decision list is:

1. **D3:** accept the per-platform mechanisms, principal, allowlists and residual model above
   (or replace them and require re-qualification), including the explicit Windows elevation
   residual and the sampled-watchdog/ADS limitation.
2. **D4:** accept or version the receipt/binding contract, explicitly preserving protocol v1,
   and name the persisted receipt payload for a production route.
3. **Runtime closure:** accept measured-snapshot semantics and name the artifact-trust and
   same-user mutation gaps.
4. **Consumption receipt:** accept the sidecar schema and supervisor correlation as the only
   admissibility evidence, with the worker self-report treated as untrusted input.
5. **Adapter identity:** re-accept the MuJoCo adapter implementation digest produced by the
   added `physics.compile_model()` entry point.
6. **Process containment:** require a delegated cgroup v2 root and supervisor child on Linux,
   and a host-provisioned scratch filesystem if an aggregate disk bound is claimed; do not
   promote the sampled watchdog to a production quota.
7. **Independent review:** obtain and record the human security, runtime and
   scientific/architecture review of the exact head.
8. **ADR-027:** adopt the native-output/output-policy rows separately before any native
   extraction or seal. ADR-028 does not accept ADR-027 by numbering.

The smallest subsequent production increment is described in
`evidence/RES-555/gate-b2/production-increment.md`: connect the accepted protected bootstrap
to `execute_preflighted`, execute the verified materialized pendulum bytes through the real
supervisor, and preserve refusal, cancellation, resource and consumption-evidence guarantees.
It is **not authorized** by this packet and must not be activated before the owner records
these decisions.

Until then, the only executable increment is the probe-only qualification described in
`python/tools/res555_gate_b2/README.md`. No production route is enabled by this packet.
