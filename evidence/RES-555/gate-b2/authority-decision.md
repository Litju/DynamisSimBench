# RES-555 Gate B2 — Authority Decision Packet (proposal, not acceptance)

Status: **PROPOSED FOR OWNER ADOPTION. NOT ACCEPTED AUTHORITY. NOT A PRODUCTION ACTIVATION.**
This packet records the minimum decisions that must exist before a materialized model may be
executed by a production worker. It does not edit an accepted ADR, does not change the worker
protocol, and does not enable native extraction or sealing. RES-555 remains In Review.
ADR-027 remains proposed.

The executable qualification in `python/tools/res555_gate_b2/` is deliberately probe-only. It
runs behind `DYNAMISBENCH_RES555_B2_PROBE=1` and is not reachable from the supervisor, API,
CLI, or any production route. Its purpose is to demonstrate or refute the mechanisms below so
the owner can decide with evidence rather than a design document.

## 1. Baseline and exact heads

- Protected main at the time of this packet: `485171f` (RES-742 Gate 3 merged).
- B2 feature head: `47ca8d3` (`res-555-b2-protected-worker`, PR #35).
- Qualified integration head: `911d2e6` (`res-555-b2-main-qualification`), workflow_dispatch
  `45270650148`: all 10 jobs successful. That result qualifies `911d2e6` only; it is not a
  qualification of an unchanged old PR head.
- Hardening head: **PENDING** (this packet's branch head; the exact SHA and hosted run are
  recorded in the final report and must be read from the exact head, not from this paragraph).
- A1 stack: PR #31 `bfd5e6a` → PR #32 `e705841` → PR #34 `5860904`. A1 verification,
  materialization and the 2,000-step reference trajectory are unchanged by this increment.
- Accepted: ADR-026 (InputManifest v1, disposable CACHE, admission binding, self-contained
  inputs) and ADR-028. Proposed: ADR-027. ADR-028 does not accept ADR-027 by numbering.
- Existing production boundary: `execute_preflighted` launches the selected diagnostic worker
  with protocol v1 and writes only `diagnostics.json` / `logs/`. `physics.load_model()` still
  reads the packaged XML. `PrepareExecutionInputs` has no production execution caller.
- Adapter identity change: the probe needs the `physics.compile_model()` entry point to
  compile verified input bytes. `physics.py` is part of `ADAPTER_SOURCE_FILES`, so the adapter
  implementation digest changes. No existing acceptance is silently re-used: the owner must
  re-accept the adapter identity (and therefore its implementation digest) before any
  production materialized route. `load_model()` and the packaged-model path are unchanged.
- Existing A1 boundary: `WorkerInputBinding`, `verify_worker_input_view`, anchored Windows and
  Linux readers. A1 proves sequential content identity on mutable storage; it is not OS
  immutability or read containment.

## 2. Observed engineering results

These are observations from the probe on the named hosts. A result on one host is not a
cross-platform result; the matrix in §4 names the unverified assumptions.

### 2.1 Windows x86-64

- **Mechanism:** per-attempt AppContainer profile, suspended `CreateProcessW` with
  `SECURITY_CAPABILITIES`, Job Object with `ActiveProcessLimit=8`, `KILL_ON_JOB_CLOSE`,
  process/job memory limits, and an explicit `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` containing
  only the three stdio pipe ends.
- **Observed:** the AppContainer token has the expected package SID and no internet
  capability; outbound TCP connect times out and no connection reaches the supervisor's
  localhost canary; UDP `sendto` returns success but no datagram reaches the UDP canary; raw
  send is denied; AF_UNIX is unavailable in the qualified interpreter; `socketpair` works as
  local IPC. The profile therefore declares `network_access: restricted`, not `denied`.
- **Observed:** a deliberately inheritable non-stdio file handle is not inherited by the
  worker; the handle list is the mechanism.
- **Observed:** a descendant that outlives its direct parent remains in the Job Object and is
  terminated by `TerminateJobObject`; cancellation leaves zero active processes; repeated
  launches leave none.
- **Observed:** during an attempt the runtime, input and attempt trees grant the worker
  `RX` and the interactive user `RX,DE,DC`; the same user can delete but cannot rewrite the
  measured bytes. The user's full control is restored after the attempt so the next
  pre-launch closure can stage a controlled substitution; the pre-launch and post-exit
  closures detect a deletion or mutation. This closes content rewriting during the attempt,
  not deletion denial-of-service.
- **Scratch:** the standard desktop host has no dedicated volume; the probe uses a sampled
  supervisor watchdog (20 ms) and the post-exit exact measurement. An over-budget writer was
  killed while running, but a fast writer can exceed the bound before the next sample. This is
  not a hard quota.
- **Runtime:** the probe re-measures the installed interpreter, base installation,
  site-packages, native extension files and adapter source before launch and after exit; the
  worker re-measures the snapshot. The dependency closure must equal the locked worker
  environment; a mismatch is a refusal before physics.
- **Scientific:** the real pinned MuJoCo 3.17.0 run executes exactly 2,000 steps and its
  trajectory SHA-256 equals the existing qualified reference digest. The model bytes come
  from the verified input view and the packaged XML is absent.

### 2.2 Linux x86-64

- **Mechanism:** Landlock ABI >= 4 filesystem allowlist and TCP deny, `PR_SET_NO_NEW_PRIVS`,
  zero effective capabilities, rlimits, seccomp-BPF, and a supervisor-owned cgroup v2 subtree
  with `pids.max`, `memory.max`, `memory.swap.max=0`, `memory.oom.group=1` and `cgroup.kill`.
- **Observed:** the supervisor must run in a child of the delegated root; the root stays
  empty so its controllers can be enabled. A writable leaf root with the supervisor outside
  it, or no root at all, is a refusal; the session/process-group primitive is not used as a
  fallback.
- **Observed:** a forked child that calls `setsid()` remains in the attempt cgroup; a child
  that outlives its direct parent remains and is killed; cancellation and timeout use the
  same `cgroup.kill`; repeated launches leave no attempt subtrees; failed setup removes its
  partial subtree.
- **Observed:** `pids.max` counts tasks, including threads. With `pids.max=4`, a 12-thread
  probe is partly refused and `pids.events.max` increments. With `pids.max=64`, the real
  NumPy/MuJoCo import fits and `pids.peak <= 64`; the materialized run records its actual
  peak.
- **Observed:** the seccomp policy denies socket creation and use for every family, including
  UDP, raw and Unix-domain sockets, plus `socketpair`, `io_uring`, namespace/mount changes,
  ptrace/process-vm/pidfd and process-signalling paths. The supervisor reads
  `Seccomp: 2`, at least one filter, `NoNewPrivs: 1`, zero effective capabilities, the
  worker's cgroup path and a descriptor table with no socket descriptors from `/proc`.
  `clone3` is refused with `ENOSYS` so glibc falls back to `clone(2)`, whose namespace flags
  the filter can inspect; ordinary `fork` and threads remain available to the cgroup.
- **Observed:** on a host that provisions a dedicated 64 MiB tmpfs scratch root, an
  over-capacity write fails while the worker is alive (ENOSPC); the probe declares
  `dedicated-filesystem`. Without one, it uses the sampled watchdog and says so. The
  post-exit acceptance check is separate and is never called prevention.
- **Local diagnostic limit:** the WSL development kernel exposes Landlock ABI 3. The full
  Linux materialized/verify-only B2 integration was exercised there for mechanism debugging
  only (cgroup + seccomp + runtime + dependency closure + probes + receipt), but the
  authority profile requires ABI >= 4 and the qualifying Linux result is the hosted
  `ubuntu-24.04` job. A local ABI 3 run is not a qualification of this profile.

### 2.3 Cross-platform

- The Windows and Linux observations are compared by `tools.res555_gate_b2.compare`, which
  requires the same model SHA-256, the same 2,000-step trajectory, the qualified reference
  match, the platform mechanisms, the cgroup/seccomp checks and zero TCP/UDP/Unix canary
  traffic. It does not require equal ExecutionFingerprints or InputManifestDigests: those
  include platform-specific environment definitions and are expected to differ.
- The comparison job is additional RES-555 evidence, not one of the eight ADR-025 gates.

## 3. Decisions requested

### D3 — OS enforcement (hard)

Adopt a per-platform, fail-closed profile. A Windows Job Object alone is not a filesystem
sandbox; re-running A1 hashes is not A2 isolation. If the named mechanism is unavailable,
admission refuses and no weaker fallback is attempted.

| Platform | Mechanism | Worker principal | Input | Runtime | Scratch | Scientific sources / staging / sealed | Network |
|---|---|---|---|---|---|---|---|
| Windows x86-64 | AppContainer profile per attempt (`CreateAppContainerProfile` + `SECURITY_CAPABILITIES`), Job Object with `ActiveProcessLimit=8`, stdio-only handle list, explicit DACLs | AppContainer package SID; no capabilities | read-only | read/execute-only | read/write | denied by token (no user SID, no capability) | restricted: outbound TCP/UDP dropped; raw send denied; AF_UNIX unavailable; `socketpair` local IPC remains |
| Linux x86-64 | Landlock ABI ≥ 4 + seccomp-BPF + supervisor-owned cgroup v2 subtree + `PR_SET_NO_NEW_PRIVS`, zero capabilities, rlimits | same UID in an irreversible Landlock/seccomp domain, in a supervisor cgroup | read-only | read/execute-only | read/write | denied by Landlock allowlist | denied through Landlock TCP deny **and** seccomp socket/`io_uring` policy; stdio pipes remain |

Residual threat model, stated so it is not mistaken for a stronger claim:

- **Same-user modification.** On Linux the worker is the same UID; a process outside the
  sandbox can modify a runtime or input file between measurements. The supervisor measures
  before launch and after exit and refuses a mismatch, but that is detection, not prevention.
  A read-only volume or a different principal remains the stronger production answer. On
  Windows the attempt DACL prevents content rewriting during the attempt and allows deletion;
  deletion is detected post-exit.
- **Runtime authenticity.** File hashes identify bytes, not a vendor signature. The file-level
  closure does not prove the wheel was published by an approved builder; the lockfile and
  distribution provenance are inputs to, not a substitute for, an artifact-trust decision.
- **Landlock has no externally readable marker.** The supervisor verifies `/proc` `Seccomp`,
  `NoNewPrivs`, capabilities and cgroup membership, and the in-worker probes; a substituted
  bootstrap could decline to apply Landlock. The supervisor measures and hashes the bootstrap
  and the whole runtime, denies the worker write access to the runtime, and refuses a
  closure mismatch. The worker-written `sandbox-ready.json` is a configuration echo, not
  independent proof.
- **Process containment requires host delegation.** A Linux host without a writable delegated
  cgroup v2 root and a supervisor child is refused; the probe does not inherit
  `max_processes: null`. `pids.max` counts tasks/threads; 64 is a qualified bound, not a
  universal one. Windows `ActiveProcessLimit` counts processes, not threads.
- **Scratch.** A dedicated filesystem whose capacity is at most 64 MiB is a real aggregate
  bound; it is host-provisioned. The sampled watchdog is not a hard quota. The post-exit
  measurement is an acceptance check only. `RLIMIT_FSIZE` is per-file, not aggregate.
- **Network.** Linux denies the socket families through two independent controls. Windows
  AppContainer drops outbound IP traffic and raw send but leaves `socketpair` as local IPC;
  AF_UNIX is absent in the qualified interpreter. The profile does not claim universal
  no-socket isolation on Windows.
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
   marker), and refuses a receipt whose nonce, binding, request, manifest, fingerprint,
   runtime closure or profile does not match its own trusted observation.
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
supervisor compares all three and refuses a mismatch. The probe removes the packaged
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
unchanged. The owner must explicitly re-accept the new adapter implementation digest; this
packet does not do so and does not alter historical reference evidence.

## 4. Decision matrix

| Decision | Status | Proven control | Evidence | Unverified assumption / residual | Owner action |
|---|---|---|---|---|---|
| D1 (input materialization) | **Approved** 2026-10-31 | ADR-026 A1 | A1 stack, hosted run `45170458764` | — | None in this increment |
| D2 (materialization boundary) | **Approved** 2026-10-31 | ADR-026 | A1 stack | — | None in this increment |
| D9 (disposable cache) | **Approved** 2026-10-31 | ADR-026 | A1 stack | — | None in this increment |
| D3 Windows isolation | **Proposed** | AppContainer token, Job Object, stdio handle list, DACLs, network canaries, sampled watchdog | B2 Windows observation; containment tests | No hard Windows scratch quota; same-user deletion; kernel exploits; elevated CI token | Accept mechanism + residual, or replace and re-qualify |
| D3 Linux isolation | **Proposed** | cgroup v2 pids/kill, seccomp, Landlock ABI 4, rlimits, dedicated tmpfs scratch | B2 Linux observation; cgroup/seccomp/scratch tests | Production cgroup delegation; same-UID external writes; ABI 4 target; host-provisioned scratch | Accept mechanism + residual, or replace and re-qualify |
| D4 binding/receipt | **Proposed** | Single-use nonce, binding/view re-verification, supervisor correlation, canaries | B2 observations; replay/mutation tests | Receipt authenticity; registry garbage collection; sidecar schema acceptance | Accept/version v1 sidecar or reject |
| Runtime closure | **Proposed** | Three-point closure, dependency closure, packaged-XML removal | B2 observations; substitution tests | No vendor signature; Linux same-UID mutation; Windows deletion | Accept measured-snapshot semantics and name artifact-trust gap |
| Adapter identity | **Proposed** | Recomputed digest from sandbox source | B2 observations; identity tests | New digest not yet re-accepted | Re-accept the MuJoCo adapter identity/digest |
| ADR-027 native evidence | **Outside this increment** | None | — | Native output contract, canonicalization, assessment, sealing | Adopt ADR-027 separately before native extraction |

No row marked **Proposed** is an approval. No owner adoption is recorded by this packet.

## 5. What the probe demonstrates, and what it does not

The probe is designed to demonstrate, on an exact commit and both qualified platforms:

- platform denial of input writes, staging/sealed/source reads, runtime writes and network,
  with the probes executed inside the launched worker and the external canaries read by the
  supervisor;
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
  provisioned) or being interrupted by a sampled watchdog (Windows/Linux without one).

It does **not** demonstrate owner approval, a production launch route, native output capture,
sealing, canonicalization, assessment, cross-platform numerical equivalence, a universal
hard disk quota on every host, a Linux same-UID immutable store, Windows `socketpair`
elimination, vendor-authenticated wheels, or kernel-exploit resistance. A successful probe run
is evidence for the exact tree, not acceptance of any decision above.

## 6. Independent review

The required independent human security, runtime and scientific/architecture review has **not
been obtained** by this increment. The engineering evidence and the exact review questions are
in `evidence/RES-555/gate-b2/independent-review.md`. Automated adversarial tests and an
independent automated review are supporting evidence only and are not recorded as human
review.

## 7. Owner action

To activate a production materialized-worker route, the owner must record in Linear:

1. D3: accept the per-platform mechanisms, principal, allowlists and residual model above (or
   replace them and require re-qualification).
2. D4: accept or version the receipt/binding contract, explicitly preserving protocol v1.
3. Runtime closure: accept measured-snapshot semantics and name the artifact-trust gap and the
   Linux same-UID mutation residual.
4. Consumption receipt: accept the sidecar schema and supervisor correlation as the only
   admissibility evidence, with the worker self-report treated as untrusted input.
5. Adapter identity: re-accept the MuJoCo adapter implementation digest produced by the
   added `physics.compile_model()` entry point.
6. Process containment: require a delegated cgroup v2 root and supervisor child on Linux and a
   host-provisioned scratch filesystem if an aggregate disk bound is claimed.
7. ADR-027: adopt the native-output/output-policy rows before any native extraction or seal.
8. Independent review: obtain and record the human security, runtime and
   scientific/architecture review of the exact head.

Until then, the only executable increment is the probe-only qualification described in
`python/tools/res555_gate_b2/README.md`. No production route is enabled by this packet.
