# RES-555 — D3/D4, runtime-closure and adapter-identity owner adoption record

Status: **OWNER CONDITIONAL APPROVAL RECORDED (OPTION A). PRODUCTION NOT YET ACTIVATED.**
The owner selected option A on 2026-11-25 through the T3 Code decision request: adopt D3,
D4, measured-snapshot runtime semantics and the two adapter implementation digests for the
strictly pinned-reference profile only, subject to the blocking corrections and re-qualification
in §3. The agent recorded that answer; it did not choose or sign it. The record is limited to
the pinned MuJoCo reference profile and does not activate ADR-027, native output,
canonicalization, assessment or sealing. RES-555 remains In Review.

The owner answered:

> A. Approve conditionally (Recommended) — Adopt D3, D4, measured-snapshot runtime semantics
> and the two adapter digests for the pinned profile only, subject to fixing the seven review
> blockers, stack reconciliation, exact-head re-qualification and the independent human
> review. Authorize the production increment only after those corrections.

## 1. Scope of the record

| Element | Pinned value |
|---|---|
| Adapter | `dynamisbench.mujoco.reference` `0.1.0`; `physics.compile_model()` is part of the implementation identity |
| Engine / interpreter | MuJoCo `3.17.0`; CPython `3.12.13`; qualified Windows x86-64 and Linux x86-64 |
| Model | logical path `models/reference/pendulum.xml`; SHA-256 `eac679a723ccfebb48ea5ee40692fa6ee38f965772b484b94b827be6b9dbfdfd` |
| Definitions | `db.reference.pendulum` / `sc.reference.pendulum` / `rl.mujoco.reference-pendulum` / `sut.reference.pendulum`, all `1.0.0`, IN_PROCESS |
| Run | seed `0`, outcome `reference-state`, 2.0 s, 0.001 s timestep, exactly 2,000 steps |
| Physics | one body, one frictionless hinge, no contacts, no actuators, RK4/Newton, tolerance `1e-12`, gravity `9.80665` |
| Protocol | WorkerRequest/WorkerResponse v1 exactly; no new wire field, no second execution protocol |
| Inputs | exactly the five resolved definitions plus the one declared realization asset in a verified read-only view |
| Numerical reference | trajectory `f585292dae08650de7980e5ff00256e1ca9a80bd28474f9357df9f6daf3278bf`; 2,000 steps; final angle `0.5192097890514507`; final angular velocity `0.2069654165048836`; initial energy `1.3138419739773342` J; final energy `1.3138419739773048` J |
| Reference basis | the RES-550 packaged-path qualification's independent nonlinear-pendulum comparison; the exact-head RES-550 artifact on run `45684551797` reproduces the same trajectory and expected values |

Any request that differs in adapter, implementation digest, model bytes, definition
identity/semantic digest, environment identity, seed, outcome, factor, step count, timestep or
duration is refused. A different model or adapter is a new authority decision, not a parameter
to this profile. The only eligible platform mechanisms are the ones in §3.

## 2. Decisions requested

### D3 — Windows OS enforcement

**Proposed:** adopt a per-attempt AppContainer profile with `CreateAppContainerProfile`, the
package SID, zero package capabilities, a Job Object with `ActiveProcessLimit=8`,
`KILL_ON_JOB_CLOSE`, per-process/job memory and CPU limits, a stdio-only
`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, and explicit DACLs: runtime and input read/execute,
scratch read/write, scientific source/staging/sealed denied. Network is `restricted`: the
measured localhost paths showed TCP connect not completing and zero delivery, one UDP
`sendto` accepted with zero delivery, raw send denied, AF_UNIX unavailable; `socketpair`
remains local IPC. This is not a universal no-socket or no-UDP claim.

**Residuals to name:** the hosted CI token is elevated (`elevated=true`, `elevation_type=1`,
low integrity `S-1-16-4096`, zero capabilities, `SeChangeNotifyPrivilege` enabled,
`SeIncreaseWorkingSetPrivilege` disabled). Production must run under a non-elevated
supervisor, or the owner must explicitly accept the elevated residual and re-qualify that
principal. The same-user owner can rewrite the DACL/delete entries; the post-exit closure is
detection, not prevention. The sampled watchdog is not a hard quota; a fast writer can
overshoot between samples. A different destination, family, inherited handle or host
firewall policy is not covered by the canary evidence. Kernel exploits are not addressed.

### D3 — Linux OS enforcement

**Proposed:** adopt Landlock ABI >= 4 with a filesystem allowlist, `PR_SET_NO_NEW_PRIVS`,
zero effective capabilities, rlimits (2 GiB address space, 120 s CPU, 64 MiB per file,
256 open files, no core), seccomp-BPF (socket/socketpair/all socket data paths/io_uring/
namespace/mount/ptrace/pidfd/signalling paths denied; `clone3` returns `ENOSYS` so glibc falls
back to `clone`, whose namespace flags are checked), and a supervisor-owned cgroup v2 subtree
in a delegated root with `pids.max=64`, `memory.max=2 GiB`, `memory.swap.max=0`,
`memory.oom.group=1` and `cgroup.kill`. The supervisor must be a child of the delegated root;
the delegated root must be empty of internal processes. Network is denied by Landlock TCP and
seccomp.

**Residuals to name:** the worker is the same UID; a process outside the sandbox can modify a
runtime/input file between measurements, including between the worker's measurement and its
import (detection, not immutable storage). The host must delegate the cgroup v2 root and (for
a claimed aggregate scratch bound) provision a dedicated scratch filesystem; a missing
mechanism refuses. The execute allowlist includes system library directories such as
`/usr/lib`; those directories can contain executables. Landlock has no externally readable
marker; a substituted bootstrap could decline to apply it. Kernel exploits are not addressed.

### D4 — Request/receipt binding

**Proposed:** preserve WorkerRequest/WorkerResponse v1 exactly. The supervisor builds
`dynamisbench.worker-input-binding/1` with a fresh 32-byte `launch_nonce`, the request,
preflight, input-manifest, environment, worker-selection, adapter-implementation,
runtime-closure and isolation-profile digests. The supervisor writes the exact admitted
manifest, definitions and asset bytes into a per-attempt `inputs/` view; the worker receives
no caller-supplied path. A single-use, fsynced nonce marker is created before process
creation; reuse is refused. The worker writes a bounded canonical sidecar
`dynamisbench.res555.consumption-receipt/1` at `scratch/consumption.json`. The supervisor
reads it as **untrusted input**, verifies canonical bytes, and correlates run id, completion/
failure, nonce, binding, request, preflight, manifest, environment, worker selection,
fingerprint, runtime closure, profile, adapter digest, model digest, step count and trajectory
with its own observations. The sidecar alone is not evidence; `receipt` values are never
promoted to supervisor authority.

**Proposed persisted supervisor record:** a staging payload `protected-consumption.json`
with schema `dynamisbench.protected-consumption/1`, authored by the supervisor, containing the
correlated admission/binding/view/runtime/profile/receipt/observation digests and the
structural outcome. It is not `native/`, not canonical, not an assessment and not a seal. The
worker sidecar remains `scratch/consumption.json` and is not sealed. The owner may choose a
different name/schema; it must be recorded here.

### Runtime closure

**Proposed:** adopt measured-snapshot semantics for the installed interpreter, base
installation, site-packages, adapter source and native extension files. The supervisor
measures the installed source, derives the snapshot the worker will execute, re-measures it
immediately before launch, and re-measures after exit; the worker re-measures its own roots
and the dependency closure. A mismatch refuses before/after physics; the packaged reference
XML is removed from the snapshot. The expected digest is a measurement, not caller-supplied
proof.

**Residuals to name:** measured hashes are not vendor signatures; the wheel/artifact
provenance is the lockfile plus the measured distribution closure, not an authenticated
builder chain. On Linux the worker is the same UID; the exact unmeasured windows are
pre-measure→launch, launch→worker measure/import, worker measure→import, and exit→post-
measure. On Windows the owner can rewrite the DACL; deletion is a denial-of-service residual.
The worker-authored trajectory is correlated with the committed reference, not independently
re-executed by the supervisor; the pinned adapter is trusted code, not an independent
scientific oracle.

**Conditions from the automated review:** before production reuse, include the generated
bootstrap, the sandbox policy/config and the Linux venv `pyvenv.cfg`/startup hooks in the
measured/pinned closure; launch with `-S` and a minimal supervisor-supplied environment; and
verify them after the DACL grant and immediately before exec. See
`automated-review-2026-11-25.md` findings F1, F2, F3 and F7. Until those are fixed and
re-qualified, the runtime-closure claim is limited to the measured roots, not the whole
launch path.

### Adapter implementation identity

**Proposed:** re-accept the MuJoCo adapter implementation identity produced by adding
`physics.compile_model()`. This is a new identity, not a reuse of the RES-550 packaging
acceptance. The exact-head B2 receipts record:

| Platform | Implementation digest | Source manifest files | Dependency closure |
|---|---|---:|---|
| Windows x86-64 | `4a907d4262ceca66588188ddcc37894ec488a55f0756886864c89bc5f99827b8` | 10 | `6a2f7ad6b36c71ac3c17466934843666efe35d743502be64837bb322f8275d5c` |
| Linux x86-64 | `7993ac96c91de71a7b5f8770d444c318d6c1283de5b8f0f0d1c615d7c6afe097` | 10 | `6a2f7ad6b36c71ac3c17466934843666efe35d743502be64837bb322f8275d5c` |

The source manifest hashes are recorded in the retained observations
(`windows-x86-64.json`, `linux-x86-64.json`, receipt `source_manifest`). The digest includes
platform and Python patch version; both platform values must be accepted. The packaged model
digest remains `eac679...`; the materialized route supplies the same bytes through the input
view.

The owner must explicitly re-accept these digests. The B2 packet does not do so, and no
existing acceptance is silently reused.

### Conditionally accepted 13-file production identity (2026-11-26)

The owner explicitly accepted the schema-2 digests for the fixed pinned MuJoCo reference
in [Linear RES-555](https://linear.app/alignerr-cmj/issue/RES-555/db-33-content-addressed-modeldefinition-materialization-worker-input),
decision comment `a6712040-c29a-47c1-9cb3-d885b763743b`.

| Platform | Owner-accepted schema-2 SHA-256 | Files |
|---|---|---:|
| Windows x86-64 | `86d5e912fa876208e156bfe13f91be6a5cfde7f0aefcc9e0bbf3aedbc7051f20` | 13 |
| Linux x86-64 | `9ea31547f2246e2a8eedcaefcac8ae767086711c96ad79d5da835f72e5bc2ea1` | 13 |

**Exact implementation boundary:** the historical 10-file protocol-v1 adapter digest
continues to be checked by the worker. The supervisor *additionally* validates the
owner-accepted schema-2 digest over the ten adapter files and the three production-entry
files (`protected_contracts.py`, `protected_worker.py`, `protected_bootstrap.py`) from
the measured source snapshot at route construction, before execution and after exit.
The accepted hashes and WorkerRequest/WorkerResponse v1 remain unchanged.

This is a dual-binding compatibility implementation, rather than putting the schema-2
digest directly into the v1 wire adapter identity. A named independent human reviewer
must evaluate its equivalence to the proposed replacement contract before the owner
authorizes PR #35 integration. The 13 bound source bytes are unchanged; modifying them
would require a newly calculated owner decision. No production UI/API activation, native
evidence, canonicalization, assessment or sealing is granted.

The exact manifest payload and regeneration command remain in
[`adapter-manifest-reacceptance.md`](./adapter-manifest-reacceptance.md) and
[`adapter-manifest-candidate.json`](./adapter-manifest-candidate.json).

### Pinned numerical reference

**Proposed:** accept `f585292...` as the only eligible trajectory and the numeric values in
§1 as the retained reference. The basis is the RES-550 packaged-path qualification with the
independent nonlinear-pendulum comparison; the exact-head RES-550 artifact on run
`45684551797` reproduces the same trajectory and values. A different trajectory is a refusal,
not a tolerance. Cross-platform equivalence is not claimed beyond the identical trajectory
and the shared model/definition content; full ExecutionFingerprints and InputManifestDigests
differ by platform environment definition.

## 3. Blocking corrections before production activation

No production route is authorized by this record until all of the following are implemented,
independently reviewed, and qualified on the exact head:

1. **Bootstrap closure (F1):** frozen bootstrap artifact included in the protected profile
   and runtime identity; verified after the DACL grant and immediately before exec; post-change
   refusal test.
2. **Sandbox policy pinning (F2):** `sandbox.json`/policy and the Landlock/seccomp modules
   pinned through a supervisor-held handle or an out-of-band digest; no mutable module
   selection; post-change refusal test.
3. **Pre-sandbox startup (F3):** `-S`, minimal supervisor-supplied environment, no inherited
   secrets, no `sitecustomize`/`.pth` execution before the sandbox; negative test.
4. **Scratch accounting (F4):** count directories and directory alternate streams; make the
   entry budget trigger the watchdog; tests for directory trees and directory ADS; or narrow
   the claim.
5. **Pinned request authority (F5):** reuse the production `_verify_reference_authority` in
   the materialized worker; refusal tests for a changed scenario/seed/outcome/factor/adapter
   identity; include the worker entry in the identity.
6. **Canary drain (F6):** post-exit settle/drain before reading the counters; re-qualify; or
   narrow the Windows network claim.
7. **Linux venv closure (F7):** measure `pyvenv.cfg`/startup hooks or make them irrelevant
   with `-S`; test.
8. **Adapter identity:** include the production bootstrap/worker additions in the source
   manifest and re-accept the resulting digests; do not permanently reuse the probe-only
   `_b2_probe_worker` identity for a production entry without recording it.
9. **Non-elevated Windows principal (F10):** refuse an elevated supervisor or record an
   explicit owner acceptance and re-qualify.
10. **Comparator/reference quality (F11, F12):** compare the pinned numeric fields; load the
    committed reference in the probe/profile rather than accepting it from the caller.
11. **Stack reconciliation (F8, F9):** update #34 to a qualified head; update #31-#35 with
    current main using merge commits; run the eight required checks plus the B2/receipt on
    each exact head; merge with merge commits; postmerge-qualify each merge SHA.
12. **Independent human review:** a named human security/runtime/scientific reviewer must
    inspect the exact head and record name, role, date and approve/approve-with-conditions/
    reject in `independent-review.md`. This record and the automated review are not that
    sign-off.
13. **ADR-027:** remains proposed. No native output, canonicalization, assessment or sealing
    is activated by this record.

## 4. Decision and signature

The owner is asked to choose one:

- **A. Approve conditionally (recommended):** adopt D3, D4, the measured-snapshot runtime
  semantics and the two adapter implementation digests for the pinned-reference profile only,
  subject to the blocking corrections and re-qualification in §3. Authorize the production
  increment after those corrections, not before.
- **B. Approve the mechanism evidence only:** record the B2 mechanisms and residuals as
  evidence; do not adopt D3/D4 or the adapter identity; keep production blocked.
- **C. Reject/revise:** specify the changes; the record is not adopted.

| Field | Owner entry |
|---|---|
| Decision (A/B/C) | **A. Approve conditionally** |
| Owner name / role | **Litju (owner), via T3 Code RES-555 decision request** |
| Date | **2026-11-25** |
| Linear RES-555 reference / decision comment | [RES-555](https://linear.app/alignerr-cmj/issue/RES-555/db-33-content-addressed-modeldefinition-materialization-worker-input), conditionally adopted D3/D4 `f240705a`, schema-2 acceptance `a6712040` |
| Adapter identity re-accepted (Windows digest / Linux digest) | **Windows `4a907d4262ceca66588188ddcc37894ec488a55f0756886864c89bc5f99827b8`; Linux `7993ac96c91de71a7b5f8770d444c318d6c1283de5b8f0f0d1c615d7c6afe097`** |
| Adapter schema-2 production identity accepted? | **YES, CONDITIONALLY, 2026-11-26 — Windows `86d5e912fa876208e156bfe13f91be6a5cfde7f0aefcc9e0bbf3aedbc7051f20`; Linux `9ea31547f2246e2a8eedcaefcac8ae767086711c96ad79d5da835f72e5bc2ea1`. Supervisor dual-binding implementation requires named human review and qualification before merge.** |
| Persisted supervisor record name/schema | **`protected-consumption.json` / `dynamisbench.protected-consumption/1`** (accepted conditionally; worker sidecar remains `scratch/consumption.json`) |
| Windows production principal (non-elevated required? accepted residual?) | **Non-elevated required for production. The hosted elevated CI token remains mechanism evidence only; a non-elevated principal or an explicit residual acceptance and re-qualification is still required.** |
| Linux delegated cgroup + dedicated scratch required? | **Yes for production.** |
| Pinned reference accepted (`f585292...`)? | **Yes, `f585292dae08650de7980e5ff00256e1ca9a80bd28474f9357df9f6daf3278bf`, with the numeric values in §1.** |
| Blocking conditions accepted (§3)? | **Yes; production is not activated until they are implemented, exact-head re-qualified, and the human review is recorded.** |
| Human reviewer name / role / exact head / date / disposition | **PENDING — the independent human security/runtime/scientific sign-off is not obtained by this record or the automated review.** |

**The owner conditionally approved the direction. No production activation, native output,
canonicalization, assessment, seal or RES-555 completion follows from this record. The agent
did not adopt the decision on the owner's behalf; the owner's explicit answer is the record.**
