# RES-555 Gate B2 — Authority Decision Packet (proposal, not acceptance)

Status: **PROPOSED FOR OWNER ADOPTION. NOT ACCEPTED AUTHORITY. NOT A PRODUCTION ACTIVATION.**
This packet records the minimum decisions that must exist before a materialized model may be
executed by a production worker. It does not edit an accepted ADR, does not change the worker
protocol, and does not enable native extraction or sealing. RES-555 remains In Review.

The executable qualification in `python/tools/res555_gate_b2/` is deliberately probe-only. It
runs behind `DYNAMISBENCH_RES555_B2_PROBE=1` and is not reachable from the supervisor, API,
CLI, or any production route. Its purpose is to demonstrate or refute the mechanisms below so
the owner can decide with evidence rather than a design document.

## 1. Baseline reconciled

- Protected main: `16adf8a` (PR #33 merged).
- A1 stack: #31 `bfd5e6a` → #32 `e705841` → #34 `5860904`.
- Combined A1 + main qualification: `d310f7f`; eight required jobs and the MuJoCo receipt
  comparison passed on attempt 1.
- Accepted: ADR-026 (InputManifest v1, disposable CACHE, admission binding, self-contained
  inputs) and ADR-028. Proposed: ADR-027. ADR-028 does not accept ADR-027 by numbering.
- Existing production boundary: `execute_preflighted` launches the selected diagnostic worker
  with protocol v1 and writes only `diagnostics.json` / `logs/`. `physics.load_model()` still
  reads the packaged XML. `PrepareExecutionInputs` has no production execution caller.
- Adapter identity change: the probe needs the same `physics.compile_model()` entry point to
  compile verified input bytes. `physics.py` is part of `ADAPTER_SOURCE_FILES`, so the
  adapter implementation digest changes. No existing acceptance is silently re-used: the
  owner must re-accept the adapter identity (and therefore its implementation digest) before
  any production materialized route. `load_model()` and the packaged-model path are
  unchanged.
- Existing A1 boundary: `WorkerInputBinding`, `verify_worker_input_view`, anchored Windows and
  Linux readers. A1 proves sequential content identity on mutable storage; it is not OS
  immutability or read containment.

## 2. Decisions requested

### D3 — OS enforcement (hard)

Adopt a per-platform, fail-closed profile. A Windows Job Object alone is not a filesystem
sandbox; re-running A1 hashes is not A2 isolation. If the named mechanism is unavailable,
admission refuses and no weaker fallback is attempted.

| Platform | Proposed mechanism | Worker principal | Input | Runtime | Scratch | Scientific sources / staging / sealed | Network |
|---|---|---|---|---|---|---|---|
| Windows x86-64 | AppContainer profile per attempt (`CreateAppContainerProfile` + `SECURITY_CAPABILITIES` + Job Object limits with an active-process limit of 8) | AppContainer package SID; no capabilities | read-only | read/execute-only | read/write | denied by token (no user SID, no capability) | denied (no `internetClient` capability; outbound TCP/UDP) |
| Linux x86-64 | Landlock ABI ≥ 4 (`landlock_create_ruleset` / `landlock_add_rule` / `landlock_restrict_self`) plus `PR_SET_NO_NEW_PRIVS`, zero capabilities, rlimits | same UID in an irreversible Landlock domain | read-only | read/execute-only | read/write | denied by allowlist | TCP bind/connect denied by handled access with no allow rules; UDP, raw and Unix-domain sockets are **not** restricted by this profile |

Residual threat model, stated so it is not mistaken for a stronger claim:

- A same-UID process outside the sandbox can still modify files the worker may read unless the
  runtime is on a read-only volume or an immutable artifact store. The probe removes
  substitutable scientific fallbacks and measures the runtime before and inside launch; a
  determined same-UID writer can still race a read-only file it owns.
- Windows AppContainer protects against the worker reading the user profile and the original
  workspace because the package token does not carry the user SID. It does not make the
  process kernel-exploit-proof, and system files remain readable as designed.
- Landlock has no externally readable marker. The probe therefore verifies externally visible
  `NoNewPrivs`, capability and (on Windows) AppContainer token facts, and verifies behavior
  from inside the worker. A substituted bootstrap could decline to apply Landlock; the
  supervisor measures and hashes the bootstrap and the whole runtime, and denies the worker
  write access to that runtime. The worker-written `sandbox-ready.json` is a configuration
  echo, not independent proof; the external token/`proc` facts and the in-worker probes are
  the isolation evidence.
- Aggregate scratch quota is not claimed in this increment. Windows uses Job memory limits and
  post-exit size checks; Linux uses `RLIMIT_FSIZE`, `RLIMIT_AS`, `RLIMIT_CPU` and post-exit
  checks. The profile records `scratch_limit_enforcement: post-exit-acceptance-bound` so the
  claim cannot be read as prevention. A kernel-enforced aggregate directory quota remains a
  named production gap.
- No Linux process-count bound is claimed. Windows enforces a Job Object active-process limit
  of 8; the Linux profile records `max_processes: null`. A process that calls `setsid()`
  leaves the supervisor's process group, so process-tree cleanup is best effort. A
  supervisor-owned cgroup or equivalent limit is a named production gap.
- Network denial is not equivalent across platforms. The Linux scope is TCP only; UDP, raw and
  Unix-domain sockets remain available to a same-UID worker. The supervisor canary measures
  the TCP channel only.

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

### Runtime closure (hard for the immutability claim)

The expected digest must not be supplied as proof. The supervisor measures the installed
interpreter, base installation, site-packages, native extension files (MuJoCo, NumPy), and the
adapter source tree before launch. The snapshot the worker will execute is derived from those
measured bytes; the supervisor re-measures it immediately before launch and after exit. The
worker re-measures its own roots and reports the result. The supervisor compares all three and
refuses any mismatch. The probe also removes the packaged reference XML from the worker's
source snapshot and records that `reference.model_bytes()` refuses inside the worker.

Residual: hashes identify bytes, not a vendor signature. The file-level closure does not prove
the wheel was published by an approved builder; that is an artifact-trust decision outside
this increment.

### Consumption receipt (hard)

A worker self-report alone is not authenticity. The proposed bounded observation is:

- **Worker sidecar** (`scratch/consumption.json`): schema, attempt nonce, binding/request/
  manifest/fingerprint digests, runtime-closure digest, profile digest, adapter source
  manifest, dependency-closure digest, the exact model path/size/SHA-256 passed to the
  compiler, `source="input_view"`, package-asset-absence observation, compiled model structure,
  2,000-step diagnostic and trajectory digest, and in-worker read/write/network probe results.
- **Supervisor observation** (`supervisor-observation.json`, test evidence only): its own
  profile, measured runtime closure, external AppContainer/Landlock observations, process
  facts, the receipt digest, the supervisor's own comparison of the receipt trajectory with
  the separately qualified reference digest (`numerical_reference`), and the independently
  recomputed reference comparison. The supervisor is the author of the correlation; the
  worker remains untrusted. Only the positive materialized test names this file; every
  negative and verify-only test runs without an evidence name and cannot overwrite it.

This is **not** native evidence, not `native/`, not canonical, not assessment, and not sealed.
Native extraction and sealing stay blocked on ADR-027's output contract.

## 3. What the probe demonstrates, and what it does not

The probe is designed to demonstrate, on an exact commit and both qualified platforms:

- AppContainer/Landlock denial of input writes, staging/sealed/source reads, and network; and
  allowed scratch writes, with the probes executed inside the launched worker.
- measured runtime identity at three independent points and refusal on substitution;
- exact materialized XML bytes handed to `mujoco.MjModel.from_xml_string`, with the packaged
  XML absent from the worker's importable package;
- the existing pinned 2,000-step reference integration and its trajectory, compared against
  the existing qualified observation without changing tolerances;
- refusal before the first physics step on stale/replayed bindings, binding/view mutation,
  runtime substitution, and unavailable isolation.

It does **not** demonstrate owner approval, a production launch route, native output capture,
sealing, canonicalization, assessment, cross-platform numerical equivalence, an aggregate
disk quota, a Linux process-count bound, UDP/Unix-socket network denial, or
vendor-authenticated wheels. A successful probe run is evidence for the exact tree, not
acceptance of any decision above.

## 4. Owner action

To activate a production materialized-worker route, the owner must record in Linear:

1. D3: accept the per-platform mechanisms, principal, allowlists and residual model above (or
   replace them and require re-qualification).
2. D4: accept or version the receipt/binding contract, explicitly preserving protocol v1.
3. Runtime closure: accept measured-snapshot semantics and name the artifact-trust gap.
4. Consumption receipt: accept the sidecar schema and supervisor correlation as the only
   admissibility evidence, with the worker self-report treated as untrusted input.
5. Adapter identity: re-accept the MuJoCo adapter implementation digest produced by the
   added `physics.compile_model()` entry point. The packaged `load_model()` path is unchanged;
   the digest change is not retroactively covered by an earlier acceptance.
6. ADR-027: adopt the native-output/output-policy rows before any native extraction or seal.

Until then, the only executable increment is the probe-only qualification described in
`python/tools/res555_gate_b2/README.md`. No production route is enabled by this packet.
