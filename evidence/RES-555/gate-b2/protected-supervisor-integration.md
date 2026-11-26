# RES-555 — protected supervisor integration (implementation record)

Status: **IMPLEMENTED AND RUN END TO END ON A NON-ELEVATED WINDOWS PRINCIPAL. NOT
ACTIVATED.** The protected route exists inside `execute_preflighted`, but nothing in the
API, CLI, desktop shell or workbench can reach it, no environment variable enables it, and
the default remains the diagnostic worker. RES-555 stays In Review. ADR-027 native output
and sealing are untouched.

This record replaces planning with the observed execution. It is the increment the
`production-increment.md` design described, implemented, measured, and then revised in
response to two independent adversarial reviews.

## 1. What was built

| Layer | Module | What it owns |
|---|---|---|
| Profile | `execution/protected_profile.py` | the frozen pinned-reference profile and both accepted adapter digests |
| Runtime | `execution/protected_runtime.py` | measured snapshot, packaged-XML removal, Linux `pyvenv.cfg` measurement, worker dependency closure, `-I -S` command vector, minimal environment |
| Bootstrap | `execution/protected_bootstrap.py` | config and self verification, environment reduction, rlimits, digest-pinned Landlock + seccomp, readiness echo, fixed `sys.path` |
| Contracts | `adapters/mujoco/protected_contracts.py` | runtime closure measurement, view verification, untrusted receipt model, probe observations |
| Worker | `adapters/mujoco/protected_worker.py` | production authority check, view compile with `physics.compile_model`, pinned 2,000 steps, bounded receipt |
| Host (Windows) | `host/protected_windows.py` | AppContainer profile, Job Object, token observation, **non-elevated principal gate**, kernel-resolved system tools |
| Host (Linux) | `host/protected_cgroup.py` | delegated cgroup v2 subtree, attach-before-exec, `cgroup.kill`, `populated` emptiness |
| Canary | `host/protected_canary.py` | TCP/UDP/Unix canaries with a cycle-counted post-exit drain |
| Scratch | `execution/protected_scratch.py` | entry/byte accounting, directory and NTFS-stream counts, sampled watchdog |
| Launcher | `execution/protected_launch.py` | route, attempt, view, sandbox policy, single-use admission marker, correlation, `protected-consumption.json` |
| Supervision | `execution/supervisor.py` | `execute_preflighted(..., protected=ProtectedRun)` |

The probe harness now imports the production host mechanisms through thin re-exports, so its
qualified observations exercise the same AppContainer and cgroup code the route uses.

## 2. Lifecycle guarantees preserved

- **Admission is unchanged and re-derived** immediately before staging and again before
  launch. The pinned authority tuple is checked before a process: adapter and implementation
  digest, all five definition identities and semantic digests, environment identity, seed,
  outcome, the single gravity factor (id, quantity, unit, target, value), protocol version
  and capabilities. Duration, timestep and step count are bound pre-process by the scenario
  semantic digest and compared numerically against the profile after the run.
- **Bounded IPC is the existing one.** One canonical request through the bounded writer, one
  bounded stdout response, one bounded stderr log, one deadline, one cancellation path.
  For a protected attempt the deadline is `min(manifest timeout, profile wall clock)` and the
  output bounds are the profile's, so a longer diagnostic manifest cannot widen them.
- **The tree is the mechanism.** `_terminate_and_reap` accepts either the Job Object or the
  cgroup subtree. On Linux the route requests `cgroup.kill`, the POSIX session kill and a
  direct-child kill, and requires both the cgroup and the session to be empty; a subtree that
  cannot be released is a terminal refusal.
- **The admission marker is single-use.** It is keyed by the request digest *and* the
  workspace staging root, created with `O_EXCL` and fsynced (plus a directory fsync on POSIX)
  before `CreateProcess`/`exec`. A run-level replay is refused by the staging bundle before
  any attempt exists.
- **The runtime is revalidated three times** — after route preparation, immediately before
  launch, and after exit — plus the bootstrap digest against the profile, the Linux
  `pyvenv.cfg`, a post-exit packaged-model rescan, and a post-exit `__pycache__` refusal.
  The view is verified before launch and after exit.
- **The receipt is untrusted.** `scratch/consumption.json` is parsed, canonicality-checked,
  and correlated with the supervisor's own measurement of the nonce, binding, request,
  preflight, manifest, environment, selection, adapter, runtime closure, profile, runtime
  roots, the exact probe set and expectations, the adapter source manifest, the worker
  dependency closure, the scientific imports, the model path/size/digest, the achieved step
  count, duration, stability and the committed trajectory.
- **No fallback exists.** A missing mechanism, an elevated Windows principal, a missing
  delegated cgroup, a shared scratch volume on Linux, a changed view, a changed runtime, a
  consumed admission, a missing or mismatched receipt, a scratch overrun and a canary
  connection are all refusals or failed terminals. No path starts an unsandboxed worker.

## 3. Observed end-to-end execution (Windows, exact tree of this document)

| Fact | Observation |
|---|---|
| Principal | non-elevated supervisor: `elevated=false`, `elevation_type=3`, integrity `S-1-16-8192`, 0 capabilities |
| Worker token | AppContainer, package SID matched, low integrity `S-1-16-4096`, 0 capabilities, 2 privileges |
| Mechanism | `windows-appcontainer`; Job Object accounting; tree verified empty and released |
| Result | `COMPLETED`, 0 refusals, exit 0, stdin delivered, reaped, `process_tree_cleaned=True` |
| Supervisor checks | **53 / 53 passed** |
| Inside-worker probes | 18 recorded and required as an exact set; the 5 documented Windows-informational observations (UDP sendto, AF_UNIX, socketpair, io_uring, inherited-socket walk) are excluded from the gate and every gating probe observed its **expected** outcome |
| Model | `eac679a7…` from the verified view, packaged XML absent **from the sandbox snapshot** (`denied`) |
| Reference | 2,000 steps, trajectory `f585292d…`, final angle/velocity and both energies equal to the committed reference; achieved final time within 1e-12 s of 2.0 s |
| Runtime identity | supervisor snapshot == post-exit measurement (`205cf15e…`) |
| Runtime closure | supervisor, worker and receipt agree (`a6c12cd7…`) |
| View | before == after (`b020fd42…`) |
| Dependency closure | worker-reported closure equals the closure measured from the worker interpreter (`6a2f7ad6…`) |
| Scratch | 4 entries / 4 files / 9,038 bytes, 0 links, watchdog 745 samples, not triggered (`sampled-watchdog`) |
| Persisted record | `protected-consumption.json`, `dynamisbench.protected-consumption/1`, carrying the full untrusted receipt so its digest is recomputable |
| Retained artifact | `evidence/RES-555/gate-b2/protected-supervisor/windows-x86-64.json`, SHA-256 `1752b6c0f8b29c169b5a39a24334ac4a4658517cdb9bcc9bd5e7f6d07e3947d6` |

Linux, on the dedicated CI job at the exact head `afb93db` (`res555-protected-supervisor`, run
[45740396472](https://github.com/Litju/DynamisSimBench/actions/runs/45740396472); the same
job also passed at `33630f7`):

| Fact | Observation |
|---|---|
| Principal | same-UID supervisor, `CapEff=0000000000000000`, `NoNewPrivs=0` before the sandbox |
| Worker process | `NoNewPrivs=1`, `Seccomp=2`, `Seccomp_filters=1`, `CapEff=0000000000000000`, sampled from the worker's own `/proc/<pid>/status` while it ran |
| Mechanism | Landlock ABI 8, seccomp network policy, delegated cgroup v2 subtree, dedicated 64 MiB scratch tmpfs |
| Result | `COMPLETED`, 0 refusals, exit 0, stdin delivered, reaped, `process_tree_cleaned=True` |
| Supervisor checks | **55 / 55 passed** |
| Inside-worker probes | 18 recorded, **all** observed their expected outcome, including UDP, raw, Unix-domain, socketpair and `io_uring` denials |
| Adapter identity | `7993ac96…` (the accepted Linux digest) |
| Profile | `e240a17d…` (platform-constant) |
| Runtime | snapshot == post-exit (`4702a77b…`); closure `99885179…` matched by the worker; `pyvenv.cfg` `2e6f87b8…` measured and re-verified |
| Reference | 2,000 steps, trajectory `f585292d…` equal to the committed reference |
| Scratch | `dedicated-filesystem`, 4 entries / 8,146 bytes, 0 links, 145 watchdog samples |
| Retained artifact | `evidence/RES-555/gate-b2/protected-supervisor/linux-x86-64.json`, SHA-256 `f58f57b3b5e0e3ccf2cd36c63f61ed15afcbe0ad6bdc0d62f23a202abcaf1d0a` |

The Linux runtime closure digest differs between the two qualifying runs (`b18e773f…` at
`33630f7`, `99885179…` at `afb93db`) because it measures the runner's installed CPython
base, which is not byte-identical across hosts. The profile, the adapter identity, the
model, the `pyvenv.cfg` and the trajectory are stable; the closure is a measurement of the
executed bytes on that host, not a cross-host constant.

Negative and boundary tests that ran on the same tree: protected timeout (`TIMED_OUT`, tree
cleaned, no success seal), pre-set cancellation (`CANCELED`), resource-bound violation
(scratch entry bound), altered C A S input bytes (refused before any process), altered
runtime bytes (refused before any process), prepared inputs for another request (refused
before any process), replayed admission marker (refused), a foreign admitted request refused
by the profile, and receipt substitution across nonce, trajectory, runtime roots, source
manifest, dependency closure, imports, duration, failure text and probe set.

The first real supervisor run found four defects the probe could not reach, all fixed with
regression tests: the bootstrap did not consume its own digests, the AppContainer
`CreateProcess` path requires `LOCALAPPDATA` in a caller-supplied environment block, a
minimal environment hid `PROCESSOR_ARCHITECTURE` from `platform.machine()`, and a corrupt
C A S object escaped as an exception instead of a refusal.

## 4. Review dispositions

Two independent adversarial reviews read the exact tree (`ef5c317` plus the revisions that
produce this document): a security/runtime review and a scientific/evidentiary review. They
are **not** the human sign-off the owner requires.

Fixed in response:

- Linux external isolation sampled the attach launcher rather than the worker; the worker now
  publishes its own pid and the supervisor samples that process's `NoNewPrivs=1`,
  `Seccomp=2` and zero capabilities. Landlock ABI and seccomp state are gates, not echoes.
- A cgroup escape could report an empty tree and leave a session descendant; termination now
  kills the cgroup, the session and the direct child, and requires both primitives empty.
- The admission marker could never collide; it is now keyed by the request and workspace.
- Cleanup was not guaranteed on several early-return paths; one managed scope now unwinds
  every resource, and cleanup never raises.
- Refusal conditions could escape as exceptions; `begin_protected_attempt`, `observe` and
  the persist path now convert them to bounded terminal refusals.
- The probe gate trusted worker-authored probe names and expectations; the supervisor now
  requires the exact probe set it requested and refuses duplicates or relabelling.
- A completed receipt could carry a failure string; that is now refused.
- The source manifest, dependency closure, scientific imports, model path/size and achieved
  duration are now compared against supervisor-held values.
- `environment_sanitized` could be recorded false without a refusal; it is now a refusal.
- The canary drain is confirmed by its cycle counter, not only by the absence of an exception.
- System tools are resolved from the kernel system directory, not `%SYSTEMROOT%`, and the
  availability check uses the route's explicit cgroup root.
- A post-exit `__pycache__` or packaged model is now a refusal.

Recorded as accepted residuals rather than fixed:

- **The supervisor does not re-execute the physics.** The trajectory comparison is against
  the committed reference; a hostile replacement worker could fabricate a canonical receipt.
  The pinned adapter is trusted code, not an independent oracle.
- **A same-user writer is detection, not prevention.** The DACL and the pre/post hashes
  reduce and detect substitution; they do not make the supervisor user unable to rewrite a
  tree it owns.
- **The base installation's `bin`/`Scripts` and base site-packages are excluded from the base
  closure** but remain inside the worker's read-execute tree on both platforms.
- **Windows network denial is the measured-paths claim**, and the informational probes record
  it as such.

## 5. Linux status

The Linux path is the same launcher with the adopted Landlock ABI >= 4 + seccomp +
delegated cgroup v2 + dedicated scratch mechanism, the digest-pinned sandbox modules, the
measured `pyvenv.cfg` in the read allowlist, and the worker-pid isolation sampler. It is
**qualified on the dedicated CI job at the exact head `afb93db`**: Landlock ABI 8,
`Seccomp=2`, `NoNewPrivs=1`, zero effective capabilities in the worker, a delegated cgroup
subtree, a dedicated 64 MiB scratch filesystem, 55/55 supervisor checks, all 18 probes at
their expected outcome, and the committed trajectory. The retained record is
`protected-supervisor/linux-x86-64.json`. The step takes roughly half an hour because the
route re-measures the runner's CPython base before and after every attempt; a per-route
cache of the unchanged base measurement is a worthwhile follow-up, not a correctness issue.

The hosted Windows runner is elevated, so its job asserts that the non-elevated gate refuses
and runs the launch contracts; the qualified Windows execution above is from a non-elevated
local principal. The general Linux suite skips the protected module unless
`DYNAMISBENCH_PROTECTED_ROUTE=1`; the dedicated job sets it and fails rather than skips when
the mechanism is unavailable.

## 6. Remaining activation blockers, mapped to the owner record §3

| Owner condition | Status |
|---|---|
| F1 bootstrap closure | **implemented**: bootstrap is a source file, hashed in the profile, verified by the bootstrap and re-verified after exit |
| F2 sandbox policy pinning | **implemented**: config bytes pinned by digest, module paths and digests pinned, modules executed from verified bytes |
| F3 pre-sandbox startup | **implemented**: `-I -S`, minimal supervisor environment, exact key-set gate; `LOCALAPPDATA` is a documented Windows `CreateProcess` requirement removed by the bootstrap |
| F4 scratch accounting | **implemented**: directories, entries and NTFS streams counted; entry budget drives the watchdog; post-exit fail-closed |
| F5 pinned request authority | **implemented**: the production `_verify_reference_authority` runs before compile, and the profile compares the same tuple |
| F6 canary drain | **implemented**: two-cycle drain confirmed by the cycle counter |
| F7 Linux venv closure | **implemented**: `pyvenv.cfg` measured, in the read allowlist, re-verified by the worker and after exit |
| #8 adapter identity including worker/bootstrap | **NOT satisfied**: the accepted digests remain the 10-file B2 manifest. The bootstrap is profile-pinned and the worker entry is in the runtime source closure and recorded as `worker_entry_sha256`, but the owner's requested manifest change is a new acceptance decision that this increment does not make |
| #9 non-elevated Windows principal | **implemented as a gate**; **unqualified on hosted CI**, which is elevated |
| #10 comparator/reference quality | **partly**: the supervisor compares the pinned numerics; the profile does not load `reference-observation.json`, and a test asserting profile == committed reference is still absent |
| #11 stack reconciliation (F8/F9) | **open**: #31–#35 are behind current main and need merge-commit updates and exact-head re-qualification |
| #12 independent human review | **open**: `independent-review.md` is blank. The two adversarial reviews above are not that sign-off |
| #13 ADR-027 | **unchanged**: proposed; no native output, canonicalization, assessment or seal |

Additional open items not owned by the owner record: the Linux qualification result, the
`__pycache__`-free base-installation surface (residual), a Windows network claim beyond the
measured paths, and a kernel-enforced aggregate scratch quota on a shared volume.

## 7. What this record is not

It is not an acceptance of D3/D4, not a re-acceptance of the adapter identity, not a merge
authorization, and not a scientific verdict. It does not activate ADR-027. The retained
record is a staging diagnostic authored by the supervisor, not native evidence.
