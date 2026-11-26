# RES-555 — protected supervisor integration (implementation record)

Status: **IMPLEMENTED AND RUN END TO END ON A NON-ELEVATED WINDOWS PRINCIPAL. NOT
ACTIVATED.** The protected route exists inside `execute_preflighted`, but nothing in the
API, CLI, desktop shell or workbench can reach it, no environment variable enables it, and
the default remains the diagnostic worker. RES-555 stays In Review. ADR-027 native output
and sealing are untouched.

This record replaces planning with the observed execution. It is the increment the
`production-increment.md` design described, implemented and measured.

## 1. What was built

| Layer | Module | What it owns |
|---|---|---|
| Profile | `execution/protected_profile.py` | the frozen pinned-reference profile and both accepted adapter digests |
| Runtime | `execution/protected_runtime.py` | measured snapshot, packaged-XML removal, Linux `pyvenv.cfg` measurement, `-I -S` command vector, minimal environment |
| Bootstrap | `execution/protected_bootstrap.py` | config and self verification, environment reduction, rlimits, Landlock + seccomp, readiness echo, fixed `sys.path` |
| Contracts | `adapters/mujoco/protected_contracts.py` | runtime closure measurement, view verification, untrusted receipt model, probe observations |
| Worker | `adapters/mujoco/protected_worker.py` | production authority check, view compile with `physics.compile_model`, pinned 2,000 steps, bounded receipt |
| Host (Windows) | `host/protected_windows.py` | AppContainer profile, Job Object, token observation, **non-elevated principal gate** |
| Host (Linux) | `host/protected_cgroup.py` | delegated cgroup v2 subtree, attach-before-exec, `cgroup.kill`, `populated` emptiness |
| Canary | `host/protected_canary.py` | TCP/UDP/Unix canaries with a post-exit drain |
| Scratch | `execution/protected_scratch.py` | entry/byte accounting, directory and NTFS-stream counts, sampled watchdog |
| Launcher | `execution/protected_launch.py` | route, attempt, view, sandbox policy, single-use binding, correlation, `protected-consumption.json` |
| Supervision | `execution/supervisor.py` | `execute_preflighted(..., protected=ProtectedRun)` |

The probe harness now imports the production host mechanisms through thin re-exports, so its
qualified observations exercise the same AppContainer and cgroup code the route uses.

## 2. Lifecycle guarantees preserved

- **Admission is unchanged and re-derived** immediately before staging and again before
  launch. A protected attempt re-checks the pinned authority tuple (adapter and
  implementation digest, all five definition identities and semantic digests, environment,
  seed, outcome, single gravity factor, duration, timestep and steps) before a process.
- **Bounded IPC is the existing one.** One canonical request through the bounded writer, one
  bounded stdout response, one bounded stderr log, one deadline, one cancellation path.
- **The tree is the mechanism.** `_terminate_and_reap` now accepts either the Job Object or
  the cgroup subtree and treats both timeout exceptions identically; emptiness is proved by
  the primitive, never by reaping the direct child.
- **The binding is single-use.** The marker is created with `O_EXCL` and fsynced (plus a
  directory fsync on POSIX) before `CreateProcess`/`exec`; a replay is a refusal.
- **The runtime is revalidated three times** — after route preparation, immediately before
  launch, and after exit — plus the bootstrap digest against the profile and, on Linux, the
  selected `pyvenv.cfg`. The view is verified before launch and after exit.
- **The receipt is untrusted.** `scratch/consumption.json` is parsed, canonicality-checked,
  and correlated with the supervisor's own measurement of the nonce, binding, request,
  preflight, manifest, environment, selection, adapter, runtime closure, profile, runtime
  roots, model bytes, step count, stability and the committed trajectory.
- **No fallback exists.** A missing mechanism, an elevated Windows principal, a missing
  delegated cgroup, a shared scratch volume on Linux, a changed view, a changed runtime, a
  consumed binding, a missing or mismatched receipt, a scratch overrun and a canary
  connection are all refusals or failed terminals. No path starts an unsandboxed worker.

## 3. Observed end-to-end execution (Windows, exact local head)

| Fact | Observation |
|---|---|
| Principal | non-elevated supervisor: `elevated=false`, `elevation_type=3`, integrity `S-1-16-8192`, 0 capabilities |
| Worker token | AppContainer, package SID matched, low integrity `S-1-16-4096`, 0 capabilities, 2 privileges |
| Mechanism | `windows-appcontainer`; Job Object accounting; tree verified empty |
| Result | `COMPLETED`, 0 refusals, exit 0, stdin delivered, reaped, tree cleaned |
| Supervisor checks | 45 / 45 passed |
| Inside-worker probes | 18 recorded; the 5 documented Windows-informational observations (UDP sendto, AF_UNIX, socketpair, io_uring, inherited-socket walk) are excluded from the gate and every gating probe observed its denial |
| Model | `eac679a7…` from the verified view, packaged XML absent (`denied`) |
| Reference | 2,000 steps, trajectory `f585292d…`, final angle/velocity and both energies equal to the committed reference |
| Runtime | supervisor snapshot == post-exit measurement == worker measurement (`2cc9ffb8…`) |
| View | before == after (`d63602d2…`) |
| Scratch | 4 entries / 4 files / 9,020 bytes, 0 links, watchdog 989 samples, not triggered (`sampled-watchdog`) |
| Persisted record | `protected-consumption.json`, `dynamisbench.protected-consumption/1` |
| Retained artifact | `evidence/RES-555/gate-b2/protected-supervisor/windows-x86-64.json`, SHA-256 `a879672fab2e8177a3a217aedf3f7e1eb2080f2c7f326aebec092d467d4ef8aa` |

Negative and boundary tests that ran on the same tree: protected timeout (`TIMED_OUT`,
tree cleaned, no success seal), pre-set cancellation (`CANCELED`), resource-bound violation
(scratch entry bound), altered C A S input bytes (refused before any process), altered
runtime bytes (refused before any process), prepared inputs for another request (refused
before any process), replayed binding (refused), and the pinned profile rejecting a foreign
admitted request.

The first real supervisor run also found four defects the probe could not reach, all fixed
with regression tests in `7e23ce9`: the bootstrap did not consume its own digests, the
AppContainer `CreateProcess` path requires `LOCALAPPDATA` in a caller-supplied environment
block, a minimal environment hid `PROCESSOR_ARCHITECTURE` from `platform.machine()`, and a
corrupt C A S object escaped as an exception instead of a refusal.

## 4. Linux status

The Linux path is the same launcher with the adopted Landlock ABI >= 4 + seccomp +
delegated cgroup v2 + dedicated scratch mechanism, and now adds the measured `pyvenv.cfg`
to the read allowlist and re-verifies it after exit (finding F7's launcher half). It cannot
be qualified on this host. The CI job runs
`tests/execution/mujoco/test_protected_supervisor_execution.py` inside the delegated cgroup
with `DYNAMISBENCH_REQUIRE_PROTECTED_ROUTE=1`, so an unavailable mechanism fails the job
instead of skipping. The hosted Windows runner is elevated, so its job asserts the
non-elevated gate refuses rather than claiming an unqualified execution; the qualified
Windows observation above is from a non-elevated local principal.

## 5. Remaining activation blockers

No production route is activated. The following are still open, and the owner's conditional
requirements are not satisfied by this record:

1. **Named human review.** `independent-review.md`'s signature block is still blank. This
   record and any automated review are not that sign-off.
2. **Qualified non-elevated Windows principal in CI.** The hosted runner is elevated. A
   non-elevated runner, or an explicit owner residual acceptance that re-qualifies the
   elevated principal, is required.
3. **Exact-head Windows and Linux CI on the final stack head**, with the eight ADR-025
   checks plus the B2 and MuJoCo receipt comparisons.
4. **Stack reconciliation (F8/F9).** #31–#35 are still behind current main; each layer must
   be updated with merge commits and re-qualified at the merge SHA.
5. **Linux cgroup and scratch provisioning** are host facts, not code: a delegated leaf
   cgroup with `pids`/`memory` controllers, the supervisor placed in a child of it, and a
   dedicated scratch mount at or below the 64 MiB bound.
6. **Aggregate scratch prevention.** The Windows route records `sampled-watchdog`; the
   adopted claim is detection, not a kernel quota. A dedicated volume is the Linux
   mechanism. No aggregate quota is claimed on a shared Windows volume.
7. **UDP/raw/Unix network scope on Windows** remains the measured-paths claim, not a
   universal denial. The five informational probes record that honestly.
8. **ADR-027** remains proposed: no native extraction, canonicalization, assessment or
   seal is activated, and `protected-consumption.json` is a staging diagnostic, not evidence.

## 6. What this record is not

It is not an acceptance of D3/D4, not a re-acceptance of the adapter identity beyond the
conditional owner record, not a merge authorization, and not a scientific verdict. The
trajectory comparison is against the committed RES-550-derived reference; the supervisor
does not independently re-execute the physics, and the pinned adapter is trusted code rather
than an independent oracle.
