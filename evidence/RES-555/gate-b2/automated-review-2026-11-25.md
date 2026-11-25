# RES-555 Gate B2 — automated source review and local reproduction

Status: **AUTOMATED REVIEW ONLY. NOT A HUMAN SECURITY, RUNTIME OR SCIENTIFIC SIGN-OFF.**
This document records what an automated source review and local test reproduction found on the
exact B2 tree. It does not accept D3, D4, the runtime closure or the adapter identity, and it
does not authorize a production route. The human review packet remains
`evidence/RES-555/gate-b2/independent-review.md`; its signature block is still blank.

## Exact material reviewed

| Item | Value |
|---|---|
| Qualified B2 **code** head | `b2c230930ee0db77b878abe62fa363314cd03c25e` (`b2c2309`) |
| Retained **evidence** head | `7d436c8e8a7ea51826668520054a9bfcede9fe2b` (`7d436c8`) |
| Hosted exact-head run | [45684551797](https://github.com/Litju/DynamisSimBench/actions/runs/45684551797), `workflow_dispatch`, 10/10 jobs |
| Protected main at review | `16adf8a7173339b7be47dffe280915e826329e3e` (`16adf8a`) |
| PR stack | #31 `bfd5e6a` → #32 `e705841` → #34 `5860904` → #35 `7d436c8` |
| B2 observations | `evidence/RES-555/gate-b2/observations/` at `7d436c8` |
| Reference | `evidence/RES-555/gate-b2/reference-observation.json`; trajectory `f585292dae08650de7980e5ff00256e1ca9a80bd28474f9357df9f6daf3278bf` |
| Model | `models/reference/pendulum.xml`; SHA-256 `eac679a723ccfebb48ea5ee40692fa6ee38f965772b484b94b827be6b9dbfdfd` |

The four retained JSON artifacts were downloaded from run `45684551797` and compared
byte-for-byte with `7d436c8`:

| Artifact | SHA-256 | Equal to committed |
|---|---|---|
| `res555-gate-b2-windows-x64/windows-x86-64.json` | `f9164d8309f08eda2e3ebe4e4cfeecdeb7862e4a6a0b88026f7c68066be54f31` | yes |
| `res555-gate-b2-linux-x64/linux-x86-64.json` | `798955279add25af93053d6e043c49441f74f2264914d4f7e34451181f83358f` | yes |
| `res555-gate-b2-comparison/res555-gate-b2-comparison.json` | `928e7d07725bda881c8020a9058fc0cae1a151170ad00a2ff14917f641a9392c` | yes |
| `mujoco-receipt-comparison/mujoco-receipt-comparison.json` | `3f8d054eac89e51c58ec96136458eb9348d7d23ca6b3e75349d34199ac58eb48` | yes |

The exact-head Windows observation is `demonstrated` with 51/51 checks; Linux is
`demonstrated` with 57/57. Both contain the pinned model, exactly 2,000 steps, the same
trajectory, zero failed checks and no refusals. The RES-550 qualification artifact from the
same run independently reproduces the trajectory and records the nonlinear-pendulum
comparison. The local Windows review also reproduced the positive materialized run, all six
negative B2 tests, the verify-only test, the Windows containment tests and the A1 input tests.

Local Windows results on the exact tree (`7d436c8`, code `b2c2309`):

| Suite | Result |
|---|---|
| `test_b2_contracts.py`, `test_b2_scratch_budget.py` | 18 passed, 4 skipped (host privilege fixtures) |
| `test_b2_windows_containment.py` | 5 passed |
| `test_b2_protected_consumption.py` positive test | 1 passed |
| `test_b2_protected_consumption.py` six negative tests | 6 passed |
| `test_b2_protected_verify_only.py` | 1 passed |
| A1 `test_input_admission.py` (both modules) | 44 passed, 3 skipped |

These are local regression results, not hosted qualification and not human review. The hosted
run remains the qualification of the exact code head.

## Concrete findings

The findings below are ordered by what they block. "Blocking" means a claim in the authority
packet cannot be adopted as written, or a production route cannot reuse the B2 bootstrap,
until the disposition is implemented and re-qualified. Findings marked "integration" are
requirements for the next increment rather than defects in the probe-only code.

### F1 — The generated bootstrap is not in the measured runtime closure (blocking)

`python/tools/res555_gate_b2/runtime.py` generates `runtime.root/bootstrap.py`. The bootstrap
is the code that sanitises the environment, applies Landlock/seccomp, writes
`sandbox-ready.json`, fixes `sys.path` and imports the worker. It is **not** one of the
measured roots: `RuntimeIdentity` covers only `executable`, `base`, `site_packages` and
`source`. `run_protected_probe` checks `runtime.bootstrap_sha256() == runtime.bootstrap_digest`
once, before the `tamper` hook, and never checks it again. The post-exit
`measure_runtime_identity` cannot see it.

Reproduction: a review-only test appended one comment line to `runtime.bootstrap_path` inside
the existing `tamper` hook, after the hash check and before launch. The observation still
returned `verdict=demonstrated`, `refusals=()`, with the pinned trajectory. The modified
bootstrap executed. The test took 299.76 s on the review host.

Impact: a same-user writer who wins the pre-launch window can replace the code that applies
the sandbox and writes the readiness echo. The in-worker probes are not an independent
defence: the bootstrap can be changed to skip or subvert them, and the worker/ receipt are
downstream of the bootstrap. This is the one same-user window the packet describes as
"measured"; in fact the bootstrap is measured once and not bound to the execution.

Required disposition: make the bootstrap a frozen, versioned artifact included in the
protected profile and runtime identity; pin it through a held read-only handle or an
out-of-band digest that the supervisor verifies after the DACL grant and immediately before
`CreateProcess`/`exec`; re-verify in the worker where possible; add a regression that a
post-check bootstrap change is refused. Do not reuse the generated probe bootstrap for
production until this is fixed.

### F2 — `sandbox.json` is mutable, unmeasured, and selects the sandbox modules (blocking)

The bootstrap reads `Path.cwd() / "sandbox.json"` before applying any sandbox. `launch.py`
writes that file with, among other fields, `landlock_module`, `seccomp_module`,
`read_execute`, `read_only`, `read_write`, `probe_targets`, `max_file_bytes` and
`max_open_files`. The file is not part of `RuntimeIdentity` or the binding. The only check,
`sandbox_config_written`, hashes the file **after** the attempt; a writer can restore the
original bytes before that check. A same-user writer can point `landlock_module` at a
scratch-resident module, which the bootstrap imports and executes **before** Landlock, or
broaden the allowlists. The worker's in-worker probes are the only backstop and are executed
by code the bootstrap can influence.

Required disposition: pass the policy through a supervisor-pinned handle or a
supervisor-supplied digest that is not in the mutable file; use fixed, measured module paths;
verify the config bytes immediately before launch; include `sandbox.json` in the protected
profile/closure; add a negative test for a modified config and a modified `landlock_module`.

### F3 — Python startup runs before the sandbox, and Windows inherits the full environment (blocking)

The worker is launched with `-I`, not `-S`. `-I` disables `PYTHON*` environment handling and
user site, but `site` still imports `sitecustomize` and processes `.pth` files from
site-packages **before** `bootstrap.py` runs. On Windows,
`AppContainerProcess.launch(environment=None)` inherits the supervisor's full environment;
the bootstrap sanitises `os.environ` only after Python startup. A `sitecustomize.py` or
`.pth` added in the measurement-to-launch window can therefore execute before Landlock,
seccomp or the environment sanitisation, read inherited credentials and use the network.
The pre/post closure detects the added file after execution; it does not prevent the
execution or the exfiltration.

Required disposition: launch with `-S` and a minimal supervisor-supplied environment on both
platforms; do not rely on the child to sanitise inherited secrets; include startup hooks and
`.pth` files in the closure; add a negative test that a `sitecustomize.py`/`.pth` added in
the window is not executed (or that the route refuses before startup). This is required
before the "no network/credential inheritance" claim can be adopted.

### F4 — The 256-entry scratch bound counts files only; directory metadata and directory ADS are invisible (blocking)

`measure_scratch` pushes directories onto `pending` and counts `files` only for
`stat.S_ISREG`; it counts bytes only for regular files and calls `_windows_stream_bytes` only
in the regular-file branch. A local Windows probe produced:

| Probe | `bytes` | `files` | `links` | `unmeasured` |
|---|---:|---:|---:|---:|
| 1,000 empty directories | 0 | 0 | 0 | 0 |
| 2,000 nested empty directories | 0 | 0 | 0 | 0 |
| one 1 MiB **directory** alternate data stream | 0 | 0 | 0 | 0 |
| one 1 MiB **file** alternate data stream (positive control) | 1,048,577 | 1 | 0 | 0 |

The watchdog triggers on `usage.files > max_files`, so a directory-only writer never
triggers it; the post-exit check also passes. On Windows the sampled watchdog is not a hard
quota, so directory/MFT exhaustion is not bounded. On Linux the dedicated tmpfs capacity is a
hard bound, but the reported 256-file claim still does not bound directory metadata, and the
directory ADS observation is Windows-specific.

Required disposition: count every non-root directory and file entry (and both normal and
alternate streams on directories) against an explicit entry budget; make the watchdog trigger
on that budget; add tests for directory trees and directory ADS; or narrow the owner claim and
resource profile to what is actually enforced. The current "inode exhaustion" and "large ADS"
wording is not supported for directories.

### F5 — The B2 worker does not enforce the pinned RunSpec/adapter authority (blocking)

The production diagnostic worker has `_verify_reference_authority` in
`python/src/dynamisbench/adapters/mujoco/worker.py`. It checks adapter id/version/engine/
protocol/capabilities, every definition identifier/version and semantic digest, the seed,
the single outcome and the gravity factor before physics. The B2
`_b2_probe_worker._run` does not import or call it. It reconstructs the implementation digest
from the adapter source (which contains the reference constants), but it does not reject a
request with a different `adapter_id`, engine declaration, scenario/benchmark/realization/SUT/
environment semantic digest, seed, outcome or factor. `physics.run_reference` always uses the
pinned 2.0 s / 0.001 s constants, so a different admitted RunSpec can run the pinned physics
under a different identity and still produce the pinned trajectory. The tests use only the
canonical fixture; there is no zero-step refusal test for a changed RunSpec.

Impact: the packet's statement "any request that differs in adapter, implementation digest,
model digest, scenario, environment identity, seed, outcome, step count, timestep or duration
is refused" is true for the production diagnostic worker, not for the qualified B2
consumption worker. The probe-only scope is narrower than the claimed profile until the
production authority check is reused.

Required disposition: call the shared production `_verify_reference_authority` (or a
factored shared function) in the materialized worker before compiling the model or advancing
physics; add refusal tests for a changed scenario/seed/outcome/factor/adapter id; include the
materialized worker entry in the adapter identity and protected profile.

### F6 — The canary counters can miss a last-instant datagram (blocking for the Windows network claim)

`_NetworkCanary._run` is a single thread that performs TCP `accept` (0.2 s timeout), UDP
`recvfrom` (0.2 s) and Unix `accept` (0.2 s) in sequence. The supervisor reads
`canary.udp_datagrams` immediately after the worker exits, with no post-exit drain. On the
review host, after a successful control, a UDP datagram sent immediately was `0` at 0 ms and
50 ms and `1` at 550 ms in five of five runs. A worker that sends a datagram just before
exit can deliver it and still leave a zero count at the moment the supervisor reads it. The
Linux route has seccomp as an independent denial; the Windows route relies on the canary for
delivery evidence and already narrows its claim to the measured paths.

Required disposition: add a post-exit `drain`/`settle` that waits at least one listener cycle
and then reads all counters, or give each family an independent listener; re-qualify; or
narrow the Windows network claim further. Do not describe the current zero count as proof of
zero delivery for a last-instant datagram.

### F7 — The Linux venv `pyvenv.cfg` is not in the measured closure (blocking for the Linux runtime claim)

`prepare_runtime` measures the executable, base prefix, site-packages and source. On Linux the
snapshot launches the venv interpreter (not the resolved base interpreter), so Python reads
`pyvenv.cfg` from the venv root. That file is not in any `RootClosure`. `include-system-site-
packages`, `home`, and other interpreter-selection settings can change Python startup before
the bootstrap. The Windows snapshot launches a copied base interpreter, so this is Linux
specific. The same concern applies to any interpreter-startup hook not covered by the
measured source/site roots.

Required disposition: measure the venv config and any startup hooks, or launch with `-S` and a
controlled `sys.path` that makes the config irrelevant; include the measured file in the
runtime identity; add a test for a changed `pyvenv.cfg`.

### F8 — PR #34's current head is not qualified (merge blocker)

PR #34 head `5860904f37226d2d2749573a5f52c0c89c68c692` was run
[45169206418](https://github.com/Litju/DynamisSimBench/actions/runs/45169206418): Windows
`python (windows-x64)` failed in the full pytest step; Linux and the other jobs passed. The
separate integration head `d310f7f8c1eb075208e90d2f4a39679b57e8f879` was run
[45170458764](https://github.com/Litju/DynamisSimBench/actions/runs/45170458764): all eight
required jobs plus the MuJoCo receipt comparison passed. `d310f7f` is a fast-forward
descendant of `5860904` and contains protected main `16adf8a`.

The current PR head is still `5860904`. Merging it would use a failed exact head. The ruleset
requires strict status checks on the head. The recorded failure must be superseded by a
qualified head, not waived.

Required disposition: update #34 to `d310f7f` (preserving the atomic commits) or a new
current-main merge, push, and record the exact-head run. Do not merge `5860904`. Retain the
old failure as historical evidence.

### F9 — The stack is behind current main and the final B2 head has no exact-head PR run (merge blocker)

The repository ruleset `24680388` ("DynamisBench main qualification") is active on the default
branch and requires:

- `strict_required_status_checks_policy: true` — the head must be up to date with main;
- required contexts `platform-identity`, `python`, `frontend`, `desktop` on Windows and Linux
  (eight checks);
- `allowed_merge_methods: ["merge"]` — merge commits only; no squash or rebase;
- no bypass use.

Current state:

| PR | Head | Base | Behind main / base | Last exact-head run |
|---|---|---|---|---|
| #31 | `bfd5e6a` | `main` | 36 behind `16adf8a` | 44298784653 success (old base) |
| #32 | `e705841` | `res-555-exact-input-admission` | base stack | 44339225463 success |
| #34 | `5860904` | `res-555-offline-input-verification` | base stack | 45169206418 **failure**; integration `d310f7f` 45170458764 success |
| #35 | `7d436c8` | `res-555-a1-filesystem-checkpoints` | code `b2c2309` = run 45684551797 success; evidence head has no run | 45684551797 (code head only) |

The B2 code head is qualified; the retained evidence commit is after the run. Under strict
status checks, the final PR head must itself have the eight required checks (and the B2
comparison/receipt for RES-555 acceptance) before it can merge.

Required disposition: update each stack layer with current main using merge commits (never
rewrite or squash), retarget each child to `main` after its parent merges, rerun the exact
head, and use merge commits only. See `stack-reconciliation.md` for the exact sequence.

### F10 — The elevated Windows token is described inconsistently (documentation, production condition)

The hosted Windows token observation is `is_appcontainer=true`, `sid_matches=true`,
`capability_count=0`, `integrity_level=S-1-16-4096` (low), `elevated=true`,
`elevation_type=1`, with `SeChangeNotifyPrivilege` enabled and
`SeIncreaseWorkingSetPrivilege` disabled. `authority-decision.md` §2.1 correctly says low
integrity; §4 says "a high-integrity AppContainer token", which is wrong. The code only reads
and records elevation; it does not refuse an elevated supervisor. Production is required to
be non-elevated or to record an explicit residual.

Required disposition: correct the high-integrity sentence; add a production non-elevated
principal refusal (or explicit owner acceptance with re-qualification); do not treat the
hosted elevated token as the production isolation fact.

### F11 — Comparator coverage and reference provenance (evidence quality, not a blocker)

`tools/res555_gate_b2/compare.py` checks the trajectory digest, step count, model digest and
mechanism checks, but not all pinned numeric fields in `reference-observation.json`
(`expected_final_angle_rad`, `expected_final_angular_velocity_rad_s`,
`expected_energy_initial_j`, `expected_energy_final_j`). The positive test checks those fields
against the fresh diagnostic; the retained observation also matches. The comparator alone
could accept a worker-authored receipt whose trajectory hash is valid but whose summary
values are inconsistent. The reference file's `source` sentence cites the existing RES-550
qualification; the exact-head RES-550 artifact confirms the trajectory and the independent
nonlinear-pendulum comparison, but the pre-B2 historical artifact is not in the repository.

Required disposition: add the numeric fields to the comparator and a retained-reference test;
cite the exact RES-550 run/artifact in the provenance sentence. This does not block the
trajectory identity, which is strong.

### F12 — The expected trajectory is caller-supplied in the probe (integration requirement)

`run_protected_probe` validates only that `expected_trajectory_sha256` is one lowercase hex
digest. For `materialized-mujoco` it requires the argument, but it does not load the committed
reference; the tests pass `_REFERENCE_TRAJECTORY`. The B2 comparator independently requires
the pinned value, so the retained evidence is sound. A production caller could pass a
different value, including the worker's own claimed digest. The production
`ProtectedExecutionProfile` must embed/load the committed reference and its digest, and the
probe should load the committed reference itself rather than accept the value from the
caller.

## Confirmed strengths (not findings)

- The exact-head artifacts are byte-identical to the committed observations; the run is on
  the exact code head and all ten jobs passed.
- Windows: expected AppContainer package SID, zero capabilities, low integrity, two recorded
  privileges; Job Object; stdio-only handle list; scratch 4 files / 9,794 bytes; sampled
  watchdog 521 samples / zero unmeasured; zero worker canary traffic after controls; clean
  headless stderr.
- Linux: Landlock ABI 8, seccomp mode 2, `NoNewPrivs=1`, zero effective capabilities,
  cgroup `pids.max=64`, `pids.peak=4`, `pids.events.max=0`, empty subtree, dedicated 64 MiB
  tmpfs, zero canary traffic after controls, clean headless stderr.
- Both platforms: model `eac679...`, 2,000 steps, trajectory `f585292...`, finite state,
  energy drift 7.45e-14, package XML absent, input-view model source, exact four-file scratch
  use, canonical receipts, complete request/preflight/manifest/environment/worker-selection/
  runtime/profile/adapter correlation, single-use nonce, replay refusal, input/runtime
  substitution refusal and late-hardlink refusal.
- The local Windows positive and six negative tests reproduce on the review host.

## Implementation status after the conditional owner decision

The owner selected option A on 2026-11-25. The first correction increment is on the B2 branch
after the review record:

| Commit | Scope | Tests |
|---|---|---|
| `18ebfc7` | Frozen `PinnedReferenceProfile` with the accepted platform adapter digests, pinned trajectory and resource bounds; a protected bootstrap source file requiring `-I -S`, config and self digests, and fixed sandbox module paths; a production worker that calls `_verify_reference_authority` before compiling the view bytes and checks the committed trajectory | `test_protected_profile.py`, `test_protected_bootstrap.py` (16 passed local) |
| `888e5d5` | Production scratch accounting: directories, combined entries and directory NTFS streams; entry-budget watchdog | `test_protected_scratch.py` (4 passed local, one Windows directory-stream test) |
| `570fefc` | Production canary with a two-cycle post-exit drain | `test_protected_canary.py` (3 passed, one AF_UNIX skip on the review host) |

This is not the production launcher. The following remain before activation: the production
runtime/snapshot and `execute_preflighted` integration, the Linux venv-closure disposition
(F7), the non-elevated Windows principal decision on the hosted runner, the stack
reconciliation (F8/F9), the exact-head CI for the final head, and the human review. The
worker and bootstrap still reuse the qualified B2 helper models; promoting those helpers out
of the probe namespace is part of the launcher increment. No supervisor route, native output,
canonicalization, assessment or seal is activated.

## What this review is not

This is not the independent human security/runtime/scientific review required by RES-555.
The reviewer table and signature in `independent-review.md` remain blank. Automated tests,
this document and any AI review cannot be counted as that sign-off. A human reviewer must
inspect the exact head, the findings above, and the dispositions, and record name, role,
date, exact head and approve/approve-with-conditions/reject.

No production route, native output, canonicalization, assessment or seal is activated by this
document. ADR-027 remains proposed.
