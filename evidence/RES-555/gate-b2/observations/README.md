# RES-555 Gate B2 — retained hosted observations

Status: **PROBE-ONLY EVIDENCE. NOT NATIVE EVIDENCE. NOT OWNER ACCEPTANCE.** These files are
the Windows and Linux supervisor observations from the exact-head hosted qualification and
the derived comparison artifacts. They are not `native/`, not canonical, not assessment and
not sealed. ADR-027 remains proposed.

## Exact run

- Workflow: `.github/workflows/quality.yml`, `workflow_dispatch`.
- Final code head: `b2c2309` (`res-555-b2-protected-worker`, PR #35).
- Historical code head `9206648`: hosted run `45680046080`, 10/10 jobs, Windows 51/51 and
  Linux 57/57 checks.
- Final exact-head run: `45684551797` — **all 10 jobs passed**, Windows 51/51 checks and
  Linux 57/57 checks; `res555-gate-b2-comparison` and `mujoco-receipt-comparison` passed.
- Retained artifacts: `res555-gate-b2-windows-x64`, `res555-gate-b2-linux-x64`,
  `res555-gate-b2-comparison`, `mujoco-receipt-comparison`.

## Files

| File | Meaning |
|---|---|
| `windows-x86-64.json` | Windows supervisor observation from the final exact-head run |
| `linux-x86-64.json` | Linux supervisor observation from the final exact-head run |
| `comparison.json` | `res555-gate-b2-comparison` artifact for the same pair |
| `mujoco-receipt-comparison.json` | Existing MuJoCo qualification-receipt comparison (supporting, not a B2 gate) |
| `reference-observation.json` | Committed independently qualified model/trajectory reference |

## Required result

- Windows and Linux verdicts are `demonstrated` with no refusals.
- Both observations contain the same model SHA-256
  `eac679a723ccfebb48ea5ee40692fa6ee38f965772b484b94b827be6b9dbfdfd` and the same
  2,000-step trajectory `f585292dae08650de7980e5ff00256e1ca9a80bd28474f9357df9f6daf3278bf`.
- Windows: expected AppContainer package SID, zero capabilities, recorded privileges and
  integrity, zero worker canary traffic after successful controls, sampled-watchdog scratch
  within 64 MiB and 256 files with zero unmeasured entries, clean headless stderr.
- Linux: Landlock ABI >= 4, seccomp filter, `NoNewPrivs=1`, zero effective capabilities,
  delegated cgroup with `pids.peak <= 64` and empty subtree, dedicated 64 MiB scratch,
  zero worker canary traffic after successful controls, clean headless stderr.
- `comparison.json` has `verdict: pass` and no failed checks.
- `mujoco-receipt-comparison.json` has `verdict: pass` and no failed checks.

## Non-claims

These observations do not accept D3/D4, do not re-accept the adapter implementation digest,
do not authorize a production route, do not produce native output, and do not substitute for
the independent human security/runtime/scientific review. A same-user writer can still win a
measurement-to-use window; the report describes detection, not immutable storage.
