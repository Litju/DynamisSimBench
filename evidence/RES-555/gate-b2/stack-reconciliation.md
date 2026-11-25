# RES-555 — protected-main stack reconciliation

Status: **PLAN ONLY. NO BRANCH WAS UPDATED, NO PR WAS MERGED, NO ATOMIC COMMIT WAS REWRITTEN.**
This document records the exact retargeting, qualification and merge requirements for the
four existing PRs against the current protected main. It is a review artifact, not authority
to merge.

## Current protected-main ruleset

Ruleset `24680388` ("DynamisBench main qualification"), active on the default branch:

- `strict_required_status_checks_policy: true` — the PR head must be up to date with main;
- required checks: `platform-identity (windows-x64)`, `platform-identity (linux-x64)`,
  `python (windows-x64)`, `python (linux-x64)`, `frontend (windows-x64)`,
  `frontend (linux-x64)`, `desktop (windows-x64)`, `desktop (linux-x64)`;
- `allowed_merge_methods: ["merge"]` — merge commits only; no squash, no rebase;
- `required_approving_review_count: 0`, but RES-555's acceptance record independently requires
  a human security/runtime/scientific review of the exact head;
- `require_last_push_approval: false`; `required_review_thread_resolution: true`;
- do not use the ruleset bypass. The owner's authorization is required before any merge.

The eight required checks are ADR-025 gates. `res555-gate-b2-comparison` and
`mujoco-receipt-comparison` are additional RES-555 acceptance evidence; they must also pass
for the B2 layer, but they do not replace the eight.

Current main: `16adf8a7173339b7be47dffe280915e826329e3e` (`16adf8a`, RES-742 Gate 3).

## Current PR state

| PR | Branch | Head | Base | Position | Last exact-head result |
|---|---|---|---|---|---|
| #31 | `res-555-exact-input-admission` | `bfd5e6a805deaad6648666ebca4ec5b8abb8d3b1` | `main` | 2 commits ahead, **36 behind main** | [44298784653](https://github.com/Litju/DynamisSimBench/actions/runs/44298784653) success on the old base |
| #32 | `res-555-offline-input-verification` | `e7058418e3dbb72038accb8e04996c4d8e4ed1f1` | `res-555-exact-input-admission` | stacked on #31 | [44339225463](https://github.com/Litju/DynamisSimBench/actions/runs/44339225463) success |
| #34 | `res-555-a1-filesystem-checkpoints` | `5860904f37226d2d2749573a5f52c0c89c68c692` | `res-555-offline-input-verification` | stacked on #32 | [45169206418](https://github.com/Litju/DynamisSimBench/actions/runs/45169206418) **failure** (Windows `python`); integration `d310f7f` [45170458764](https://github.com/Litju/DynamisSimBench/actions/runs/45170458764) success |
| #35 | `res-555-b2-protected-worker` | `7d436c8e8a7ea51826668520054a9bfcede9fe2b` | `res-555-a1-filesystem-checkpoints` | stacked on #34 | code `b2c2309` [45684551797](https://github.com/Litju/DynamisSimBench/actions/runs/45684551797) success (10/10); final evidence head has no exact-head run |

Current B2 branch after the owner decision and correction commits:
`5c963ebb6aaf4e828bb2ae7a8ff3b2c80b14b7dd` (`5c963eb`), docs/evidence and the first
correction increment; code head for the original B2 observations remains `b2c2309`. The
docs-only head `b5371fc` passed run `45701637459` (10/10). The correction head run
`45704314850` is the exact-head qualification for the new tests; the earlier correction run
`45704103596` covered the profile/scratch commits before the canary/status commits. No layer
has been merged.

Qualified integration facts:

- `d310f7f8c1eb075208e90d2f4a39679b57e8f879` is a merge commit of `16adf8a` and the #34 head
  `5860904`. It is a fast-forward descendant of `5860904` and was qualified on
  [45170458764](https://github.com/Litju/DynamisSimBench/actions/runs/45170458764).
- `7d436c8` contains `16adf8a` and the A1 stack. Its B2 code head `b2c2309` was qualified on
  [45684551797](https://github.com/Litju/DynamisSimBench/actions/runs/45684551797); the
  artifact pair is byte-identical to the committed observations. The retained evidence commit
  itself is after the code-head run.

## Exact reconciliation sequence

The atomic commits must be preserved. Use **merge commits** to bring main into each layer;
never rewrite, squash, rebase or force-push the PR branches. The stack order is dependency
order: #31 → #32 → #34 → #35. Each layer is merged to `main` before its child is retargeted.

### 1. PR #31

1. Update the branch with current main using a merge commit (not a rebase):
   `git switch res-555-exact-input-admission`; `git merge --no-ff origin/main`.
2. Resolve conflicts without changing the two atomic commits; push.
3. Run `quality` on the new head (push to a `main`-based PR triggers the workflow; otherwise
   `workflow_dispatch`), require all eight checks and the MuJoCo receipt comparison.
4. Confirm the head is no longer behind main and the ruleset is green.
5. Owner authorizes the merge; merge with a **merge commit** only, pinned to the exact head
   (`pull_request_merge` with `expectedHeadSha`).
6. Postmerge: the push to `main` runs `quality`; retain the run on the merge SHA. Do not mark
   the issue Done from the PR result alone.

### 2. PR #32

1. After #31 is merged, retarget #32's base to `main`.
2. Merge the new `main` (the #31 merge commit) into the #32 branch with `--no-ff`; preserve
   `e705841` and its history; push.
3. Run the exact-head `quality`; require the eight checks and the receipt comparison. The old
   run `44339225463` is historical, not a qualification of the new head.
4. Merge with a merge commit only; postmerge-qualify the merge SHA on main.

### 3. PR #34

1. After #32 is merged, retarget #34's base to `main`.
2. Bring the current main into the branch. The already-qualified integration head
   `d310f7f` is a fast-forward descendant of `5860904`; pushing it (or a new equivalent
   merge of current main) is preferable to re-merging by hand. The old head `5860904` must not
   be merged: its exact-head run `45169206418` failed in Windows `python`.
3. If `d310f7f` is used and main has not moved since `16adf8a`, its run `45170458764` is the
   exact-head qualification (eight checks + receipt). If main moved, create a new merge and
   run the workflow on the new head.
4. Merge with a merge commit only; postmerge-qualify the merge SHA on main. Retain the
   `5860904` failure and its disposition as historical evidence; do not waive it.

### 4. PR #35

1. After #34 is merged, retarget #35's base to `main`.
2. Merge current main (the #34 merge commit) into #35 with `--no-ff`; preserve the B2 atomic
   commits and the retained `7d436c8` evidence. The B2 code head remains `b2c2309`; the
   evidence/owner-record head is a docs-only descendant.
3. Run the exact-head `quality` on the new head; require the eight checks **and**
   `res555-gate-b2-comparison` and `mujoco-receipt-comparison`. The run `45684551797` is a
   qualification of `b2c2309`, not of the new merge head; the new head needs its own run.
4. Before merge, the owner must record the D3/D4/runtime/adapter adoption and the independent
   human review; the automated review is not a substitute. The seven proposed blockers in
   `automated-review-2026-11-25.md` must be dispositioned; production activation is separate.
5. Merge with a merge commit only; postmerge-qualify the merge SHA on main. Mark RES-555
   Done only after the postmerge run, the retained receipts and the human review are recorded.

## What must not happen

- No squash or rebase of any layer; the atomic commits are the review units.
- No merging #32 into #31's branch and then #31 to main in a way that bypasses #32's own
  exact-head checks and postmerge receipt.
- No merge of #34 at `5860904` while its exact-head run is failed.
- No use of the ruleset bypass or `--admin`.
- No merging without the owner's explicit authorization.
- No production activation, native output, ADR-027, canonicalization, assessment or sealing
  from this reconciliation.

## Required evidence per layer

- Exact head SHA and PR number.
- `quality` run ID, head SHA, attempt, all eight required contexts and the receipt comparison.
- Postmerge `quality` run ID and merge SHA on main.
- A retained copy of the B2 observations and comparison for #35; byte-identical to the
  committed evidence for the code head.
- Independent human review record on the exact head.

This plan makes no claim that any layer is merged or authorized. The owner decision is
requested separately in `owner-adoption-record.md`.
