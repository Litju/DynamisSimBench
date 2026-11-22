# RES-742 external-results acceptance

[Linear issue](https://linear.app/alignerr-cmj/issue/RES-742/db-app-01-first-usable-simulation-agnostic-diagnostic-workspace) · [Accepted roadmap](https://linear.app/alignerr-cmj/document/dynamisbench-roadmap-and-delivery-governance-simulation-agnostic-03b89000a9ef)

## Gate 3 — Compare external results

1. Copy [damped-oscillator.csv](../../apps/workbench/e2e/data/external-results/damped-oscillator.csv) and [damped-oscillator-double-amplitude.csv](../../apps/workbench/e2e/data/external-results/damped-oscillator-double-amplitude.csv) into the opened workspace's `external-results/` folder. Choose **Modules → Workspace & Models → External results**. Set the first file as A and the double-amplitude file as B. B uses twice the recorded signal values and a different column order, with the same 81 recorded times.
2. Check both SHA-256 digests. **Timebase and overlap** shows 81 exact pairs over 0–4 s. Select **position** and **velocity**. Use **Inspect comparison time** or click a plot. Both plots follow the same cursor and zoom. Verify the source row numbers in the readout.
3. Confirm the shared origin, scale, frame and quantity definitions for these fixtures. At 0.05 s, position reads 0.99 m in A, 1.98 m in B and 0.99 m as B − A. Velocity reads −0.2, −0.4 and −0.2 m/s. Clear the confirmation to withhold the deltas.
4. Select the scalar decay as B for an unsupported quantity comparison. Restore the oscillator variant, change a value in that file and choose **Revalidate sources**. Verify the refusal, then **Refresh results** and select the updated entry to compare its current bytes.
5. Run `pnpm --filter @dynamisbench/workbench run test:e2e external-comparison.spec.ts` to exercise the same secured browser flow and the partial, disjoint, ambiguous and corrupt cases. The test also compares two 20,000-row sources. Set `DYNAMISBENCH_RESULTS_SCREENSHOTS` to a local directory to capture the views.

Comparison v1 matches exact column names, declared units and canonical unit metadata. Its shared cursor visits the union of recorded times. Exact timestamp equality is evaluated after binary64 decoding, including equality of signed zeros. Distinct decoded timestamps remain distinct regardless of spacing. Repeated or reversed timestamps make the timebase unsupported. A delta requires a confirmed comparison, an exact timestamp pair, two finite values and a finite subtraction result. Blanks, nonfinite values and unmatched timestamps remain visible. The method uses the recorded values at their original times and scales.

- [Oscillator overlays, provenance and deltas](gate-3-oscillator-comparison.png)
- [Partial-grid comparison and a nonfinite refusal](gate-3-partial-grid.png)

## Gate 2 — Plots and numerical diagnostics

1. Open both fixture CSVs using the Gate 1 steps below. On scalar decay, move the **Inspect sample** slider one row with the right arrow. Row 2 shows 0.05 s and 0.9375 mol/m³. Zoom in, then zoom out to restore the original time span.
2. On damped oscillator, select **position** and **velocity**. Click a plot to inspect the nearest recorded time on both channels, zoom in around that row, then reset. Each panel has its own labeled value scale. The slider steps through visible rows in source order, including duplicates.
3. Expand a finding in **Numerical diagnostics**. Verify its recorded quantity, source SHA-256, method and limits. Both fixtures pass the descriptive checks. Zoom and signal selection leave their diagnostic sample counts fixed.
4. Run the focused secured-sidecar test with `pnpm --filter @dynamisbench/workbench run test:e2e external-results.spec.ts`. It also exercises extrema, missing and nonfinite samples, irregular and repeated timestamps, extreme binary64 values, large offsets, malformed rows, source changes and narrow-screen controls. A 20,000-row import verifies that zoom changes the visible extrema while the findings still account for every admitted row. Set `DYNAMISBENCH_RESULTS_SCREENSHOTS` to a local directory to capture the Gate 2 views.

Diagnostics v1 checks admitted binary64 values. Sampling regularity uses a relative tolerance of 1 ppm against the median observed interval. This describes the recorded grid and says nothing about the simulator or the intended cadence. Plots use every visible row and draw line guides only between adjacent finite samples on a time grid that passes the regularity check. The marks under the axis locate missing and nonfinite values without assigning them a y value.

- [Scalar plot and traceable diagnostics](gate-2-scalar.png)
- [Linked oscillator signal plots](gate-2-oscillator.png)

## Gate 1 — Source admission and inspection

1. Open a workspace with distinct source and evidence roots. In the source root, create an `external-results/` folder and copy the [scalar decay and damped oscillator CSVs](../../apps/workbench/e2e/data/external-results/) into it.
2. Choose **Modules → Workspace & Models → External results**. Select each CSV. Inspect its time and signal columns, cycle through the sample pages, and compare the visible SHA-256 to the output of `Get-FileHash -Algorithm SHA256` or `sha256sum` on the file.
3. Update one CSV on disk. Select the changed file using its old listing entry. Verify the change refusal, then choose **Refresh results** and reselect the file to read the new bytes.
4. Run the focused browser test above for the admission and revalidation workflow.

The CSVs are numerical fixtures generated independently of the Workbench. The scalar decay solves `dc/dt = -1.25 c` with explicit Euler, starting at 1 mol/m³. The damped oscillator integrates `dx/dt = v`, `dv/dt = -4 x - 0.5 v` with velocity-first Euler from `x = 1 m`, `v = 0 m/s`. Both record 81 samples including the initial state, at nominal 0.05 s spacing. These fixtures qualify transport and inspection.

The CSV reader preserves file order and uses binary64 values. Repeated or reversed times are available for timebase analysis. Units describe recorded values in their declared scale. A dimensionless unit of `1` leaves meanings such as angle and ratio to the researcher. The SHA-256 identifies the selected bytes at read time.

- [Scalar result inspection](gate-1-scalar.png)
- [Multichannel result inspection](gate-1-oscillator.png)
