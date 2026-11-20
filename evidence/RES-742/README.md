# RES-742 Gate 1 acceptance

[Linear issue](https://linear.app/alignerr-cmj/issue/RES-742/db-app-01-first-usable-simulation-agnostic-diagnostic-workspace) · [Accepted roadmap](https://linear.app/alignerr-cmj/document/dynamisbench-roadmap-and-delivery-governance-simulation-agnostic-03b89000a9ef)

1. Open a workspace with distinct source and evidence roots. In the source root, create an `external-results/` folder and copy both [fixture CSVs](../../apps/workbench/e2e/data/external-results/) into it.
2. Choose **Modules → Workspace & Models → External results**. Select each CSV. Inspect its time and signal columns, cycle through the sample pages, and compare the visible SHA-256 to the output of `Get-FileHash -Algorithm SHA256` or `sha256sum` on the file.
3. Update one CSV on disk. Select the changed file using its old listing entry. Verify the change refusal, then choose **Refresh results** and reselect the file to read the new bytes.
4. Run the same workflow against the secured sidecar with `pnpm --filter @dynamisbench/workbench run test:e2e external-results.spec.ts`. Set `DYNAMISBENCH_RESULTS_SCREENSHOTS` to a local directory to capture the inspection views.

The CSVs are numerical fixtures generated independently of the Workbench. The scalar decay solves `dc/dt = -1.25 c` with explicit Euler, starting at 1 mol/m³. The damped oscillator integrates `dx/dt = v`, `dv/dt = -4 x - 0.5 v` with velocity-first Euler from `x = 1 m`, `v = 0 m/s`. Both record 81 samples including the initial state, at nominal 0.05 s spacing. These fixtures qualify transport and inspection.

The CSV reader preserves file order and uses binary64 values. Repeated or reversed times are available for timebase analysis. Units describe recorded values in their declared scale. A dimensionless unit of `1` leaves meanings such as angle and ratio to the researcher. The SHA-256 identifies the selected bytes at read time.

- [Scalar result inspection](gate-1-scalar.png)
- [Multichannel result inspection](gate-1-oscillator.png)
