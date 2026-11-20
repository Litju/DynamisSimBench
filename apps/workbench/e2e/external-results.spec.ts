import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import { expect } from "@playwright/test";

import { test } from "./support/fixtures";
import { repositoryRoot } from "./support/paths";

test("discovers and inspects numeric files through the secured sidecar", async ({ page, harness, network }) => {
  const { sourceRoot, evidenceRoot } = harness.workspace;
  const folder = path.join(sourceRoot, "external-results");
  const fixtures = path.join(repositoryRoot(), "apps/workbench/e2e/data/external-results");
  const scalar = await readFile(path.join(fixtures, "scalar-decay.csv"));
  const oscillator = await readFile(path.join(fixtures, "damped-oscillator.csv"));
  const digest = (source: Buffer) => createHash("sha256").update(source).digest("hex");
  await mkdir(folder);
  await Promise.all([
    writeFile(path.join(folder, "scalar-decay.csv"), scalar),
    writeFile(path.join(folder, "damped-oscillator.csv"), oscillator),
    writeFile(path.join(folder, "wrong-schema.csv"), "time[ms],x[m]\n0,2"),
    writeFile(path.join(folder, "oversize.csv"), Buffer.alloc(1024 * 1024 + 1)),
    writeFile(path.join(folder, "unsupported.parquet"), Buffer.from("PAR1")),
    writeFile(path.join(evidenceRoot, "outside.csv"), scalar),
  ]);

  const apiUrls: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname.includes("/external-results")) apiUrls.push(request.url());
  });
  await page.getByLabel("Source root").fill(sourceRoot);
  await page.getByLabel("Evidence root").fill(evidenceRoot);
  await page.getByRole("button", { name: "Open workspace", exact: true }).click();
  await page.waitForURL(/\/workspace\/[A-Za-z0-9_-]+$/);
  await page.getByRole("button", { name: "Modules", exact: true }).click();
  await page.getByRole("navigation", { name: "Modules", exact: true }).getByRole("link", { name: /^External results/ }).click();
  await expect(page.getByRole("heading", { name: "External results" })).toBeVisible();
  await expect(page.getByText("oversize.csv", { exact: true })).toBeVisible();
  await expect(page.getByText("The source exceeds the external-results limits.")).toBeVisible();
  await expect(page.getByText("unsupported.parquet", { exact: true })).toHaveCount(0);
  await expect(page.getByText("outside.csv", { exact: true })).toHaveCount(0);

  await page.getByRole("button", { name: "scalar-decay.csv", exact: true }).click();
  await expect(page.getByRole("columnheader", { name: "concentration [mol/m^3]" })).toBeVisible();
  const source = page.getByLabel("Result source", { exact: true });
  await expect(source).toContainText(digest(scalar));
  const scalarPlot = page.getByRole("img", { name: "concentration [mol/m^3] over time [s]" });
  await expect(scalarPlot).toBeVisible();
  const slider = page.getByRole("slider", { name: "Inspect sample" });
  await slider.focus();
  await slider.press("ArrowRight");
  await expect(slider).toHaveAttribute("aria-valuetext", "Row 2, time 0.05 s");
  await expect(page.getByLabel("Inspected signal values")).toContainText("0.9375 [mol/m^3]");
  await page.getByRole("button", { name: "Zoom in", exact: true }).click();
  await expect(page.getByLabel("Visible time span")).not.toContainText("81 of 81 rows");
  await page.getByRole("button", { name: "Zoom out", exact: true }).click();
  await expect(page.getByLabel("Visible time span")).toHaveText("0 to 4 s · 81 of 81 rows");
  const diagnostics = page.getByRole("region", { name: "Numerical diagnostics" });
  await expect(diagnostics).toContainText("external-results/diagnostics-v1");
  await expect(diagnostics.getByText("PASS", { exact: true })).toHaveCount(5);
  const sampling = diagnostics.locator("details").filter({ hasText: "Sampling regularity" });
  await sampling.locator("summary").click();
  await expect(sampling.getByText(digest(scalar), { exact: true })).toBeVisible();
  await expect(sampling).toContainText("median observed step");
  await expect(sampling).toContainText("cannot infer a prescribed cadence");
  await expect(page.getByRole("cell", { name: "0.9375", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Next rows" }).click();
  await expect(page.getByText("Recorded samples 13–24 of 81")).toBeVisible();
  await page.getByRole("button", { name: "Previous rows" }).click();
  await expect(page.getByText("Recorded samples 1–12 of 81")).toBeVisible();

  const screenshotDir = process.env.DYNAMISBENCH_RESULTS_SCREENSHOTS;
  if (screenshotDir) {
    await page.setViewportSize({ width: 1440, height: 1140 });
    await page.getByRole("heading", { name: "External results" }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: path.join(screenshotDir, "gate-2-scalar.png") });
  }
  await page.getByRole("button", { name: "damped-oscillator.csv", exact: true }).click();
  await expect(page.getByRole("columnheader", { name: "acceleration [m/s^2]" })).toBeVisible();
  await expect(source).toContainText(digest(oscillator));
  await expect(page.getByLabel("Visible time span")).toHaveText("0 to 4 s · 81 of 81 rows");
  await expect(diagnostics.getByText("PASS", { exact: true })).toHaveCount(9);
  await page.getByRole("checkbox", { name: "velocity [m/s]", exact: true }).check();
  const position = page.getByRole("img", { name: "position [m] over time [s]" });
  const velocity = page.getByRole("img", { name: "velocity [m/s] over time [s]" });
  await expect(position).toBeVisible();
  await expect(velocity).toBeVisible();
  const box = await velocity.boundingBox();
  if (box === null) throw new Error("Expected a visible velocity plot");
  await velocity.click({ position: { x: box.width - 42, y: 30 } });
  await expect(slider).toHaveAttribute("aria-valuetext", "Row 81, time 4 s");
  await expect(page.getByLabel("Inspected signal values")).toContainText("position");
  await expect(page.getByLabel("Inspected signal values")).toContainText("velocity");
  await page.getByRole("button", { name: "Zoom in", exact: true }).click();
  await expect(page.getByLabel("Visible time span")).toHaveText("2 to 4 s · 41 of 81 rows");
  await page.getByRole("button", { name: "Reset zoom", exact: true }).click();
  await page.getByRole("checkbox", { name: "position [m]", exact: true }).uncheck();
  await expect(position).toHaveCount(0);
  await page.getByRole("checkbox", { name: "position [m]", exact: true }).check();
  await expect(page.getByRole("cell", { name: "-4", exact: true })).toBeVisible();
  if (screenshotDir) {
    await page.getByRole("region", { name: "Time-series plots" })
      .screenshot({ path: path.join(screenshotDir, "gate-2-oscillator.png") });
  }
  await page.setViewportSize({ width: 420, height: 850 });
  await expect(position).toBeVisible();
  await expect(velocity).toBeVisible();
  await expect.poll(() => page.getByRole("region", { name: "Time-series plots" }).evaluate(
    (element) => element.scrollWidth - element.clientWidth,
  )).toBeLessThanOrEqual(1);
  await page.setViewportSize({ width: 1280, height: 800 });

  await page.getByRole("button", { name: "wrong-schema.csv", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("Use a header beginning with time[s]");
  await page.getByRole("button", { name: "scalar-decay.csv", exact: true }).click();
  await expect(source).toContainText(digest(scalar));
  await writeFile(path.join(folder, "scalar-decay.csv"), "time[s],concentration[mol/m^3]\n0,42");
  await page.getByRole("button", { name: "scalar-decay.csv", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("The result changed.");
  await expect(page.getByRole("table")).toHaveCount(0);
  await expect(scalarPlot).toHaveCount(0);
  await expect(diagnostics).toHaveCount(0);
  await page.getByRole("button", { name: "Refresh results" }).click();
  await page.getByRole("button", { name: "scalar-decay.csv", exact: true }).click();
  await expect(page.getByRole("cell", { name: "42", exact: true })).toBeVisible();
  await expect(page.getByText(digest(scalar), { exact: true })).toHaveCount(0);
  await expect(diagnostics.getByText("INCONCLUSIVE", { exact: true })).toHaveCount(2);
  await expect(page.getByRole("button", { name: "Zoom in", exact: true })).toBeDisabled();

  expect(apiUrls.length).toBeGreaterThan(6);
  for (const url of apiUrls) {
    expect(new URL(url).pathname).toMatch(
      /^\/api\/v1\/workspaces\/[A-Za-z0-9_-]{32}\/external-results(?:\/[A-Za-z0-9_-]{32}(?:\/samples)?)?$/,
    );
    expect(new URL(url).search).toBe("");
    expect(url).not.toContain(harness.sidecar.credential);
  }
  expect(await page.content()).not.toContain(harness.sidecar.credential);
  expect(network.offenses).toEqual([]);

  await page.goto("/workspace/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/results");
  await expect(page.getByRole("alert")).toContainText("Open the workspace");
  await expect(page.getByRole("alert").getByRole("link", { name: "Open workspace" })).toBeVisible();
});

test("exposes gaps, nonfinite observations, irregular grids and source refusals", async ({ page, harness }) => {
  const { sourceRoot, evidenceRoot } = harness.workspace;
  const folder = path.join(sourceRoot, "external-results");
  await mkdir(folder);
  const gaps = "time[s],x[m]\n0,2\n1,100\n2,\n3,-100\n4,NaN\n5,+Inf\n6,-Inf\n7,3";
  const files = {
    "gaps.csv": gaps,
    "irregular.csv": "time[s],x[m]\n0,0\n1,2\n5,-9\n6,5",
    "duplicates.csv": "time[s],x[m]\n0,0\n2,1\n0,2",
    "extreme.csv": "time[s],x[m]\n-1e308,-1e308\n1e308,1e308",
    "bad-row.csv": "time[s],x[m]\n0,1\n1,2,3",
  };
  await Promise.all(Object.entries(files).map(([name, contents]) => writeFile(path.join(folder, name), contents)));

  await page.getByLabel("Source root").fill(sourceRoot);
  await page.getByLabel("Evidence root").fill(evidenceRoot);
  await page.getByRole("button", { name: "Open workspace", exact: true }).click();
  await page.waitForURL(/\/workspace\/[A-Za-z0-9_-]+$/);
  await page.getByRole("button", { name: "Modules", exact: true }).click();
  await page.getByRole("navigation", { name: "Modules", exact: true }).getByRole("link", { name: /^External results/ }).click();

  const choose = (name: keyof typeof files) => page.getByRole("button", { name, exact: true }).click();
  const plot = page.getByRole("img", { name: "x [m] over time [s]" });
  const diagnostics = page.getByRole("region", { name: "Numerical diagnostics" });
  const finding = (label: string) => diagnostics.locator("details").filter({ hasText: label });

  await choose("gaps.csv");
  await expect(plot).toBeVisible();
  await expect(page.getByText("Missing · upper marks")).toBeVisible();
  await expect(page.getByText("Nonfinite · lower marks")).toBeVisible();
  await expect(plot.getByText("100", { exact: true })).toBeVisible();
  await expect(plot.getByText("-100", { exact: true })).toBeVisible();
  await expect(finding("Missing values").locator("summary")).toContainText("FAIL");
  const nonfinite = finding("Nonfinite values");
  await nonfinite.locator("summary").click();
  await expect(nonfinite).toContainText("3 of 7 present values are nonfinite (1 NaN, 1 +Inf, 1 −Inf).");
  await expect(nonfinite.getByText(createHash("sha256").update(gaps).digest("hex"), { exact: true })).toBeVisible();
  const slider = page.getByRole("slider", { name: "Inspect sample" });
  await slider.focus();
  await slider.press("Home");
  await slider.press("ArrowRight");
  await slider.press("ArrowRight");
  await expect(page.getByLabel("Inspected signal values")).toContainText("Missing [m]");
  await slider.press("End");
  await slider.press("ArrowLeft");
  await expect(page.getByLabel("Inspected signal values")).toContainText("-Infinity [m]");
  await page.getByRole("button", { name: "Zoom in", exact: true }).click();
  await expect(page.getByLabel("Visible time span")).toContainText("4 of 8 rows");
  await expect(nonfinite).toContainText("3 of 7 present values");

  await choose("irregular.csv");
  const regularity = finding("Sampling regularity");
  await expect(regularity.locator("summary")).toContainText("FAIL");
  await regularity.locator("summary").click();
  await expect(regularity).toContainText("1 of 3 intervals exceed the tolerance. Median 1 s, range 1 to 4 s.");
  await expect(page.getByText(/Line guides require a regular time grid/)).toBeVisible();

  await choose("duplicates.csv");
  await expect(finding("Strict time increase").locator("summary")).toContainText("FAIL");
  await expect(finding("Duplicate timestamps").locator("summary")).toContainText("FAIL");
  await expect(regularity.locator("summary")).toContainText("INCONCLUSIVE");
  await slider.focus();
  await slider.press("End");
  await expect(slider).toHaveAttribute("aria-valuetext", "Row 3, time 0 s");

  await choose("extreme.csv");
  await expect(regularity.locator("summary")).toContainText("UNSUPPORTED");
  await expect(plot).toBeVisible();
  expect(await plot.locator("[d]").evaluateAll((paths) => paths.map((element) => element.getAttribute("d"))))
    .not.toEqual(expect.arrayContaining([expect.stringMatching(/NaN|Infinity/)]));

  await choose("bad-row.csv");
  await expect(page.getByRole("alert")).toContainText("Each row must match the header");
  await expect(plot).toHaveCount(0);
  await expect(diagnostics).toHaveCount(0);
});
