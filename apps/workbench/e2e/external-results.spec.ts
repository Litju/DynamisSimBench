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
  await expect(page.getByText(digest(scalar), { exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "0.9375", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Next rows" }).click();
  await expect(page.getByText("Recorded samples 13–24 of 81")).toBeVisible();
  await page.getByRole("button", { name: "Previous rows" }).click();
  await expect(page.getByText("Recorded samples 1–12 of 81")).toBeVisible();

  const screenshotDir = process.env.DYNAMISBENCH_RESULTS_SCREENSHOTS;
  if (screenshotDir) {
    await page.setViewportSize({ width: 1440, height: 1040 });
    await page.screenshot({ path: path.join(screenshotDir, "gate-1-scalar.png") });
  }
  await page.getByRole("button", { name: "damped-oscillator.csv", exact: true }).click();
  await expect(page.getByRole("columnheader", { name: "acceleration [m/s^2]" })).toBeVisible();
  await expect(page.getByText(digest(oscillator), { exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "-4", exact: true })).toBeVisible();
  if (screenshotDir) {
    await page.screenshot({ path: path.join(screenshotDir, "gate-1-oscillator.png") });
  }

  await page.getByRole("button", { name: "wrong-schema.csv", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("Use a header beginning with time[s]");
  await page.getByRole("button", { name: "scalar-decay.csv", exact: true }).click();
  await expect(page.getByText(digest(scalar), { exact: true })).toBeVisible();
  await writeFile(path.join(folder, "scalar-decay.csv"), "time[s],concentration[mol/m^3]\n0,42");
  await page.getByRole("button", { name: "scalar-decay.csv", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("The result changed.");
  await expect(page.getByRole("table")).toHaveCount(0);
  await page.getByRole("button", { name: "Refresh results" }).click();
  await page.getByRole("button", { name: "scalar-decay.csv", exact: true }).click();
  await expect(page.getByRole("cell", { name: "42", exact: true })).toBeVisible();
  await expect(page.getByText(digest(scalar), { exact: true })).toHaveCount(0);

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
