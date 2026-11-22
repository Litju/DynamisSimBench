import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import { expect, type Page } from "@playwright/test";

import { test, type Harness } from "./support/fixtures";
import { repositoryRoot } from "./support/paths";

async function openComparisonWorkspace(page: Page, { workspace }: Harness) {
  await page.getByLabel("Source root").fill(workspace.sourceRoot);
  await page.getByLabel("Evidence root").fill(workspace.evidenceRoot);
  await page.getByRole("button", { name: "Open workspace", exact: true }).click();
  await page.waitForURL(/\/workspace\/[A-Za-z0-9_-]+$/);
  await page.getByRole("button", { name: "Modules", exact: true }).click();
  await page.getByRole("navigation", { name: "Modules", exact: true }).getByRole("link", { name: /^External results/ }).click();
  return {
    pickA: (name: string) => page.getByRole("button", { name, exact: true }).click(),
    sourceB: page.getByRole("combobox", { name: "Source B" }),
    comparison: page.getByRole("region", { name: "A/B comparison", exact: true }),
    cursor: page.getByRole("slider", { name: "Inspect comparison time" }),
    confirm: page.getByRole("checkbox", { name: /^I confirm/ }),
  };
}

test("compares two revalidated multichannel CSV recordings using linked keyboard and pointer inspection", async ({ page, harness, network }) => {
  const folder = path.join(harness.workspace.sourceRoot, "external-results");
  const fixtureFolder = path.join(repositoryRoot(), "apps/workbench/e2e/data/external-results");
  const nameA = "damped-oscillator.csv";
  const nameB = "damped-oscillator-double-amplitude.csv";
  const [a, b] = await Promise.all([readFile(path.join(fixtureFolder, nameA)), readFile(path.join(fixtureFolder, nameB))]);
  const digest = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");
  await mkdir(folder);
  await Promise.all([writeFile(path.join(folder, nameA), a), writeFile(path.join(folder, nameB), b)]);
  const requests: URL[] = [];
  page.on("request", (request) => {
    if (request.url().includes("/external-results")) requests.push(new URL(request.url()));
  });

  const { pickA, sourceB, comparison, cursor, confirm } = await openComparisonWorkspace(page, harness);
  await sourceB.selectOption({ label: nameB });
  await expect(page.getByText("Select a readable source A to compare.", { exact: false })).toContainText(digest(b));
  const beforePair = requests.length;
  await pickA(nameA);
  await expect(comparison).toContainText("81 exact pairs · 0 A-only · 0 B-only");
  expect(requests.slice(beforePair).filter(({ pathname }) => pathname.endsWith("/samples"))).toHaveLength(2);
  await expect(comparison.getByRole("article", { name: "Source A provenance" })).toContainText(digest(a));
  await expect(comparison.getByRole("article", { name: "Source B provenance" })).toContainText(digest(b));
  await expect(comparison).toContainText("3 compatible quantities");
  const table = comparison.getByRole("table");
  const position = comparison.getByRole("img", { name: "A and B · position [m] over time [s]" });
  const velocity = comparison.getByRole("img", { name: "A and B · velocity [m/s] over time [s]" });
  await expect(position).toBeVisible();
  await expect(table.getByRole("cell", { name: "Confirm comparability" })).toBeVisible();
  await confirm.focus();
  await confirm.press("Space");
  await expect(table.getByRole("row", { name: "position [m] 1 2 1" })).toBeVisible();
  await comparison.getByRole("checkbox", { name: "velocity [m/s]" }).check();
  await expect(velocity).toBeVisible();
  await cursor.focus();
  await cursor.press("ArrowRight");
  await expect(cursor).toHaveAttribute("aria-valuetext", "0.05 s · A row 2 · B row 2");
  await expect(table.getByRole("row", { name: "position [m] 0.99 1.98 0.99" })).toBeVisible();
  await expect(table.getByRole("row", { name: "velocity [m/s] -0.2 -0.4 -0.2" })).toBeVisible();
  const box = await velocity.boundingBox();
  if (box === null) throw new Error("Expected a visible velocity overlay");
  await velocity.click({ position: { x: box.width - 42, y: 30 } });
  await expect(cursor).toHaveAttribute("aria-valuetext", "4 s · A row 81 · B row 81");
  await comparison.getByRole("button", { name: "Zoom in", exact: true }).click();
  await expect(comparison.getByLabel("Comparison visible time span")).toHaveText("2 to 4 s · 41 of 81 times");
  await comparison.getByRole("button", { name: "Reset zoom", exact: true }).click();
  await cursor.focus();
  await cursor.press("Home");
  await cursor.press("ArrowRight");
  const screenshots = process.env.DYNAMISBENCH_RESULTS_SCREENSHOTS;
  if (screenshots !== undefined) {
    await page.setViewportSize({ width: 1440, height: 1570 });
    await page.getByRole("heading", { name: "External results" }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: path.join(screenshots, "gate-3-oscillator-comparison.png") });
  }
  await page.setViewportSize({ width: 420, height: 850 });
  await expect.poll(() => comparison.evaluate((element) => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(1);

  // Change B after metadata succeeds, just as its separate Arrow read reaches the sidecar.
  const handleB = await sourceB.inputValue();
  await page.route((url) => url.pathname.endsWith(`/${handleB}/samples`), async (route) => {
    await writeFile(path.join(folder, nameB), "time[s],position[m]\n0,3");
    await route.continue();
  }, { times: 1 });
  await page.getByRole("button", { name: "Revalidate sources" }).click();
  await expect(page.getByRole("alert")).toContainText("Source B · The result changed");
  await expect(comparison).toHaveCount(0);
  await page.getByRole("button", { name: "Refresh results" }).click();
  await expect(page.getByText("Source B changed or became unavailable.")).toBeVisible();
  await sourceB.selectOption({ label: nameB });
  await expect(comparison).toContainText("1 exact pair ·");
  await expect(confirm).not.toBeChecked();
  await writeFile(path.join(folder, nameA), "time[s],position[m]\n0,7");
  await page.getByRole("button", { name: "Revalidate sources" }).click();
  await expect(page.getByRole("alert")).toContainText("Source A · The result changed");
  await expect(comparison).toHaveCount(0);

  expect(requests.length).toBeGreaterThan(12);
  for (const url of requests) {
    expect(url.pathname).toMatch(/^\/api\/v1\/workspaces\/[A-Za-z0-9_-]{32}\/external-results(?:\/[A-Za-z0-9_-]{32}(?:\/samples)?)?$/);
    expect(url.search).toBe("");
    expect(url.href).not.toContain(harness.sidecar.credential);
  }
  expect(await page.content()).not.toContain(harness.sidecar.credential);
  expect(network.offenses).toEqual([]);
});

test("explains quantity, timebase and value refusals using admitted and corrupt sources", async ({ page, harness }) => {
  const folder = path.join(harness.workspace.sourceRoot, "external-results");
  const files = {
    "a.csv": "time[s],position[m],force[N]\n0,1,3\n1,2,3\n2,,3\n3,4,3\n4,5,3",
    "b.csv": "time[s],position[m],force[kg*m/s^2]\n0,4,1\n0.5,1,1\n2,9,1\n3,Inf,1\n4,2,1",
    "units.csv": "time[s],position[s]\n0,2\n1,3",
    "duplicate.csv": "time[s],position[m]\n0,2\n0,3",
    "shifted.csv": "time[s],position[m]\n0.5,2\n1.5,3",
    "disjoint.csv": "time[s],position[m]\n5,2\n6,3",
    "corrupt.csv": "time[s],position[m]\n0,1,2",
  };
  await mkdir(folder);
  await Promise.all(Object.entries(files).map(([name, contents]) => writeFile(path.join(folder, name), contents)));
  const { pickA, sourceB, comparison, cursor, confirm } = await openComparisonWorkspace(page, harness);
  await pickA("a.csv");
  await sourceB.selectOption({ label: "b.csv" });
  await expect(comparison).toContainText("4 exact pairs · 1 A-only · 1 B-only");
  await expect(comparison).toContainText("Different recorded time grids");
  await confirm.check();
  await cursor.focus();
  await cursor.press("ArrowRight");
  const table = comparison.getByRole("table");
  await expect(table).toContainText("Unmatched time");
  await expect(table).toContainText("No sample");
  await cursor.press("ArrowRight");
  await expect(table).toContainText("Unmatched time");
  await cursor.press("ArrowRight");
  await expect(table).toContainText("Missing value");
  await cursor.press("ArrowRight");
  await expect(table).toContainText("Nonfinite value");
  await cursor.press("End");
  await expect(table.getByRole("row", { name: "position [m] 5 2 -3" })).toBeVisible();
  await expect(comparison.getByText("Marks below axis · A above B")).toBeVisible();
  await comparison.getByText("1 unsupported quantity", { exact: true }).click();
  await expect(comparison.getByText("force · unit mismatch · A [N] · B [kg*m/s^2]")).toBeVisible();

  const screenshots = process.env.DYNAMISBENCH_RESULTS_SCREENSHOTS;
  if (screenshots !== undefined) {
    await page.setViewportSize({ width: 1440, height: 1380 });
    await cursor.focus();
    await cursor.press("ArrowLeft");
    await page.getByRole("heading", { name: "External results" }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: path.join(screenshots, "gate-3-partial-grid.png") });
  }
  await sourceB.selectOption({ label: "units.csv" });
  await expect(comparison).toContainText("Unsupported quantities");
  await expect(comparison).toContainText("position · unit mismatch · A [m] · B [s]");
  await expect(comparison.getByRole("img")).toHaveCount(0);
  await sourceB.selectOption({ label: "duplicate.csv" });
  await expect(comparison).toContainText("Unsupported timebase");
  await expect(comparison).toContainText("Check source B");
  await expect(comparison.getByRole("img")).toHaveCount(0);
  await sourceB.selectOption({ label: "shifted.csv" });
  await expect(comparison).toContainText("overlap with no exact timestamp matches");
  await expect(confirm).toHaveCount(0);
  await expect(table).toContainText("Unmatched time");
  await sourceB.selectOption({ label: "disjoint.csv" });
  await expect(comparison).toContainText("ranges are disjoint");
  await expect(table).toContainText("Unmatched time");
  await sourceB.selectOption({ label: "corrupt.csv" });
  await expect(page.getByRole("alert")).toContainText("Source B · Each row must match the header");
  await expect(comparison).toHaveCount(0);

  await sourceB.selectOption({ label: "b.csv" });
  await expect(comparison).toBeVisible();
  const handleB = await sourceB.inputValue();
  await page.route((url) => url.pathname.endsWith(`/${handleB}/samples`), async (route) => {
    const real = await route.fetch();
    expect(real.ok()).toBe(true);
    await route.fulfill({ status: 200, contentType: "application/vnd.apache.arrow.stream", body: "corrupt Arrow" });
  }, { times: 1 });
  await page.getByRole("button", { name: "Revalidate sources" }).click();
  await expect(page.getByRole("alert")).toContainText("Source B · The recorded data could not be decoded.");
  await expect(comparison).toHaveCount(0);
});

test("keeps both maximum-row sources inspectable and refuses an oversized candidate", async ({ page, harness }) => {
  const folder = path.join(harness.workspace.sourceRoot, "external-results");
  await mkdir(folder);
  const dense = (offset: number) => "time[s],x[m],y[m],z[m],speed[m/s]\n" +
    Array.from({ length: 20_000 }, (_, index) => `${2 * index + offset},${index},0,0,0`).join("\n");
  await Promise.all([
    writeFile(path.join(folder, "dense-a.csv"), dense(0)),
    writeFile(path.join(folder, "dense-b.csv"), dense(1)),
    writeFile(path.join(folder, "oversized.csv"), Buffer.alloc(1024 * 1024 + 1)),
  ]);
  const { pickA, sourceB, comparison, cursor } = await openComparisonWorkspace(page, harness);
  await expect(page.getByText("The source exceeds the external-results limits.")).toBeVisible();
  await expect(sourceB.getByRole("option", { name: "oversized.csv" })).toHaveCount(0);
  await pickA("dense-a.csv");
  await sourceB.selectOption({ label: "dense-b.csv" });
  await expect(comparison.getByLabel("Comparison visible time span")).toHaveText("0 to 39999 s · 40000 of 40000 times");
  await expect(comparison).toContainText("0 exact pairs · 20000 A-only · 20000 B-only");
  await cursor.focus();
  await cursor.press("End");
  await expect(cursor).toHaveAttribute("aria-valuetext", "39999 s · A has no row · B row 20000");
  await expect(comparison.getByRole("row", { name: "x [m] No sample 19999 Unmatched time" })).toBeVisible();
});
