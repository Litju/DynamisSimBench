import { expect, type Page } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import path from "node:path";

import { test } from "./support/fixtures";

// The platform Modules menu against a real secured sidecar: keyboard, focus, Escape, workspace
// context and the truthful Planned/Unsupported states, in the production route tree.

function menu(page: Page) {
  return {
    toggle: page.getByRole("button", { name: "Modules", exact: true }),
    panel: page.getByRole("navigation", { name: "Modules", exact: true }),
  };
}

test("the Modules menu opens by keyboard, states what is planned, and returns focus on Escape", async ({
  page,
  harness,
  network,
}) => {
  const { toggle, panel } = menu(page);
  await expect(toggle).toHaveAttribute("aria-expanded", "false");

  await toggle.focus();
  await page.keyboard.press("Enter");
  await expect(panel).toBeVisible();
  await expect(toggle).toHaveAttribute("aria-expanded", "true");

  await page.keyboard.press("Tab");
  await expect(panel.getByRole("link", { name: /Open workspace/ })).toBeFocused();

  // Nothing planned or unsupported is a link or a Tab stop.
  for (const name of [/Diagnostics/, /Benchmark packages/, /^Extensions/, /Model Studio/]) {
    await expect(panel.getByRole("link", { name })).toHaveCount(0);
  }
  await expect(panel.getByText("Unsupported", { exact: true })).toBeVisible();
  await expect(panel.getByText("Open a workspace first")).toBeVisible();

  await page.keyboard.press("Escape");
  await expect(panel).toBeHidden();
  await expect(toggle).toBeFocused();

  expect(await page.content()).not.toContain(harness.sidecar.credential);
  expect(network.offenses).toEqual([]);
});

test("the Modules menu keeps the opaque workspace context and opens real Laboratory folios", async ({
  page,
  harness,
  network,
}) => {
  test.setTimeout(120_000);
  await page.getByLabel("Source root").fill(harness.workspace.sourceRoot);
  await page.getByLabel("Evidence root").fill(harness.workspace.evidenceRoot);
  await page.getByRole("button", { name: "Open workspace", exact: true }).click();
  await page.waitForURL(/\/workspace\/[A-Za-z0-9_-]+$/);
  const workspaceUrl = page.url();
  const workspaceId = new URL(workspaceUrl).pathname.split("/").pop() ?? "";

  const { toggle, panel } = menu(page);
  await toggle.click();
  await expect(panel.getByRole("link", { name: /Current workspace/ })).toHaveAttribute(
    "href",
    `/workspace/${workspaceId}`,
  );

  await panel.getByRole("link", { name: /^Evidence/ }).click();
  await page.waitForURL(
    (url) => url.pathname === "/laboratory" && url.search === `?workspace=${workspaceId}`,
  );
  await expect(page.getByRole("heading", { name: "Biomechanics Laboratory", exact: true })).toBeVisible({
    timeout: 30_000,
  });
  await expect(page.getByRole("navigation", { name: "Folios" }).getByRole("button", { pressed: true })).toContainText(
    "Evidence",
  );
  await expect(toggle).toHaveAttribute("aria-expanded", "false");

  await toggle.click();
  await expect(panel.getByRole("link", { name: /^Evidence/ })).toHaveAttribute("aria-current", "page");
  await expect(panel.getByRole("link", { name: /^Analysis/ })).not.toHaveAttribute("aria-current", "page");

  // Back to the workspace by the menu, with the same identifier.
  await panel.getByRole("link", { name: /Current workspace/ }).click();
  await page.waitForURL(workspaceUrl);

  // The workspace identifier is the only context in any URL.
  expect(page.url()).not.toContain(harness.workspace.sourceRoot);
  expect(page.url()).not.toContain(harness.sidecar.credential);
  expect(network.offenses).toEqual([]);
});

test("the Modules panel stays inside narrow windows", async ({ page, harness }) => {
  expect(harness.sidecar.credential).not.toBe("");
  for (const width of [1280, 820, 600]) {
    await page.setViewportSize({ width, height: 800 });
    const { toggle, panel } = menu(page);
    await toggle.click();
    const box = await panel.boundingBox();
    expect(box, `panel at ${width}px`).not.toBeNull();
    expect(box!.x).toBeGreaterThanOrEqual(0);
    expect(box!.x + box!.width).toBeLessThanOrEqual(width);
    await page.keyboard.press("Escape");
  }
});

// Opt-in screenshots of the open menu, captured from the running application.
test("modules menu screenshots", async ({ page, harness }) => {
  const directory = process.env.DYNAMISBENCH_UX_SCREENSHOTS;
  test.skip(directory === undefined, "set DYNAMISBENCH_UX_SCREENSHOTS to a directory to capture");
  if (directory === undefined) return;
  expect(harness.sidecar.credential).not.toBe("");
  await mkdir(directory, { recursive: true });
  for (const [name, width, height] of [
    ["desktop", 1440, 900],
    ["narrow", 700, 900],
  ] as const) {
    await page.setViewportSize({ width, height });
    await menu(page).toggle.click();
    await page.waitForTimeout(300);
    await page.screenshot({ path: path.join(directory, `modules-menu-${name}-studiolo.png`) });
    await page.keyboard.press("Escape");
    await page.getByRole("button", { name: "Toggle color theme" }).click();
    await menu(page).toggle.click();
    await page.waitForTimeout(300);
    await page.screenshot({ path: path.join(directory, `modules-menu-${name}-vellum.png`) });
    await page.keyboard.press("Escape");
    await page.getByRole("button", { name: "Toggle color theme" }).click();
  }
});
