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

  // A folio link's address opens that folio on its own, as a new tab or window loads it.
  await toggle.click();
  const analysisHref = await panel.getByRole("link", { name: /^Analysis/ }).getAttribute("href");
  expect(analysisHref).toBe(`/laboratory?workspace=${workspaceId}&folio=analysis`);
  await page.goto(analysisHref!);
  await expect(page.getByRole("navigation", { name: "Folios" }).getByRole("button", { pressed: true })).toContainText(
    "Analysis",
    { timeout: 30_000 },
  );
  await page.waitForURL((url) => url.pathname === "/laboratory" && url.search === `?workspace=${workspaceId}`);
  await page.goto(workspaceUrl);

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

test("a narrow window keeps the header to two rows and the folio names whole", async ({ page, harness }) => {
  expect(harness.sidecar.credential).not.toBe("");
  await page.setViewportSize({ width: 760, height: 900 });
  const { toggle } = menu(page);
  const theme = page.getByRole("button", { name: "Toggle color theme" });
  const workbench = page.getByRole("navigation", { name: "Workbench" });

  // Identity, Modules, status and ground share the first row; the Workbench links the second.
  const [toggleBox, themeBox, navBox] = await Promise.all([toggle.boundingBox(), theme.boundingBox(), workbench.boundingBox()]);
  expect(Math.abs(themeBox!.y + themeBox!.height / 2 - (toggleBox!.y + toggleBox!.height / 2))).toBeLessThan(8);
  expect(navBox!.y).toBeGreaterThanOrEqual(toggleBox!.y + toggleBox!.height);

  await workbench.getByRole("link", { name: "Laboratory", exact: true }).click();
  const folios = page.getByRole("navigation", { name: "Folios" });
  await expect(folios).toBeVisible({ timeout: 30_000 });
  for (const button of await folios.getByRole("button").all()) {
    const box = await button.boundingBox();
    expect(box!.height, (await button.textContent()) ?? "").toBeLessThan(40);
  }
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(0);
});

// Opt-in screenshots of the shell and the open menu, captured from the running application:
// the overview, a real opened workspace and a workspace-bound Laboratory folio, at a desktop
// and a narrow width, in Studiolo and Vellum. Nothing is captured unless a directory is named.
test("modules menu screenshots", async ({ page, harness }) => {
  const directory = process.env.DYNAMISBENCH_UX_SCREENSHOTS;
  test.skip(directory === undefined, "set DYNAMISBENCH_UX_SCREENSHOTS to a directory to capture");
  if (directory === undefined) return;
  test.setTimeout(300_000);
  await mkdir(directory, { recursive: true });
  const { toggle, panel } = menu(page);
  const shoot = async (name: string) => {
    await page.waitForTimeout(300);
    await page.screenshot({ path: path.join(directory, `${name}.png`) });
  };
  const ground = async (want: "studiolo" | "vellum") => {
    const dark = (await page.locator(".wb-shell").getAttribute("data-theme")) === "dark";
    if (dark !== (want === "studiolo")) await page.getByRole("button", { name: "Toggle color theme" }).click();
  };

  for (const [width, height] of [[1440, 900], [760, 900]] as const) {
    await page.setViewportSize({ width, height });
    for (const theme of ["studiolo", "vellum"] as const) {
      await page.goto("/");
      await ground(theme);
      await toggle.click();
      await shoot(`overview-menu-${width}-${theme}`);
      await page.keyboard.press("Escape");
    }
  }

  await page.setViewportSize({ width: 1440, height: 900 });
  await page.getByLabel("Source root").fill(harness.workspace.sourceRoot);
  await page.getByLabel("Evidence root").fill(harness.workspace.evidenceRoot);
  await page.getByRole("button", { name: "Open workspace", exact: true }).click();
  await page.waitForURL(/\/workspace\/[A-Za-z0-9_-]+$/);
  const workspaceUrl = page.url();

  for (const [width, height] of [[1440, 900], [760, 900]] as const) {
    await page.setViewportSize({ width, height });
    for (const theme of ["studiolo", "vellum"] as const) {
      await page.goto(workspaceUrl);
      await ground(theme);
      await shoot(`workspace-${width}-${theme}`);
      await toggle.click();
      await page.keyboard.press("Tab");
      await shoot(`workspace-menu-${width}-${theme}`);
      await page.keyboard.press("Escape");
      await toggle.click();
      await panel.getByRole("link", { name: /^Analysis/ }).click();
      await expect(page.getByRole("heading", { name: "Biomechanics Laboratory", exact: true })).toBeVisible({
        timeout: 30_000,
      });
      await shoot(`laboratory-${width}-${theme}`);
      await toggle.click();
      await shoot(`laboratory-menu-${width}-${theme}`);
      await page.keyboard.press("Escape");
    }
  }
  expect(await page.content()).not.toContain(harness.sidecar.credential);
});
