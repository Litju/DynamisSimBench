/**
 * The Modules disclosure, driven the way a person drives it: real clicks and keys, against the
 * production route tree in a browser with no desktop session.
 */

import { userEvent } from "@testing-library/user-event";
import { screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { resetLaboratoryStore, useLaboratoryStore } from "../laboratory/store";
import { renderApplication } from "../test/render-app";

afterEach(() => {
  resetLaboratoryStore();
});

async function openMenu(path = "/") {
  const user = userEvent.setup();
  const view = renderApplication(path);
  const toggle = await screen.findByRole("button", { name: "Modules" });
  await user.click(toggle);
  const panel = screen.getByRole("navigation", { name: "Modules" });
  return { user, toggle, panel, ...view };
}

describe("the Modules disclosure", () => {
  it("is collapsed by default and exposes its state", async () => {
    renderApplication("/");
    const toggle = await screen.findByRole("button", { name: "Modules" });

    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("navigation", { name: "Modules" })).not.toBeInTheDocument();
  });

  it("opens by keyboard and lists the eight groups", async () => {
    const user = userEvent.setup();
    renderApplication("/");
    const toggle = await screen.findByRole("button", { name: "Modules" });
    toggle.focus();
    await user.keyboard("{Enter}");

    expect(toggle).toHaveAttribute("aria-expanded", "true");
    const panel = screen.getByRole("navigation", { name: "Modules" });
    expect(within(panel).getAllByRole("heading", { level: 2 }).map((h) => h.textContent)).toEqual([
      "Workspace & Models",
      "Simulation Laboratory",
      "Diagnostics",
      "Experiments & Comparison",
      "Benchmarks & Analysis",
      "Evidence & Provenance",
      "Extensions",
      "Model Studio",
    ]);
  });

  it("links only implemented destinations and states the rest plainly", async () => {
    const { panel } = await openMenu("/");
    const links = within(panel).getAllByRole("link");

    expect(links.map((link) => link.textContent?.split("Reference")[0])).toHaveLength(6);
    expect(within(panel).getByRole("link", { name: /Open workspace/ })).toHaveAttribute(
      "href",
      "/#open-workspace",
    );
    expect(within(panel).getByRole("link", { name: /^Analysis/ })).toHaveAttribute("href", "/laboratory");

    for (const name of ["Diagnostics", "Extensions", "Benchmark packages", "Model Studio"]) {
      expect(within(panel).queryByRole("link", { name: new RegExp(name) })).not.toBeInTheDocument();
    }
    expect(within(panel).getAllByText("Planned").length).toBeGreaterThanOrEqual(7);
    expect(within(panel).getByText("Unsupported")).toBeInTheDocument();
    expect(within(panel).getByText("Open a workspace first")).toBeInTheDocument();
  });

  it("opens a Laboratory folio and marks it as the current location", async () => {
    const { user, toggle } = await openMenu("/");
    await user.click(screen.getByRole("link", { name: /^Evidence/ }));

    expect(useLaboratoryStore.getState().folio).toBe("record");
    expect(toggle).toHaveAttribute("aria-expanded", "false");

    await user.click(toggle);
    expect(screen.getByRole("link", { name: /^Evidence/ })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: /^Analysis/ })).not.toHaveAttribute("aria-current");
  });

  it("carries the workspace context into the workspace and Laboratory links", async () => {
    const { panel } = await openMenu("/workspace/ws_abc-1");

    expect(within(panel).getByRole("link", { name: /Current workspace/ })).toHaveAttribute(
      "href",
      "/workspace/ws_abc-1",
    );
    expect(within(panel).getByRole("link", { name: /Study & Runs/ })).toHaveAttribute(
      "href",
      "/laboratory?workspace=ws_abc-1",
    );
  });

  it("says when the local API session is not ready", async () => {
    const { panel } = await openMenu("/");
    expect(within(panel).getByRole("status")).toHaveTextContent(/session is not ready/);
  });
});

describe("the Modules disclosure's focus behaviour", () => {
  it("closes on Escape and returns focus to its button", async () => {
    const { user, toggle, panel } = await openMenu("/");
    within(panel).getByRole("link", { name: /Open workspace/ }).focus();

    await user.keyboard("{Escape}");

    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(toggle).toHaveFocus();
  });

  it("reaches the first destination with Tab and closes when focus leaves the panel", async () => {
    const { user, toggle, panel } = await openMenu("/");
    toggle.focus();
    await user.tab();
    expect(within(panel).getByRole("link", { name: /Open workspace/ })).toHaveFocus();

    // Only available destinations take focus: one Tab stop per link.
    const links = within(panel).getAllByRole("link");
    for (let i = 1; i < links.length; i += 1) await user.tab();
    expect(links[links.length - 1]).toHaveFocus();

    await user.tab();
    expect(toggle).toHaveAttribute("aria-expanded", "false");
  });

  it("closes on a press outside without taking focus", async () => {
    const { user, toggle } = await openMenu("/");
    await user.click(document.body);
    expect(toggle).toHaveAttribute("aria-expanded", "false");
  });

  it("closes when the location changes underneath it", async () => {
    const { user, toggle, router } = await openMenu("/");
    await router.navigate({ to: "/laboratory" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    await user.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
  });
});
