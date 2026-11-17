/**
 * The workbench shell: product identity, the runtime status it carries, and the one piece of
 * UI-local state a user can actually change.
 *
 * The collapse control is the only interaction in this milestone, so it is driven the way a
 * person drives it — a real click — rather than by calling the store.
 */

import { userEvent } from "@testing-library/user-event";
import { screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { useUiStore } from "../store/ui";
import { renderApplication } from "../test/render-app";

beforeEach(() => {
  useUiStore.setState({ sidebarCollapsed: false });
});

afterEach(() => {
  useUiStore.setState({ sidebarCollapsed: false });
});

describe("the workbench shell", () => {
  it("identifies the product", async () => {
    renderApplication("/");

    expect(await screen.findByText("DynamisBench")).toBeInTheDocument();
    expect(
      screen.getByText("Simulation diagnosis & benchmarking workbench"),
    ).toBeInTheDocument();
  });

  it("carries the runtime status in the header", async () => {
    renderApplication("/");

    // The label appears in the header and again in the route's explanation; the header's is
    // the first in the document.
    const [status] = await screen.findAllByText("Desktop session unavailable");

    expect(status).toBeDefined();
    expect(status?.closest("[data-runtime-state]")).toHaveAttribute(
      "data-runtime-state",
      "browser_unavailable",
    );
  });

  it("keeps header links keyboard accessible without a redundant Navigator control", async () => {
    const user = userEvent.setup();
    renderApplication("/");
    const overview = await screen.findByRole("link", { name: "Overview" });
    overview.focus();
    await user.tab();
    expect(screen.getByRole("link", { name: "Open workspace" })).toHaveFocus();
    expect(
      screen.queryByRole("button", { name: "Collapse navigation" }),
    ).not.toBeInTheDocument();
  });

  it("offers the explicit open-workspace flow from the navigation rail", async () => {
    renderApplication("/");

    const open = await screen.findByRole("link", { name: "Open workspace" });

    expect(open).toHaveAttribute("href", "/#open-workspace");
  });
});

describe("the header's workspace context", () => {
  const header = () => within(screen.getByRole("navigation", { name: "Workbench" }));

  it("offers no workspace and no scientific contexts on the overview", async () => {
    renderApplication("/");
    await screen.findByRole("link", { name: "Overview" });

    expect(header().queryByRole("link", { name: "Workspace" })).not.toBeInTheDocument();
    expect(header().getByRole("link", { name: "Laboratory" })).toHaveAttribute("href", "/laboratory");
    expect(screen.queryByRole("navigation", { name: "Scientific contexts" })).not.toBeInTheDocument();
  });

  it("marks the workspace as the location and keeps it on the way to the Laboratory", async () => {
    renderApplication("/workspace/ws_abc-1");
    const workspace = await screen.findByRole("link", { name: "Workspace" });

    expect(workspace).toHaveAttribute("href", "/workspace/ws_abc-1");
    expect(workspace).toHaveAttribute("data-active", "true");
    expect(header().getByRole("link", { name: "Laboratory" })).toHaveAttribute(
      "href",
      "/laboratory?workspace=ws_abc-1",
    );
    expect(screen.getByRole("navigation", { name: "Scientific contexts" })).toBeInTheDocument();
  });

  it("returns from a bound Laboratory to the same workspace", async () => {
    renderApplication("/laboratory?workspace=ws_abc-1");
    // The first render loads the Laboratory route's lazy chunk before the tree is drawn.
    const laboratory = await screen.findByRole("link", { name: "Laboratory" }, { timeout: 10_000 });

    expect(laboratory).toHaveAttribute("data-active", "true");
    expect(header().getByRole("link", { name: "Workspace" })).toHaveAttribute("href", "/workspace/ws_abc-1");
    expect(header().getByRole("link", { name: "Workspace" })).not.toHaveAttribute("data-active");
  });
});
