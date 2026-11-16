/** The Modules model: truthful availability, and no link without a real destination. */

import { describe, expect, it } from "vitest";

import { FOLIOS } from "../laboratory/store";

import { MODULE_GROUPS, resolveEntry, workspaceContext } from "./modules";

const entries = MODULE_GROUPS.flatMap((group) => group.entries);

describe("the module groups", () => {
  it("are the eight platform groups, in order", () => {
    expect(MODULE_GROUPS.map((group) => group.label)).toEqual([
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

  it("give every entry a unique id", () => {
    expect(new Set(entries.map((entry) => entry.id)).size).toBe(entries.length);
  });

  it("carry a target exactly when they are available", () => {
    for (const entry of entries) {
      expect(entry.target !== undefined, entry.id).toBe(entry.availability === "available");
    }
  });

  it("only target Laboratory folios that exist", () => {
    for (const entry of entries) {
      if (entry.target?.kind === "folio") {
        expect(FOLIOS).toContain(entry.target.folio);
      }
    }
  });

  it("keep the later modules planned or unsupported", () => {
    const state = (id: string) => entries.find((entry) => entry.id === id)?.availability;
    for (const id of [
      "model-registry",
      "external-execution",
      "diagnostics-engine",
      "experiments",
      "benchmark-packages",
      "evidence-browser",
      "extensions",
    ]) {
      expect(state(id), id).toBe("planned");
    }
    expect(state("model-studio")).toBe("unsupported");
  });
});

describe("resolving an entry", () => {
  const entry = (id: string) => {
    const found = entries.find((candidate) => candidate.id === id);
    if (found === undefined) throw new Error(id);
    return found;
  };

  it("never resolves a planned or unsupported entry to a link", () => {
    expect(resolveEntry(entry("diagnostics-engine"), "ws1").kind).toBe("planned");
    expect(resolveEntry(entry("model-studio"), "ws1").kind).toBe("unsupported");
  });

  it("blocks the workspace entry until there is a workspace", () => {
    expect(resolveEntry(entry("current-workspace"), null).kind).toBe("blocked");
    expect(resolveEntry(entry("current-workspace"), "ws1")).toEqual({
      kind: "link",
      to: "/workspace/$workspaceId",
      params: { workspaceId: "ws1" },
    });
  });

  it("carries the opaque workspace id into Laboratory folios", () => {
    expect(resolveEntry(entry("analysis"), "ws1")).toEqual({
      kind: "link",
      to: "/laboratory",
      folio: "analysis",
      search: { workspace: "ws1" },
    });
    expect(resolveEntry(entry("analysis"), null)).toEqual({
      kind: "link",
      to: "/laboratory",
      folio: "analysis",
    });
  });
});

describe("the workspace context", () => {
  it("reads the workspace route's identifier", () => {
    expect(workspaceContext("/workspace/abc_123-X", {})).toBe("abc_123-X");
  });

  it("reads the Laboratory's workspace search parameter", () => {
    expect(workspaceContext("/laboratory", { workspace: "abc" })).toBe("abc");
  });

  it("ignores anything that is not an opaque token", () => {
    expect(workspaceContext("/laboratory", { workspace: "C:\data" })).toBeNull();
    expect(workspaceContext("/laboratory", { workspace: "../x" })).toBeNull();
    expect(workspaceContext("/workspace/%E0%A4%A", {})).toBeNull();
    expect(workspaceContext("/", { workspace: "abc" })).toBeNull();
  });
});
