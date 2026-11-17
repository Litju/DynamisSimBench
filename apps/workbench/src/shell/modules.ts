/**
 * The platform Modules model: which destinations exist, and how truthfully each is described.
 *
 * Presentation metadata only. It is not a capability registry and not a plugin manifest: an
 * entry is `available` only when it points at a route or Laboratory folio that exists in this
 * build. Everything else is `planned` or `unsupported` and carries no target, so the menu can
 * never render a link that leads nowhere. Availability here is a statement about *navigation*,
 * not about scientific capability — the reference Laboratory folios remain squat-specific.
 */

import type { Folio } from "../laboratory/store";

export type ModuleAvailability = "available" | "planned" | "unsupported";

/** Where an available entry goes. */
export type ModuleTarget =
  /** The explicit open-workspace flow on the overview. */
  | { readonly kind: "open-workspace" }
  /** The workspace the shell currently has context for; needs one. */
  | { readonly kind: "workspace" }
  /** The Laboratory route, on a folio, bound to the current workspace when there is one. */
  | { readonly kind: "folio"; readonly folio: Folio };

export interface ModuleEntry {
  readonly id: string;
  readonly label: string;
  readonly availability: ModuleAvailability;
  /** What this destination is today, or why it is not available. */
  readonly note: string;
  readonly target?: ModuleTarget;
}

export interface ModuleGroup {
  readonly id: string;
  readonly label: string;
  readonly entries: readonly ModuleEntry[];
}

export const MODULE_GROUPS: readonly ModuleGroup[] = [
  {
    id: "workspace-models",
    label: "Workspace & Models",
    entries: [
      {
        id: "open-workspace",
        label: "Open workspace",
        availability: "available",
        note: "Read-only discovery and inspection",
        target: { kind: "open-workspace" },
      },
      {
        id: "current-workspace",
        label: "Current workspace",
        availability: "available",
        note: "Explorer, source content and Inspector",
        target: { kind: "workspace" },
      },
      {
        id: "model-atlas",
        label: "Model Atlas",
        availability: "available",
        note: "Reference squat model only",
        target: { kind: "folio", folio: "atlas" },
      },
      {
        id: "model-registry",
        label: "Model import & registry",
        availability: "planned",
        note: "Generic import, revisions and adapter compatibility are not built",
      },
    ],
  },
  {
    id: "simulation-laboratory",
    label: "Simulation Laboratory",
    entries: [
      {
        id: "laboratory",
        label: "Laboratory",
        availability: "available",
        note: "Reference squat recordings",
        target: { kind: "folio", folio: "laboratory" },
      },
      {
        id: "study-runs",
        label: "Study & Runs",
        availability: "available",
        note: "Reference studies; run execution is not enabled",
        target: { kind: "folio", folio: "study" },
      },
      {
        id: "external-execution",
        label: "External-model execution",
        availability: "planned",
        note: "RunSpec, preflight and launch for other models are not built",
      },
    ],
  },
  {
    id: "diagnostics",
    label: "Diagnostics",
    entries: [
      {
        id: "diagnostics-engine",
        label: "Diagnostics",
        availability: "planned",
        note: "Solver and numerical diagnostics are not built",
      },
    ],
  },
  {
    id: "experiments-comparison",
    label: "Experiments & Comparison",
    entries: [
      {
        id: "experiments",
        label: "Experiments & comparison",
        availability: "planned",
        note: "Sweeps and model-revision comparison are not built",
      },
    ],
  },
  {
    id: "benchmarks-analysis",
    label: "Benchmarks & Analysis",
    entries: [
      {
        id: "analysis",
        label: "Analysis",
        availability: "available",
        note: "Reference squat analysis only",
        target: { kind: "folio", folio: "analysis" },
      },
      {
        id: "benchmark-packages",
        label: "Benchmark packages",
        availability: "planned",
        note: "Versioned generic packages are not built",
      },
    ],
  },
  {
    id: "evidence-provenance",
    label: "Evidence & Provenance",
    entries: [
      {
        id: "evidence",
        label: "Evidence",
        availability: "available",
        note: "Reference runs only",
        target: { kind: "folio", folio: "record" },
      },
      {
        id: "evidence-browser",
        label: "Evidence browser",
        availability: "planned",
        note: "A generic evidence and provenance browser is not built",
      },
    ],
  },
  {
    id: "extensions",
    label: "Extensions",
    entries: [
      {
        id: "extensions",
        label: "Extensions",
        availability: "planned",
        note: "No adapters or packages can be installed; no extension code is loaded",
      },
    ],
  },
  {
    id: "model-studio",
    label: "Model Studio",
    entries: [
      {
        id: "model-studio",
        label: "Model Studio",
        availability: "unsupported",
        note: "In-Workbench model authoring is a later stage and is not available",
      },
    ],
  },
];

/** The opaque identifier shape the API mints; anything else is not a workspace. */
const WORKSPACE_TOKEN = /^[A-Za-z0-9_-]{1,128}$/;
const WORKSPACE_PATH = /^\/workspace\/([^/]+)\/?$/;

/**
 * The workspace the shell is looking at, if any: the path's identifier on the workspace
 * route, or the `workspace` search parameter on the Laboratory. Only token-shaped values
 * count, so nothing path-like can be carried into a link.
 */
export function workspaceContext(pathname: string, search: unknown): string | null {
  const fromPath = WORKSPACE_PATH.exec(pathname)?.[1];
  if (fromPath !== undefined) {
    let decoded = fromPath;
    try {
      decoded = decodeURIComponent(fromPath);
    } catch {
      return null;
    }
    return WORKSPACE_TOKEN.test(decoded) ? decoded : null;
  }
  if (pathname === "/laboratory" && typeof search === "object" && search !== null) {
    const candidate = (search as { workspace?: unknown }).workspace;
    if (typeof candidate === "string" && WORKSPACE_TOKEN.test(candidate)) {
      return candidate;
    }
  }
  return null;
}

export type ResolvedEntry =
  | {
      readonly kind: "link";
      readonly to: "/" | "/laboratory" | "/workspace/$workspaceId";
      readonly hash?: string;
      readonly params?: { readonly workspaceId: string };
      readonly search?: { readonly workspace?: string; readonly folio?: Folio };
      readonly folio?: Folio;
    }
  | { readonly kind: "blocked"; readonly reason: string }
  | { readonly kind: "planned" }
  | { readonly kind: "unsupported" };

/** Turn an entry into what the menu may render, given the current workspace context. */
export function resolveEntry(entry: ModuleEntry, workspaceId: string | null): ResolvedEntry {
  if (entry.availability !== "available") {
    return { kind: entry.availability };
  }
  const target = entry.target;
  if (target === undefined) {
    // An available entry without a target would be a dead end; refuse to draw it as a link.
    return { kind: "planned" };
  }
  switch (target.kind) {
    case "open-workspace":
      return { kind: "link", to: "/", hash: "open-workspace" };
    case "workspace":
      return workspaceId === null
        ? { kind: "blocked", reason: "Open a workspace first" }
        : { kind: "link", to: "/workspace/$workspaceId", params: { workspaceId } };
    case "folio":
      return {
        kind: "link",
        to: "/laboratory",
        folio: target.folio,
        // The folio is in the address too, so a new tab or window opens on it.
        search: { ...(workspaceId === null ? {} : { workspace: workspaceId }), folio: target.folio },
      };
  }
}
