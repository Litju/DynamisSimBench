/**
 * The platform Modules disclosure in the shell header.
 *
 * One button, one panel of grouped destinations. Available entries are real links to existing
 * routes and Laboratory folios; planned and unsupported entries are plain text with their state
 * spelled out, never focusable and never links. The menu holds only its own open/closed state:
 * which workspace is in context is read from the location, and the Laboratory folio is the
 * Laboratory store's existing presentation state.
 *
 * The panel opens with the context it navigates in — the workspace in force, or that there is
 * none — so a person knows before choosing whether a destination will be bound to a workspace.
 */

import { useRouter, useRouterState } from "@tanstack/react-router";
import {
  Activity,
  Boxes,
  ChartColumn,
  ChevronDown,
  FlaskConical,
  GitCompareArrows,
  LayoutGrid,
  PenTool,
  Puzzle,
  ScrollText,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";

import { FOLIO_LABELS, useLaboratoryStore, type Folio } from "../laboratory/store";
import { useSession } from "../session/provider";

import {
  MODULE_GROUPS,
  resolveEntry,
  workspaceContext,
  type ModuleAvailability,
  type ModuleEntry,
  type ResolvedEntry,
} from "./modules";

type ResolvedLink = Extract<ResolvedEntry, { kind: "link" }>;

const STATE_LABEL: Record<Exclude<ModuleAvailability, "available">, string> = {
  planned: "Planned",
  unsupported: "Unsupported",
};

/** A recognisable mark per group; decorative, the group's heading carries the name. */
const GROUP_ICON: Record<string, LucideIcon> = {
  "workspace-models": Boxes,
  "simulation-laboratory": FlaskConical,
  diagnostics: Activity,
  "experiments-comparison": GitCompareArrows,
  "benchmarks-analysis": ChartColumn,
  "evidence-provenance": ScrollText,
  extensions: Puzzle,
  "model-studio": PenTool,
};

export function ModulesMenu() {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const root = useRef<HTMLDivElement>(null);
  const toggle = useRef<HTMLButtonElement>(null);
  const { session } = useSession();
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const search = useRouterState({ select: (state) => state.location.search });
  const folio = useLaboratoryStore((state) => state.folio);
  const setFolio = useLaboratoryStore((state) => state.setFolio);
  const workspaceId = workspaceContext(pathname, search);

  // A disclosure, not a modal: Escape closes it and returns focus to its button; a pointer
  // press elsewhere closes it and leaves focus where the person put it.
  useEffect(() => {
    if (!open) return;
    const onPointer = (event: PointerEvent) => {
      if (event.target instanceof Node && root.current?.contains(event.target) !== true) {
        setOpen(false);
      }
    };
    document.addEventListener("pointerdown", onPointer);
    return () => document.removeEventListener("pointerdown", onPointer);
  }, [open]);

  // Any navigation, however it was made, leaves the menu closed.
  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  const isCurrent = (entry: ModuleEntry) => {
    switch (entry.target?.kind) {
      case "folio":
        return pathname === "/laboratory" && folio === entry.target.folio;
      case "workspace":
        return workspaceId !== null && pathname.startsWith("/workspace/");
      default:
        return false;
    }
  };

  return (
    <div
      ref={root}
      className="wb-modules"
      data-open={open}
      onKeyDown={(event) => {
        if (event.key === "Escape" && open) {
          event.stopPropagation();
          setOpen(false);
          toggle.current?.focus();
        }
      }}
      onBlur={(event) => {
        // Tabbing out of the panel closes it; focus is already where the person sent it.
        if (open && event.relatedTarget instanceof Node && !event.currentTarget.contains(event.relatedTarget)) {
          setOpen(false);
        }
      }}
    >
      <button
        ref={toggle}
        type="button"
        className="wb-modules-toggle"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((value) => !value)}
      >
        <LayoutGrid aria-hidden size={14} />
        Modules
        <ChevronDown aria-hidden size={14} className="wb-modules-chevron" />
      </button>

      <nav id={panelId} className="wb-modules-panel" aria-label="Modules" hidden={!open}>
        {/* Drawn only while open: nothing else in the document needs a second copy of the token. */}
        {open && (
          <div className="wb-modules-context">
            {workspaceId === null ? (
              <span>No workspace open · Laboratory folios show the packaged reference recordings</span>
            ) : (
              <span>
                Workspace <code title={workspaceId}>{workspaceId}</code>
              </span>
            )}
          </div>
        )}

        {session.phase !== "ready" && (
          <p className="wb-modules-session" role="status">
            The local API session is not ready. Destinations that read it will say so until it is.
          </p>
        )}

        <div className="wb-modules-groups">
          {MODULE_GROUPS.map((group) => {
            const Icon = GROUP_ICON[group.id];
            return (
              <section key={group.id} aria-labelledby={`${panelId}-${group.id}`}>
                <h2 id={`${panelId}-${group.id}`}>
                  {Icon !== undefined && <Icon aria-hidden size={13} />}
                  {group.label}
                </h2>
                <ul>
                  {group.entries.map((entry) => (
                    <li key={entry.id}>
                      <ModuleItem
                        entry={entry}
                        workspaceId={workspaceId}
                        active={isCurrent(entry)}
                        // Inside the Laboratory a folio change replaces the entry, as its tabs do.
                        replace={pathname === "/laboratory"}
                        onFolio={setFolio}
                        onNavigate={() => setOpen(false)}
                      />
                    </li>
                  ))}
                </ul>
              </section>
            );
          })}
        </div>
      </nav>
    </div>
  );
}

function ModuleItem({
  entry,
  workspaceId,
  active,
  replace,
  onFolio,
  onNavigate,
}: {
  entry: ModuleEntry;
  workspaceId: string | null;
  active: boolean;
  replace: boolean;
  onFolio: (folio: Folio) => void;
  onNavigate: () => void;
}) {
  const router = useRouter();
  const resolved = resolveEntry(entry, workspaceId);
  const navigation = (link: ResolvedLink) => ({
    to: link.to,
    ...(link.params === undefined ? {} : { params: link.params }),
    ...(link.search === undefined ? {} : { search: link.search }),
    ...(link.hash === undefined ? {} : { hash: link.hash }),
  });

  if (resolved.kind === "link") {
    const numeral = resolved.folio === undefined ? null : FOLIO_LABELS[resolved.folio].numeral;
    return (
      <a
        className="wb-modules-item"
        href={router.buildLocation(navigation(resolved)).href}
        aria-current={active ? "page" : undefined}
        onClick={(event) => {
          // Let the browser handle new-tab and modified clicks (the href names the folio);
          // route the plain click in place.
          if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
            return;
          }
          event.preventDefault();
          if (resolved.folio !== undefined) onFolio(resolved.folio);
          onNavigate();
          void router.navigate({ ...navigation(resolved), replace: replace && resolved.folio !== undefined });
        }}
      >
        <span className="wb-modules-label">
          {entry.label}
          {numeral !== null && (
            <span className="wb-modules-numeral" title={`Laboratory folio ${numeral}`}>
              <span className="sr-only">, Laboratory folio</span> {numeral}
            </span>
          )}
        </span>{" "}
        <span className="wb-modules-note">{entry.note}</span>
      </a>
    );
  }

  const state = resolved.kind === "blocked" ? resolved.reason : STATE_LABEL[resolved.kind];
  return (
    <div className="wb-modules-item" data-state={resolved.kind}>
      <span className="wb-modules-label">
        {entry.label}
        <span className="wb-modules-state">{state}</span>
      </span>{" "}
      <span className="wb-modules-note">{entry.note}</span>
    </div>
  );
}
