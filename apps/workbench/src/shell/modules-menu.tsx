/**
 * The platform Modules disclosure in the shell header.
 *
 * One button, one panel of grouped destinations. Available entries are real links to existing
 * routes and Laboratory folios; planned and unsupported entries are plain text with their state
 * spelled out, never focusable and never links. The menu holds only its own open/closed state:
 * which workspace is in context is read from the location, and the Laboratory folio is the
 * Laboratory store's existing presentation state.
 */

import { useRouter, useRouterState } from "@tanstack/react-router";
import { ChevronDown } from "lucide-react";
import { useId, useState } from "react";

import { useLaboratoryStore, type Folio } from "../laboratory/store";
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

export function ModulesMenu() {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const { session } = useSession();
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const search = useRouterState({ select: (state) => state.location.search });
  const folio = useLaboratoryStore((state) => state.folio);
  const setFolio = useLaboratoryStore((state) => state.setFolio);
  const workspaceId = workspaceContext(pathname, search);

  return (
    <div className="wb-modules" data-open={open}>
      <button
        type="button"
        className="wb-modules-toggle"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((value) => !value)}
      >
        Modules
        <ChevronDown aria-hidden size={14} />
      </button>

      <nav id={panelId} className="wb-modules-panel" aria-label="Modules" hidden={!open}>
        {session.phase !== "ready" && (
          <p className="wb-modules-session" role="status">
            The local API session is not ready. Destinations that read it will say so until it is.
          </p>
        )}

        {MODULE_GROUPS.map((group) => (
          <section key={group.id} aria-labelledby={`${panelId}-${group.id}`}>
            <h2 id={`${panelId}-${group.id}`}>{group.label}</h2>
            <ul>
              {group.entries.map((entry) => (
                <li key={entry.id}>
                  <ModuleItem
                    entry={entry}
                    workspaceId={workspaceId}
                    active={
                      entry.target?.kind === "folio" &&
                      pathname === "/laboratory" &&
                      folio === entry.target.folio
                    }
                    onFolio={setFolio}
                    onNavigate={() => setOpen(false)}
                  />
                </li>
              ))}
            </ul>
          </section>
        ))}
      </nav>
    </div>
  );
}

function ModuleItem({
  entry,
  workspaceId,
  active,
  onFolio,
  onNavigate,
}: {
  entry: ModuleEntry;
  workspaceId: string | null;
  active: boolean;
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
  const href = (link: ResolvedLink) => router.buildLocation(navigation(link)).href;

  if (resolved.kind === "link") {
    const activate = () => {
      if (resolved.folio !== undefined) onFolio(resolved.folio);
      onNavigate();
    };
    const content = (
      <>
        <span className="wb-modules-label">{entry.label}</span>
        <span className="wb-modules-note">{entry.note}</span>
      </>
    );
    return (
      <a
        className="wb-modules-item"
        href={href(resolved)}
        aria-current={active ? "page" : undefined}
        onClick={(event) => {
          // Let the browser handle new-tab and modified clicks; route the plain click.
          if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
            return;
          }
          event.preventDefault();
          activate();
          void router.navigate(navigation(resolved));
        }}
      >
        {content}
      </a>
    );
  }

  const state =
    resolved.kind === "blocked" ? resolved.reason : STATE_LABEL[resolved.kind];
  return (
    <div className="wb-modules-item" data-state={resolved.kind}>
      <span className="wb-modules-label">
        {entry.label}
        <span className="wb-modules-state">{state}</span>
      </span>
      <span className="wb-modules-note">{entry.note}</span>
    </div>
  );
}
