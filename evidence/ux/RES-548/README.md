# RES-548 Modules navigation: before/after screenshots

Captured from the running application (production route tree, real secured Python sidecar,
Chromium via Playwright, Windows 11), with a real temporary workspace opened through the UI.
The workspace identifiers shown are opaque per-run tokens; no filesystem path or session
credential appears in any image.

- `before/`: branch head `8fa317b`, before the UI/UX review changes.
- `after/`: after the RES-548 review commits on PR #30.

Regenerate the `after/` set (and more) with:

```sh
cd apps/workbench
DYNAMISBENCH_UX_SCREENSHOTS=<directory> pnpm exec playwright test e2e/modules-menu.spec.ts -g screenshots
```

| # | View | Width | Ground |
|---|------|-------|--------|
| 01 | Workspace route, Modules open, focus on first destination | 1440 | Studiolo |
| 02 | Laboratory (Analysis folio), Modules open | 1440 | Vellum |
| 03 | Workspace route, Modules open | 760 | Vellum |
| 04 | Laboratory (Analysis folio) | 760 | Studiolo |
| 05 | Workspace route | 760 | Studiolo |
| 06 | Overview, Modules open, no workspace (after only) | 1440 | Vellum |

The before set for 01 was captured with the menu open but without the Tab focus step.
These are presentation evidence for navigation usability only; they are not scientific
qualification of any module or of the reference squat data shown.
