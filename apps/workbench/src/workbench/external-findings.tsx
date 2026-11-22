import { useId } from "react";

import type { DiagnosticStatus, ExternalDiagnostics } from "./external-diagnostics";

const STATUS_COLOR: Record<DiagnosticStatus, string> = {
  PASS: "bg-ok-soft text-ok",
  FAIL: "bg-err-soft text-err",
  INCONCLUSIVE: "bg-warn-soft text-warn",
  UNSUPPORTED: "bg-panel-2 text-ink-2",
};

export function ExternalFindings({ diagnostics }: { diagnostics: ExternalDiagnostics }) {
  const title = useId();
  return (
    <section className="my-5" aria-labelledby={title}>
      <h3 id={title} className="font-display text-xl">Numerical diagnostics</h3>
      <p className="my-2 text-xs text-ink-2">
        <code>{diagnostics.version}</code> · All {diagnostics.findings[0]?.sampleCount} admitted rows · Recorded data checks
      </p>
      <ul className="divide-y divide-line rounded border border-line">
        {diagnostics.findings.map((finding) => (
          <li key={`${finding.quantity.name}-${finding.check}`}>
            <details className="px-3 py-2">
              <summary className="cursor-pointer text-sm">
                <span className={`mx-2 inline-block rounded px-1.5 py-0.5 font-mono text-[10px] ${STATUS_COLOR[finding.status]}`}>
                  {finding.status}
                </span>
                <span className="font-medium">{finding.label}</span>
                <span className="ml-2 wrap-anywhere text-xs text-ink-2">
                  {finding.quantity.name} [{finding.quantity.unit}]
                </span>
              </summary>
              <p className="mt-1 pl-5 text-xs text-ink-2">{finding.summary}</p>
              <dl className="mt-2 grid gap-x-3 gap-y-1 border-t border-line pt-2 text-xs sm:grid-cols-[max-content_minmax(0,1fr)]">
                <dt className="font-medium">Source SHA-256</dt>
                <dd className="break-all"><code>{finding.sourceSha256}</code></dd>
                <dt className="font-medium">Method</dt>
                <dd>{finding.method}</dd>
                <dt className="font-medium">Limitations</dt>
                <dd>{finding.limitations}</dd>
                {finding.firstAffectedRow !== undefined && (
                  <>
                    <dt className="font-medium">First affected data row</dt>
                    <dd>{finding.firstAffectedRow}</dd>
                  </>
                )}
              </dl>
            </details>
          </li>
        ))}
      </ul>
    </section>
  );
}
