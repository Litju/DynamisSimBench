import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createRoute, Link } from "@tanstack/react-router";
import { lazy, Suspense, useMemo, useState } from "react";

import type { ApiClient } from "../api/client";
import { ApiClientError } from "../api/errors";
import type { ResultEntry } from "../api/external-results";
import { useApiClient } from "../session/provider";
import { Button } from "../ui/button";
import { diagnoseExternalResult } from "../workbench/external-diagnostics";
import { ExternalFindings } from "../workbench/external-findings";
import { ExternalPlots } from "../workbench/external-plots";
import type { ExternalResult } from "../workbench/external-samples";
import { recordedValue } from "../workbench/external-trace";
import { rootRoute } from "./root";

const ExternalComparison = lazy(async () => ({
  default: (await import("../workbench/external-comparison-view")).ExternalComparison,
}));

export const externalResultsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/workspace/$workspaceId/results",
  component: ExternalResultsPage,
});

function ExternalResultsPage() {
  const { workspaceId } = externalResultsRoute.useParams();
  const client = useApiClient();
  return (
    <section className="mx-auto w-full max-w-6xl px-4 py-6 sm:px-6" aria-labelledby="results-title">
      <h1 id="results-title" className="text-2xl font-semibold">External results</h1>
      {client === null
        ? <p role="status" className="mt-3">The local workspace session is unavailable.</p>
        : <ResultBrowser key={workspaceId} client={client} workspaceId={workspaceId} />}
    </section>
  );
}

function ResultBrowser({ client, workspaceId }: { client: ApiClient; workspaceId: string }) {
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<string | null>(null);
  const [selectedB, setSelectedB] = useState<string | null>(null);
  const listing = useQuery({
    queryKey: ["external-results", workspaceId],
    queryFn: () => client.listExternalResults(workspaceId),
    // The sidecar is loopback. Attempt a fresh read even when the browser reports offline.
    networkMode: "always",
    retry: false,
  });
  const currentList = listing.isError || listing.isFetching ? undefined : listing.data;
  const entries = currentList?.results ?? [];
  const current = selected === null ? undefined : entries.find((entry) => entry.result_id === selected);
  const currentB = selectedB === null ? undefined : entries.find((entry) => entry.result_id === selectedB);
  const sameSource = current !== undefined && current === currentB;

  return (
    <>
      <details className="my-4 rounded-md border border-slate-200 bg-white p-3 text-sm" open={listing.isSuccess && entries.length === 0}>
        <summary className="cursor-pointer font-medium">CSV format and location</summary>
        <p className="mt-2">Put a CSV file in <code>external-results/</code> directly inside the opened source root, then refresh the list.</p>
        <p className="mt-1">Use unquoted cells and a header such as <code>time[s],position[m],velocity[m/s]</code>. Time must be finite. Leave missing signal cells blank and use <code>NaN</code> or <code>Inf</code> for recorded nonfinite values.</p>
        <p className="mt-1">Use a portable filename of at most 100 characters, including the <code>.csv</code> extension. Remove empty lines.</p>
        <p className="mt-1">Limits per file are 1 MiB, 20,000 rows, 16 columns and 100,000 cells. The folder supports up to 32 CSV files and 256 entries.</p>
      </details>
      <div className="grid gap-4 md:grid-cols-[minmax(12rem,1fr)_minmax(0,3fr)]">
        <section className="min-w-0 rounded-md border border-slate-200 bg-white p-3" aria-label="Workspace result files">
          <div className="flex flex-wrap items-center justify-between gap-1">
            <h2 className="font-semibold">Workspace files</h2>
            <Button type="button" className="w-auto" disabled={listing.isFetching} onClick={() => void listing.refetch()}>
              Refresh results
            </Button>
          </div>
          {listing.isFetching && <p role="status">Reading workspace files…</p>}
          {listing.isError && (
            <div role="alert">
              <p>{failureMessage(listing.error)}</p>
              {listing.error instanceof ApiClientError && listing.error.status === 404 &&
                <Link to="/" hash="open-workspace" className="underline">Open workspace</Link>}
            </div>
          )}
          {listing.isSuccess && !listing.isFetching && entries.length === 0 && <p>No discoverable CSV files.</p>}
          {currentList !== undefined && currentList.ignored_names > 0 && (
            <p role="status" className="text-rose-900">{currentList.ignored_names} CSV entries have unsupported filenames.</p>
          )}
          <ul className="space-y-1">
            {entries.length > 0 && <li className="mt-2 text-xs font-medium text-ink-3">Select source A</li>}
            {entries.map((entry) => (
              <li key={entry.name} className="break-all">
                {entry.result_id !== null ? (
                  <Button
                    type="button"
                    className="h-auto min-h-9 border border-transparent whitespace-normal py-1 text-left aria-pressed:border-[var(--color-accent)] aria-pressed:bg-slate-100"
                    aria-pressed={entry === current}
                    onClick={() => {
                      if (entry === current) {
                        void queryClient.invalidateQueries({
                          queryKey: ["external-result", workspaceId],
                        });
                      } else {
                        setSelected(entry.result_id);
                      }
                    }}
                  >
                    {entry.name}
                  </Button>
                ) : (
                  <div className="rounded-md bg-rose-50 p-2 text-rose-900">
                    <strong>{entry.name}</strong>
                    <p className="break-normal">{entry.refusal}</p>
                  </div>
                )}
              </li>
            ))}
          </ul>
          {entries.some((entry) => entry.result_id !== null) && (
            <div className="mt-3 min-w-0 border-t border-line pt-3">
              <label htmlFor="external-source-b" className="block text-sm font-medium">Source B</label>
              <select id="external-source-b" value={currentB?.result_id ?? ""}
                onChange={(event) => setSelectedB(event.currentTarget.value || null)}
                className="mt-1 w-full min-w-0 rounded border border-line bg-panel-2 p-2 text-sm">
                <option value="">No comparison</option>
                {entries.map((entry) => entry.result_id !== null && (
                  <option key={entry.result_id} value={entry.result_id} disabled={entry === current}>
                    {entry.name}
                  </option>
                ))}
              </select>
              {sameSource && <p role="status" className="mt-1 text-sm">Choose a different file for source B.</p>}
            </div>
          )}
          {currentList !== undefined && selectedB !== null && currentB === undefined && (
            <p role="status" className="mt-1 text-sm">Source B changed or became unavailable. Select its current entry.</p>
          )}
        </section>
        <section className="min-w-0 rounded-md border border-slate-200 bg-white p-4" aria-label="Result inspection">
          {currentList !== undefined && selected !== null && current === undefined && (
            <p role="status">The selected source changed or became unavailable. Select a file to inspect its current data.</p>
          )}
          {current === undefined && currentB === undefined
            ? <p>Select a workspace file to inspect its recorded data.</p>
            : <ResultInspection key={`${current?.result_id ?? ""}:${currentB?.result_id ?? ""}`}
                client={client} workspaceId={workspaceId} a={current} b={sameSource ? undefined : currentB} />}
        </section>
      </div>
    </>
  );
}

function ResultInspection({ client, workspaceId, a, b }: {
  client: ApiClient;
  workspaceId: string;
  a?: ResultEntry;
  b?: ResultEntry;
}) {
  const result = useQuery({
    queryKey: ["external-result", workspaceId, a?.result_id ?? null, b?.result_id ?? null],
    queryFn: ({ signal }) => {
      async function read(source?: ResultEntry) {
        if (source?.result_id == null) return null;
        const result = await client.getExternalResult(workspaceId, source.result_id, signal);
        if (result.metadata.source_name !== source.name) throw new ApiClientError("invalid_response");
        signal.throwIfAborted();
        const { decodeExternalSamples } = await import("../workbench/external-samples");
        signal.throwIfAborted();
        return decodeExternalSamples(result);
      }
      return Promise.allSettled([read(a), read(b)] as const);
    },
    networkMode: "always",
    retry: false,
    gcTime: 0,
    refetchOnMount: "always",
  });
  const [outcomeA, outcomeB] = result.isSuccess && !result.isFetching ? result.data : [];
  const readA = outcomeA?.status === "fulfilled" ? outcomeA.value : null;
  const readB = outcomeB?.status === "fulfilled" ? outcomeB.value : null;
  return (
    <>
      {b !== undefined && (
        <Button type="button" className="mb-2 w-auto border border-line" disabled={result.isFetching}
          onClick={() => void result.refetch()}>Revalidate sources</Button>
      )}
      {result.isFetching && <p role="status">Reading recorded samples…</p>}
      {result.isError && <p role="alert">{failureMessage(result.error)}</p>}
      {outcomeA?.status === "rejected" && <p role="alert">{b !== undefined && "Source A · "}{failureMessage(outcomeA.reason)}</p>}
      {outcomeB?.status === "rejected" && <p role="alert">Source B · {failureMessage(outcomeB.reason)}</p>}
      {readA !== null && readB !== null ? (
        <Suspense fallback={<p role="status">Opening comparison…</p>}>
          <ExternalComparison a={readA} b={readB} />
        </Suspense>
      ) : (
        <>
          {readB !== null && <p className="mb-3 wrap-anywhere text-sm">Source B · {readB.metadata.source_name} · SHA-256 <code>{readB.metadata.source_sha256}</code>. Select a readable source A to compare.</p>}
          {readA !== null && <SampleInspection result={readA} />}
        </>
      )}
    </>
  );
}

function failureMessage(error: unknown): string {
  return error instanceof ApiClientError
    ? error.apiMessage ?? error.message
    : "The recorded data could not be decoded.";
}

const PAGE_SIZE = 12;

function SampleInspection({ result }: { result: ExternalResult }) {
  const { metadata, rows } = result;
  const signalCount = metadata.columns.length - 1;
  const diagnostics = useMemo(() => diagnoseExternalResult(result), [result]);
  const regular = diagnostics.findings.some((finding) => finding.check === "regularity" && finding.status === "PASS");

  return (
    <>
      <h2 className="break-all text-lg font-semibold">{metadata.source_name}</h2>
      <p className="mt-1 text-sm text-slate-600">Read-only external result · {rows.length} samples · {signalCount} {signalCount === 1 ? "signal" : "signals"}</p>
      <dl aria-label="Result source" className="my-4 grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[max-content_minmax(0,1fr)]">
        <dt className="font-medium">Workspace source</dt>
        <dd className="break-all"><code>external-results/{metadata.source_name}</code></dd>
        <dt className="font-medium">Source SHA-256</dt>
        <dd className="break-all"><code>{metadata.source_sha256}</code></dd>
        <dt className="font-medium">Format</dt>
        <dd><code>{metadata.schema_version}</code> · {metadata.size_bytes.toLocaleString()} bytes</dd>
      </dl>
      <ExternalPlots result={result} connect={regular} />
      <ExternalFindings diagnostics={diagnostics} />
      <RecordedSamples result={result} />
    </>
  );
}

function RecordedSamples({ result: { metadata, rows } }: { result: ExternalResult }) {
  const [page, setPage] = useState(0);
  const start = page * PAGE_SIZE;
  const end = Math.min(start + PAGE_SIZE, rows.length);
  return (
    <>
      <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Recorded sample table">
        <table className="w-full whitespace-nowrap text-left text-sm">
          <caption className="mb-1 text-left font-medium">Recorded samples {start + 1}–{end} of {rows.length}</caption>
          <thead className="border-b border-slate-200">
            <tr>
              <th scope="col" className="px-2 py-1">Row</th>
              {metadata.columns.map((column) => (
                <th key={column.name} scope="col" className="px-2 py-1">{column.name} [{column.unit}]</th>
              ))}
            </tr>
          </thead>
          <tbody className="font-mono">
            {rows.slice(start, end).map((row, index) => (
              <tr key={start + index} className="border-b border-slate-200">
                <th scope="row" className="px-2 py-1 font-normal text-slate-600">{start + index + 1}</th>
                {row.map((value, columnIndex) => (
                  <td key={metadata.columns[columnIndex]?.name} className="px-2 py-1">
                    {recordedValue(value)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length > PAGE_SIZE && (
        <div className="mt-2 flex gap-2">
          <Button type="button" className="w-auto" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous rows</Button>
          <Button type="button" className="w-auto" disabled={end === rows.length} onClick={() => setPage(page + 1)}>Next rows</Button>
        </div>
      )}
    </>
  );
}
