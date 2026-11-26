import { useMemo, useState } from "react";

import { Button } from "../ui/button";
import { COMPARISON_VERSION, compareExternalResults, compareSampleValues, type QuantityPair } from "./external-comparison";
import { diagnoseExternalResult } from "./external-diagnostics";
import { ExternalFindings } from "./external-findings";
import { RecordedSignalPlot, usePlotWidth } from "./external-plots";
import type { ExternalResult } from "./external-samples";
import { plotFraction, plotValue, recordedValue, type PlotDomain } from "./external-trace";

type Comparison = ReturnType<typeof compareExternalResults>;

const GRID_DESCRIPTION: Record<Comparison["grid"], string> = {
  ambiguous: "Unsupported timebase. Each source must have unique timestamps in strictly increasing order.",
  disjoint: "Unsupported alignment. The recorded time ranges are disjoint.",
  "no-exact-matches": "Unsupported alignment. The recorded ranges overlap with no exact timestamp matches.",
  identical: "Identical recorded time grids.",
  partial: "Different recorded time grids. Only exact timestamp matches can produce a delta.",
};

const DELTA_REASON = {
  unmatched: "Unmatched time",
  missing: "Missing value",
  nonfinite: "Nonfinite value",
  overflow: "Outside binary64 range",
  unconfirmed: "Confirm comparability",
} as const;

const CONTROL = "w-auto border border-slate-200";

function rangeText(range: PlotDomain) {
  return `${recordedValue(range[0])} to ${recordedValue(range[1])} s`;
}

export function ExternalComparison({ a, b }: { a: ExternalResult; b: ExternalResult }) {
  const diagnosticsA = useMemo(() => diagnoseExternalResult(a), [a]);
  const diagnosticsB = useMemo(() => diagnoseExternalResult(b), [b]);
  const comparison = useMemo(() => compareExternalResults(
    { result: a, diagnostics: diagnosticsA }, { result: b, diagnostics: diagnosticsB },
  ), [a, b, diagnosticsA, diagnosticsB]);
  const { grid, pairs, overlap, invalidOrder, incompatible, matched } = comparison;

  return (
    <section aria-label="A/B comparison" className="min-w-0">
      <h2 className="font-display text-2xl">A/B comparison</h2>
      <p className="mt-1 text-xs text-ink-2"><code>{COMPARISON_VERSION}</code></p>
      <div className="my-3 grid gap-2 sm:grid-cols-2">
        {([
          ["A", a, diagnosticsA, comparison.aRange],
          ["B", b, diagnosticsB, comparison.bRange],
        ] as const).map(([side, result, diagnostics, range]) => (
          <article key={side} className="min-w-0 rounded border border-line bg-panel-2 p-3" aria-label={`Source ${side} provenance`}>
            <h3 className="wrap-anywhere font-semibold">{side} · {result.metadata.source_name}</h3>
            <p className="mt-1 text-xs text-ink-2">{result.rows.length} rows · {rangeText(range)}</p>
            <p className="text-xs">Sampling regularity · {diagnostics.findings.find(({ check }) => check === "regularity")?.status}</p>
            <p className="mt-1 text-xs text-ink-2">Source SHA-256</p>
            <code className="block break-all">{result.metadata.source_sha256}</code>
            <details className="mt-2 min-w-0">
              <summary className="cursor-pointer text-xs">Source {side} diagnostics</summary>
              <ExternalFindings diagnostics={diagnostics} />
            </details>
          </article>
        ))}
      </div>
      <section aria-label="Comparison checks" className="rounded border border-line p-3">
        <h3 className="font-semibold">Timebase and overlap</h3>
        <p className="mt-1 text-sm">{GRID_DESCRIPTION[grid]}</p>
        <p className="text-xs text-ink-2">
          Recorded overlap · {overlap === null ? "None" : rangeText(overlap)}
          {grid === "ambiguous"
            ? ` · Check source ${invalidOrder[0] && invalidOrder[1] ? "A and B" : invalidOrder[0] ? "A" : "B"}`
            : ` · ${matched} exact ${matched === 1 ? "pair" : "pairs"} · ${a.rows.length - matched} A-only · ${b.rows.length - matched} B-only`}
        </p>
        <h3 className="mt-3 font-semibold">Quantity compatibility</h3>
        <p className="mt-1 text-sm">
          {pairs.length === 0 ? "Unsupported quantities. No columns share an exact name and unit."
            : `${pairs.length} compatible ${pairs.length === 1 ? "quantity" : "quantities"} by declared name and unit.`}
        </p>
        {incompatible.length > 0 && (
          <details className="mt-1 text-xs text-ink-2" open={pairs.length === 0}>
            <summary className="cursor-pointer">{incompatible.length} unsupported {incompatible.length === 1 ? "quantity" : "quantities"}</summary>
            <ul className="mt-1 list-disc space-y-1 pl-4">
              {incompatible.map(({ a, b }) => (
                <li key={a?.name ?? b?.name} className="wrap-anywhere">
                  {a !== undefined && b !== undefined
                    ? `${a.name} · unit mismatch · A [${a.unit}] · B [${b.unit}]`
                    : a !== undefined ? `${a.name} [${a.unit}] · A only` : `${b!.name} [${b!.unit}] · B only`}
                </li>
              ))}
            </ul>
          </details>
        )}
        <p className="mt-3 text-xs text-ink-2">
          Times are compared as decoded binary64 seconds with exact equality. Each delta subtracts A from B in the shared declared unit.
          The CSV records carry no clock origin, coordinate frame or quantity definitions.
        </p>
      </section>
      {pairs.length > 0 && grid !== "ambiguous" && (
        <ComparisonPlots a={a} b={b} comparison={comparison} />
      )}
    </section>
  );
}

function ComparisonPlots({ a, b, comparison }: { a: ExternalResult; b: ExternalResult; comparison: Comparison }) {
  const { samples, pairs, matched } = comparison;
  const [selected, setSelected] = useState([pairs[0]!.aColumn]);
  const [confirmed, setConfirmed] = useState(false);
  const [zoom, setZoom] = useState<readonly PlotDomain[]>([]);
  const [sample, setSample] = useState(0);
  const { frame, width } = usePlotWidth();
  const fullDomain = useMemo<PlotDomain>(() => [samples[0]!.time, samples.at(-1)!.time], [samples]);
  const domain = zoom.at(-1) ?? fullDomain;
  const visible = useMemo(() => samples.filter(({ time }) => time >= domain[0] && time <= domain[1]), [samples, domain]);
  const cursorIndex = Math.max(0, visible.indexOf(samples[sample]!));
  const cursor = visible[cursorIndex]!;
  const { time, aRow, bRow } = cursor;
  const zoomed: PlotDomain = [plotValue([domain[0], time], 0.5), plotValue([time, domain[1]], 0.5)];
  const canZoom = zoomed[0] < zoomed[1] && (zoomed[0] > domain[0] || zoomed[1] < domain[1]);
  const plots = useMemo(() => {
    const aIndices: number[] = [];
    const bIndices: number[] = [];
    for (const { aRow, bRow } of visible) {
      if (aRow !== undefined) aIndices.push(aRow);
      if (bRow !== undefined) bIndices.push(bRow);
    }
    return pairs.map((pair) => ({
      pair,
      a: { rows: a.rows, indices: aIndices, column: pair.aColumn, connect: false },
      b: { rows: b.rows, indices: bIndices, column: pair.bColumn, connect: false },
    }));
  }, [a.rows, b.rows, pairs, visible]);

  function inspect(position: number) {
    let closest = cursor;
    let distance = Infinity;
    for (const candidate of visible) {
      const delta = Math.abs(plotFraction(candidate.time, domain) - position);
      if (delta < distance) {
        closest = candidate;
        distance = delta;
      }
    }
    setSample(samples.indexOf(closest));
  }

  const rowText = (side: string, row?: number) => row === undefined ? `${side} has no row` : `${side} row ${row + 1}`;
  const cursorLabel = `${recordedValue(time)} s · ${rowText("A", aRow)} · ${rowText("B", bRow)}`;
  const active = plots.filter(({ pair }) => selected.includes(pair.aColumn));
  const value = (source: ExternalResult, row: number | undefined, column: number) =>
    row === undefined ? undefined : source.rows[row]![column];

  return (
    <section className="mt-5" aria-label="Comparison overlays">
      <h3 className="font-display text-xl">Recorded overlays</h3>
      <fieldset className="mt-2 min-w-0">
        <legend className="text-xs font-medium text-ink-3">Shared quantities</legend>
        <div className="mt-1 flex flex-wrap gap-1.5">
          {pairs.map(({ quantity, aColumn }) => (
            <label key={quantity.name}
              className="inline-flex max-w-full cursor-pointer items-center gap-2 rounded border border-line px-2 py-1 text-sm has-checked:border-ext-line has-checked:bg-ext-soft">
              <input type="checkbox" checked={selected.includes(aColumn)} className="accent-ext" onChange={(event) => {
                const checked = event.currentTarget.checked;
                setSelected((current) => checked ? [...current, aColumn] : current.filter((column) => column !== aColumn));
              }} />
              <span className="min-w-0 wrap-anywhere">{quantity.name} [{quantity.unit}]</span>
            </label>
          ))}
        </div>
      </fieldset>
      <p className="mt-2 text-xs text-ink-2">
        Overlays share the recorded time axis and a value scale per quantity. Use the slider or select a point in a plot.
        Each mark is a recorded value. Below the axis, upper marks within each source track indicate blanks and lower marks indicate nonfinite values.
      </p>
      {matched > 0 && (
        <label className="mt-3 flex items-start gap-2 rounded border border-line bg-panel-2 p-2 text-sm">
          <input type="checkbox" className="mt-1 accent-ext" checked={confirmed}
            onChange={(event) => setConfirmed(event.currentTarget.checked)} />
          <span>I confirm that A and B share a time origin and that matching columns describe the same quantity, scale and frame.</span>
        </label>
      )}
      <div className="mt-3 flex flex-wrap items-center gap-2" role="group" aria-label="Comparison time zoom">
        <Button type="button" className={CONTROL} disabled={!canZoom} onClick={() => {
          setSample(samples.indexOf(cursor));
          setZoom((history) => [...history, zoomed]);
        }}>Zoom in</Button>
        <Button type="button" className={CONTROL} disabled={zoom.length === 0}
          onClick={() => setZoom((history) => history.slice(0, -1))}>Zoom out</Button>
        <Button type="button" className={CONTROL} disabled={zoom.length === 0} onClick={() => setZoom([])}>Reset zoom</Button>
        <span className="wrap-anywhere text-xs text-ink-2" aria-label="Comparison visible time span">
          {rangeText(domain)} · {visible.length} of {samples.length} times
        </span>
      </div>
      <div className="mt-3 rounded border border-line bg-panel-2 p-2">
        <div className="flex flex-wrap items-center gap-2">
          <label className="font-medium" htmlFor="comparison-sample">Inspect comparison time</label>
          <input id="comparison-sample" type="range" min={0} max={Math.max(1, visible.length - 1)}
            className="min-w-20 flex-1 accent-ext" value={cursorIndex} disabled={visible.length < 2}
            aria-valuetext={cursorLabel} onChange={(event) =>
              setSample(samples.indexOf(visible[event.currentTarget.valueAsNumber]!))} />
          <p className="wrap-anywhere font-mono text-xs" aria-label="Inspected comparison time">{cursorLabel}</p>
        </div>
        {active.length > 0 && (
          <table className="mt-2 w-full table-fixed text-left text-xs">
            <caption className="sr-only">Recorded values and differences at the inspected time</caption>
            <thead>
              <tr>
                {["Quantity", "A", "B", "B − A"].map((heading) => (
                  <th key={heading} scope="col" className="border-b border-line p-1">{heading}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {active.map(({ pair }) => (
                <ComparisonValues key={pair.quantity.name} pair={pair} confirmed={confirmed}
                  a={value(a, aRow, pair.aColumn)} b={value(b, bRow, pair.bColumn)} />
              ))}
            </tbody>
          </table>
        )}
      </div>
      <div ref={frame} className="mt-3 grid gap-2">
        {active.length === 0 && <p className="text-sm text-ink-2">Select a shared quantity to show its overlay.</p>}
        {active.map((plot) => (
          <RecordedSignalPlot key={plot.pair.quantity.name} channel={plot.pair.quantity}
            a={plot.a} b={plot.b} domain={domain} width={width} time={time} inspect={inspect}
            aValue={value(a, aRow, plot.pair.aColumn)} bValue={value(b, bRow, plot.pair.bColumn)} />
        ))}
      </div>
    </section>
  );
}

function ComparisonValues({ pair, a, b, confirmed }: {
  pair: QuantityPair;
  a: number | null | undefined;
  b: number | null | undefined;
  confirmed: boolean;
}) {
  const delta = compareSampleValues(a, b, confirmed);
  return (
    <tr className="border-b border-line last:border-0">
      <th scope="row" className="wrap-anywhere p-1 font-medium">{pair.quantity.name} [{pair.quantity.unit}]</th>
      <td className="wrap-anywhere p-1 font-mono">{a === undefined ? "No sample" : recordedValue(a)}</td>
      <td className="wrap-anywhere p-1 font-mono">{b === undefined ? "No sample" : recordedValue(b)}</td>
      <td className="wrap-anywhere p-1 font-mono">{"value" in delta ? recordedValue(delta.value) : DELTA_REASON[delta.reason]}</td>
    </tr>
  );
}
