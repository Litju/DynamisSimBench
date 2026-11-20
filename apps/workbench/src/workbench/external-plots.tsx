import { useEffect, useMemo, useRef, useState, type MouseEvent } from "react";

import type { ResultColumn } from "../api/external-results";
import { Button } from "../ui/button";
import type { ExternalResult } from "./external-samples";
import { buildTrace, plotFraction, plotValue, recordedValue, timeDomain, type PlotDomain } from "./external-trace";

const LEFT = 78;
const RIGHT = 40;
const TOP = 10;
const BASELINE = 114;
const HEIGHT = 151;
const TICK_FRACTIONS = [0, 0.5, 1];
const CONTROL = "w-auto border border-slate-200";

export function ExternalPlots({ result, connect }: { result: ExternalResult; connect: boolean }) {
  const { metadata, rows } = result;
  const [selected, setSelected] = useState([1]);
  const [zoomHistory, setZoomHistory] = useState<readonly PlotDomain[]>([]);
  const [sample, setSample] = useState(0);
  const frame = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(640);
  useEffect(() => {
    if (frame.current === null || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(([entry]) => {
      if (entry !== undefined) setWidth(Math.max(LEFT + RIGHT + 1, Math.floor(entry.contentRect.width)));
    });
    observer.observe(frame.current);
    return () => observer.disconnect();
  }, []);

  const fullDomain = useMemo(() => timeDomain(rows), [rows]);
  const domain = zoomHistory.at(-1) ?? fullDomain;
  const indices = useMemo(() => rows.flatMap(([time], index) =>
    time >= domain[0] && time <= domain[1] ? [index] : [],
  ), [rows, domain]);
  const cursorIndex = Math.max(0, indices.indexOf(sample));
  const cursorRow = indices[cursorIndex]!;
  const cursor = rows[cursorRow]!;
  const zoomed: PlotDomain = [plotValue([domain[0], cursor[0]], 0.5), plotValue([cursor[0], domain[1]], 0.5)];
  const canZoom = zoomed[0] < zoomed[1] && (zoomed[0] > domain[0] || zoomed[1] < domain[1]);
  const channels = metadata.columns.slice(1);

  function inspect(event: MouseEvent<SVGSVGElement>) {
    const bounds = event.currentTarget.getBoundingClientRect();
    const pixel = (event.clientX - bounds.left) / bounds.width * width;
    const position = (pixel - LEFT) / (width - LEFT - RIGHT);
    let closest = cursorRow;
    let distance = Infinity;
    for (const index of indices) {
      const delta = Math.abs(plotFraction(rows[index]![0], domain) - position);
      if (delta < distance) {
        distance = delta;
        closest = index;
      }
    }
    setSample(closest);
  }

  return (
    <section aria-label="Time-series plots" className="mt-5">
      <h3 className="font-display text-xl">Time series</h3>
      <fieldset className="mt-2 min-w-0">
        <legend className="text-xs font-medium text-ink-3">Signals</legend>
        <div className="mt-1 flex flex-wrap gap-1.5">
          {channels.map((channel, index) => {
            const column = index + 1;
            const checked = selected.includes(column);
            return (
              <label key={channel.name}
                className="inline-flex max-w-full cursor-pointer items-center gap-2 rounded border border-line px-2 py-1 text-sm has-checked:border-ext-line has-checked:bg-ext-soft">
                <input type="checkbox" checked={checked} className="accent-ext" onChange={() => {
                  setSelected((current) => checked ? current.filter((item) => item !== column) : [...current, column]);
                }} />
                <span className="min-w-0 wrap-anywhere">{channel.name} [{channel.unit}]</span>
              </label>
            );
          })}
        </div>
      </fieldset>

      <div className="mt-4 flex flex-wrap items-center gap-2" aria-label="Time zoom">
        <Button type="button" className={CONTROL} disabled={!canZoom} onClick={() => {
          setSample(cursorRow);
          setZoomHistory((history) => [...history, zoomed]);
        }}>Zoom in</Button>
        <Button type="button" className={CONTROL} disabled={zoomHistory.length === 0}
          onClick={() => setZoomHistory((history) => history.slice(0, -1))}>Zoom out</Button>
        <Button type="button" className={CONTROL} disabled={zoomHistory.length === 0}
          onClick={() => setZoomHistory([])}>Reset zoom</Button>
        <span className="min-w-0 wrap-anywhere text-xs text-ink-2" aria-label="Visible time span">
          {recordedValue(domain[0])} to {recordedValue(domain[1])} s · {indices.length} of {rows.length} rows
        </span>
      </div>
      <div className="mt-3 rounded border border-line bg-panel-2 px-3 py-2">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <label htmlFor="external-sample" className="font-medium">Inspect sample</label>
          <input id="external-sample" type="range" min={0} max={Math.max(1, indices.length - 1)}
            value={cursorIndex} disabled={indices.length < 2}
            aria-valuetext={`Row ${cursorRow + 1}, time ${recordedValue(cursor[0])} s`}
            onChange={(event) => setSample(indices[event.currentTarget.valueAsNumber]!)}
            className="min-w-20 flex-1 accent-ext" />
          <p className="font-mono text-xs" aria-label="Inspected row">
            Row {cursorRow + 1} · {recordedValue(cursor[0])} s
          </p>
        </div>
        <dl className="mt-1 flex flex-wrap gap-x-4 gap-y-1" aria-label="Inspected signal values">
          {channels.map((channel, index) => selected.includes(index + 1) && (
            <div key={channel.name} className="flex min-w-0 flex-wrap items-baseline gap-x-1.5">
              <dt className="wrap-anywhere text-ink-2">{channel.name}</dt>
              <dd className="wrap-anywhere font-mono text-xs">{recordedValue(cursor[index + 1]!)} [{channel.unit}]</dd>
            </div>
          ))}
        </dl>
      </div>
      <p className="mt-2 text-xs text-ink-2">
        Select a time on any plot or use the sample slider. Zoom in around the inspected time.
        {connect
          ? " Lines guide the eye between adjacent finite samples. Every point is a recorded value."
          : " Points show each recorded value. Line guides require a regular time grid."}
      </p>
      <div ref={frame} className="mt-3 grid gap-2">
        {selected.length === 0 && <p className="text-sm text-ink-2">Select a signal to show its plot.</p>}
        {channels.map((channel, index) => selected.includes(index + 1) && (
          <SignalPlot key={channel.name} channel={channel} column={index + 1}
            rows={rows} indices={indices} domain={domain} width={width} connect={connect}
            cursor={cursor} inspect={inspect} />
        ))}
      </div>
    </section>
  );
}

function ticks(domain: PlotDomain, fractions: readonly number[]) {
  const seen = new Set<string>();
  return fractions.flatMap((fraction) => {
    const value = plotValue(domain, fraction);
    const label = String(Number(value.toPrecision(5)));
    if (seen.has(label)) return [];
    seen.add(label);
    return [{ label, fraction: plotFraction(value, domain) }];
  });
}

function SignalPlot({ channel, column, rows, indices, domain, width, connect, cursor, inspect }: {
  channel: ResultColumn;
  column: number;
  rows: ExternalResult["rows"];
  indices: readonly number[];
  domain: PlotDomain;
  width: number;
  connect: boolean;
  cursor: ExternalResult["rows"][number];
  inspect: (event: MouseEvent<SVGSVGElement>) => void;
}) {
  const span = width - LEFT - RIGHT;
  const x = (time: number) => LEFT + plotFraction(time, domain) * span;
  const y = (fraction: number) => BASELINE - fraction * (BASELINE - TOP);
  const trace = useMemo(() => buildTrace(rows, indices, column, (time) =>
    LEFT + plotFraction(time, domain) * span, y, connect), [rows, indices, column, domain, span, connect]);
  const timeTicks = ticks(domain, width < 420 ? [0, 1] : TICK_FRACTIONS);
  const valueTicks = trace.domain === null ? [] : ticks(trace.domain, TICK_FRACTIONS);
  const cursorValue = cursor[column]!;
  const cursorX = x(cursor[0]);
  const title = `${channel.name} [${channel.unit}]`;

  return (
    <figure className="min-w-0 rounded border border-line bg-scene py-2">
      <figcaption className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3">
        <span className="min-w-0 wrap-anywhere font-medium text-ext">{title}</span>
        {trace.domain === null && <span className="text-xs text-ink-2">No finite values in view</span>}
        {trace.missing !== "" && <span className="text-xs text-warn">Missing · upper marks</span>}
        {trace.nonfinite !== "" && <span className="text-xs text-err">Nonfinite · lower marks</span>}
      </figcaption>
      <svg viewBox={`0 0 ${width} ${HEIGHT}`} width="100%" height={HEIGHT}
        preserveAspectRatio="none" role="img"
        aria-label={`${title} over time [s]`} onClick={inspect} className="block cursor-crosshair">
        <g className="fill-ink-3 font-mono text-[10px]">
          {valueTicks.map(({ label, fraction }) => (
            <g key={label}>
              <line x1={LEFT} x2={width - RIGHT} y1={y(fraction)} y2={y(fraction)} className="stroke-line-2" />
              <text x={LEFT - 6} y={y(fraction) + 3} textAnchor="end">{label}</text>
            </g>
          ))}
          {timeTicks.map(({ label, fraction }) => (
            <text key={label} x={LEFT + fraction * span} y={HEIGHT - 6}
              textAnchor={fraction === 1 ? "end" : "middle"}>{label}</text>
          ))}
          <text x={width - 5} y={HEIGHT - 6} textAnchor="end">s</text>
        </g>
        <line x1={LEFT} x2={width - RIGHT} y1={BASELINE} y2={BASELINE} className="stroke-line-2" />
        <path d={trace.lines} fill="none" className="stroke-ext" strokeWidth={1.4} />
        <path d={trace.points} fill="none" className="stroke-ext" strokeLinecap="round"
          strokeWidth={connect && indices.length > 150 ? 1.3 : 3} />
        <g transform={`translate(0, ${BASELINE + 2})`}>
          <path d={trace.missing} className="stroke-warn" strokeWidth={2} />
          <path d={trace.nonfinite} className="stroke-err" strokeWidth={2} />
        </g>
        <line x1={cursorX} x2={cursorX} y1={TOP} y2={BASELINE + 16} className="stroke-accent" strokeDasharray="3 3" />
        {trace.domain !== null && cursorValue !== null && Number.isFinite(cursorValue) && (
          <circle cx={cursorX} cy={y(plotFraction(cursorValue, trace.domain))} r={4}
            className="fill-scene stroke-accent" strokeWidth={2} />
        )}
      </svg>
    </figure>
  );
}
