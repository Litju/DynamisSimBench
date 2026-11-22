import type { ExternalResult } from "./external-samples";

export type PlotDomain = readonly [min: number, max: number];

export function timeDomain(rows: ExternalResult["rows"]): PlotDomain {
  let min = Infinity;
  let max = -Infinity;
  for (const [time] of rows) {
    min = Math.min(min, time);
    max = Math.max(max, time);
  }
  return [min, max];
}

export function plotFraction(value: number, [min, max]: PlotDomain): number {
  if (min === max) return 0.5;
  const span = max - min;
  return Number.isFinite(span)
    ? (value - min) / span
    : (value / 2 - min / 2) / (max / 2 - min / 2);
}

export function plotValue([min, max]: PlotDomain, fraction: number): number {
  if (fraction === 1) return max;
  const span = max - min;
  return Number.isFinite(span)
    ? min + span * fraction
    : min * (1 - fraction) + max * fraction;
}

export function recordedValue(value: number | null): string {
  if (value === null) return "Missing";
  return Object.is(value, -0) ? "-0" : String(value);
}

function tickLabel(value: number): string {
  // Keep the rounded decimal as text. Re-parsing can overflow near Number.MAX_VALUE.
  return value.toPrecision(5).replace(/(\.\d*?[1-9])0+(?=e|$)|\.0+(?=e|$)/, "$1");
}

export function plotTicks(domain: PlotDomain, fractions: readonly number[]) {
  const values = [...new Set(fractions.map((fraction) => plotValue(domain, fraction)))];
  const labels = values.map(tickLabel);
  // Large offsets can make distinct ticks round to the same label. Express that
  // narrow axis relative to its minimum and expose the origin next to the plot.
  const origin = new Set(labels).size < values.length ? domain[0] : null;
  return {
    origin,
    ticks: values.map((value, index) => ({
      label: origin === null ? labels[index]! : tickLabel(value - origin),
      fraction: plotFraction(value, domain),
    })),
  };
}

export function signalDomain(
  rows: ExternalResult["rows"],
  indices: readonly number[],
  column: number,
): PlotDomain | null {
  let min = Infinity;
  let max = -Infinity;
  for (const index of indices) {
    const value = rows[index]![column]!;
    if (value === null || !Number.isFinite(value)) continue;
    min = Math.min(min, value);
    max = Math.max(max, value);
  }
  return min <= max ? [min, max] : null;
}

/** Map every visible source row to geometry before rounding coordinates for SVG. */
export function buildTrace(
  rows: ExternalResult["rows"],
  indices: readonly number[],
  column: number,
  x: (time: number) => number,
  y: (fraction: number) => number,
  connect: boolean,
  scale?: { readonly domain: PlotDomain | null; readonly diamond: boolean },
) {
  const domain = scale === undefined ? signalDomain(rows, indices, column) : scale.domain;
  let lines = "";
  let points = "";
  let missing = "";
  let nonfinite = "";
  let previous = -2;
  for (const index of indices) {
    const row = rows[index]!;
    const value = row[column]!;
    const px = x(row[0]).toFixed(2);
    if (value === null) {
      missing += `M${px},1v5`;
    } else if (!Number.isFinite(value)) {
      nonfinite += `M${px},9v5`;
    } else {
      const point = `${px},${y(plotFraction(value, domain!)).toFixed(2)}`;
      points += scale?.diamond === true
        ? `M${point}m0,-2l2,2l-2,2l-2,-2z`
        : `M${point}h0.01`;
      if (connect) lines += `${previous === index - 1 ? "L" : "M"}${point}`;
      previous = index;
    }
  }
  return { domain, lines, points, missing, nonfinite };
}
