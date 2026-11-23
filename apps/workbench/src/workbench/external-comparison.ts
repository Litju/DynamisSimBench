import type { ResultColumn } from "../api/external-results";
import type { ExternalDiagnostics } from "./external-diagnostics";
import type { ExternalResult } from "./external-samples";
import { timeDomain, type PlotDomain } from "./external-trace";

export const COMPARISON_VERSION = "external-results/exact-comparison-v1";

export interface QuantityPair {
  readonly quantity: ResultColumn;
  readonly aColumn: number;
  readonly bColumn: number;
}

export interface ComparisonSample {
  readonly time: number;
  readonly aRow?: number;
  readonly bRow?: number;
}

interface Source {
  readonly result: ExternalResult;
  readonly diagnostics: ExternalDiagnostics;
}

/** Compare declarations and merge the two admitted timelines in source order, without resampling. */
export function compareExternalResults(a: Source, b: Source) {
  const pairs: QuantityPair[] = [];
  const incompatible: { a?: ResultColumn; b?: ResultColumn }[] = [];
  const bColumns = new Map(b.result.metadata.columns.slice(1).map((quantity, index) =>
    [quantity.name, { quantity, column: index + 1 }] as const,
  ));
  for (const [index, quantity] of a.result.metadata.columns.entries()) {
    if (index === 0) continue;
    const match = bColumns.get(quantity.name);
    if (match === undefined) {
      incompatible.push({ a: quantity });
    } else if (quantity.unit !== match.quantity.unit || quantity.canonical_unit !== match.quantity.canonical_unit) {
      incompatible.push({ a: quantity, b: match.quantity });
    } else {
      pairs.push({ quantity, aColumn: index, bColumn: match.column });
    }
    bColumns.delete(quantity.name);
  }
  for (const { quantity } of bColumns.values()) incompatible.push({ b: quantity });

  const aRange = timeDomain(a.result.rows);
  const bRange = timeDomain(b.result.rows);
  const overlapStart = Math.max(aRange[0], bRange[0]);
  const overlapEnd = Math.min(aRange[1], bRange[1]);
  const overlap: PlotDomain | null = overlapStart <= overlapEnd ? [overlapStart, overlapEnd] : null;
  const invalidOrder = [a, b].map(({ diagnostics }) =>
    diagnostics.findings.some(({ check, status }) => check === "monotonicity" && status === "FAIL"),
  );
  const samples: ComparisonSample[] = [];
  let matched = 0;
  if (!invalidOrder.includes(true)) {
    const aRows = a.result.rows;
    const bRows = b.result.rows;
    let aRow = 0;
    let bRow = 0;
    while (aRow < aRows.length || bRow < bRows.length) {
      const aTime = aRows[aRow]?.[0] ?? Infinity;
      const bTime = bRows[bRow]?.[0] ?? Infinity;
      if (aTime === bTime) {
        samples.push({ time: aTime, aRow: aRow++, bRow: bRow++ });
        matched++;
      } else if (aTime < bTime) {
        samples.push({ time: aTime, aRow: aRow++ });
      } else {
        samples.push({ time: bTime, bRow: bRow++ });
      }
    }
  }

  const grid = invalidOrder.includes(true) ? "ambiguous"
    : overlap === null ? "disjoint"
    : matched === 0 ? "no-exact-matches"
    : matched === samples.length ? "identical"
    : "partial";
  return { pairs, incompatible, aRange, bRange, overlap, grid, invalidOrder, samples, matched };
}

export type ComparisonDelta =
  | { readonly value: number }
  | { readonly reason: "unmatched" | "missing" | "nonfinite" | "unconfirmed" | "overflow" };

/** Undefined means no row at this time, and null means a recorded blank cell. */
export function compareSampleValues(
  a: number | null | undefined,
  b: number | null | undefined,
  confirmed: boolean,
): ComparisonDelta {
  if (a === undefined || b === undefined) return { reason: "unmatched" };
  if (a === null || b === null) return { reason: "missing" };
  if (!Number.isFinite(a) || !Number.isFinite(b)) return { reason: "nonfinite" };
  if (!confirmed) return { reason: "unconfirmed" };
  const delta = b - a;
  return Number.isFinite(delta) ? { value: delta } : { reason: "overflow" };
}
