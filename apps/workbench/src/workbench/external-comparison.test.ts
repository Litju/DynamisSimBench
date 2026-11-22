import { describe, expect, it } from "vitest";

import { compareExternalResults, compareSampleValues } from "./external-comparison";
import { diagnoseExternalResult } from "./external-diagnostics";
import type { ExternalResult } from "./external-samples";

const time = { name: "time", unit: "s", canonical_unit: "s" };
const distance = { name: "distance", unit: "m", canonical_unit: "m" };
const force = { name: "force", unit: "N", canonical_unit: "kg.m/s^2" };

function source(rows: ExternalResult["rows"], columns = [time, distance]) {
  const result: ExternalResult = {
    rows,
    metadata: {
      result_id: "b".repeat(32), source_name: "sample.csv", source_sha256: "a".repeat(64),
      columns, schema_version: "external-results/csv-v1", size_bytes: 32, sample_count: rows.length,
    },
  };
  return { result, diagnostics: diagnoseExternalResult(result) };
}

describe("recorded result comparison", () => {
  it("matches quantities by exact name and declared/canonical unit, independent of column order", () => {
    const a = source([[0, 3, 2, 4]], [time, distance, force, { ...distance, name: "a_only" }]);
    const b = source([[0, 2, 3, 4]], [time, { ...force, unit: "kg*m/s^2" }, distance, { ...distance, name: "b_only" }]);
    expect(compareExternalResults(a, b)).toMatchObject({
      pairs: [{ quantity: distance, aColumn: 1, bColumn: 2 }],
      incompatible: [{ a: force, b: b.result.metadata.columns[1] }, { a: { name: "a_only" } }, { b: { name: "b_only" } }],
      grid: "identical", matched: 1, overlap: [0, 0],
    });
  });

  it("preserves exact matches and every unmatched row on a partially overlapping irregular grid", () => {
    const a = source([[-1, 4], [-0, null], [0.3, NaN], [2, 9]]);
    const b = source([[0, 3], [0.1 + 0.2, 4], [2, 12], [3, Infinity]]);
    expect(compareExternalResults(a, b)).toMatchObject({
      grid: "partial", aRange: [-1, 2], bRange: [0, 3], overlap: [0, 2], matched: 2,
      samples: [
        { time: -1, aRow: 0 }, { time: -0, aRow: 1, bRow: 0 }, { time: 0.3, aRow: 2 },
        { time: 0.1 + 0.2, bRow: 1 }, { time: 2, aRow: 3, bRow: 2 }, { time: 3, bRow: 3 },
      ],
    });
  });

  it("distinguishes disjoint ranges, overlapping ranges with no match, and ambiguous timebases", () => {
    const a = source([[0, 42], [1, 43]]);
    expect(compareExternalResults(a, source([[2, 0]]))).toMatchObject({ grid: "disjoint", overlap: null });
    expect(compareExternalResults(a, source([[0.5, 0]]))).toMatchObject({ grid: "no-exact-matches", overlap: [0.5, 0.5] });
    for (const b of [source([[0, 1], [0, 2]]), source([[1, 1], [0, 2]])]) {
      expect(compareExternalResults(a, b)).toMatchObject({ grid: "ambiguous", samples: [], matched: 0 });
    }
  });

  it("keeps the full union bounded by the two source row counts", () => {
    const a = source(Array.from({ length: 20_000 }, (_, index) => [2 * index, 1]));
    const b = source(Array.from({ length: 20_000 }, (_, index) => [2 * index + 1, 2]));
    const comparison = compareExternalResults(a, b);
    expect(comparison.samples).toHaveLength(40_000);
    expect(comparison.samples.at(-1)).toEqual({ time: 39_999, bRow: 19_999 });
    expect(comparison.matched).toBe(0);
  });

  it("requires confirmed finite exact pairs and suppresses differences outside binary64", () => {
    expect(compareSampleValues(2, 5, true)).toEqual({ value: 3 });
    expect(compareSampleValues(2, 5, false)).toEqual({ reason: "unconfirmed" });
    expect(compareSampleValues(2, undefined, true)).toEqual({ reason: "unmatched" });
    expect(compareSampleValues(null, 1, true)).toEqual({ reason: "missing" });
    expect(compareSampleValues(NaN, Infinity, true)).toEqual({ reason: "nonfinite" });
    expect(compareSampleValues(-Number.MAX_VALUE, Number.MAX_VALUE, true)).toEqual({ reason: "overflow" });
  });
});
