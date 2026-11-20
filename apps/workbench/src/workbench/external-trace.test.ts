import { describe, expect, it } from "vitest";

import { buildTrace, plotFraction, plotValue, timeDomain } from "./external-trace";
import type { ExternalResult } from "./external-samples";

describe("external trace geometry", () => {
  it("preserves both extrema and separates blank and nonfinite cells", () => {
    const rows: ExternalResult["rows"] = [[0, 2], [1, 100], [2, null], [3, -100], [4, Infinity], [5, 3]];
    const trace = buildTrace(rows, [0, 1, 2, 3, 4, 5], 1, (time) => time, (unit) => unit, true);
    expect(trace.domain).toEqual([-100, 100]);
    expect(trace.lines).toBe("M0.00,0.51L1.00,1.00M3.00,0.00M5.00,0.52");
    expect(trace.points.match(/M/g)).toHaveLength(4);
    expect(trace.missing).toBe("M2.00,1v5");
    expect(trace.nonfinite).toBe("M4.00,9v5");
  });

  it("keeps duplicate and reversed rows as points and uses the true time extent", () => {
    const rows: ExternalResult["rows"] = [[4, 1], [2, 2], [4, -3]];
    expect(timeDomain(rows)).toEqual([2, 4]);
    const trace = buildTrace(rows, [0, 1, 2], 1, (time) => time, (unit) => unit, false);
    expect(trace.lines).toBe("");
    expect(trace.points.match(/M/g)).toHaveLength(3);
  });

  it("uses only visible rows for the y domain and never joins across a skipped row", () => {
    const rows: ExternalResult["rows"] = [[0, 1], [1, -2], [2, 9]];
    const trace = buildTrace(rows, [0, 2], 1, (time) => time, (unit) => unit, true);
    expect(trace.domain).toEqual([1, 9]);
    expect(trace.lines).toBe("M0.00,0.00M2.00,1.00");
  });

  it("makes all-invalid, constant and extreme binary64 views representable", () => {
    const trace = buildTrace([[0, null], [1, NaN]], [0, 1], 1, (time) => time, (unit) => unit, true);
    expect(trace.domain).toBeNull();
    expect(trace.points).toBe("");
    expect(plotFraction(0, [-Number.MAX_VALUE, Number.MAX_VALUE])).toBe(0.5);
    expect(plotValue([-Number.MAX_VALUE, Number.MAX_VALUE], 0.5)).toBe(0);
    expect(plotFraction(8, [8, 8])).toBe(0.5);
  });
});
