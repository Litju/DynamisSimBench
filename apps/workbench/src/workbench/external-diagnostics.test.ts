import { describe, expect, it } from "vitest";

import { diagnoseExternalResult, DIAGNOSTICS_VERSION } from "./external-diagnostics";
import type { ExternalResult } from "./external-samples";

const sourceSha256 = "ab".repeat(32);
const time = { name: "time", unit: "s", canonical_unit: "s" };
const position = { name: "position", unit: "m", canonical_unit: "m" };
const velocity = { name: "velocity", unit: "m/s", canonical_unit: "m/s" };

function diagnose(rows: ExternalResult["rows"]) {
  return diagnoseExternalResult({
    metadata: {
      result_id: "a".repeat(32),
      source_name: "result.csv",
      source_sha256: sourceSha256,
      size_bytes: 64,
      schema_version: "external-results/csv-v1",
      sample_count: rows.length,
      columns: [time, position, velocity],
    },
    rows,
  });
}

describe("external diagnostics v1", () => {
  it("traces each check to the exact source and declared quantity", () => {
    const result = diagnose([[0, 0, 1], [0.05, 0.1, 1], [0.1, 0.2, 1], [0.15, 0.3, 1]]);
    expect(result.version).toBe(DIAGNOSTICS_VERSION);
    expect(result.findings.map(({ quantity }) => quantity)).toEqual(
      [time, time, time, position, position, velocity, velocity],
    );
    for (const finding of result.findings) {
      expect(finding).toMatchObject({
        status: "PASS", sourceSha256, sampleCount: 4, affectedCount: 0,
        method: expect.any(String), limitations: expect.any(String),
      });
    }
  });

  it("finds steps beyond the relative tolerance and records the later row", () => {
    const { findings } = diagnose([[0, 0, 1], [0.05, 0, 1], [0.2, 0, 1], [0.25, 0, 1]]);
    expect(findings[2]).toMatchObject({
      check: "regularity", status: "FAIL", affectedCount: 1, firstAffectedRow: 3,
    });
  });

  it("counts nonadjacent duplicates and retains order and value defects independently", () => {
    const { findings } = diagnose([[0, null, NaN], [2, null, Infinity], [-0, null, -Infinity], [0, null, 42]]);
    expect(findings).toMatchObject([
      { check: "monotonicity", status: "FAIL", affectedCount: 2, firstAffectedRow: 3 },
      { check: "duplicates", status: "FAIL", affectedCount: 2, firstAffectedRow: 3 },
      { check: "regularity", status: "INCONCLUSIVE" },
      { check: "missing", status: "FAIL", affectedCount: 4, firstAffectedRow: 1 },
      { check: "nonfinite", status: "INCONCLUSIVE" },
      { check: "missing", status: "PASS" },
      { check: "nonfinite", status: "FAIL", affectedCount: 3, firstAffectedRow: 1 },
    ]);
    expect(findings[6]?.summary).toContain("1 NaN, 1 +Inf, 1 −Inf");
  });

  it("distinguishes insufficient observations from unrepresentable steps", () => {
    expect(diagnose([[5, 1, 1]]).findings.slice(0, 3).map(({ status }) => status)).toEqual(
      ["INCONCLUSIVE", "PASS", "INCONCLUSIVE"],
    );
    expect(diagnose([[0, 1, 1], [1, 1, 1]]).findings[2]?.status).toBe("INCONCLUSIVE");
    expect(diagnose([[-1e308, 1, 1], [1e308, 1, 1]]).findings[2]?.status).toBe("UNSUPPORTED");
  });

  it("checks the last admitted row even in a dense result", () => {
    const rows: ExternalResult["rows"] = Array.from({ length: 20_000 }, (_, i) => [
      i, i === 19_999 ? null : 1, i === 19_999 ? Infinity : 1,
    ]);
    const { findings } = diagnose(rows);
    expect(findings[3]).toMatchObject({ status: "FAIL", affectedCount: 1, firstAffectedRow: 20_000 });
    expect(findings[6]).toMatchObject({ status: "FAIL", affectedCount: 1, firstAffectedRow: 20_000 });
  });
});
