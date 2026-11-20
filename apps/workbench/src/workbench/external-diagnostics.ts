import type { ResultColumn } from "../api/external-results";
import type { ExternalResult } from "./external-samples";

export const DIAGNOSTICS_VERSION = "external-results/diagnostics-v1";
const RELATIVE_STEP_TOLERANCE = 1e-6;

export type DiagnosticStatus = "PASS" | "FAIL" | "INCONCLUSIVE" | "UNSUPPORTED";

const METHODS = {
  monotonicity: {
    label: "Strict time increase",
    method: "Compare adjacent timestamps in source order. Count each later row whose time is less than or equal to the preceding time.",
    limitations: "Requires two rows. Compares decoded binary64 timestamps exactly.",
  },
  duplicates: {
    label: "Duplicate timestamps",
    method: "Count every occurrence of a decoded timestamp after its first occurrence, including nonadjacent repeats.",
    limitations: "Binary64 equality treats signed zeros as equal. Nearby distinct values are counted separately.",
  },
  regularity: {
    label: "Sampling regularity",
    method: "Compare each adjacent time step with the median observed step. Flag relative deviations greater than 1 ppm (10⁻⁶).",
    limitations: "Requires at least two positive, finite steps in strictly increasing source order. Relative comparisons scale steps by the upper middle step. The displayed median is rounded to binary64 seconds. The check cannot infer a prescribed cadence, omitted rows or clock accuracy.",
  },
  missing: {
    label: "Missing values",
    method: "Count Arrow nulls from blank signal cells.",
    limitations: "Counts explicit missing cells in admitted rows. Omitted rows and other missing-value conventions are outside this check.",
  },
  nonfinite: {
    label: "Nonfinite values",
    method: "Count NaN, positive infinity and negative infinity separately among non-null values.",
    limitations: "Checks numeric representation. Finite values can still be physically implausible.",
  },
} as const;

type DiagnosticCheck = keyof typeof METHODS;

export interface DiagnosticFinding {
  readonly check: DiagnosticCheck;
  readonly status: DiagnosticStatus;
  readonly sourceSha256: string;
  readonly quantity: ResultColumn;
  readonly sampleCount: number;
  readonly label: string;
  readonly method: string;
  readonly limitations: string;
  readonly summary: string;
  readonly affectedCount?: number;
  /** One-based data row, excluding the CSV header. For a pair, this is its later row. */
  readonly firstAffectedRow?: number;
}

export interface ExternalDiagnostics {
  readonly version: typeof DIAGNOSTICS_VERSION;
  readonly findings: readonly DiagnosticFinding[];
}

interface Tally {
  count: number;
  firstRow?: number;
}

function countAt(tally: Tally, rowIndex: number) {
  tally.count++;
  tally.firstRow ??= rowIndex + 1;
}

/** The complete admitted result is the input. Viewport and signal selection have no bearing here. */
export function diagnoseExternalResult({ metadata, rows }: ExternalResult): ExternalDiagnostics {
  function finding(
    check: DiagnosticCheck, quantity: ResultColumn, status: DiagnosticStatus, summary: string, tally?: Tally,
  ): DiagnosticFinding {
    return {
      check, quantity, status, summary, ...METHODS[check],
      sourceSha256: metadata.source_sha256,
      sampleCount: rows.length,
      affectedCount: tally?.count,
      firstAffectedRow: tally?.firstRow,
    };
  }

  const time = metadata.columns[0]!;
  const order: Tally = { count: 0 };
  const repeats: Tally = { count: 0 };
  const timestamps = new Set<number>();
  const steps: number[] = [];
  for (const [index, row] of rows.entries()) {
    const current = row[0];
    if (timestamps.has(current)) countAt(repeats, index);
    timestamps.add(current);
    const previous = rows[index - 1]?.[0];
    if (previous === undefined) continue;
    if (current <= previous) countAt(order, index);
    steps.push(current - previous);
  }

  const findings = [
    rows.length < 2
      ? finding("monotonicity", time, "INCONCLUSIVE", "One timestamp provides no adjacent pair.")
      : finding("monotonicity", time, order.count === 0 ? "PASS" : "FAIL",
        `${order.count} of ${steps.length} adjacent pairs do not strictly increase.`, order),
    finding("duplicates", time, repeats.count === 0 ? "PASS" : "FAIL",
      `${repeats.count} of ${rows.length} timestamps repeat an earlier timestamp.`, repeats),
  ];

  if (order.count > 0) {
    findings.push(finding("regularity", time, "INCONCLUSIVE", "The source timestamps are out of strict order."));
  } else if (steps.some((step) => !Number.isFinite(step))) {
    findings.push(finding("regularity", time, "UNSUPPORTED", "At least one interval exceeds the binary64 range."));
  } else if (steps.length < 2) {
    findings.push(finding("regularity", time, "INCONCLUSIVE", "At least three timestamps are needed to compare intervals."));
  } else {
    const sorted = steps.toSorted((a, b) => a - b);
    const lower = sorted[Math.floor((sorted.length - 1) / 2)]!;
    const upper = sorted[Math.floor(sorted.length / 2)]!;
    // In units of the upper middle step, the median stays in [0.5, 1] even
    // when its value in seconds falls between adjacent positive subnormals.
    const scaledMedian = (lower / upper + 1) / 2;
    const median = scaledMedian * upper;
    const irregular: Tally = { count: 0 };
    for (const [index, step] of steps.entries()) {
      if (Math.abs(step / upper - scaledMedian) / scaledMedian > RELATIVE_STEP_TOLERANCE) {
        countAt(irregular, index + 1);
      }
    }
    findings.push(finding("regularity", time, irregular.count === 0 ? "PASS" : "FAIL",
      `${irregular.count} of ${steps.length} intervals exceed the tolerance. Median ${median} s, range ${sorted[0]} to ${sorted.at(-1)} s.`,
      irregular));
  }

  for (const [index, quantity] of metadata.columns.entries()) {
    if (index === 0) continue;
    const missing: Tally = { count: 0 };
    const nonfinite: Tally = { count: 0 };
    let nan = 0;
    let positiveInfinity = 0;
    let negativeInfinity = 0;
    for (const [rowIndex, row] of rows.entries()) {
      const value = row[index]!;
      if (value === null) {
        countAt(missing, rowIndex);
      } else if (!Number.isFinite(value)) {
        countAt(nonfinite, rowIndex);
        if (Number.isNaN(value)) nan++;
        else if (value === Infinity) positiveInfinity++;
        else negativeInfinity++;
      }
    }
    findings.push(
      finding("missing", quantity, missing.count === 0 ? "PASS" : "FAIL",
        `${missing.count} of ${rows.length} values are missing.`, missing),
      missing.count === rows.length
        ? finding("nonfinite", quantity, "INCONCLUSIVE", "Every value is missing.")
        : finding("nonfinite", quantity, nonfinite.count === 0 ? "PASS" : "FAIL",
          `${nonfinite.count} of ${rows.length - missing.count} present values are nonfinite (${nan} NaN, ${positiveInfinity} +Inf, ${negativeInfinity} −Inf).`,
          nonfinite),
    );
  }

  return { version: DIAGNOSTICS_VERSION, findings };
}
