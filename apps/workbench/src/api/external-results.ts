import { decodeArrowIpcStream } from "../arrow/arrow";
import { ApiClientError } from "./errors";

export interface ResultEntry {
  readonly name: string;
  readonly result_id: string | null;
  readonly refusal: string | null;
}

export interface ResultList {
  readonly results: readonly ResultEntry[];
  readonly ignored_names: number;
}

export interface ResultColumn {
  readonly name: string;
  readonly unit: string;
  readonly canonical_unit: string;
}

export interface ResultMetadata {
  readonly result_id: string;
  readonly source_name: string;
  readonly source_sha256: string;
  readonly size_bytes: number;
  readonly schema_version: "external-results/csv-v1";
  readonly sample_count: number;
  readonly columns: readonly ResultColumn[];
}

export interface ExternalResult {
  readonly metadata: ResultMetadata;
  readonly rows: readonly (readonly (number | null)[])[];
}

const HANDLE = /^[A-Za-z0-9_-]{32}$/;
const CSV_NAME = /^[^/\\<>:"|?*\p{C}]{1,96}\.csv$/iu;
const COLUMN_NAME = /^[A-Za-z][A-Za-z0-9_]{0,47}$/;

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function matches(value: unknown, pattern: RegExp): value is string {
  return typeof value === "string" && pattern.test(value);
}

function boundedInteger(value: unknown, maximum: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1 && value <= maximum;
}

export function externalResultsPath(workspaceId: string, resultId?: string): string {
  if (!HANDLE.test(workspaceId) || (resultId !== undefined && !HANDLE.test(resultId))) {
    throw new ApiClientError("invalid_response");
  }
  const base = `/workspaces/${workspaceId}/external-results`;
  return resultId === undefined ? base : `${base}/${resultId}`;
}

export function decodeResultList(value: unknown): ResultList | null {
  const listing = record(value);
  if (listing === null) return null;
  const entries: unknown = listing.results;
  const ignored = listing.ignored_names;
  if (!Array.isArray(entries) || (ignored !== 0 && !boundedInteger(ignored, 32)) ||
      entries.length + ignored > 32) return null;
  const results: ResultEntry[] = [];
  const names = new Set<string>();
  const handles = new Set<string>();
  for (const entry of entries) {
    const item = record(entry);
    if (item === null || !matches(item.name, CSV_NAME) || names.has(item.name)) return null;
    const { name, result_id, refusal } = item;
    if (result_id === null && typeof refusal === "string" && refusal.length <= 256) {
      results.push({ name, result_id, refusal });
    } else if (matches(result_id, HANDLE) && refusal === null && !handles.has(result_id)) {
      results.push({ name, result_id, refusal });
      handles.add(result_id);
    } else {
      return null;
    }
    names.add(name);
  }
  return { results, ignored_names: ignored };
}

export function decodeResultMetadata(value: unknown): ResultMetadata | null {
  const item = record(value);
  if (item === null) return null;
  const { result_id, source_name, source_sha256, size_bytes, schema_version, sample_count } = item;
  if (
    !matches(result_id, HANDLE) || !matches(source_name, CSV_NAME) ||
    !matches(source_sha256, /^[a-f0-9]{64}$/) || !boundedInteger(size_bytes, 1024 * 1024) ||
    schema_version !== "external-results/csv-v1" || !boundedInteger(sample_count, 20_000) ||
    !Array.isArray(item.columns) || item.columns.length < 2 || item.columns.length > 16 ||
    sample_count * item.columns.length > 100_000
  ) return null;

  const columns: ResultColumn[] = [];
  const names = new Set<string>();
  for (const entry of item.columns) {
    const column = record(entry);
    if (column === null) return null;
    const { name, unit, canonical_unit } = column;
    if (
      !matches(name, COLUMN_NAME) || names.has(name.toLowerCase()) ||
      !matches(unit, /^[A-Za-z0-9*/^-]{1,64}$/) ||
      !matches(canonical_unit, /^[A-Za-z0-9.*/^-]{1,128}$/)
    ) return null;
    names.add(name.toLowerCase());
    columns.push({ name, unit, canonical_unit });
  }
  if (columns[0]?.name !== "time" || columns[0].unit !== "s" || columns[0].canonical_unit !== "s") {
    return null;
  }
  return { result_id, source_name, source_sha256, size_bytes, schema_version, sample_count, columns };
}

export async function decodeExternalSamples(
  metadata: ResultMetadata,
  payload: Uint8Array,
): Promise<ExternalResult> {
  const table = await decodeArrowIpcStream(payload);
  if (
    table.numRows !== metadata.sample_count || table.fields.length !== metadata.columns.length ||
    !table.fields.every((field, index) =>
      field.name === metadata.columns[index]?.name && field.type === "Float64" && field.nullable)
  ) throw new ApiClientError("invalid_response");

  const rows = table.rows.map((row) => metadata.columns.map(({ name }, index) => {
    const value = Object.hasOwn(row, name) ? row[name] : undefined;
    if (index === 0 && typeof value === "number" && Number.isFinite(value)) return value;
    if (index > 0 && (typeof value === "number" || value === null)) return value;
    throw new ApiClientError("invalid_response");
  }));
  return { metadata, rows };
}
