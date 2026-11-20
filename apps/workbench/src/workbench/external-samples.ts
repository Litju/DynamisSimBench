import { ApiClientError } from "../api/errors";
import type { ExternalResultPayload, ResultMetadata } from "../api/external-results";
import { decodeArrowIpcStream } from "../arrow/arrow";

export interface ExternalResult {
  readonly metadata: ResultMetadata;
  readonly rows: readonly (readonly (number | null)[])[];
}

export async function decodeExternalSamples({
  metadata,
  bytes,
}: ExternalResultPayload): Promise<ExternalResult> {
  const table = await decodeArrowIpcStream(bytes);
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
