import { describe, expect, it } from "vitest";

import { decodeResultList, decodeResultMetadata, externalResultsPath } from "./external-results";

const handle = "A".repeat(32);
const metadata = {
  result_id: handle,
  source_name: "résultat (1).csv",
  source_sha256: "f".repeat(64),
  size_bytes: 73,
  schema_version: "external-results/csv-v1",
  sample_count: 3,
  columns: [
    { name: "time", unit: "s", canonical_unit: "s" },
    { name: "position", unit: "mm", canonical_unit: "0.001*m" },
  ],
};

describe("external result contracts", () => {
  it("only builds result URLs out of opaque tokens", () => {
    expect(externalResultsPath(handle, handle)).toBe(`/workspaces/${handle}/external-results/${handle}`);
    expect(() => externalResultsPath(handle, "../result.csv")).toThrow();
    expect(() => externalResultsPath(handle, handle + "\n")).toThrow();
    expect(() => externalResultsPath("C:/workspaces/example", handle)).toThrow();
  });

  it("decodes bounded result candidates including portable names", () => {
    const item = { name: metadata.source_name, result_id: handle, refusal: null };
    expect(decodeResultList({ results: [item], ignored_names: 1 })).toEqual({
      results: [item], ignored_names: 1,
    });
    expect(decodeResultList({ results: [item, item], ignored_names: 0 })).toBeNull();
    expect(decodeResultList({ results: [{ ...item, name: "../result.csv" }], ignored_names: 0 })).toBeNull();
    expect(decodeResultList({ results: [item], ignored_names: 32 })).toBeNull();
  });

  it("validates the reported time field, source digest, and sample bounds", () => {
    expect(decodeResultMetadata(metadata)).toEqual(metadata);
    expect(decodeResultMetadata({ ...metadata, source_sha256: "abcd" })).toBeNull();
    expect(decodeResultMetadata({ ...metadata, sample_count: 20001 })).toBeNull();
    expect(decodeResultMetadata({ ...metadata, columns: [...metadata.columns].reverse() })).toBeNull();
  });
});
