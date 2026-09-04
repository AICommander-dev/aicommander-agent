// The renderings the published texts are built from. Each case below is a
// sentence that exists on a real surface today ("1 MiB", "256 KiB", "1 hr",
// "1 h", "a one-hour download link", "after ONE hour"), so a change to these
// helpers that reworded any of them would land here rather than in the docs.

import { describe, expect, it } from "vitest";

import {
  COMMAND_MAX_TIMEOUT_MS,
  FILE_BLOB_TTL_MS,
  FILE_MAX_BYTES,
  JOB_LOGS_MAX_SLICE_BYTES,
  JOB_MAX_LOG_BYTES,
  JOB_RETENTION_MS,
  MAX_OUTPUT_TOTAL_BYTES,
} from "../constants.js";
import {
  formatBytes,
  formatDuration,
  formatDurationShort,
  formatDurationSymbol,
  formatDurationWords,
} from "../limit-text.js";

describe("formatBytes", () => {
  it.each([
    [MAX_OUTPUT_TOTAL_BYTES, "1 MiB"],
    [JOB_MAX_LOG_BYTES, "256 MiB"],
    [JOB_LOGS_MAX_SLICE_BYTES, "256 KiB"],
    [FILE_MAX_BYTES, "100 MiB"],
  ])("renders %i as %s", (bytes, text) => {
    expect(formatBytes(bytes)).toBe(text);
  });

  it("keeps a size that is not a whole unit as a byte count", () => {
    // Rounding it would publish a limit a caller cannot reproduce.
    expect(formatBytes(1_048_577)).toBe("1048577 bytes");
    expect(formatBytes(512)).toBe("512 bytes");
  });
});

describe("durations", () => {
  it("renders the exec deadline in all four widths", () => {
    expect(formatDuration(COMMAND_MAX_TIMEOUT_MS)).toBe("1 hour");
    expect(formatDurationShort(COMMAND_MAX_TIMEOUT_MS)).toBe("1 hr");
    expect(formatDurationSymbol(COMMAND_MAX_TIMEOUT_MS)).toBe("1 h");
    expect(formatDurationWords(COMMAND_MAX_TIMEOUT_MS)).toBe("one hour");
  });

  it("pluralises and reduces to the largest whole unit", () => {
    expect(formatDuration(JOB_RETENTION_MS)).toBe("7 days");
    expect(formatDuration(300_000)).toBe("5 minutes");
  });

  it("honours a pinned unit, so a 24-hour TTL never becomes 1 day", () => {
    expect(formatDuration(FILE_BLOB_TTL_MS)).toBe("1 day");
    expect(formatDuration(FILE_BLOB_TTL_MS, "hour")).toBe("24 hours");
  });

  it("writes the count as a word, hyphenated or shouted, where the texts do", () => {
    expect(formatDurationWords(COMMAND_MAX_TIMEOUT_MS, { hyphenate: true })).toBe("one-hour");
    expect(formatDurationWords(COMMAND_MAX_TIMEOUT_MS, { upperCount: true })).toBe("ONE hour");
    expect(formatDurationWords(FILE_BLOB_TTL_MS, { unit: "hour" })).toBe("24 hours");
  });

  it("falls back to milliseconds rather than dropping the unit", () => {
    expect(formatDuration(1_500)).toBe("1500 ms");
    expect(formatDurationShort(1_500)).toBe("1500 ms");
  });
});
