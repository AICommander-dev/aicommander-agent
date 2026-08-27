// These constants are a wire contract shared by the agent, the relay and the
// clients: a bad value here is not a local bug but a fleet-wide one, and some of
// the relations between them are load-bearing safety properties rather than
// taste. The cases below pin exactly those relations.

import { describe, it, expect } from "vitest";

import {
  clampCommandTimeout,
  COMMAND_DEFAULT_TIMEOUT_MS,
  COMMAND_MAX_TIMEOUT_MS,
  COMMAND_MIN_TIMEOUT_MS,
  gpuLockFileName,
  GPU_POLL_INTERVAL_MS,
  GPU_PROBE_TIMEOUT_MS,
  isGpuLockFileName,
  JOB_LIST_DEFAULT_ENTRIES,
  JOB_MAX_GPU_INDEX,
  JOB_LOGS_DEFAULT_TAIL_LINES,
  JOB_WIRE_MAX_LIST_ENTRIES,
  JOB_LOGS_MAX_SLICE_BYTES,
  JOB_MAX_CONCURRENT,
  JOB_MAX_LOG_BYTES,
  JOB_RETENTION_MS,
  JOB_RPC_TIMEOUT_MS,
  MAX_EPOCH_MS,
  MAX_OUTPUT_TOTAL_BYTES,
} from "../constants.js";

describe("remote command timeout contract", () => {
  it("uses the default for missing, non-numeric, NaN, and infinite values", () => {
    for (const value of [undefined, null, "1000", Number.NaN, Infinity, -Infinity]) {
      expect(clampCommandTimeout(value)).toBe(COMMAND_DEFAULT_TIMEOUT_MS);
    }
  });

  it("clamps finite values to the documented inclusive min/max bounds", () => {
    expect(clampCommandTimeout(-1)).toBe(COMMAND_MIN_TIMEOUT_MS);
    expect(clampCommandTimeout(0)).toBe(COMMAND_MIN_TIMEOUT_MS);
    expect(clampCommandTimeout(COMMAND_MIN_TIMEOUT_MS)).toBe(COMMAND_MIN_TIMEOUT_MS);
    expect(clampCommandTimeout(COMMAND_MIN_TIMEOUT_MS + 1)).toBe(COMMAND_MIN_TIMEOUT_MS + 1);
    expect(clampCommandTimeout(COMMAND_MAX_TIMEOUT_MS)).toBe(COMMAND_MAX_TIMEOUT_MS);
    expect(clampCommandTimeout(COMMAND_MAX_TIMEOUT_MS + 1)).toBe(COMMAND_MAX_TIMEOUT_MS);
  });

  it("keeps min, default, and max ordered finite positive integers", () => {
    for (const value of [
      COMMAND_MIN_TIMEOUT_MS,
      COMMAND_DEFAULT_TIMEOUT_MS,
      COMMAND_MAX_TIMEOUT_MS,
    ]) {
      expect(Number.isFinite(value)).toBe(true);
      expect(Number.isInteger(value)).toBe(true);
      expect(value).toBeGreaterThan(0);
    }
    expect(COMMAND_MIN_TIMEOUT_MS).toBeLessThan(COMMAND_DEFAULT_TIMEOUT_MS);
    expect(COMMAND_DEFAULT_TIMEOUT_MS).toBeLessThan(COMMAND_MAX_TIMEOUT_MS);
  });
});

/** Encoded length of `bytes` raw bytes as base64, the form a log slice travels in. */
function base64Length(bytes: number): number {
  return Math.ceil(bytes / 3) * 4;
}

describe("job + GPU constants", () => {
  const positiveFinite: Array<[name: string, value: number]> = [
    ["GPU_POLL_INTERVAL_MS", GPU_POLL_INTERVAL_MS],
    ["GPU_PROBE_TIMEOUT_MS", GPU_PROBE_TIMEOUT_MS],
    ["JOB_MAX_LOG_BYTES", JOB_MAX_LOG_BYTES],
    ["JOB_LOGS_MAX_SLICE_BYTES", JOB_LOGS_MAX_SLICE_BYTES],
    ["JOB_LOGS_DEFAULT_TAIL_LINES", JOB_LOGS_DEFAULT_TAIL_LINES],
    ["JOB_RETENTION_MS", JOB_RETENTION_MS],
    ["JOB_RPC_TIMEOUT_MS", JOB_RPC_TIMEOUT_MS],
    ["JOB_MAX_CONCURRENT", JOB_MAX_CONCURRENT],
  ];

  // A zero, negative, NaN or Infinity value would turn a timer into a busy loop
  // or a cap into "unlimited"; both fail silently at runtime.
  it.each(positiveFinite)("%s is a finite positive integer", (_name, value) => {
    expect(Number.isFinite(value)).toBe(true);
    expect(Number.isInteger(value)).toBe(true);
    expect(value).toBeGreaterThan(0);
  });

  // THE invariant: a job_logs reply is buffered in the Worker isolate, so one
  // slice must stay far below what the relay already considers heap-safe for a
  // whole command's output. Anything else reintroduces the very OOM that
  // MAX_OUTPUT_TOTAL_BYTES exists to prevent.
  it("keeps one job_logs slice under the relay's total-output cap", () => {
    expect(JOB_LOGS_MAX_SLICE_BYTES).toBeLessThan(MAX_OUTPUT_TOTAL_BYTES);
  });

  // The slice crosses the wire base64-encoded (~4/3 expansion); the ENCODED form
  // is what is actually held in memory, so it must clear the cap too.
  it("keeps a base64-encoded slice under the relay's total-output cap", () => {
    expect(base64Length(JOB_LOGS_MAX_SLICE_BYTES)).toBeLessThan(MAX_OUTPUT_TOTAL_BYTES);
  });

  // A per-call slice larger than the whole log cap would be unreachable, and
  // signals someone changed one of the two without the other.
  it("keeps one slice smaller than the whole on-disk log cap", () => {
    expect(JOB_LOGS_MAX_SLICE_BYTES).toBeLessThan(JOB_MAX_LOG_BYTES);
  });

  // The probe must finish (or be killed) well before the next poll fires,
  // otherwise a hung nvidia-smi accumulates overlapping probes forever.
  it("bounds the nvidia-smi probe well inside one poll interval", () => {
    expect(GPU_PROBE_TIMEOUT_MS).toBeLessThan(GPU_POLL_INTERVAL_MS);
  });

  // Retention is measured in days: a value shorter than a day would delete a job
  // the user is still waiting on.
  it("retains finished jobs for at least a day", () => {
    expect(JOB_RETENTION_MS).toBeGreaterThanOrEqual(24 * 60 * 60 * 1000);
  });
});

// MAX_EPOCH_MS is the one constant here that is not a judgement call: it is a fact
// about `Date`, and both the agent's `wireEpochMs` and the relay's `isEpochMs` refuse
// past it purely so nothing downstream calls toISOString() on a value that THROWS.
// That makes it the one constant a copy cannot check — both copies could agree on a
// wrong number and every suite would stay green while the crash came back. So it is
// pinned to the language rather than to another spelling of 8.64e15: the assertions
// below ask `Date` itself where the edge is, and fail if the constant moves off it in
// either direction. Both signs, because the check is applied with Math.abs.
describe("MAX_EPOCH_MS is the real Date boundary", () => {
  it("renders at the ceiling", () => {
    expect(() => new Date(MAX_EPOCH_MS).toISOString()).not.toThrow();
    expect(() => new Date(-MAX_EPOCH_MS).toISOString()).not.toThrow();
  });

  it("is the LAST millisecond that renders — one past it throws", () => {
    // This is the half that catches a LOWERED constant: a smaller value would still
    // render above, and only this case notices that it is no longer the edge.
    expect(() => new Date(MAX_EPOCH_MS + 1).toISOString()).toThrow();
    expect(() => new Date(-MAX_EPOCH_MS - 1).toISOString()).toThrow();
  });

  // The bound is reached through Number.isSafeInteger on both sides, so a ceiling
  // outside the safe range would be unreachable: the check would refuse values the
  // constant says are fine, and the constant would stop describing the real cutoff.
  it("is itself a safe integer, so both sides can actually reach it", () => {
    expect(Number.isSafeInteger(MAX_EPOCH_MS)).toBe(true);
  });
});

// Two callers act on the answer: the agent reaps stale locks (a name it does not
// recognise wedges a GPU forever) and `uninstall` decides whether a jobs root is
// safe to delete RECURSIVELY (a name it wrongly calls ours widens an rm -rf). So
// recognition must be exactly the set of names gpuLockFileName can produce —
// neither more nor less — for EVERY index, including at whatever JOB_MAX_GPU_INDEX
// happens to be.
describe("GPU lock file names", () => {
  it("recognises every name it can build, including both ends of the range", () => {
    for (const index of [0, 1, 9, 10, 99, 1000, JOB_MAX_GPU_INDEX]) {
      expect(isGpuLockFileName(gpuLockFileName(index)), String(index)).toBe(true);
    }
  });

  it("rejects an index past the shared ceiling", () => {
    // The permissive direction is the dangerous one: this is a name job-manager
    // could never have written, so a jobs root containing it is NOT ours.
    expect(isGpuLockFileName(gpuLockFileName(JOB_MAX_GPU_INDEX + 1))).toBe(false);
    expect(isGpuLockFileName("gpu-999999.lock")).toBe(false);
  });

  it("rejects spellings of an in-range index that we never emit", () => {
    for (const name of [
      "gpu-007.lock", // zero-padded
      "gpu-+1.lock",
      "gpu-1e3.lock", // Number() would take this; the builder never writes it
      "gpu- 1.lock",
      "gpu-1.5.lock",
      "gpu--1.lock",
      "gpu-.lock",
      "gpu-1.lock.bak",
      "notes-gpu-1.lock",
      "gpu-1.LOCK",
      "0123456789abcdef",
    ]) {
      expect(isGpuLockFileName(name), name).toBe(false);
    }
  });
});

describe("job_list page size contract", () => {
  it("keeps the default page strictly inside the wire page cap", () => {
    // The default is a CONTEXT budget (what an LLM should get when it did not
    // ask) and the cap is a WIRE bound. A default at or above the cap would make
    // `limit` meaningless in the only direction it matters — down.
    expect(JOB_LIST_DEFAULT_ENTRIES).toBeGreaterThan(0);
    expect(JOB_LIST_DEFAULT_ENTRIES).toBeLessThan(JOB_WIRE_MAX_LIST_ENTRIES);
    expect(Number.isSafeInteger(JOB_LIST_DEFAULT_ENTRIES)).toBe(true);
  });
});
