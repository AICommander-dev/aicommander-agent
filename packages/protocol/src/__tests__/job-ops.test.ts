import { describe, expect, it } from "vitest";
import {
  isOperationKey,
  JOB_LOCKS_MAX,
  JOB_OPS_NAME_MAX_CHARS,
  validateJobLocks,
  validateOperationId,
} from "../job-ops.js";

describe("validateOperationId", () => {
  it("treats absent / null / empty as no operation", () => {
    expect(validateOperationId(undefined)).toEqual({ ok: true });
    expect(validateOperationId(null)).toEqual({ ok: true });
    expect(validateOperationId("").ok).toBe(false);
  });

  it("accepts the documented alphabet up to the length cap", () => {
    expect(validateOperationId("train-x_2")).toEqual({ ok: true, operationId: "train-x_2" });
    expect(validateOperationId("a.b_c:d@e/f-1")).toEqual({ ok: true, operationId: "a.b_c:d@e/f-1" });
    const max = "x".repeat(JOB_OPS_NAME_MAX_CHARS);
    expect(validateOperationId(max)).toEqual({ ok: true, operationId: max });
  });

  it("rejects other characters, overlong ids and non-strings", () => {
    for (const bad of ["has space", "semi;colon", "x".repeat(JOB_OPS_NAME_MAX_CHARS + 1), 42, {}, "a\nb"]) {
      expect(validateOperationId(bad).ok).toBe(false);
    }
  });
});

describe("validateJobLocks", () => {
  it("treats absent and empty as no locks", () => {
    expect(validateJobLocks(undefined)).toEqual({ ok: true });
    expect(validateJobLocks([])).toEqual({ ok: true });
  });

  it("dedupes and sorts", () => {
    expect(validateJobLocks(["b", "a", "b"])).toEqual({ ok: true, locks: ["a", "b"] });
  });

  it("rejects empty names, bad characters, non-arrays and too many names", () => {
    expect(validateJobLocks([""]).ok).toBe(false);
    expect(validateJobLocks(["ok", "no way"]).ok).toBe(false);
    expect(validateJobLocks("a").ok).toBe(false);
    expect(validateJobLocks([1]).ok).toBe(false);
    const many = Array.from({ length: JOB_LOCKS_MAX + 1 }, (_, i) => `l${i}`);
    expect(validateJobLocks(many).ok).toBe(false);
    // Duplicates do not count against the cap.
    expect(validateJobLocks([...many.slice(0, JOB_LOCKS_MAX), "l0"]).ok).toBe(true);
  });
});

describe("isOperationKey", () => {
  it("accepts only 64 lowercase hex chars", () => {
    expect(isOperationKey("a".repeat(64))).toBe(true);
    expect(isOperationKey("A".repeat(64))).toBe(false);
    expect(isOperationKey("a".repeat(63))).toBe(false);
    expect(isOperationKey("../x")).toBe(false);
  });
});
