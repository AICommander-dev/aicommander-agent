import { describe, expect, it } from "vitest";

import { JOB_MAX_CONCURRENT } from "../constants.js";
import { parseRunningJobs, RUNNING_JOBS_REPORT_MAX } from "../job-state.js";

describe("parseRunningJobs", () => {
  it("accepts non-negative integers up to the report ceiling", () => {
    expect(parseRunningJobs(0)).toBe(0);
    expect(parseRunningJobs(3)).toBe(3);
    expect(parseRunningJobs(RUNNING_JOBS_REPORT_MAX)).toBe(RUNNING_JOBS_REPORT_MAX);
  });

  it("rejects garbage instead of clamping it", () => {
    for (const bad of [-1, 1.5, NaN, Infinity, RUNNING_JOBS_REPORT_MAX + 1, "2", null, undefined, {}]) {
      expect(parseRunningJobs(bad)).toBeUndefined();
    }
  });

  it("leaves room above the agent's own start ceiling", () => {
    expect(RUNNING_JOBS_REPORT_MAX).toBeGreaterThanOrEqual(JOB_MAX_CONCURRENT);
  });
});
