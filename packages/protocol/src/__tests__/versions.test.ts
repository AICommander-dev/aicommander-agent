// Version comparison — moved here from @aicommander/agent so the Worker's
// update feed and the clients share ONE implementation. The table pins the
// exact behavior both sides relied on before the move.

import { describe, it, expect } from "vitest";

import { compareVersions, isNewerVersion } from "../versions.js";

describe("compareVersions", () => {
  it("orders dotted numeric versions", () => {
    expect(compareVersions("1.0.18", "1.0.9")).toBeGreaterThan(0);
    expect(compareVersions("1.0.9", "1.0.18")).toBeLessThan(0);
    expect(compareVersions("2.0.0", "1.9.9")).toBeGreaterThan(0);
    expect(compareVersions("1.2.3", "1.2.3")).toBe(0);
  });

  it("treats missing/short segments as 0", () => {
    expect(compareVersions("1.0", "1.0.0")).toBe(0);
    expect(compareVersions("1.0.1", "1.0")).toBeGreaterThan(0);
  });

  it("coerces non-numeric parts to 0 instead of throwing", () => {
    expect(compareVersions("1.0.0-beta", "1.0.0")).toBe(0);
    expect(compareVersions("abc", "0.0.0")).toBe(0);
  });
});

describe("isNewerVersion", () => {
  const table: Array<[latest: string, current: string, newer: boolean]> = [
    ["1.0.18", "1.0.9", true],
    ["1.0.9", "1.0.18", false],
    ["1.2.3", "1.2.3", false],
    ["2.0.0", "1.9.9", true],
    ["1.0.0", "2.0.0", false],
    ["1.0", "1.0.0", false],
    ["1.0.0-beta", "1.0.0", false],
  ];

  it.each(table)("isNewerVersion(%s, %s) → %s", (latest, current, newer) => {
    expect(isNewerVersion(latest, current)).toBe(newer);
  });
});
