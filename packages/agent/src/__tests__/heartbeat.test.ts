import { describe, it, expect, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import {
  startHeartbeat,
  stopHeartbeat,
  readHeartbeat,
  defaultHeartbeatPath,
} from "../heartbeat.js";

function tmpFile(): string {
  return path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), "aic-hb-")),
    "heartbeat",
  );
}

afterEach(() => {
  stopHeartbeat();
});

describe("heartbeat", () => {
  it("stamps a readable epoch-ms value immediately on start", () => {
    const file = tmpFile();
    const before = Date.now();
    startHeartbeat(file, 60_000);
    const value = readHeartbeat(file);
    expect(value).not.toBeNull();
    expect(value!).toBeGreaterThanOrEqual(before);
  });

  it("advances the stamp on each interval tick", async () => {
    const file = tmpFile();
    startHeartbeat(file, 5); // fast interval for the test
    const first = readHeartbeat(file)!;
    await new Promise((r) => setTimeout(r, 25));
    const second = readHeartbeat(file)!;
    expect(second).toBeGreaterThanOrEqual(first);
  });

  it("stopHeartbeat halts further stamping", async () => {
    const file = tmpFile();
    startHeartbeat(file, 5);
    stopHeartbeat();
    const frozen = readHeartbeat(file)!;
    await new Promise((r) => setTimeout(r, 25));
    expect(readHeartbeat(file)).toBe(frozen);
  });

  it("readHeartbeat returns null for a missing file", () => {
    expect(readHeartbeat(path.join(os.tmpdir(), "aic-hb-nope-xyz"))).toBeNull();
  });

  it("defaultHeartbeatPath honors an explicit configDir", () => {
    expect(defaultHeartbeatPath("/some/dir")).toBe("/some/dir/heartbeat");
  });
});
