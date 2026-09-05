// The lines that only a dying agent can write.
//
// Every event this log exists for is written immediately before the process
// stops: registration refused, the credential store refusing us, the state file
// refusing us — the EACCES/EPERM-on-our-own-paths shape the module header calls
// "the antivirus signature". `diag()` deliberately does its I/O on a timer, and
// `process.exit` never lets a timer fire, so for as long as the exits were bare
// those lines were formatted into memory and thrown away. The file that goes
// into the support ticket was empty for exactly the failures it was built for.
//
// THE TRAP THESE TESTS CLOSE. The suite that shipped with the feature passed
// because it called `flushDiagLog()` itself — asserting something production
// never did. So these run under FAKE TIMERS: the queue's own `setTimeout(…, 0)`
// can never fire, no test here flushes anything, and the only way a line reaches
// the disk is the production path flushing before it exits. Take the flush out
// of run.ts and every assertion below fails.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { MockInstance } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// The real RegistrationError travels with the mock: run.ts branches on it to
// record the relay's own status and code, and a mock without it turns that
// branch into a TypeError instead of a log line.
vi.mock("../register.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../register.js")>()),
  register: vi.fn(),
}));
vi.mock("../connection.js", () => ({
  runConnectionLoop: vi.fn(async () => undefined),
  AGENT_TOKEN_ROTATE_MS: 21_600_000,
}));
vi.mock("../display.js", () => ({ showCode: vi.fn() }));
vi.mock("../state.js", () => ({
  writeState: vi.fn(async () => undefined),
  clearState: vi.fn(async () => undefined),
}));
vi.mock("../device.js", () => ({
  loadOrCreateDevice: vi.fn(() => ({ deviceId: "dev-1", deviceSecret: "sec-1" })),
}));
vi.mock("../session-store.js", () => ({
  loadSession: vi.fn(() => null),
  saveSession: vi.fn(),
  consumeRotateMarker: vi.fn(() => false),
}));

import { register } from "../register.js";
import { saveSession } from "../session-store.js";
import { writeState } from "../state.js";
import { closeDiagLog } from "../diag-log.js";

let configDir: string;
let exitSpy: MockInstance<typeof process.exit>;
const previousConfigDir = process.env["AICOMMANDER_CONFIG_DIR"];

/** The errno an on-access scanner produces for a file it has taken or denied. */
function denied(syscall: string): NodeJS.ErrnoException {
  const err: NodeJS.ErrnoException = new Error(`EACCES: permission denied, ${syscall}`);
  err.code = "EACCES";
  err.syscall = syscall;
  return err;
}

/** The worker log, read straight off the disk — nothing here flushes it first. */
function workerLog(): string {
  return fs.readFileSync(path.join(configDir, "logs", "worker.log"), "utf8");
}

async function loadRun() {
  vi.resetModules();
  return import("../run.js");
}

beforeEach(() => {
  vi.clearAllMocks();
  configDir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-fatal-"));
  process.env["AICOMMANDER_CONFIG_DIR"] = configDir;
  // The queue's flush timer can never fire on its own from here on.
  vi.useFakeTimers();
  exitSpy = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
  vi.spyOn(process, "on").mockImplementation((() => process) as typeof process.on);
  vi.spyOn(console, "log").mockImplementation(() => undefined);
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
  vi.spyOn(console, "error").mockImplementation(() => undefined);
  vi.mocked(register).mockResolvedValue({ sessionCode: "AIC-CODE-0001", agentToken: "tok-1" });
});

afterEach(() => {
  closeDiagLog();
  vi.useRealTimers();
  vi.restoreAllMocks();
  if (previousConfigDir === undefined) delete process.env["AICOMMANDER_CONFIG_DIR"];
  else process.env["AICOMMANDER_CONFIG_DIR"] = previousConfigDir;
  fs.rmSync(configDir, { recursive: true, force: true });
});

describe("the last lines before a fatal exit", () => {
  it("writes conn.register_failed to disk before exiting", async () => {
    vi.mocked(register).mockRejectedValue(denied("connect"));
    const { runAgent } = await loadRun();

    await runAgent();

    expect(exitSpy).toHaveBeenCalledWith(1);
    const text = workerLog();
    expect(text).toContain("conn.register_failed");
    expect(text).toContain("code=EACCES");
  });

  it("writes the sessionStore path.error to disk before exiting", async () => {
    // Our own credential store refusing us: the incident's signature, and the
    // one line that tells a support engineer this was not the relay's doing.
    vi.mocked(saveSession).mockImplementation(() => {
      throw denied("open");
    });
    const { runAgent } = await loadRun();

    await runAgent();

    expect(exitSpy).toHaveBeenCalledWith(1);
    const text = workerLog();
    expect(text).toContain("path.error");
    expect(text).toContain("path_role=sessionStore");
    expect(text).toContain("code=EACCES");
    expect(text).not.toContain("conn.register_failed");
  });

  it("writes the state path.error to disk before exiting", async () => {
    vi.mocked(writeState).mockRejectedValue(denied("open"));
    const { runAgent } = await loadRun();

    await runAgent();

    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(workerLog()).toContain("path_role=state");
  });

  it("leaves no fatal exit in this package that a diag line cannot survive", async () => {
    // The structural half: the three cases above pin the paths that exist today,
    // and this pins that no NEW one can be added the old way. Every module that
    // logs must reach a fatal exit through exitAfterDiagFlush, which is the only
    // thing that turns a queued line into bytes on disk.
    //
    // RECURSIVELY, over the whole package. It used to read one flat directory
    // listing of `src/*.ts`, which stopped covering the package the moment code
    // moved into folders: `src/doctor/**` and `src/ctl/**` both import the
    // logger today, and a `process.exit()` in either would have discarded queued
    // lines with every assertion here still green. The import is matched at any
    // depth for the same reason — a nested module spells it `../diag-log.js`.
    const root = path.join(import.meta.dirname, "..");
    const files: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        // The tests are not the package: they mock and spy on process.exit by
        // design, and they are not shipped.
        if (entry.isDirectory()) {
          if (entry.name !== "__tests__" && entry.name !== "node_modules") walk(full);
          continue;
        }
        if (entry.isFile() && entry.name.endsWith(".ts")) files.push(full);
      }
    };
    walk(root);
    const offenders: string[] = [];
    for (const file of files) {
      const name = path.relative(root, file);
      if (name === "diag-log.ts") continue;
      const source = fs.readFileSync(file, "utf8");
      if (!/from "(?:\.\.\/)*\.?\/?diag-log\.js"/.test(source)) continue;
      // Comments mention it; only real calls count.
      const calls = source
        .split("\n")
        .filter((line) => /(?<!\/\/.*)\bprocess\.exit\(/.test(line.replace(/^\s*\/\/.*$/, "")));
      if (calls.length > 0) offenders.push(`${name}: ${calls.join(" | ")}`);
    }
    expect(offenders).toEqual([]);
  });
});
