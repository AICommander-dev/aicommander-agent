import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { MockInstance } from "vitest";
import { ui, requireRoot } from "../ctl/ui.js";

let exitSpy: MockInstance<typeof process.exit>;
let logSpy: ReturnType<typeof vi.spyOn>;
let errSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  // process.exit must not actually terminate the test runner.
  exitSpy = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
  logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
  errSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("requireRoot", () => {
  // process.getuid is `(() => number) | undefined`, so we swap it directly and
  // restore the original in each test rather than spying (which infers `never`).
  let originalGetuid: typeof process.getuid;

  beforeEach(() => {
    originalGetuid = process.getuid;
  });

  afterEach(() => {
    process.getuid = originalGetuid;
  });

  it("exits(1) when getuid() !== 0", () => {
    process.getuid = (() => 1000) as typeof process.getuid;
    requireRoot();
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errSpy).toHaveBeenCalled();
  });

  it("passes (no exit) when running as root (getuid() === 0)", () => {
    process.getuid = (() => 0) as typeof process.getuid;
    requireRoot();
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it("exits when getuid is undefined (optional chaining yields !== 0)", () => {
    // On platforms without getuid, `process.getuid?.()` is undefined !== 0 → exit.
    process.getuid = undefined;
    requireRoot();
    expect(exitSpy).toHaveBeenCalledWith(1);
  });
});

describe("ui helpers", () => {
  it("ok/warn/step/info/header/blank write to console.log", () => {
    ui.ok("done");
    ui.warn("careful");
    ui.step("working");
    ui.info("Key", "value");
    ui.header("Title");
    ui.blank();
    expect(logSpy).toHaveBeenCalled();
    const joined = logSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(joined).toContain("done");
    expect(joined).toContain("value");
  });

  it("error writes to console.error", () => {
    ui.error("boom");
    expect(errSpy).toHaveBeenCalled();
    expect(String(errSpy.mock.calls[0]![0])).toContain("boom");
  });
});
