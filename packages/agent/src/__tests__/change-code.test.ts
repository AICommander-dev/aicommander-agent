import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// change-code must: requireRoot, then write the rotate marker AND clear the
// stored session BEFORE restarting the service (so the new code is forced on
// the next startup), then poll readState for the new code.
const order: string[] = [];

vi.mock("../ctl/systemctl.js", () => ({
  systemctlRestart: vi.fn(() => {
    order.push("restart");
  }),
}));

vi.mock("../session-store.js", () => ({
  writeRotateMarker: vi.fn(() => {
    order.push("writeRotateMarker");
  }),
  clearSession: vi.fn(() => {
    order.push("clearSession");
  }),
}));

vi.mock("../state.js", () => ({
  readState: vi.fn(async () => null),
}));

vi.mock("../ctl/ui.js", () => ({
  requireRoot: vi.fn(),
  confirm: vi.fn(async () => true),
  ui: {
    header: vi.fn(),
    ok: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    step: vi.fn(),
    blank: vi.fn(),
  },
}));

import { systemctlRestart } from "../ctl/systemctl.js";
import { writeRotateMarker, clearSession } from "../session-store.js";
import { readState } from "../state.js";
import { ui, requireRoot } from "../ctl/ui.js";
import { cmdChangeCode } from "../ctl/commands/change-code.js";

beforeEach(() => {
  order.length = 0;
  vi.clearAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("cmdChangeCode", () => {
  it("requires root", async () => {
    vi.mocked(readState).mockResolvedValue({
      sessionCode: "AIC-NEW-0001",
      pid: 1,
      startedAt: "2026-06-14T00:00:00.000Z",
      serverUrl: "https://aicommander.dev",
    });
    await cmdChangeCode({ yes: true });
    expect(vi.mocked(requireRoot)).toHaveBeenCalled();
  });

  it("writes the rotate marker AND clears the session BEFORE restart", async () => {
    vi.mocked(readState).mockResolvedValue({
      sessionCode: "AIC-NEW-0001",
      pid: 1,
      startedAt: "2026-06-14T00:00:00.000Z",
      serverUrl: "https://aicommander.dev",
    });
    await cmdChangeCode({ yes: true });

    expect(vi.mocked(writeRotateMarker)).toHaveBeenCalled();
    expect(vi.mocked(clearSession)).toHaveBeenCalled();
    expect(vi.mocked(systemctlRestart)).toHaveBeenCalled();

    const restartIdx = order.indexOf("restart");
    expect(order.indexOf("writeRotateMarker")).toBeLessThan(restartIdx);
    expect(order.indexOf("clearSession")).toBeLessThan(restartIdx);
  });

  it("reports the new session code once state becomes available", async () => {
    // First poll returns null, second returns the new state — exercises the loop.
    vi.mocked(readState)
      .mockResolvedValueOnce(null)
      .mockResolvedValue({
        sessionCode: "AIC-NEW-0002",
        pid: 2,
        startedAt: "2026-06-14T00:00:00.000Z",
        serverUrl: "https://aicommander.dev",
      });
    await cmdChangeCode({ yes: true });
    const okMsgs = vi.mocked(ui.ok).mock.calls.map((c) => String(c[0])).join("\n");
    expect(okMsgs).toContain("AIC-NEW-0002");
  });

  it("refuses non-interactively without --yes (no rotation)", async () => {
    const prevExitCode = process.exitCode;
    // Not a TTY in the test runner → must refuse rather than prompt.
    await cmdChangeCode();
    expect(vi.mocked(writeRotateMarker)).not.toHaveBeenCalled();
    expect(vi.mocked(systemctlRestart)).not.toHaveBeenCalled();
    expect(vi.mocked(ui.error)).toHaveBeenCalled();
    process.exitCode = prevExitCode; // don't leak a non-zero exit into the suite
  });

  it("warns when state never appears within the deadline", async () => {
    // Use fake timers so the 10s polling loop resolves instantly.
    vi.useFakeTimers();
    vi.mocked(readState).mockResolvedValue(null);
    const promise = cmdChangeCode({ yes: true });
    await vi.runAllTimersAsync();
    await promise;
    vi.useRealTimers();
    expect(vi.mocked(ui.warn)).toHaveBeenCalled();
  });
});
