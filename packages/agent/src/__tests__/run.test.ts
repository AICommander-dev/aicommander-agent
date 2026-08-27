import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { MockInstance } from "vitest";

// run.ts orchestrates startup: load device, consume the rotate marker (→ forceNew
// or currentCode), register, saveSession on success, write state, then run the
// connection loop. SIGINT/SIGTERM must clear the transient state file. We mock
// every collaborator and dynamically import run.ts per-test for isolation.
vi.mock("../register.js", () => ({ register: vi.fn() }));
vi.mock("../connection.js", () => ({
  runConnectionLoop: vi.fn(async () => undefined),
  AGENT_TOKEN_ROTATE_MS: 21_600_000,
}));
vi.mock("../display.js", () => ({ showCode: vi.fn() }));
vi.mock("../state.js", () => ({ writeState: vi.fn(async () => undefined), clearState: vi.fn(async () => undefined) }));
vi.mock("../device.js", () => ({
  loadOrCreateDevice: vi.fn(() => ({ deviceId: "dev-1", deviceSecret: "sec-1" })),
}));
vi.mock("../session-store.js", () => ({
  loadSession: vi.fn(() => null),
  saveSession: vi.fn(),
  consumeRotateMarker: vi.fn(() => false),
}));

import { register } from "../register.js";
import { runConnectionLoop } from "../connection.js";
import { showCode } from "../display.js";
import { writeState, clearState } from "../state.js";
import { loadOrCreateDevice } from "../device.js";
import { loadSession, saveSession, consumeRotateMarker } from "../session-store.js";

async function loadRun() {
  vi.resetModules();
  return import("../run.js");
}

let exitSpy: MockInstance<typeof process.exit>;
const onHandlers = new Map<string, (...a: unknown[]) => void>();

beforeEach(() => {
  vi.clearAllMocks();
  onHandlers.clear();
  exitSpy = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
  vi.spyOn(process, "on").mockImplementation(((event: string, handler: (...a: unknown[]) => void) => {
    onHandlers.set(event, handler);
    return process;
  }) as typeof process.on);
  vi.spyOn(console, "log").mockImplementation(() => undefined);
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
  vi.spyOn(console, "error").mockImplementation(() => undefined);
  // Defaults: a successful registration.
  vi.mocked(register).mockResolvedValue({ sessionCode: "AIC-CODE-0001", agentToken: "tok-1" });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("runAgent — normal startup", () => {
  it("loads the device and passes its identity to register", async () => {
    vi.mocked(consumeRotateMarker).mockReturnValue(false);
    vi.mocked(loadSession).mockReturnValue({ sessionCode: "AIC-OLD-9999", agentToken: "old" });
    const { runAgent } = await loadRun();
    await runAgent();

    expect(vi.mocked(loadOrCreateDevice)).toHaveBeenCalled();
    const [, device, opts] = vi.mocked(register).mock.calls[0]!;
    expect(device).toEqual({ deviceId: "dev-1", deviceSecret: "sec-1" });
    // Normal path: pass the stored code as currentCode, no forceNew.
    expect(opts).toEqual({ forceNew: false, currentCode: "AIC-OLD-9999" });
  });

  it("saves the session and writes state on success", async () => {
    const { runAgent } = await loadRun();
    await runAgent();
    expect(vi.mocked(saveSession)).toHaveBeenCalledWith({
      sessionCode: "AIC-CODE-0001",
      agentToken: "tok-1",
    });
    expect(vi.mocked(writeState)).toHaveBeenCalledWith(
      expect.objectContaining({ sessionCode: "AIC-CODE-0001" }),
    );
    expect(vi.mocked(runConnectionLoop)).toHaveBeenCalled();
  });
});

// The startup banner reveals the FULL root-exec code on an interactive terminal
// OR on any foreground run that is NOT the systemd service (piped, nohup, CI).
// The ONE place it must stay masked is under the service, where the same `run` is
// supervised and its stdout is inherited into journald — revealing there would
// persist the credential in the journal. runAgent detects the service via
// systemd's env markers (INVOCATION_ID / JOURNAL_STREAM) rather than TTY-ness
// alone, so legitimate non-TTY foreground runs still show the code.
describe("runAgent — session-code reveal is service-gated (journal-leak guard)", () => {
  let originalIsTTY: boolean | undefined;
  let originalInvocationId: string | undefined;
  let originalJournalStream: string | undefined;
  beforeEach(() => {
    originalIsTTY = process.stdout.isTTY;
    originalInvocationId = process.env["INVOCATION_ID"];
    originalJournalStream = process.env["JOURNAL_STREAM"];
    // Start each case from a clean, non-service environment.
    delete process.env["INVOCATION_ID"];
    delete process.env["JOURNAL_STREAM"];
  });
  afterEach(() => {
    Object.defineProperty(process.stdout, "isTTY", {
      value: originalIsTTY,
      configurable: true,
    });
    if (originalInvocationId === undefined) delete process.env["INVOCATION_ID"];
    else process.env["INVOCATION_ID"] = originalInvocationId;
    if (originalJournalStream === undefined) delete process.env["JOURNAL_STREAM"];
    else process.env["JOURNAL_STREAM"] = originalJournalStream;
  });

  const setIsTTY = (value: boolean | undefined) => {
    Object.defineProperty(process.stdout, "isTTY", { value, configurable: true });
  };

  it("reveals the full code on an interactive TTY (foreground run)", async () => {
    setIsTTY(true);
    const { runAgent } = await loadRun();
    await runAgent();
    expect(vi.mocked(showCode)).toHaveBeenCalledWith("AIC-CODE-0001", expect.any(String), true);
  });

  it("reveals the full code on a non-TTY foreground run (piped / nohup / CI)", async () => {
    setIsTTY(undefined);
    const { runAgent } = await loadRun();
    await runAgent();
    expect(vi.mocked(showCode)).toHaveBeenCalledWith("AIC-CODE-0001", expect.any(String), true);
  });

  it("masks the code under the systemd service (non-TTY, JOURNAL_STREAM set)", async () => {
    setIsTTY(undefined);
    process.env["JOURNAL_STREAM"] = "8:12345";
    const { runAgent } = await loadRun();
    await runAgent();
    expect(vi.mocked(showCode)).toHaveBeenCalledWith("AIC-CODE-0001", expect.any(String), false);
  });

  it("masks the code under the systemd service (non-TTY, INVOCATION_ID set)", async () => {
    setIsTTY(undefined);
    process.env["INVOCATION_ID"] = "deadbeefcafebabe";
    const { runAgent } = await loadRun();
    await runAgent();
    expect(vi.mocked(showCode)).toHaveBeenCalledWith("AIC-CODE-0001", expect.any(String), false);
  });
});

describe("runAgent — rotate marker (change-code) path", () => {
  it("forces a new code and does NOT pass currentCode", async () => {
    vi.mocked(consumeRotateMarker).mockReturnValue(true);
    // Even if a stored session exists, the rotate path must not re-assert it.
    vi.mocked(loadSession).mockReturnValue({ sessionCode: "AIC-OLD-9999", agentToken: "old" });
    const { runAgent } = await loadRun();
    await runAgent();

    const [, , opts] = vi.mocked(register).mock.calls[0]!;
    expect(opts).toEqual({ forceNew: true });
    // loadSession is skipped on the forceNew path.
    expect(vi.mocked(loadSession)).not.toHaveBeenCalled();
  });
});

describe("runAgent — first install (no stored session)", () => {
  it("registers with forceNew:false and no currentCode", async () => {
    vi.mocked(consumeRotateMarker).mockReturnValue(false);
    vi.mocked(loadSession).mockReturnValue(null);
    const { runAgent } = await loadRun();
    await runAgent();
    const [, , opts] = vi.mocked(register).mock.calls[0]!;
    expect(opts).toEqual({ forceNew: false });
  });
});

describe("runAgent — registration failure", () => {
  it("logs and exits(1) when register rejects", async () => {
    vi.mocked(register).mockRejectedValue(new Error("relay down"));
    const { runAgent } = await loadRun();
    await runAgent();
    expect(exitSpy).toHaveBeenCalledWith(1);
  });
});

describe("runAgent — signal cleanup", () => {
  it("registers SIGINT/SIGTERM handlers that clear state BEFORE exiting(0)", async () => {
    const { runAgent } = await loadRun();
    await runAgent();

    expect(onHandlers.has("SIGINT")).toBe(true);
    expect(onHandlers.has("SIGTERM")).toBe(true);

    for (const signal of ["SIGINT", "SIGTERM"] as const) {
      vi.mocked(clearState).mockClear();
      exitSpy.mockClear();
      // A controllable clearState, so the ORDER is what gets asserted: exit(0)
      // used to race the un-awaited rm and routinely win, which is what made a
      // stale state.json the NORMAL leftover of every clean stop rather than a
      // rare one — the upstream cause the uninstaller's pid checks then had to
      // absorb.
      let resolveClear!: () => void;
      vi.mocked(clearState).mockImplementation(
        () => new Promise<void>((resolve) => { resolveClear = resolve; }),
      );
      onHandlers.get(signal)!();
      expect(vi.mocked(clearState)).toHaveBeenCalled();
      // While the state file is still on disk, the process must still be alive.
      await Promise.resolve();
      expect(exitSpy).not.toHaveBeenCalled();
      resolveClear();
      await vi.waitFor(() => expect(exitSpy).toHaveBeenCalledWith(0));
    }
  });
});
