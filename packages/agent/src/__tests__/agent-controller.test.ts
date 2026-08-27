import { describe, it, expect, vi, beforeEach, afterEach, beforeAll, afterAll } from "vitest";

vi.mock("../register.js", () => ({
  register: vi.fn(),
  DEVICE_SECRET_MISMATCH: "device_secret_mismatch",
  // Real-ish class so `err instanceof RegistrationError` works in the controller
  // (it imports from this same mocked module, so identities match) AND `err.code`
  // is parsed from the JSON body exactly like the production class — the
  // controller now keys regeneration off `code`, not a bare status===403.
  RegistrationError: class RegistrationError extends Error {
    public code: string | null;
    constructor(
      public status: number,
      public body: string,
    ) {
      super(`Registration failed (${status}): ${body}`);
      this.name = "RegistrationError";
      try {
        const parsed = JSON.parse(body) as { code?: unknown };
        this.code = typeof parsed.code === "string" ? parsed.code : null;
      } catch {
        this.code = null;
      }
    }
  },
}));

vi.mock("../connection.js", () => ({
  runConnectionLoop: vi.fn(),
  sleepAbortable: vi.fn(),
  AGENT_TOKEN_ROTATE_MS: 21_600_000,
}));

vi.mock("../device.js", () => ({
  loadOrCreateDevice: vi.fn(() => ({ deviceId: "dev-1", deviceSecret: "secret-1" })),
  regenerateDevice: vi.fn(() => ({ deviceId: "dev-2", deviceSecret: "secret-2" })),
}));

vi.mock("../session-store.js", () => ({
  loadSession: vi.fn(() => null),
  saveSession: vi.fn(),
  clearSession: vi.fn(),
  writeRotateMarker: vi.fn(),
  consumeRotateMarker: vi.fn(() => false),
}));

import { AgentController } from "../agent-controller.js";
import { register, RegistrationError } from "../register.js";
import { runConnectionLoop, sleepAbortable } from "../connection.js";
import { loadOrCreateDevice, regenerateDevice } from "../device.js";
import {
  loadSession,
  saveSession,
  clearSession,
  writeRotateMarker,
  consumeRotateMarker,
} from "../session-store.js";

const sessionCtx = (configDir?: string) => ({ configDir, tokenVault: undefined });

function makeCtrl(opts?: { configDir?: string }) {
  return new AgentController("https://test.example", opts);
}

function mockRegisterOk(code = "AIC-TEST-1234") {
  vi.mocked(register).mockResolvedValue({ sessionCode: code, agentToken: "token-abc" });
}

// runConnectionLoop runs until signal aborted — simulate that
function mockConnectRunsUntilAborted() {
  vi.mocked(runConnectionLoop).mockImplementation(
    ({ signal }) =>
      new Promise<void>((resolve) => {
        signal?.addEventListener("abort", () => resolve(), { once: true });
      }),
  );
}

function collectStatuses(ctrl: AgentController) {
  const statuses: string[] = [];
  ctrl.on("status", (s) => statuses.push(s));
  return statuses;
}

function collectCodes(ctrl: AgentController) {
  const codes: string[] = [];
  ctrl.on("code", (c) => codes.push(c));
  return codes;
}

describe("AgentController", () => {
  // The controller host-locks its relay URL (resolveTrustedServerUrl): a
  // non-canonical origin like the "https://test.example" fixture is rewritten to
  // the canonical relay unless the dev escape hatch is on. These tests assert the
  // controller forwards the GIVEN serverUrl to register(), so enable the hatch.
  let prevDev: string | undefined;
  beforeAll(() => {
    prevDev = process.env["AICOMMANDER_DEV"];
    process.env["AICOMMANDER_DEV"] = "1";
  });
  afterAll(() => {
    if (prevDev === undefined) delete process.env["AICOMMANDER_DEV"];
    else process.env["AICOMMANDER_DEV"] = prevDev;
  });

  beforeEach(() => {
    vi.mocked(register).mockReset();
    vi.mocked(runConnectionLoop).mockReset();
    vi.mocked(sleepAbortable).mockReset();
    vi.mocked(loadOrCreateDevice).mockClear();
    vi.mocked(loadOrCreateDevice).mockReturnValue({ deviceId: "dev-1", deviceSecret: "secret-1" });
    vi.mocked(regenerateDevice).mockClear();
    vi.mocked(regenerateDevice).mockReturnValue({ deviceId: "dev-2", deviceSecret: "secret-2" });
    vi.mocked(loadSession).mockReset();
    vi.mocked(loadSession).mockReturnValue(null);
    vi.mocked(saveSession).mockReset();
    vi.mocked(clearSession).mockReset();
    vi.mocked(writeRotateMarker).mockReset();
    vi.mocked(consumeRotateMarker).mockReset();
    vi.mocked(consumeRotateMarker).mockReturnValue(false);
    mockConnectRunsUntilAborted();
    // sleepAbortable: resolves immediately so retry tests don't hang
    vi.mocked(sleepAbortable).mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ── Initial state ──────────────────────────────────────────────
  it("starts as disabled with null code", () => {
    const ctrl = makeCtrl();
    expect(ctrl.status).toBe("disabled");
    expect(ctrl.sessionCode).toBeNull();
  });

  // ── start() ────────────────────────────────────────────────────
  it("start() emits connecting then code when register succeeds", async () => {
    mockRegisterOk();
    const ctrl = makeCtrl();
    const statuses = collectStatuses(ctrl);
    const codes = collectCodes(ctrl);

    ctrl.start();
    await vi.waitFor(() => expect(codes).toHaveLength(1));

    expect(statuses).toContain("connecting");
    expect(codes).toEqual(["AIC-TEST-1234"]);
    expect(ctrl.sessionCode).toBe("AIC-TEST-1234");
    ctrl.stop();
  });

  it("records lastHeartbeatAt and emits 'heartbeat' when the link proves alive", async () => {
    mockRegisterOk();
    // Capture the onHeartbeat callback the controller passes to the connection.
    let fireHeartbeat: (() => void) | undefined;
    vi.mocked(runConnectionLoop).mockImplementation(
      ({ signal, onHeartbeat }) =>
        new Promise<void>((resolve) => {
          fireHeartbeat = onHeartbeat;
          signal?.addEventListener("abort", () => resolve(), { once: true });
        }),
    );

    const ctrl = makeCtrl();
    const beats: number[] = [];
    ctrl.on("heartbeat", (ts: number) => beats.push(ts));

    expect(ctrl.lastHeartbeatAt).toBe(0);
    ctrl.start();
    await vi.waitFor(() => expect(fireHeartbeat).toBeTypeOf("function"));

    fireHeartbeat!();
    expect(ctrl.lastHeartbeatAt).toBeGreaterThan(0);
    expect(beats).toHaveLength(1);
    ctrl.stop();
  });

  // The relay's machine-readable reason for a stale/unknown device identity 403.
  const MISMATCH_BODY = JSON.stringify({
    error: "Device secret mismatch.",
    code: "device_secret_mismatch",
  });

  it("regenerates the device identity and recovers on a device_secret_mismatch 403", async () => {
    // First register is rejected (stale/legacy device record); the controller must
    // regenerate the identity and re-register as a fresh device instead of spinning.
    vi.mocked(register)
      .mockRejectedValueOnce(new RegistrationError(403, MISMATCH_BODY))
      .mockResolvedValue({ sessionCode: "AIC-NEW-5678", agentToken: "token-new" });

    const ctrl = makeCtrl();
    const codes = collectCodes(ctrl);

    ctrl.start();
    await vi.waitFor(() => expect(codes).toContain("AIC-NEW-5678"));

    expect(vi.mocked(regenerateDevice)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(clearSession)).toHaveBeenCalled();
    // The retry registers with the REGENERATED identity, not the rejected one.
    expect(vi.mocked(register).mock.calls[1]?.[1]).toEqual({
      deviceId: "dev-2",
      deviceSecret: "secret-2",
    });
    ctrl.stop();
  });

  it("does NOT regenerate the device more than once for a persistent 403", async () => {
    vi.mocked(register).mockRejectedValue(new RegistrationError(403, MISMATCH_BODY));
    // Yield to a macrotask each backoff so the retry loop doesn't starve the
    // event loop (in production this is a real timer; the default mock resolves
    // synchronously, which would hot-loop on microtasks).
    vi.mocked(sleepAbortable).mockImplementation(() => new Promise((r) => setTimeout(r, 0)));

    const ctrl = makeCtrl();
    ctrl.start();
    // Let several retry iterations run.
    await vi.waitFor(() => expect(vi.mocked(register).mock.calls.length).toBeGreaterThan(2));

    expect(vi.mocked(regenerateDevice)).toHaveBeenCalledTimes(1);
    ctrl.stop();
  });

  it("does NOT regenerate the device on a 403 WITHOUT the device_secret_mismatch code", async () => {
    // A different 403 reason (e.g. an auth/policy rejection without the machine-
    // readable code) must NOT wipe the device binding — only the specific stale-
    // identity reason triggers regeneration.
    vi.mocked(register).mockRejectedValue(
      new RegistrationError(403, JSON.stringify({ error: "Forbidden" })),
    );
    vi.mocked(sleepAbortable).mockImplementation(() => new Promise((r) => setTimeout(r, 0)));

    const ctrl = makeCtrl();
    ctrl.start();
    await vi.waitFor(() => expect(vi.mocked(register).mock.calls.length).toBeGreaterThan(2));

    // Identity is preserved: never regenerated, session never cleared, and every
    // retry still uses the ORIGINAL device identity.
    expect(vi.mocked(regenerateDevice)).not.toHaveBeenCalled();
    expect(vi.mocked(clearSession)).not.toHaveBeenCalled();
    expect(vi.mocked(register).mock.calls.every((c) => c[1]?.deviceId === "dev-1")).toBe(true);
    ctrl.stop();
  });

  it("start() is idempotent — second call ignored while running", async () => {
    mockRegisterOk();
    const ctrl = makeCtrl();

    ctrl.start();
    ctrl.start(); // second call is no-op
    await vi.waitFor(() => expect(ctrl.sessionCode).toBeTruthy());

    expect(vi.mocked(register)).toHaveBeenCalledTimes(1);
    ctrl.stop();
  });

  it("start() retries after register() failure instead of staying disconnected", async () => {
    vi.mocked(register)
      .mockRejectedValueOnce(new Error("timeout"))
      .mockResolvedValueOnce({ sessionCode: "AIC-TEST-5555", agentToken: "tok" });

    const ctrl = makeCtrl();
    const statuses = collectStatuses(ctrl);
    const codes = collectCodes(ctrl);

    ctrl.start();
    await vi.waitFor(() => expect(codes).toHaveLength(1));

    expect(statuses).toContain("disconnected"); // transient during retry backoff
    expect(statuses).toContain("connecting");
    expect(codes).toEqual(["AIC-TEST-5555"]);
    ctrl.stop();
  });

  it("start() aborted before register resolves — no connection loop started", async () => {
    let resolveRegister!: () => void;
    vi.mocked(register).mockReturnValue(
      new Promise<{ sessionCode: string; agentToken: string }>((resolve) => {
        resolveRegister = () => resolve({ sessionCode: "AIC-X", agentToken: "t" });
      }),
    );

    const ctrl = makeCtrl();
    ctrl.start();
    ctrl.stop(); // abort before register resolves
    resolveRegister();

    await new Promise((r) => setTimeout(r, 20));

    expect(ctrl.status).toBe("disabled");
    expect(ctrl.sessionCode).toBeNull();
    expect(runConnectionLoop).not.toHaveBeenCalled();
  });

  // ── stop() ─────────────────────────────────────────────────────
  it("stop() sets status=disabled and clears sessionCode", async () => {
    mockRegisterOk();
    const ctrl = makeCtrl();

    ctrl.start();
    await vi.waitFor(() => expect(ctrl.sessionCode).toBeTruthy());

    ctrl.stop();
    expect(ctrl.status).toBe("disabled");
    expect(ctrl.sessionCode).toBeNull();
  });

  it("stop() is idempotent — safe to call multiple times", () => {
    const ctrl = makeCtrl();
    expect(() => { ctrl.stop(); ctrl.stop(); ctrl.stop(); }).not.toThrow();
    expect(ctrl.status).toBe("disabled");
  });

  it("stop() before start() is safe (no-op)", () => {
    const ctrl = makeCtrl();
    expect(() => ctrl.stop()).not.toThrow();
  });

  // ── restart() ──────────────────────────────────────────────────
  it("restart() emits a new code", async () => {
    vi.mocked(register)
      .mockResolvedValueOnce({ sessionCode: "AIC-FIRST-1111", agentToken: "t1" })
      .mockResolvedValueOnce({ sessionCode: "AIC-SECOND-2222", agentToken: "t2" });

    const ctrl = makeCtrl();
    const codes = collectCodes(ctrl);

    ctrl.start();
    await vi.waitFor(() => expect(codes).toHaveLength(1));

    await ctrl.restart();
    await vi.waitFor(() => expect(codes).toHaveLength(2));

    expect(codes).toEqual(["AIC-FIRST-1111", "AIC-SECOND-2222"]);
    ctrl.stop();
  });

  it("restart() from stopped controller works", async () => {
    mockRegisterOk("AIC-NEW-9999");
    const ctrl = makeCtrl();
    const codes = collectCodes(ctrl);

    await ctrl.restart(); // restart from disabled
    await vi.waitFor(() => expect(codes).toHaveLength(1));

    expect(codes).toEqual(["AIC-NEW-9999"]);
    ctrl.stop();
  });

  // ── Disable → Enable flow ──────────────────────────────────────
  it("disable → enable reconnects with fresh code", async () => {
    vi.mocked(register)
      .mockResolvedValueOnce({ sessionCode: "AIC-FIRST-1111", agentToken: "t1" })
      .mockResolvedValueOnce({ sessionCode: "AIC-SECOND-2222", agentToken: "t2" });

    const ctrl = makeCtrl();
    const codes = collectCodes(ctrl);

    ctrl.start(); // Enable
    await vi.waitFor(() => expect(codes).toHaveLength(1));

    ctrl.stop(); // Disable

    ctrl.start(); // Enable again
    await vi.waitFor(() => expect(codes).toHaveLength(2));

    expect(codes).toEqual(["AIC-FIRST-1111", "AIC-SECOND-2222"]);
    ctrl.stop();
  });

  it("full status cycle: disabled→connecting→connected→disconnected→disabled", async () => {
    mockRegisterOk();
    vi.mocked(runConnectionLoop).mockImplementation(({ signal, onStatus }) => {
      onStatus?.("connected");
      return new Promise<void>((resolve) => {
        signal?.addEventListener("abort", () => {
          onStatus?.("disconnected");
          resolve();
        }, { once: true });
      });
    });

    const ctrl = makeCtrl();
    const statuses = collectStatuses(ctrl);

    ctrl.start();
    await vi.waitFor(() => expect(statuses).toContain("connected"));

    ctrl.stop();
    await new Promise((r) => setTimeout(r, 10));

    expect(statuses).toEqual(["connecting", "connected", "disconnected", "disabled"]);
  });

  it("3× start→stop cycles each produce a distinct code", async () => {
    vi.mocked(register)
      .mockResolvedValueOnce({ sessionCode: "AIC-A-0001", agentToken: "t1" })
      .mockResolvedValueOnce({ sessionCode: "AIC-B-0002", agentToken: "t2" })
      .mockResolvedValueOnce({ sessionCode: "AIC-C-0003", agentToken: "t3" });

    const ctrl = makeCtrl();
    const codes = collectCodes(ctrl);

    for (let i = 1; i <= 3; i++) {
      ctrl.start();
      await vi.waitFor(() => expect(codes).toHaveLength(i));
      ctrl.stop();
      await new Promise((r) => setTimeout(r, 5));
    }

    expect(codes).toEqual(["AIC-A-0001", "AIC-B-0002", "AIC-C-0003"]);
  });

  // ── Error safety ───────────────────────────────────────────────
  it("emit('error') does not throw (no listener guard)", () => {
    const ctrl = makeCtrl();
    expect(() => ctrl.emit("error", new Error("test"))).not.toThrow();
  });

  it("listener throwing in 'status' does not crash the loop", async () => {
    mockRegisterOk();
    const ctrl = makeCtrl();
    ctrl.on("status", () => { throw new Error("bad listener"); });

    expect(() => ctrl.start()).not.toThrow();
    await new Promise((r) => setTimeout(r, 20));

    expect(ctrl.sessionCode).toBe("AIC-TEST-1234");
    ctrl.stop();
  });

  it("listener throwing in 'code' does not crash the loop", async () => {
    mockRegisterOk();
    const ctrl = makeCtrl();
    ctrl.on("code", () => { throw new Error("bad listener"); });

    ctrl.start();
    await new Promise((r) => setTimeout(r, 20));

    expect(ctrl.sessionCode).toBe("AIC-TEST-1234");
    ctrl.stop();
  });

  // ── Device + session persistence ───────────────────────────────
  describe("device + session persistence", () => {
    it("loads device with the controller's configDir and passes it to register", async () => {
      mockRegisterOk();
      const ctrl = makeCtrl({ configDir: "/data/userData" });
      const codes = collectCodes(ctrl);

      ctrl.start();
      await vi.waitFor(() => expect(codes).toHaveLength(1));

      expect(loadOrCreateDevice).toHaveBeenCalledWith("/data/userData");
      expect(register).toHaveBeenCalledWith(
        "https://test.example",
        { deviceId: "dev-1", deviceSecret: "secret-1" },
        expect.objectContaining({ forceNew: false }),
      );
      ctrl.stop();
    });

    it("saves the session after a successful register", async () => {
      mockRegisterOk("AIC-SAVE-1234");
      const ctrl = makeCtrl({ configDir: "/data/userData" });
      const codes = collectCodes(ctrl);

      ctrl.start();
      await vi.waitFor(() => expect(codes).toHaveLength(1));

      expect(saveSession).toHaveBeenCalledWith(
        { sessionCode: "AIC-SAVE-1234", agentToken: "token-abc" },
        sessionCtx("/data/userData"),
      );
      ctrl.stop();
    });

    it("passes the stored session code as currentCode", async () => {
      mockRegisterOk();
      vi.mocked(loadSession).mockReturnValue({ sessionCode: "AIC-STORED-9999", agentToken: "old" });
      const ctrl = makeCtrl({ configDir: "/data/userData" });
      const codes = collectCodes(ctrl);

      ctrl.start();
      await vi.waitFor(() => expect(codes).toHaveLength(1));

      expect(register).toHaveBeenCalledWith(
        "https://test.example",
        expect.anything(),
        expect.objectContaining({ currentCode: "AIC-STORED-9999", forceNew: false }),
      );
      ctrl.stop();
    });

    it("reuses the stored code on the second loop iteration (after a register retry)", async () => {
      // First register throws (transient), the loop backs off and re-registers.
      // The session was persisted on a previous run, so loadSession returns it on
      // BOTH iterations and the second register carries it as currentCode.
      vi.mocked(loadSession).mockReturnValue({ sessionCode: "AIC-LOOP-0001", agentToken: "tok1" });
      vi.mocked(register)
        .mockRejectedValueOnce(new Error("network blip"))
        .mockResolvedValueOnce({ sessionCode: "AIC-LOOP-0001", agentToken: "tok1" });

      const ctrl = makeCtrl({ configDir: "/data/userData" });
      ctrl.start();

      await vi.waitFor(() => expect(register).toHaveBeenCalledTimes(2));

      // Second register call must include the stored code as currentCode.
      const secondCall = vi.mocked(register).mock.calls[1];
      expect(secondCall[2]).toEqual(
        expect.objectContaining({ currentCode: "AIC-LOOP-0001", forceNew: false }),
      );
      ctrl.stop();
    });

    it("changeCode() clears the session, writes the rotate marker, and forces a new code", async () => {
      vi.mocked(register)
        .mockResolvedValueOnce({ sessionCode: "AIC-OLD-1111", agentToken: "t1" })
        .mockResolvedValueOnce({ sessionCode: "AIC-NEW-2222", agentToken: "t2" });

      const ctrl = makeCtrl({ configDir: "/data/userData" });
      const codes = collectCodes(ctrl);

      ctrl.start();
      await vi.waitFor(() => expect(codes).toHaveLength(1));

      // On change-code the rotate marker is consumed → forceNew on re-register.
      vi.mocked(consumeRotateMarker).mockReturnValue(true);

      await ctrl.changeCode();
      await vi.waitFor(() => expect(codes).toHaveLength(2));

      expect(clearSession).toHaveBeenCalledWith(sessionCtx("/data/userData"));
      expect(writeRotateMarker).toHaveBeenCalledWith(sessionCtx("/data/userData"));

      // The post-restart register must set forceNew and NOT send currentCode.
      const lastCall = vi.mocked(register).mock.calls.at(-1)!;
      expect(lastCall[2]).toEqual(expect.objectContaining({ forceNew: true }));
      expect((lastCall[2] as { currentCode?: string }).currentCode).toBeUndefined();

      expect(codes).toEqual(["AIC-OLD-1111", "AIC-NEW-2222"]);
      ctrl.stop();
    });

    it("ignores a stale in-flight reauth after changeCode() restarts the controller", async () => {
      let resolveStaleReauth!: (value: { sessionCode: string; agentToken: string }) => void;
      const staleReauth = new Promise<{ sessionCode: string; agentToken: string }>((resolve) => {
        resolveStaleReauth = resolve;
      });

      vi.mocked(register)
        .mockResolvedValueOnce({ sessionCode: "AIC-OLD-1111", agentToken: "t1" })
        .mockReturnValueOnce(staleReauth)
        .mockResolvedValueOnce({ sessionCode: "AIC-NEW-2222", agentToken: "t2" });

      let firstReauth!: () => Promise<string>;
      vi.mocked(runConnectionLoop)
        .mockImplementationOnce(({ signal, reauth }) => {
          firstReauth = reauth!;
          return new Promise<void>((resolve) => {
            signal?.addEventListener("abort", () => resolve(), { once: true });
          });
        })
        .mockImplementation(({ signal }) =>
          new Promise<void>((resolve) => {
            signal?.addEventListener("abort", () => resolve(), { once: true });
          }),
        );

      const ctrl = makeCtrl({ configDir: "/data/userData" });
      const codes = collectCodes(ctrl);

      ctrl.start();
      await vi.waitFor(() => expect(codes).toEqual(["AIC-OLD-1111"]));

      const reauthPromise = firstReauth();
      await vi.waitFor(() => expect(register).toHaveBeenCalledTimes(2));

      vi.mocked(consumeRotateMarker).mockReturnValue(true);
      await ctrl.changeCode();
      await vi.waitFor(() => expect(codes).toEqual(["AIC-OLD-1111", "AIC-NEW-2222"]));

      resolveStaleReauth({ sessionCode: "AIC-OLD-1111", agentToken: "stale-token" });
      await expect(reauthPromise).rejects.toMatchObject({ name: "AbortError" });

      expect(saveSession).toHaveBeenCalledWith(
        { sessionCode: "AIC-OLD-1111", agentToken: "t1" },
        sessionCtx("/data/userData"),
      );
      expect(saveSession).toHaveBeenCalledWith(
        { sessionCode: "AIC-NEW-2222", agentToken: "t2" },
        sessionCtx("/data/userData"),
      );
      expect(saveSession).not.toHaveBeenCalledWith(
        { sessionCode: "AIC-OLD-1111", agentToken: "stale-token" },
        sessionCtx("/data/userData"),
      );
      expect(register).toHaveBeenNthCalledWith(
        2,
        "https://test.example",
        expect.anything(),
        { currentCode: "AIC-OLD-1111" },
      );
      ctrl.stop();
    });

    it("uses the default (undefined) configDir for device/session when none given (CLI parity)", async () => {
      mockRegisterOk();
      const ctrl = makeCtrl();
      const codes = collectCodes(ctrl);

      ctrl.start();
      await vi.waitFor(() => expect(codes).toHaveLength(1));

      expect(loadOrCreateDevice).toHaveBeenCalledWith(undefined);
      expect(saveSession).toHaveBeenCalledWith(expect.anything(), sessionCtx());
      ctrl.stop();
    });
  });
});
