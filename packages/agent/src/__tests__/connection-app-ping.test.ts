// The agent half of the app-level heartbeat (AgentRegisterMsg.appPing): we
// advertise it, start pinging only once the relay acknowledges it with
// do:ping {heartbeat:"app"}, treat the auto-response pong as liveness, and
// reconnect when pongs stop. Against a relay that never acknowledges, the legacy
// do:ping/agent:pong heartbeat is untouched.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  APP_PING_FRAME,
  APP_PING_INTERVAL_MS,
  APP_PONG_FRAME,
  APP_PONG_TIMEOUT_MS,
} from "@aicommander/protocol";

interface MockWSInstance {
  sent: string[];
  terminated: boolean;
  _emit: (event: string, ...args: unknown[]) => void;
  close: (code: number, reason: string) => void;
}

vi.mock("ws", () => {
  const instances: unknown[] = [];
  class MockWS {
    _handlers: Record<string, ((...args: unknown[]) => void)[]> = {};
    sent: string[] = [];
    terminated = false;
    constructor() {
      instances.push(this);
    }
    on(event: string, cb: (...args: unknown[]) => void) {
      (this._handlers[event] ??= []).push(cb);
    }
    send(data: string) {
      this.sent.push(data);
    }
    terminate() {
      this.terminated = true;
      this._emit("close", 1006, Buffer.from("terminated"));
    }
    close(code: number, reason: string) {
      this._emit("close", code, Buffer.from(reason));
    }
    _emit(event: string, ...args: unknown[]) {
      for (const cb of this._handlers[event] ?? []) cb(...args);
    }
  }
  return { default: MockWS, __instances: instances };
});

vi.mock("../executor.js", () => ({ executeCommand: vi.fn() }));
vi.mock("../secure-executor.js", () => ({ executeSecureCommand: vi.fn() }));
vi.mock("../elevated-executor.js", () => ({ executeElevatedCommand: vi.fn() }));
vi.mock("../elevated-availability.js", () => ({
  resolveElevatedAvailability: vi.fn(async () => ({ available: false, reason: "platform_unsupported" })),
  staticElevatedUnavailableReason: vi.fn(() => "platform_unsupported"),
}));
vi.mock("../gpu.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../gpu.js")>()),
  probeGpuState: vi.fn(async () => ({ certainty: "unknown" })),
}));
vi.mock("../login-shell-path.js", () => ({
  startLoginShellPathProbe: vi.fn(async () => null),
  pendingLoginShellPath: vi.fn(() => null),
}));
vi.mock("../installed-version.js", () => ({
  startInstalledVersionProbe: vi.fn(async () => undefined),
  installedVersionSnapshot: vi.fn(() => undefined),
}));
vi.mock("../job-scope.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../job-scope.js")>()),
  startJobScopeProbe: vi.fn(async () => null),
  pendingJobScope: vi.fn(() => null),
}));
vi.mock("../job-manager.js", () => ({
  JobError: class extends Error {},
  countRunningJobRecords: vi.fn(() => 0),
  getJobManager: vi.fn(() => ({
    setKnownGpus: vi.fn(),
    runningJobCount: vi.fn(() => 0),
    onRunningJobsChange: vi.fn(() => () => undefined),
  })),
}));
vi.mock("../file-transfer.js", () => ({ pullFileToRelay: vi.fn(), pushFileFromRelay: vi.fn() }));

import * as WsMod from "ws";
import { createAppHeartbeat, isAppPong } from "../app-heartbeat.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const wsInstances: MockWSInstance[] = (WsMod as any).__instances;

async function connect() {
  const { runConnectionLoop } = await import("../connection.js");
  const onHeartbeat = vi.fn();
  const stop = new AbortController();
  const promise = runConnectionLoop({
    signal: stop.signal,
    serverUrl: "https://aic-worker.test",
    sessionCode: "AIC-WOLF-1234",
    agentToken: "test-token",
    silent: true,
    onHeartbeat,
  });
  promise.catch(() => undefined);
  await new Promise((r) => setTimeout(r, 0));
  for (let i = 0; i < 8; i++) await Promise.resolve();
  return { stop, ws: wsInstances[wsInstances.length - 1]!, onHeartbeat };
}

const pings = (ws: MockWSInstance) => ws.sent.filter((s) => s === APP_PING_FRAME).length;

describe("app heartbeat — connection", () => {
  beforeEach(() => {
    wsInstances.length = 0;
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ ticket: "a".repeat(64) }) }) as Response),
    );
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("advertises appPing on register", async () => {
    const { ws } = await connect();
    ws._emit("open");
    const register = JSON.parse(ws.sent[0]!);
    expect(register.type).toBe("agent:register");
    expect(register.appPing).toBe(true);
    ws.close(1000, "ok");
  });

  it("stays on the legacy heartbeat when the relay does not acknowledge it", async () => {
    const { ws } = await connect();
    vi.useFakeTimers();
    ws._emit("open");
    ws._emit("message", JSON.stringify({ type: "do:ping", ts: 1 }));
    await vi.advanceTimersByTimeAsync(APP_PING_INTERVAL_MS * 2);
    expect(pings(ws)).toBe(0);
    expect(ws.sent.some((s) => s.includes('"agent:pong"'))).toBe(true);
    ws.close(1000, "ok");
  });

  it("pings every APP_PING_INTERVAL_MS once acknowledged, and pongs keep the link alive", async () => {
    const { ws, onHeartbeat, stop } = await connect();
    vi.useFakeTimers();
    ws._emit("open");
    ws._emit("message", JSON.stringify({ type: "do:ping", ts: 1, heartbeat: "app" }));
    // A repeated acknowledgement (re-register) must not stack timers.
    ws._emit("message", JSON.stringify({ type: "do:ping", ts: 2, heartbeat: "app" }));
    onHeartbeat.mockClear();
    for (let i = 1; i <= 6; i++) {
      await vi.advanceTimersByTimeAsync(APP_PING_INTERVAL_MS);
      expect(pings(ws)).toBe(i);
      ws._emit("message", Buffer.from(APP_PONG_FRAME));
    }
    // 3 minutes in, well past APP_PONG_TIMEOUT_MS, and still alive on pongs alone.
    expect(ws.terminated).toBe(false);
    expect(onHeartbeat).toHaveBeenCalledTimes(6);
    stop.abort();
  });

  it("terminates and reports a ping timeout when pongs stop", async () => {
    const { ws, stop } = await connect();
    vi.useFakeTimers();
    ws._emit("open");
    ws._emit("message", JSON.stringify({ type: "do:ping", ts: 1, heartbeat: "app" }));
    await vi.advanceTimersByTimeAsync(APP_PONG_TIMEOUT_MS + 1);
    // Terminated → the loop reconnects (the link-dead path every ping timeout takes).
    expect(ws.terminated).toBe(true);
    // And the ping timer died with the socket.
    const sent = pings(ws);
    await vi.advanceTimersByTimeAsync(APP_PING_INTERVAL_MS * 3);
    expect(pings(ws)).toBe(sent);
    stop.abort();
  });
});

describe("app heartbeat — module", () => {
  afterEach(() => vi.useRealTimers());

  it("start is idempotent and stop halts pinging", () => {
    vi.useFakeTimers();
    const send = vi.fn();
    const hb = createAppHeartbeat(send, 1_000);
    hb.start();
    hb.start();
    expect(hb.active).toBe(true);
    vi.advanceTimersByTime(3_000);
    expect(send).toHaveBeenCalledTimes(3);
    expect(send).toHaveBeenCalledWith(APP_PING_FRAME);
    hb.stop();
    expect(hb.active).toBe(false);
    vi.advanceTimersByTime(3_000);
    expect(send).toHaveBeenCalledTimes(3);
  });

  it("swallows a send on a dead socket", () => {
    vi.useFakeTimers();
    const hb = createAppHeartbeat(() => { throw new Error("closed"); }, 1_000);
    hb.start();
    expect(() => vi.advanceTimersByTime(1_000)).not.toThrow();
    hb.stop();
  });

  it("recognises only the exact pong frame", () => {
    expect(isAppPong(APP_PONG_FRAME)).toBe(true);
    expect(isAppPong(Buffer.from(APP_PONG_FRAME))).toBe(true);
    expect(isAppPong(APP_PING_FRAME)).toBe(false);
    expect(isAppPong(JSON.stringify({ type: "do:ping", ts: 1 }))).toBe(false);
  });
});
