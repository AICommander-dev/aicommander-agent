// Reconnect backoff after an UNCLEAN close (connection.ts runConnectionLoop).
//
// A relay deploy drops every agent socket with 1006/1012. Before the fix only a
// clean close (1000/4001) reset the backoff, so a few deploy drops hours apart —
// each after a perfectly healthy connection — ratcheted the reconnect delay up to
// 30s. Now a connection that stayed open for STABLE_CONNECTION_MS retries after a
// uniformly random 250ms–3s (full jitter, so a fleet dropped by one deploy does not
// come back in lockstep); if that retry fails too, the usual schedule starts over
// at the initial 1s (1s, 2s, 4s, …). A flapping connection still escalates.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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

vi.mock("../diag-log.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../diag-log.js")>()),
  diag: vi.fn(),
}));

import * as WsMod from "ws";
import { diag } from "../diag-log.js";
import {
  STABLE_CONNECTION_MS,
  STABLE_DROP_RETRY_MAX_MS,
  STABLE_DROP_RETRY_MIN_MS,
} from "../connection.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const wsInstances: MockWSInstance[] = (WsMod as any).__instances;

/** The delayMs of every conn.retry so far. */
function retryDelays(): number[] {
  return vi
    .mocked(diag)
    .mock.calls.filter(([event]) => event === "conn.retry")
    .map(([, fields]) => (fields as { delayMs: number }).delayMs);
}

/** Let the loop run up to the point where it has opened its next socket. */
async function nextSocket(count: number): Promise<MockWSInstance> {
  for (let i = 0; i < 50 && wsInstances.length < count; i++) await vi.advanceTimersByTimeAsync(0);
  expect(wsInstances).toHaveLength(count);
  return wsInstances[count - 1]!;
}

/** Open a socket, keep it up for `upMs` (wall clock only), then drop it uncleanly. */
async function upThenDrop(ws: MockWSInstance, upMs: number, code = 1006): Promise<void> {
  ws._emit("open");
  vi.setSystemTime(Date.now() + upMs);
  ws.close(code, "gone");
  await vi.advanceTimersByTimeAsync(0);
}

describe("runConnectionLoop backoff", () => {
  let stop: AbortController;

  beforeEach(async () => {
    wsInstances.length = 0;
    vi.mocked(diag).mockClear();
    vi.spyOn(Math, "random").mockReturnValue(0.5); // jitter factor exactly 1.0
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ ticket: "a".repeat(64) }) }) as Response),
    );
    vi.useFakeTimers({ now: new Date("2026-10-09T10:00:00Z") });
    const { runConnectionLoop } = await import("../connection.js");
    stop = new AbortController();
    runConnectionLoop({
      signal: stop.signal,
      serverUrl: "https://aic-worker.test",
      sessionCode: "AIC-WOLF-1234",
      agentToken: "test-token",
      silent: true,
    }).catch(() => undefined);
  });

  afterEach(() => {
    stop.abort();
    vi.useRealTimers();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("keeps escalating while connections flap", async () => {
    for (let n = 1; n <= 4; n++) {
      await upThenDrop(await nextSocket(n), 5_000);
      await vi.advanceTimersByTimeAsync(retryDelays().at(-1)!);
    }
    expect(retryDelays()).toEqual([1_000, 2_000, 4_000, 8_000]);
  });

  it("retries within a few seconds when a long-healthy connection drops uncleanly", async () => {
    // Escalate first, as several quick drops (or deploys) would.
    for (let n = 1; n <= 3; n++) {
      await upThenDrop(await nextSocket(n), 1_000);
      await vi.advanceTimersByTimeAsync(retryDelays().at(-1)!);
    }
    expect(retryDelays()).toEqual([1_000, 2_000, 4_000]);

    // Healthy for hours, then a relay deploy (1012 service restart).
    // Math.random() = 0.5 → the middle of [250, 3000].
    await upThenDrop(await nextSocket(4), 3 * 60 * 60 * 1_000, 1012);
    expect(retryDelays().at(-1)).toBe(1_625);
    expect(vi.mocked(diag)).toHaveBeenLastCalledWith(
      "conn.retry",
      expect.objectContaining({ attempt: 1, delayMs: 1_625, upMs: 3 * 60 * 60 * 1_000 }),
    );

    // …and quick follow-up failures restart the schedule at the initial 1s
    // (the jittered retry does not count as the 1s step).
    await vi.advanceTimersByTimeAsync(1_625);
    await upThenDrop(await nextSocket(5), 1_000);
    expect(retryDelays().at(-1)).toBe(1_000);
    await vi.advanceTimersByTimeAsync(1_000);
    await upThenDrop(await nextSocket(6), 1_000);
    expect(retryDelays().at(-1)).toBe(2_000);
    await vi.advanceTimersByTimeAsync(2_000);
    await upThenDrop(await nextSocket(7), 1_000);
    expect(retryDelays()).toEqual([1_000, 2_000, 4_000, 1_625, 1_000, 2_000, 4_000]);
  });

  it("treats exactly STABLE_CONNECTION_MS as stable and just under it as a flap", async () => {
    await upThenDrop(await nextSocket(1), 1_000);
    await vi.advanceTimersByTimeAsync(1_000);
    await upThenDrop(await nextSocket(2), STABLE_CONNECTION_MS - 1);
    await vi.advanceTimersByTimeAsync(2_000);
    await upThenDrop(await nextSocket(3), STABLE_CONNECTION_MS);
    expect(retryDelays()).toEqual([1_000, 2_000, 1_625]);
  });

  it("spreads the first retry after a stable drop uniformly over 250ms–3s (full jitter)", async () => {
    const random = vi.mocked(Math.random);
    const cases: [number, number][] = [
      [0, STABLE_DROP_RETRY_MIN_MS],
      [0.999_999, STABLE_DROP_RETRY_MAX_MS],
      [0.1, 525],
    ];
    expect([STABLE_DROP_RETRY_MIN_MS, STABLE_DROP_RETRY_MAX_MS]).toEqual([250, 3_000]);
    for (const [n, [r, expected]] of cases.entries()) {
      random.mockReturnValue(r);
      await upThenDrop(await nextSocket(n + 1), STABLE_CONNECTION_MS);
      expect(retryDelays().at(-1)).toBe(expected);
      await vi.advanceTimersByTimeAsync(expected);
    }
  });

  it("does not count a socket that never opened as stable", async () => {
    await upThenDrop(await nextSocket(1), 1_000);
    await vi.advanceTimersByTimeAsync(1_000);
    const ws = await nextSocket(2);
    vi.setSystemTime(Date.now() + 5 * 60 * 1_000);
    ws._emit("error", new Error("connect ETIMEDOUT"));
    await vi.advanceTimersByTimeAsync(0);
    expect(retryDelays()).toEqual([1_000, 2_000]);
    expect(vi.mocked(diag)).toHaveBeenLastCalledWith("conn.retry", expect.objectContaining({ upMs: null }));
  });

  it("still reconnects at once after a clean close, then restarts from ~1s", async () => {
    await upThenDrop(await nextSocket(1), 1_000);
    await vi.advanceTimersByTimeAsync(1_000);
    await upThenDrop(await nextSocket(2), 1_000);
    await vi.advanceTimersByTimeAsync(2_000);
    const ws = await nextSocket(3);
    ws._emit("open");
    ws.close(1000, "bye");
    // No retry delay for a clean close: the next socket comes straight away.
    const next = await nextSocket(4);
    expect(retryDelays()).toEqual([1_000, 2_000]);
    await upThenDrop(next, 1_000);
    expect(retryDelays()).toEqual([1_000, 2_000, 1_000]);
  });
});
