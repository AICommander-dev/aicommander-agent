import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// startAgent() picks the role: supervisor by default, worker when AIC_ROLE=worker.
// We mock both branches' collaborators and assert exactly one runs per role.
vi.mock("../supervisor.js", () => ({ runSupervisor: vi.fn(async () => undefined) }));
vi.mock("../register.js", () => ({ register: vi.fn(async () => ({ sessionCode: "AIC-X", agentToken: "t" })) }));
vi.mock("../connection.js", () => ({
  runConnectionLoop: vi.fn(async () => undefined),
  AGENT_TOKEN_ROTATE_MS: 21_600_000,
}));
vi.mock("../display.js", () => ({ showCode: vi.fn() }));
vi.mock("../state.js", () => ({ writeState: vi.fn(async () => undefined), clearState: vi.fn(async () => undefined) }));
vi.mock("../device.js", () => ({ loadOrCreateDevice: vi.fn(() => ({ deviceId: "d", deviceSecret: "s" })) }));
vi.mock("../session-store.js", () => ({
  loadSession: vi.fn(() => null),
  saveSession: vi.fn(),
  consumeRotateMarker: vi.fn(() => false),
}));
vi.mock("../heartbeat.js", () => ({
  startHeartbeat: vi.fn(),
  stopHeartbeat: vi.fn(),
  defaultHeartbeatPath: vi.fn(() => "/run/hb"),
}));
// The single-instance gate's evidence source. Mocked so these tests never depend
// on the real process table (and so a stray agent on the dev box cannot fail them);
// the default is "nothing running", which every pre-existing case here assumes.
vi.mock("../live-agent.js", () => ({
  findRunningAgents: vi.fn(() => ({ running: [], unverified: [], scanFailed: false })),
}));

import { runSupervisor } from "../supervisor.js";
import { register } from "../register.js";
import { startHeartbeat } from "../heartbeat.js";
import { findRunningAgents } from "../live-agent.js";

const ORIG_ROLE = process.env["AIC_ROLE"];

beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
  vi.spyOn(process, "on").mockImplementation((() => process) as typeof process.on);
});

afterEach(() => {
  if (ORIG_ROLE === undefined) delete process.env["AIC_ROLE"];
  else process.env["AIC_ROLE"] = ORIG_ROLE;
  vi.restoreAllMocks();
});

describe("startAgent — role routing", () => {
  it("runs the supervisor (not the worker) by default", async () => {
    delete process.env["AIC_ROLE"];
    const { startAgent } = await import("../run.js");
    await startAgent();
    expect(vi.mocked(runSupervisor)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(register)).not.toHaveBeenCalled();
    expect(vi.mocked(startHeartbeat)).not.toHaveBeenCalled();
  });

  it("runs the worker (register + heartbeat, no supervisor) when AIC_ROLE=worker", async () => {
    process.env["AIC_ROLE"] = "worker";
    const { startAgent } = await import("../run.js");
    await startAgent();
    expect(vi.mocked(runSupervisor)).not.toHaveBeenCalled();
    expect(vi.mocked(register)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(startHeartbeat)).toHaveBeenCalledTimes(1);
  });
});

// A second agent does not coexist with the first — it TAKES the machine's relay
// session, silently, because both register the same device identity and the relay
// keeps only the newest connection. See single-instance.ts.
describe("startAgent — single-instance gate", () => {
  let stderr: string[];

  beforeEach(() => {
    stderr = [];
    vi.spyOn(console, "error").mockImplementation((msg: unknown) => {
      stderr.push(String(msg));
    });
    process.exitCode = undefined;
  });

  afterEach(() => {
    process.exitCode = undefined;
  });

  it("refuses to start when an agent is proven to be running", async () => {
    delete process.env["AIC_ROLE"];
    vi.mocked(findRunningAgents).mockReturnValue({ running: [4242], unverified: [], scanFailed: false });
    const { startAgent } = await import("../run.js");
    await startAgent();

    expect(vi.mocked(runSupervisor)).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(1);
    expect(stderr.join("\n")).toContain("pid 4242");
  });

  it("refuses when it merely COULD NOT TELL — doubt is not absence", async () => {
    delete process.env["AIC_ROLE"];
    vi.mocked(findRunningAgents).mockReturnValue({ running: [], unverified: [], scanFailed: true });
    const { startAgent } = await import("../run.js");
    await startAgent();

    expect(vi.mocked(runSupervisor)).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(1);
    expect(stderr.join("\n")).toMatch(/process table could not be read/);
  });

  it("starts anyway under --force, which is the operator's call to make", async () => {
    delete process.env["AIC_ROLE"];
    vi.mocked(findRunningAgents).mockReturnValue({ running: [4242], unverified: [], scanFailed: false });
    const { startAgent } = await import("../run.js");
    await startAgent({ force: true });

    expect(vi.mocked(runSupervisor)).toHaveBeenCalledTimes(1);
    expect(process.exitCode).toBeUndefined();
    // --force means "I looked, go" — it must not also print the refusal.
    expect(stderr).toEqual([]);
  });

  it("never gates the WORKER, which our own supervisor just spawned", async () => {
    // The supervisor IS a live agent by every honest measure, so a worker running
    // this check would refuse to start under the parent that started it — every
    // supervised launch would fail. The gate belongs to the process claiming the
    // session, not to its child.
    process.env["AIC_ROLE"] = "worker";
    vi.mocked(findRunningAgents).mockReturnValue({ running: [1], unverified: [2], scanFailed: true });
    const { startAgent } = await import("../run.js");
    await startAgent();

    expect(vi.mocked(findRunningAgents)).not.toHaveBeenCalled();
    expect(vi.mocked(register)).toHaveBeenCalledTimes(1);
    expect(process.exitCode).toBeUndefined();
  });
});
