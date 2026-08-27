import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

interface MockWSInstance {
  url: string;
  options?: { headers?: Record<string, string> };
  sent: string[];
  terminated: boolean;
  _emit: (event: string, ...args: unknown[]) => void;
  close: (code: number, reason: string) => void;
}

// Mock ws before importing connection
vi.mock("ws", () => {
  const instances: MockWS[] = [];

  class MockWS {
    url: string;
    options?: { headers?: Record<string, string> };
    _handlers: Record<string, ((...args: unknown[]) => void)[]> = {};
    sent: string[] = [];
    terminated = false;

    constructor(url: string, options?: { headers?: Record<string, string> }) {
      this.url = url;
      this.options = options;
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

vi.mock("../executor.js", () => ({
  executeCommand: vi.fn(),
}));

vi.mock("../secure-executor.js", () => ({
  executeSecureCommand: vi.fn(),
}));

// The GPU probe runs before every connect. Stubbed so tests neither spawn
// nvidia-smi nor depend on whether the CI box happens to have a card; individual
// tests override the resolved value to exercise the GPU paths.
// tests override the resolved value to exercise the GPU paths. `unknown` is the
// default because it is the state that changes nothing about the connection.
// Only the process boundary is faked: `wireGpus` is the REAL reduction, so these
// tests still prove what the register frame carries.
vi.mock("../gpu.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../gpu.js")>()),
  probeGpuState: vi.fn(async () => ({ certainty: "unknown" })),
}));

// The macOS login-shell PATH probe would spawn a real `$SHELL -l -i` — which on
// the dev machines this suite runs on is both slow and unpredictable. Stubbed at
// the module boundary; the deferral tests below drive it explicitly.
vi.mock("../login-shell-path.js", () => ({
  startLoginShellPathProbe: vi.fn(async () => null),
  pendingLoginShellPath: vi.fn(() => null),
}));

// The systemd-scope capability probe would run a real `systemd-run --scope`.
// Stubbed at the same boundary and for the same reason as the PATH probe above:
// the tests below drive its timing explicitly, and the real thing needs root and
// a system bus. The pure half of that module is covered in job-scope.test.ts and
// the probe/memo half in job-scope-probe.test.ts.
vi.mock("../job-scope.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../job-scope.js")>()),
  startJobScopeProbe: vi.fn(async () => null),
  pendingJobScope: vi.fn(() => null),
}));

// Job RPCs must be routable without touching a real jobs directory. `start`
// runs the REAL gpuIndex decision against whatever setKnownGpus was handed, so
// the probe → connection → JobManager wiring is exercised end to end.
vi.mock("../job-manager.js", () => {
  class JobError extends Error {}
  return {
    JobError,
    getJobManager: vi.fn(() => {
      let knownGpus: readonly unknown[] | null = null;
      return {
        setKnownGpus: vi.fn((gpus?: readonly unknown[]) => {
          knownGpus = gpus === undefined ? null : gpus.slice();
        }),
        knownGpusSeen: () => knownGpus,
        start: vi.fn((req: { gpuIndex?: number }) => {
          const decision = decideGpuIndex(req.gpuIndex, knownGpus as never);
          if ("invalid" in decision) {
            return { ok: false, reason: "invalid_request", message: decision.invalid };
          }
          return { ok: true, job: { jobId: "job_test", gpuIndex: decision.gpuIndex } };
        }),
        list: vi.fn(),
        status: vi.fn(),
        logs: vi.fn(),
        cancel: vi.fn(),
      };
    }),
  };
});

// File transfers are detached, long-running work. What these tests care about is
// how the CONNECTION tracks them — which signal it hands over and when that signal
// fires — not what a transfer does to the disk, so the module is a stub whose
// completion the test controls.
vi.mock("../file-transfer.js", () => ({
  pullFileToRelay: vi.fn(),
  pushFileFromRelay: vi.fn(),
}));

vi.mock("../elevated-executor.js", () => ({
  executeElevatedCommand: vi.fn(),
  isElevatedHelperAvailable: vi.fn(() => false),
  // No reachable helper by default → discovery never even runs (marker false), but
  // stub it so the register path can call it when a test flips the marker true.
  discoverHelper: vi.fn(async () => null),
}));

import * as WsMod from "ws";
import { probeGpuState } from "../gpu.js";
import { startLoginShellPathProbe, pendingLoginShellPath } from "../login-shell-path.js";
import { startJobScopeProbe, pendingJobScope } from "../job-scope.js";
import { getJobManager } from "../job-manager.js";
import { decideGpuIndex } from "../job-gpu-index.js";
import { executeCommand } from "../executor.js";
import { executeSecureCommand } from "../secure-executor.js";
import { executeElevatedCommand, isElevatedHelperAvailable, discoverHelper } from "../elevated-executor.js";
import { pullFileToRelay, pushFileFromRelay } from "../file-transfer.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const wsInstances: MockWSInstance[] = (WsMod as any).__instances;

function latestWS(): MockWSInstance {
  return wsInstances[wsInstances.length - 1]!;
}

function msg(data: object) {
  return JSON.stringify(data);
}

function sentFor(ws: MockWSInstance, commandId: string) {
  return ws.sent.map((s) => JSON.parse(s)).filter((m) => m.commandId === commandId);
}

function consoleOutput(): string {
  return vi.mocked(console.log).mock.calls
    .flat()
    .map((value) => String(value))
    .join("\n");
}

let ticketSequence = 0;
function nextTicket(): string {
  ticketSequence++;
  return ticketSequence.toString(16).padStart(64, "0");
}

async function flushTicketHandshake(): Promise<void> {
  for (let i = 0; i < 8; i++) await Promise.resolve();
}

describe("WebSocket connection", () => {
  beforeEach(() => {
    ticketSequence = 0;
    wsInstances.length = 0;
    vi.mocked(executeCommand).mockReset();
    vi.mocked(executeSecureCommand).mockReset();
    vi.mocked(executeElevatedCommand).mockReset();
    vi.mocked(pullFileToRelay).mockReset();
    vi.mocked(pushFileFromRelay).mockReset();
    // Default: the probe learned nothing, which is the state that changes
    // neither the register payload nor the job gpuIndex check.
    vi.mocked(probeGpuState).mockResolvedValue({ certainty: "unknown" });
    vi.mocked(startLoginShellPathProbe).mockClear();
    // Default: already resolved, so job_start has nothing to wait for.
    vi.mocked(pendingLoginShellPath).mockReturnValue(null);
    vi.mocked(startJobScopeProbe).mockClear();
    vi.mocked(pendingJobScope).mockReturnValue(null);
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        status: 200,
        json: async () => ({ ticket: nextTicket() }),
      } as Response)),
    );
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  async function connect(opts?: {
    serverUrl?: string;
    silent?: boolean;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    screenShare?: any;
  }) {
    const { runConnectionLoop } = await import("../connection.js");
    const promise = runConnectionLoop({
      serverUrl: opts?.serverUrl ?? "https://aic-worker.test",
      sessionCode: "AIC-WOLF-1234",
      agentToken: "test-token",
      silent: opts?.silent,
      screenShare: opts?.screenShare,
    });
    // Let microtasks run so WS constructor fires
    await new Promise((r) => setTimeout(r, 0));
    return { promise, ws: latestWS() };
  }

  it("uses a ticket-only URL and exact Bearer upgrade header", async () => {
    const { ws } = await connect();
    expect(ws.url).toBe(
      "wss://aic-worker.test/ws/agent?ticket=" + "1".padStart(64, "0"),
    );
    expect(ws.url).not.toContain("AIC-WOLF-1234");
    expect(ws.url).not.toContain("test-token");
    expect(ws.options?.headers).toEqual({ Authorization: "Bearer test-token" });
    ws.close(1000, "ok");
  });

  it("obtains the ticket by authenticated POST without credentials in the URL", async () => {
    const { ws } = await connect();
    const fetchMock = vi.mocked(fetch);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://aic-worker.test/api/agent/ws-ticket");
    expect(String(url)).not.toContain("AIC-WOLF-1234");
    expect(String(url)).not.toContain("test-token");
    expect(init?.headers).toEqual({
      Authorization: "Bearer test-token",
      "Content-Type": "application/json",
    });
    expect(JSON.parse(String(init?.body))).toEqual({ sessionCode: "AIC-WOLF-1234" });
    ws.close(1000, "ok");
  });

  it("redacts ticket-request network errors from local output", async () => {
    const sessionCode = "AIC-SECRET-1234";
    const agentToken = "agent-token-secret";
    const ac = new AbortController();
    vi.mocked(fetch).mockImplementationOnce(async () => {
      ac.abort();
      throw new Error(`request failed ${sessionCode} Authorization: Bearer ${agentToken}`);
    });
    const { runConnectionLoop } = await import("../connection.js");
    await runConnectionLoop({
      serverUrl: "https://aic-worker.test",
      sessionCode,
      agentToken,
      signal: ac.signal,
    });
    const local = consoleOutput();
    expect(local).not.toContain(sessionCode);
    expect(local).not.toContain(agentToken);
    expect(local).not.toContain("Authorization");
  });

  it("sends agent:register on open", async () => {
    const { ws } = await connect();
    ws._emit("open");
    await new Promise((r) => setTimeout(r, 0));

    const register = JSON.parse(ws.sent[0]!);
    expect(register.type).toBe("agent:register");
    expect(register.hostname).toBeTruthy();
    expect(register.platform).toBeTruthy();
    expect(register.arch).toBeTruthy();
    // No reachable helper (marker false) → fail-closed advertisement.
    expect(register.elevatedExec).toBe(false);
    expect(register.elevatedBootId).toBeUndefined();
    // Capability flags the relay gates whole features on. `shellSelect` is what
    // lets the relay send `shell` at all: without it the relay refuses the request
    // rather than have this agent drop the field and run the default interpreter.
    expect(register.jobs).toBe(true);
    expect(register.shellSelect).toBe(true);
    ws.close(1000, "ok");
  });

  // ── GPU knowledge: what goes on the wire vs what job_start is told ─────────
  describe("GPU probe wiring", () => {
    const CARD = {
      index: 0,
      name: "NVIDIA GeForce RTX 5080",
      memoryTotalMiB: 16303,
      memoryUsedMiB: 1024,
      utilizationPct: 37,
    };

    /** Drive one job RPC over the socket and hand back the agent:job_result. */
    async function startJob(ws: MockWSInstance, gpuIndex?: number) {
      ws._emit(
        "message",
        msg({
          type: "do:job_start",
          requestId: "req-1",
          command: "printf x",
          ...(gpuIndex !== undefined ? { gpuIndex } : {}),
        }),
      );
      // The job RPC is answered synchronously; flush microtasks only, so this
      // also works under the fake timers the re-probe tests install.
      for (let i = 0; i < 4; i++) await Promise.resolve();
      return ws.sent.map((s) => JSON.parse(s)).find((m) => m.requestId === "req-1");
    }

    it("omits gpus from register on a confidently GPU-less machine (never [])", async () => {
      // The wire contract is unchanged by the local confident-none signal: an
      // empty array would claim the same thing less clearly (AgentRegisterMsg).
      vi.mocked(probeGpuState).mockResolvedValue({ certainty: "none" });
      const { ws } = await connect();
      ws._emit("open");
      await new Promise((r) => setTimeout(r, 0));

      const register = JSON.parse(ws.sent[0]!);
      expect(register).not.toHaveProperty("gpus");
      ws.close(1000, "ok");
    });

    it("omits gpus from register when the probe could not tell", async () => {
      vi.mocked(probeGpuState).mockResolvedValue({ certainty: "unknown" });
      const { ws } = await connect();
      ws._emit("open");
      await new Promise((r) => setTimeout(r, 0));

      expect(JSON.parse(ws.sent[0]!)).not.toHaveProperty("gpus");
      ws.close(1000, "ok");
    });

    it("sends the devices it found on register", async () => {
      vi.mocked(probeGpuState).mockResolvedValue({ certainty: "devices", devices: [CARD] });
      const { ws } = await connect();
      ws._emit("open");
      await new Promise((r) => setTimeout(r, 0));

      expect(JSON.parse(ws.sent[0]!).gpus).toEqual([CARD]);
      ws.close(1000, "ok");
    });

    it("refuses a gpuIndex on a machine confidently known to have no GPU", async () => {
      // The whole point of the confident-none signal: a phantom
      // CUDA_VISIBLE_DEVICES=3 job on a card-less box is refused at start.
      vi.mocked(probeGpuState).mockResolvedValue({ certainty: "none" });
      const { ws } = await connect();
      ws._emit("open");
      await new Promise((r) => setTimeout(r, 0));

      const reply = await startJob(ws, 3);
      expect(reply.type).toBe("agent:job_result");
      expect(reply.result.ok).toBe(false);
      expect(reply.result.reason).toBe("invalid_request");
      expect(reply.result.message).toContain("no NVIDIA GPU");
      expect(reply.result.message).toContain("gpu_index 3");
      ws.close(1000, "ok");
    });

    it("still starts a GPU-less job on that machine", async () => {
      vi.mocked(probeGpuState).mockResolvedValue({ certainty: "none" });
      const { ws } = await connect();
      ws._emit("open");
      await new Promise((r) => setTimeout(r, 0));

      const reply = await startJob(ws);
      expect(reply.result.ok).toBe(true);
      ws.close(1000, "ok");
    });

    it("stays permissive when the probe could not tell", async () => {
      // Refusing a legitimate training run because nvidia-smi hiccuped would be
      // a worse bug than the one the hardware check fixes.
      vi.mocked(probeGpuState).mockResolvedValue({ certainty: "unknown" });
      const { ws } = await connect();
      ws._emit("open");
      await new Promise((r) => setTimeout(r, 0));

      const reply = await startJob(ws, 3);
      expect(reply.result.ok).toBe(true);
      expect(reply.result.job.gpuIndex).toBe(3);
      ws.close(1000, "ok");
    });

    it("does not downgrade a known list when a re-probe fails", async () => {
      vi.mocked(probeGpuState).mockResolvedValueOnce({ certainty: "devices", devices: [CARD] });
      const { ws } = await connect();
      // Fake timers only from here: connect() itself waits on a real setTimeout.
      vi.useFakeTimers();
      ws._emit("open");
      await vi.advanceTimersByTimeAsync(0);

      // Every later probe fails; neither the wire nor the job check may conclude
      // "this box lost its card". Kept under the 90s ping timeout so the socket
      // is still live when the job below is started.
      vi.mocked(probeGpuState).mockResolvedValue({ certainty: "unknown" });
      await vi.advanceTimersByTimeAsync(60_000);

      expect(ws.sent.map((s) => JSON.parse(s)).some((m) => m.type === "agent:gpu_state")).toBe(false);
      const reply = await startJob(ws, 0);
      expect(reply.result.ok).toBe(true);
      expect(reply.result.job.gpuIndex).toBe(0);
      ws.close(1000, "ok");
    });

    it("publishes and adopts a successful re-probe", async () => {
      const updated = { ...CARD, utilizationPct: 91 };
      vi.mocked(probeGpuState).mockResolvedValueOnce({ certainty: "devices", devices: [CARD] });
      const { ws } = await connect();
      vi.useFakeTimers();
      ws._emit("open");
      await vi.advanceTimersByTimeAsync(0);

      vi.mocked(probeGpuState).mockResolvedValue({ certainty: "devices", devices: [updated] });
      await vi.advanceTimersByTimeAsync(60_000);

      const push = ws.sent.map((s) => JSON.parse(s)).find((m) => m.type === "agent:gpu_state");
      expect(push.gpus).toEqual([updated]);
      ws.close(1000, "ok");
    });

    it("adopts a CONFIDENT empty re-probe: removed hardware stops being accepted", async () => {
      // Issue 23. Since the certainty rework a "none" can only come from an
      // nvidia-smi that ran and listed nothing — real information, not a failure
      // — so unlike an `unknown` it must update the local list. Otherwise a
      // pulled/failed card keeps being accepted for new jobs forever.
      vi.mocked(probeGpuState).mockResolvedValueOnce({ certainty: "devices", devices: [CARD] });
      const { ws } = await connect();
      vi.useFakeTimers();
      ws._emit("open");
      await vi.advanceTimersByTimeAsync(0);

      vi.mocked(probeGpuState).mockResolvedValue({ certainty: "none" });
      await vi.advanceTimersByTimeAsync(60_000);

      const reply = await startJob(ws, 0);
      expect(reply.result.ok).toBe(false);
      expect(reply.result.reason).toBe("invalid_request");
      expect(reply.result.message).toContain("no NVIDIA GPU");
      ws.close(1000, "ok");
    });

    it("keeps the known list across a reconnect whose initial probe fails", async () => {
      // The poll is not the only entry point to setKnownGpus: every RECONNECT
      // re-probes too, and the JobManager it talks to is a singleton that
      // outlives the socket. An `unknown` there used to push `undefined` into a
      // manager that already knew this box's card — silently downgrading a
      // characterised machine to "we know nothing" and making gpuIndex
      // permissive again, on nothing but a transient nvidia-smi failure.
      vi.mocked(probeGpuState).mockResolvedValueOnce({ certainty: "devices", devices: [CARD] });
      const ac = new AbortController();
      const { runConnectionLoop } = await import("../connection.js");
      void runConnectionLoop({
        serverUrl: "https://aic-worker.test",
        sessionCode: "AIC-WOLF-1234",
        agentToken: "test-token",
        signal: ac.signal,
        silent: true,
      }).catch(() => {});
      await flushTicketHandshake();
      const ws1 = latestWS();
      ws1._emit("open");
      await new Promise((r) => setTimeout(r, 0));
      expect(JSON.parse(ws1.sent[0]!).gpus).toEqual([CARD]);

      // Clean close → the loop reconnects immediately; this probe learns nothing.
      vi.mocked(probeGpuState).mockResolvedValue({ certainty: "unknown" });
      ws1.close(1000, "bye");
      await flushTicketHandshake();
      await new Promise((r) => setTimeout(r, 0));
      const ws2 = latestWS();
      expect(ws2).not.toBe(ws1);
      ws2._emit("open");
      await new Promise((r) => setTimeout(r, 0));

      // The WIRE keeps its own rule: with nothing learned this time, gpus is
      // omitted entirely rather than sent as [] (AgentRegisterMsg.gpus).
      expect(JSON.parse(ws2.sent[0]!)).not.toHaveProperty("gpus");
      // The LOCAL list is retained, so an index this machine does not have is
      // still refused instead of quietly starting a phantom job.
      const reply = await startJob(ws2, 3);
      expect(reply.result.ok).toBe(false);
      expect(reply.result.reason).toBe("invalid_request");
      expect(reply.result.message).toContain("no GPU 3");
      // ...and the card we do know about is still accepted.
      ws2.sent.length = 0;
      const ok = await startJob(ws2, 0);
      expect(ok.result.ok).toBe(true);
      expect(ok.result.job.gpuIndex).toBe(0);
      ac.abort();
      ws2.close(1000, "ok");
    });

    it("never publishes [] for that confident empty re-probe", async () => {
      // The local list tightens, the WIRE stays silent: `[]` is forbidden on
      // agent:gpu_state exactly as on register, so the relay keeps its last
      // reading rather than being told something the format cannot express.
      vi.mocked(probeGpuState).mockResolvedValueOnce({ certainty: "devices", devices: [CARD] });
      const { ws } = await connect();
      vi.useFakeTimers();
      ws._emit("open");
      await vi.advanceTimersByTimeAsync(0);

      vi.mocked(probeGpuState).mockResolvedValue({ certainty: "none" });
      await vi.advanceTimersByTimeAsync(60_000);

      const pushes = ws.sent.map((s) => JSON.parse(s)).filter((m) => m.type === "agent:gpu_state");
      expect(pushes).toEqual([]);
      ws.close(1000, "ok");
    });
  });

  // ── The login-shell PATH probe must be warm before the FIRST job spawns ─────
  describe("login-shell PATH warm-up", () => {
    it("starts the probe on the agent startup path, before any frame", async () => {
      // Not lazily via getJobManager()/recover(): on the desktop path the manager
      // is only reached once a do:job_* frame lands, which is too late for the
      // first job — it would inherit launchd's /usr/bin:/bin:/usr/sbin:/sbin.
      const { ws } = await connect();
      expect(startLoginShellPathProbe).toHaveBeenCalled();
      ws.close(1000, "ok");
    });

    it("defers do:job_start until the probe settles, without blocking do:ping", async () => {
      let release!: () => void;
      const pending = new Promise<void>((r) => { release = () => r(); });
      vi.mocked(pendingLoginShellPath).mockReturnValue(pending);

      const { ws } = await connect();
      ws._emit("open");
      await new Promise((r) => setTimeout(r, 0));
      // The manager is only reached (getJobManager) once the job is actually
      // started, which is exactly what must not happen yet.
      vi.mocked(getJobManager).mockClear();

      ws._emit("message", msg({ type: "do:job_start", requestId: "req-1", command: "printf x" }));
      for (let i = 0; i < 4; i++) await Promise.resolve();
      expect(getJobManager).not.toHaveBeenCalled();
      expect(ws.sent.map((s) => JSON.parse(s)).some((m) => m.requestId === "req-1")).toBe(false);

      // …and the socket is still being served meanwhile: a ping is answered while
      // the job start is still waiting.
      ws._emit("message", msg({ type: "do:ping" }));
      expect(ws.sent.map((s) => JSON.parse(s)).some((m) => m.type === "agent:pong")).toBe(true);

      release();
      for (let i = 0; i < 4; i++) await Promise.resolve();
      expect(getJobManager).toHaveBeenCalledTimes(1);
      const reply = ws.sent.map((s) => JSON.parse(s)).find((m) => m.requestId === "req-1");
      expect(reply.result.ok).toBe(true);
      ws.close(1000, "ok");
    });

    it("drops a job whose socket died while the probe was still running", async () => {
      // Starting it now would leave a job nobody can be told the id of.
      let release!: () => void;
      const pending = new Promise<void>((r) => { release = () => r(); });
      vi.mocked(pendingLoginShellPath).mockReturnValue(pending);

      const { ws } = await connect();
      ws._emit("open");
      await new Promise((r) => setTimeout(r, 0));
      vi.mocked(getJobManager).mockClear();

      ws._emit("message", msg({ type: "do:job_start", requestId: "req-1", command: "printf x" }));
      ws.close(1000, "ok");
      release();
      for (let i = 0; i < 4; i++) await Promise.resolve();
      expect(getJobManager).not.toHaveBeenCalled();
      expect(ws.sent.map((s) => JSON.parse(s)).some((m) => m.requestId === "req-1")).toBe(false);
    });
  });

  // ── The systemd-scope probe must be warm before the FIRST job spawns ───────
  describe("systemd scope warm-up", () => {
    it("starts the scope probe on the agent startup path, before any frame", async () => {
      // It used to run synchronously inside JobManager.start(), i.e. on this
      // handler's thread, where a wedged bus or polkit — the machines it exists
      // to detect — stalled the first job start for the probe's whole timeout.
      const { ws } = await connect();
      expect(startJobScopeProbe).toHaveBeenCalled();
      ws.close(1000, "ok");
    });

    it("defers do:job_start until the scope probe settles, without blocking do:ping", async () => {
      // Same deferral as the PATH probe, for the same reason: a job started
      // before the answer is in runs UNSCOPED, and an unscoped job dies with the
      // next agent restart — the failure scopes exist to fix.
      let release!: () => void;
      const pending = new Promise<void>((r) => { release = () => r(); });
      vi.mocked(pendingJobScope).mockReturnValue(pending);

      const { ws } = await connect();
      ws._emit("open");
      await new Promise((r) => setTimeout(r, 0));
      vi.mocked(getJobManager).mockClear();

      ws._emit("message", msg({ type: "do:job_start", requestId: "req-1", command: "printf x" }));
      for (let i = 0; i < 4; i++) await Promise.resolve();
      expect(getJobManager).not.toHaveBeenCalled();

      ws._emit("message", msg({ type: "do:ping" }));
      expect(ws.sent.map((s) => JSON.parse(s)).some((m) => m.type === "agent:pong")).toBe(true);

      release();
      for (let i = 0; i < 4; i++) await Promise.resolve();
      expect(getJobManager).toHaveBeenCalledTimes(1);
      const reply = ws.sent.map((s) => JSON.parse(s)).find((m) => m.requestId === "req-1");
      expect(reply.result.ok).toBe(true);
      ws.close(1000, "ok");
    });
  });

  it("registers immediately, then re-registers with elevatedBootId once discovery completes", async () => {
    vi.mocked(isElevatedHelperAvailable).mockReturnValueOnce(true);
    vi.mocked(discoverHelper).mockResolvedValueOnce({
      bootId: "boot-xyz",
      endpoint: { transport: "tcp", host: "127.0.0.1", port: 42847 },
    });

    const { ws } = await connect();
    ws._emit("open");
    await new Promise((r) => setTimeout(r, 0));

    // Frame 1 goes out BEFORE helper discovery (which can take seconds) so the
    // relay marks the machine online at once — no elevated advertisement yet.
    const first = JSON.parse(ws.sent[0]!);
    expect(first.type).toBe("agent:register");
    expect(first.elevatedExec).toBe(false);
    expect(first.elevatedBootId).toBeUndefined();

    // Frame 2 upgrades the advertisement once discovery answers.
    const second = JSON.parse(ws.sent[1]!);
    expect(second.type).toBe("agent:register");
    expect(second.elevatedExec).toBe(true);
    expect(second.elevatedBootId).toBe("boot-xyz");
    ws.close(1000, "ok");
  });

  it("advertises elevatedExec:false (single register) when the helper is installed but unreachable", async () => {
    vi.mocked(isElevatedHelperAvailable).mockReturnValueOnce(true);
    vi.mocked(discoverHelper).mockResolvedValueOnce(null);

    const { ws } = await connect();
    ws._emit("open");
    await new Promise((r) => setTimeout(r, 0));

    const registers = ws.sent
      .map((s) => JSON.parse(s))
      .filter((m) => m.type === "agent:register");
    // The immediate register already says elevatedExec:false; a null discovery
    // must NOT send a redundant second frame.
    expect(registers).toHaveLength(1);
    expect(registers[0].elevatedExec).toBe(false);
    expect(registers[0].elevatedBootId).toBeUndefined();
    ws.close(1000, "ok");
  });

  it("discards a stale discovery result when a fresher bootId was registered meanwhile", async () => {
    // Orchestrate the race the register epoch guards against: discovery (started
    // at open) is still probing when an elevated exec's onBootId observes the
    // freshly-restarted helper's nonce and re-registers. The discovery result —
    // from BEFORE the restart — must then be dropped, not re-advertised.
    vi.mocked(isElevatedHelperAvailable).mockReturnValue(true);
    let resolveDiscovery:
      | ((v: { bootId: string; endpoint: { transport: "tcp"; host: string; port: number } }) => void)
      | undefined;
    vi.mocked(discoverHelper).mockImplementationOnce(
      () => new Promise((r) => { resolveDiscovery = r; }),
    );
    let capturedOnBootId: ((bootId: string) => void) | undefined;
    vi.mocked(executeElevatedCommand).mockImplementationOnce((_cap, _id, _handlers, opts) => {
      capturedOnBootId = opts?.onBootId;
      return { kill: vi.fn() };
    });

    const { ws } = await connect();
    ws._emit("open");
    await new Promise((r) => setTimeout(r, 0));

    // Discovery still pending → only the immediate register so far.
    expect(ws.sent.map((s) => JSON.parse(s).type)).toEqual(["agent:register"]);

    // An elevated exec arrives and observes the restarted helper's fresh nonce.
    ws._emit("message", msg({ type: "do:elevated_exec", commandId: "cmd-1", capability: "cap" }));
    await new Promise((r) => setTimeout(r, 0));
    capturedOnBootId!("boot-FRESH");
    await new Promise((r) => setTimeout(r, 0));

    // Now the pending (pre-restart) discovery resolves with the STALE nonce.
    resolveDiscovery!({
      bootId: "boot-STALE",
      endpoint: { transport: "tcp", host: "127.0.0.1", port: 42847 },
    });
    await new Promise((r) => setTimeout(r, 0));

    const advertised = ws.sent
      .map((s) => JSON.parse(s))
      .filter((m) => m.type === "agent:register")
      .map((m) => m.elevatedBootId);
    // Immediate register (undefined) + onBootId re-register (fresh); the stale
    // discovery result must NOT have produced a third frame.
    expect(advertised).toEqual([undefined, "boot-FRESH"]);
    ws.close(1000, "ok");
    vi.mocked(isElevatedHelperAvailable).mockReturnValue(false);
  });

  it("responds to do:ping with agent:pong", async () => {
    const { ws } = await connect();
    ws._emit("open");
    ws._emit("message", msg({ type: "do:ping", ts: 12345 }));
    await new Promise((r) => setTimeout(r, 0));

    const pong = JSON.parse(ws.sent.find((s) => s.includes("agent:pong"))!);
    expect(pong.type).toBe("agent:pong");
    expect(pong.ts).toBe(12345);
    ws.close(1000, "ok");
  });

  it("calls executeCommand on do:exec", async () => {
    vi.mocked(executeCommand).mockImplementation((_cmd, _cwd, _env, handlers) => {
      handlers.onDone(0, 50);
      return { kill: vi.fn() };
    });

    const { ws } = await connect();
    ws._emit("open");
    ws._emit("message", msg({ type: "do:exec", commandId: "cmd-1", command: "ls", cwd: "/tmp" }));
    await new Promise((r) => setTimeout(r, 0));

    expect(executeCommand).toHaveBeenCalledWith(
      "ls", "/tmp", undefined, expect.any(Object),
      // The executor is given the same deadline the local timeout timer uses,
      // so its post-exit drain can end before we would report a timeout.
      { windowsExecLauncherPath: undefined, deadlineMs: expect.any(Number) },
    );
    ws.close(1000, "ok");
  });

  it("forwards do:exec `shell` to executeCommand instead of dropping it", async () => {
    // The failure this guards: agent:register advertises shellSelect, which is
    // the relay's ONLY evidence that a `shell` request will be honoured here. If
    // this handler stopped passing the field on, the relay would keep sending it,
    // the executor would fall back to the machine default, and the caller would
    // be told a PowerShell script succeeded that cmd.exe actually ran — exactly
    // the silent wrong-interpreter failure the capability flag exists to prevent.
    vi.mocked(executeCommand).mockImplementation((_cmd, _cwd, _env, handlers) => {
      handlers.onDone(0, 50);
      return { kill: vi.fn() };
    });

    const { ws } = await connect();
    ws._emit("open");
    ws._emit("message", msg({
      type: "do:exec",
      commandId: "cmd-shell",
      command: "Get-Date",
      shell: "powershell",
    }));
    await new Promise((r) => setTimeout(r, 0));

    expect(executeCommand).toHaveBeenCalledWith(
      "Get-Date", undefined, undefined, expect.any(Object),
      expect.objectContaining({ shell: "powershell" }),
    );
    ws.close(1000, "ok");
  });

  it("forwards a `shell` this machine cannot run, rather than filtering it", async () => {
    // Validation belongs to the executor (planExecShell), which refuses with a
    // message naming what IS available here. Quietly dropping an unrunnable value
    // at this layer would run the command in the default shell and report
    // success — the one outcome the whole refusal chain exists to make impossible.
    vi.mocked(executeCommand).mockImplementation((_cmd, _cwd, _env, handlers) => {
      handlers.onError("refused by the executor");
      return { kill: vi.fn() };
    });

    const { ws } = await connect();
    ws._emit("open");
    ws._emit("message", msg({
      type: "do:exec",
      commandId: "cmd-shell-bad",
      command: "echo hi",
      shell: "zsh",
    }));
    await new Promise((r) => setTimeout(r, 0));

    expect(executeCommand).toHaveBeenCalledWith(
      "echo hi", undefined, undefined, expect.any(Object),
      expect.objectContaining({ shell: "zsh" }),
    );
    const err = JSON.parse(ws.sent.find((s) => s.includes("agent:error"))!);
    expect(err.error).toBe("refused by the executor");
    ws.close(1000, "ok");
  });

  it("sends agent:done when command completes", async () => {
    vi.mocked(executeCommand).mockImplementation((_cmd, _cwd, _env, handlers) => {
      handlers.onDone(0, 100);
      return { kill: vi.fn() };
    });

    const { ws } = await connect();
    ws._emit("open");
    ws._emit("message", msg({ type: "do:exec", commandId: "cmd-1", command: "echo hi" }));
    await new Promise((r) => setTimeout(r, 0));

    const done = JSON.parse(ws.sent.find((s) => s.includes("agent:done"))!);
    expect(done.type).toBe("agent:done");
    expect(done.commandId).toBe("cmd-1");
    expect(done.exitCode).toBe(0);
    ws.close(1000, "ok");
  });

  it("sends agent:output chunks", async () => {
    vi.mocked(executeCommand).mockImplementation((_cmd, _cwd, _env, handlers) => {
      handlers.onOutput(Buffer.from("hello").toString("base64"), "stdout");
      handlers.onDone(0, 10);
      return { kill: vi.fn() };
    });

    const { ws } = await connect();
    ws._emit("open");
    ws._emit("message", msg({ type: "do:exec", commandId: "cmd-1", command: "echo hi" }));
    await new Promise((r) => setTimeout(r, 0));

    const output = JSON.parse(ws.sent.find((s) => s.includes("agent:output"))!);
    expect(output.type).toBe("agent:output");
    expect(output.stream).toBe("stdout");
    expect(Buffer.from(output.chunk, "base64").toString()).toBe("hello");
    ws.close(1000, "ok");
  });

  it("logs only safe command metadata in a systemd/journald context", async () => {
    const secrets = {
      command: "COMMAND_SECRET_09",
      commandId: "COMMAND_ID_SECRET_09",
      cwd: "/tmp/CWD_SECRET_09",
      env: "ENV_SECRET_09",
      output: "OUTPUT_SECRET_09",
    };
    vi.mocked(executeCommand).mockImplementation((_cmd, _cwd, _env, handlers) => {
      handlers.onOutput(Buffer.from(secrets.output).toString("base64"), "stdout");
      handlers.onDone(0, 42);
      return { kill: vi.fn() };
    });
    const previous = process.env["JOURNAL_STREAM"];
    process.env["JOURNAL_STREAM"] = "8:12345";
    try {
      const { ws } = await connect();
      ws._emit("open");
      ws._emit("message", msg({
        type: "do:exec",
        commandId: secrets.commandId,
        command: `printf ${secrets.command}`,
        cwd: secrets.cwd,
        env: { TOKEN: secrets.env },
      }));

      const local = consoleOutput();
      for (const secret of Object.values(secrets)) expect(local).not.toContain(secret);
      expect(local).toContain("Command started.");
      expect(local).toContain("Command finished. Exit 0 in 42ms.");

      const output = ws.sent.map((s) => JSON.parse(s)).find((m) => m.type === "agent:output");
      expect(Buffer.from(output.chunk, "base64").toString()).toBe(secrets.output);
      ws.close(1000, "ok");
    } finally {
      if (previous === undefined) delete process.env["JOURNAL_STREAM"];
      else process.env["JOURNAL_STREAM"] = previous;
    }
  });

  it("logs only the secure-exec basename, never argv or other payloads", async () => {
    vi.stubEnv("JOURNAL_STREAM", "8:12345");
    const secrets = ["ARGV_SECRET_09", "INPUT_SECRET_09", "CWD_SECRET_09", "ENV_SECRET_09", "OUTPUT_SECRET_09"];
    vi.mocked(executeSecureCommand).mockImplementation((_req, handlers) => {
      handlers.onOutput(Buffer.from(secrets[4]!).toString("base64"), "stderr");
      handlers.onDone(7, 91);
      return { kill: vi.fn() };
    });

    const { ws } = await connect();
    ws._emit("open");
    ws._emit("message", msg({
      type: "do:secure_exec",
      commandId: "se-safe-id",
      argv: ["wrangler", secrets[0]],
      allowedCommands: ["wrangler"],
      input: Buffer.from(secrets[1]!).toString("base64"),
      cwd: `/tmp/${secrets[2]}`,
      env: { TOKEN: secrets[3] },
    }));

    const local = consoleOutput();
    for (const secret of secrets) expect(local).not.toContain(secret);
    expect(local).toContain("Secure exec (wrangler) started.");
    expect(local).toContain("Secure exec finished. Exit 7 in 91ms.");

    const output = ws.sent.map((s) => JSON.parse(s)).find((m) => m.type === "agent:output");
    expect(Buffer.from(output.chunk, "base64").toString()).toBe(secrets[4]);
    ws.close(1000, "ok");
  });

  it("does not stringify payload-bearing execution errors to local console", async () => {
    const secret = "ERROR_PAYLOAD_SECRET_09";
    vi.mocked(executeCommand).mockImplementation(() => {
      throw new Error(`spawn rejected ${secret}`);
    });

    const { ws } = await connect();
    ws._emit("message", msg({
      type: "do:exec",
      commandId: "error-1",
      command: secret,
    }));

    expect(consoleOutput()).not.toContain(secret);
    const error = ws.sent.map((s) => JSON.parse(s)).find((m) => m.type === "agent:error");
    expect(error.error).toContain(secret);
    ws.close(1000, "ok");
  });

  it("keeps library/desktop silent mode free of local command display", async () => {
    vi.mocked(executeCommand).mockReturnValue({ kill: vi.fn() });
    const { ws } = await connect({ silent: true });
    ws._emit("message", msg({
      type: "do:exec", commandId: "silent-1", command: "SILENT_SECRET_09",
    }));
    expect(consoleOutput()).toBe("");
    ws.close(1000, "ok");
  });

  it("keeps command payload redacted on an explicit foreground TTY", async () => {
    const previous = process.stdout.isTTY;
    Object.defineProperty(process.stdout, "isTTY", { value: true, configurable: true });
    vi.mocked(executeCommand).mockReturnValue({ kill: vi.fn() });
    try {
      const { ws } = await connect();
      ws._emit("message", msg({
        type: "do:exec",
        commandId: "tty-1",
        command: "TTY_COMMAND_SECRET_09",
      }));
      expect(consoleOutput()).toContain("Command started.");
      expect(consoleOutput()).not.toContain("TTY_COMMAND_SECRET_09");
      ws.close(1000, "ok");
    } finally {
      Object.defineProperty(process.stdout, "isTTY", { value: previous, configurable: true });
    }
  });

  it("calls kill() on do:kill", async () => {
    const mockKill = vi.fn();
    vi.mocked(executeCommand).mockReturnValue({ kill: mockKill });

    const { ws } = await connect();
    ws._emit("open");
    ws._emit("message", msg({ type: "do:exec", commandId: "cmd-1", command: "sleep 60" }));
    ws._emit("message", msg({ type: "do:kill", commandId: "cmd-1" }));
    await new Promise((r) => setTimeout(r, 0));

    expect(mockKill).toHaveBeenCalled();
    ws.close(1000, "ok");
  });

  it("ignores a stale kill for the previous command and kills only the matching active command", async () => {
    const handlers: Array<Parameters<typeof executeCommand>[3]> = [];
    const firstKill = vi.fn();
    const secondKill = vi.fn();
    vi.mocked(executeCommand)
      .mockImplementationOnce((_cmd, _cwd, _env, callbacks) => {
        handlers.push(callbacks);
        return { kill: firstKill };
      })
      .mockImplementationOnce((_cmd, _cwd, _env, callbacks) => {
        handlers.push(callbacks);
        return { kill: secondKill };
      });

    const { ws } = await connect();
    ws._emit("message", msg({ type: "do:exec", commandId: "A", command: "true" }));
    handlers[0]!.onDone(0, 5);
    ws._emit("message", msg({ type: "do:exec", commandId: "B", command: "sleep 60" }));

    ws._emit("message", msg({ type: "do:kill", commandId: "A" }));
    expect(firstKill).not.toHaveBeenCalled();
    expect(secondKill).not.toHaveBeenCalled();

    ws._emit("message", msg({ type: "do:kill", commandId: "B" }));
    expect(firstKill).not.toHaveBeenCalled();
    expect(secondKill).toHaveBeenCalledOnce();
    ws.close(1000, "ok");
  });

  it("rejects an overlapping exec without replacing the first command or its timeout", async () => {
    const firstKill = vi.fn();
    const secondKill = vi.fn();
    vi.mocked(executeCommand)
      .mockReturnValueOnce({ kill: firstKill })
      .mockReturnValueOnce({ kill: secondKill });

    const { ws } = await connect();
    vi.useFakeTimers();
    ws._emit("message", msg({
      type: "do:exec",
      commandId: "first",
      command: "sleep 60",
      timeoutMs: 2_000,
    }));
    await vi.advanceTimersByTimeAsync(500);
    ws._emit("message", msg({
      type: "do:exec",
      commandId: "overlap",
      command: "should-not-run",
      timeoutMs: 1_000,
    }));

    expect(executeCommand).toHaveBeenCalledOnce();
    expect(sentFor(ws, "overlap")).toEqual([{
      type: "agent:error",
      commandId: "overlap",
      error: "Another command is already running on this connection.",
    }]);

    // The rejected frame's shorter deadline must not kill the first command.
    await vi.advanceTimersByTimeAsync(1_499);
    expect(firstKill).not.toHaveBeenCalled();
    expect(secondKill).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(firstKill).toHaveBeenCalledOnce();
    expect(secondKill).not.toHaveBeenCalled();
    expect(sentFor(ws, "first")).toEqual([{
      type: "agent:error",
      commandId: "first",
      error: "Command timed out after 2000ms",
    }]);
    ws.close(1000, "ok");
  });

  it("does not let a completed command's old deadline kill the next command", async () => {
    const handlers: Array<Parameters<typeof executeCommand>[3]> = [];
    const firstKill = vi.fn();
    const secondKill = vi.fn();
    vi.mocked(executeCommand)
      .mockImplementationOnce((_cmd, _cwd, _env, callbacks) => {
        handlers.push(callbacks);
        return { kill: firstKill };
      })
      .mockImplementationOnce((_cmd, _cwd, _env, callbacks) => {
        handlers.push(callbacks);
        return { kill: secondKill };
      });

    const { ws } = await connect();
    vi.useFakeTimers();
    ws._emit("message", msg({
      type: "do:exec", commandId: "old", command: "true", timeoutMs: 1_000,
    }));
    handlers[0]!.onDone(0, 10);
    ws._emit("message", msg({
      type: "do:exec", commandId: "current", command: "sleep 60", timeoutMs: 5_000,
    }));

    await vi.advanceTimersByTimeAsync(1_500);
    expect(firstKill).not.toHaveBeenCalled();
    expect(secondKill).not.toHaveBeenCalled();
    expect(sentFor(ws, "current")).toEqual([]);

    handlers[1]!.onDone(0, 1_500);
    expect(sentFor(ws, "current")).toEqual([{
      type: "agent:done",
      commandId: "current",
      exitCode: 0,
      durationMs: 1_500,
    }]);
    ws.close(1000, "ok");
  });

  it("ignores late callbacks from a terminal command and accepts a normal later command", async () => {
    const handlers: Array<Parameters<typeof executeCommand>[3]> = [];
    const kills = [vi.fn(), vi.fn(), vi.fn()];
    vi.mocked(executeCommand).mockImplementation((_cmd, _cwd, _env, callbacks) => {
      const index = handlers.push(callbacks) - 1;
      return { kill: kills[index]! };
    });

    const { ws } = await connect();
    ws._emit("message", msg({ type: "do:exec", commandId: "finished", command: "true" }));
    handlers[0]!.onDone(0, 5);
    ws._emit("message", msg({ type: "do:exec", commandId: "running", command: "sleep 60" }));

    handlers[0]!.onOutput(btoa("late"), "stdout");
    handlers[0]!.onError("late error");
    handlers[0]!.onDone(9, 99);
    ws._emit("message", msg({ type: "do:exec", commandId: "still-overlap", command: "false" }));

    expect(executeCommand).toHaveBeenCalledTimes(2);
    expect(sentFor(ws, "finished")).toEqual([{
      type: "agent:done",
      commandId: "finished",
      exitCode: 0,
      durationMs: 5,
    }]);
    expect(sentFor(ws, "still-overlap"))
      .toEqual([expect.objectContaining({ type: "agent:error" })]);

    handlers[1]!.onDone(0, 20);
    ws._emit("message", msg({ type: "do:exec", commandId: "later", command: "true" }));
    expect(executeCommand).toHaveBeenCalledTimes(3);
    handlers[2]!.onDone(0, 3);
    expect(sentFor(ws, "later")).toEqual([{
      type: "agent:done",
      commandId: "later",
      exitCode: 0,
      durationMs: 3,
    }]);
    expect(kills.every((kill) => kill.mock.calls.length === 0)).toBe(true);
    ws.close(1000, "ok");
  });

  it("shares the overlap guard across secure, elevated and legacy exec modes", async () => {
    let finishSecure: (() => void) | undefined;
    vi.mocked(executeSecureCommand).mockImplementation((_request, handlers) => {
      finishSecure = () => handlers.onDone(0, 25);
      return { kill: vi.fn() };
    });
    vi.mocked(executeElevatedCommand).mockReturnValue({ kill: vi.fn() });

    const { ws } = await connect();
    ws._emit("message", msg({
      type: "do:secure_exec",
      commandId: "secure-running",
      argv: ["wrangler", "deploy"],
      allowedCommands: ["wrangler"],
    }));
    ws._emit("message", msg({
      type: "do:elevated_exec", commandId: "elevated-overlap", capability: "cap",
    }));
    ws._emit("message", msg({
      type: "do:exec", commandId: "legacy-overlap", command: "true",
    }));

    expect(executeSecureCommand).toHaveBeenCalledOnce();
    expect(executeElevatedCommand).not.toHaveBeenCalled();
    expect(executeCommand).not.toHaveBeenCalled();
    for (const commandId of ["elevated-overlap", "legacy-overlap"]) {
      expect(sentFor(ws, commandId))
        .toEqual([expect.objectContaining({ type: "agent:error" })]);
    }

    finishSecure!();
    ws._emit("message", msg({
      type: "do:elevated_exec", commandId: "elevated-later", capability: "cap",
    }));
    expect(executeElevatedCommand).toHaveBeenCalledOnce();
    ws.close(1000, "ok");
  });

  it("keeps the slot through timeout termination, then releases it on the executor close callback", async () => {
    const mockKill = vi.fn();
    const handlers: Array<Parameters<typeof executeCommand>[3]> = [];
    vi.mocked(executeCommand).mockImplementation((_cmd, _cwd, _env, callbacks) => {
      handlers.push(callbacks);
      return { kill: mockKill };
    });

    const { ws } = await connect();
    vi.useFakeTimers();
    // Zero is untrusted and must normalize to the documented 1s minimum.
    ws._emit("message", msg({
      type: "do:exec",
      commandId: "timeout-1",
      command: "sleep 60",
      timeoutMs: 0,
    }));

    await vi.advanceTimersByTimeAsync(999);
    expect(mockKill).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);

    expect(mockKill).toHaveBeenCalledOnce();
    const timeoutErrors = sentFor(ws, "timeout-1").filter((m) => m.type === "agent:error");
    expect(timeoutErrors).toEqual([{
      type: "agent:error",
      commandId: "timeout-1",
      error: "Command timed out after 1000ms",
    }]);

    // TERM→KILL/taskkill is asynchronous. The timeout response is terminal for
    // the caller, but the executor has not reported that the process is gone, so
    // the connection-wide slot must remain occupied.
    ws._emit("message", msg({
      type: "do:exec", commandId: "during-kill", command: "should-not-run",
    }));
    expect(executeCommand).toHaveBeenCalledOnce();
    expect(sentFor(ws, "during-kill"))
      .toEqual([expect.objectContaining({
        type: "agent:error",
        error: "Another command is already running on this connection.",
      })]);

    // A process-close callback racing in after kill finalizes cleanup without
    // replacing or duplicating the timeout terminal frame.
    handlers[0]!.onOutput(btoa("late"), "stdout");
    handlers[0]!.onDone(0, 1_001);
    expect(ws.sent.map((s) => JSON.parse(s)).some((m) =>
      m.type === "agent:output" && m.commandId === "timeout-1"
    )).toBe(false);
    expect(ws.sent.map((s) => JSON.parse(s)).some((m) =>
      m.type === "agent:done" && m.commandId === "timeout-1"
    )).toBe(false);
    expect(ws.sent.map((s) => JSON.parse(s)).filter((m) =>
      (m.type === "agent:done" || m.type === "agent:error") && m.commandId === "timeout-1"
    )).toHaveLength(1);

    // Once the executor confirms close, the next ordinary command is accepted.
    ws._emit("message", msg({
      type: "do:exec", commandId: "after-close", command: "true",
    }));
    expect(executeCommand).toHaveBeenCalledTimes(2);
    handlers[1]!.onDone(0, 3);
    expect(sentFor(ws, "after-close"))
      .toEqual([{ type: "agent:done", commandId: "after-close", exitCode: 0, durationMs: 3 }]);
    ws.close(1000, "ok");
  });

  it("clears the do:exec timeout after normal completion", async () => {
    const mockKill = vi.fn();
    let finish: (() => void) | undefined;
    vi.mocked(executeCommand).mockImplementation((_cmd, _cwd, _env, handlers) => {
      finish = () => handlers.onDone(0, 20);
      return { kill: mockKill };
    });

    const { ws } = await connect();
    vi.useFakeTimers();
    ws._emit("message", msg({
      type: "do:exec",
      commandId: "quick-1",
      command: "true",
      timeoutMs: 1_000,
    }));
    finish!();
    await vi.advanceTimersByTimeAsync(2_000);

    expect(mockKill).not.toHaveBeenCalled();
    expect(ws.sent.map((s) => JSON.parse(s)).filter((m) =>
      (m.type === "agent:done" || m.type === "agent:error") && m.commandId === "quick-1"
    )).toEqual([{ type: "agent:done", commandId: "quick-1", exitCode: 0, durationMs: 20 }]);
    ws.close(1000, "ok");
  });

  it("routes do:secure_exec to executeSecureCommand with argv + allowlist", async () => {
    vi.mocked(executeSecureCommand).mockReturnValue({ kill: vi.fn() });

    const { ws } = await connect();
    ws._emit("open");
    ws._emit(
      "message",
      msg({
        type: "do:secure_exec",
        commandId: "se-1",
        argv: ["wrangler", "deploy"],
        allowedCommands: ["wrangler"],
      }),
    );
    await new Promise((r) => setTimeout(r, 0));

    expect(vi.mocked(executeSecureCommand)).toHaveBeenCalledOnce();
    const req = vi.mocked(executeSecureCommand).mock.calls[0]![0];
    expect(req.argv).toEqual(["wrangler", "deploy"]);
    expect(req.allowedCommands).toEqual(["wrangler"]);
    ws.close(1000, "ok");
  });

  it("fails closed to agent:error on a malformed do:secure_exec frame", async () => {
    // A pre-flight rejection (here: non-array argv) must NOT throw out of the
    // message handler — it must be caught and reported as agent:error. Guards the
    // fail-closed ordering fix (label/validation moved inside the try/catch).
    vi.mocked(executeSecureCommand).mockImplementation(() => {
      throw new Error("secure exec requires a non-empty argv");
    });

    const { ws } = await connect();
    ws._emit("open");
    // The handler runs synchronously inside _emit; if argv.join ran before the
    // try (the old bug), this _emit would throw and fail the test.
    expect(() =>
      ws._emit(
        "message",
        msg({ type: "do:secure_exec", commandId: "se-2", argv: "not-an-array", allowedCommands: [] }),
      ),
    ).not.toThrow();
    await new Promise((r) => setTimeout(r, 0));

    const err = ws.sent.find((s) => s.includes("agent:error") && s.includes("se-2"));
    expect(err).toBeDefined();
    expect(JSON.parse(err!).error).toMatch(/non-empty argv/);
    ws.close(1000, "ok");
  });

  it("routes do:elevated_exec to executeElevatedCommand, never executeCommand", async () => {
    vi.mocked(executeElevatedCommand).mockReturnValue({ kill: vi.fn() });

    const { ws } = await connect();
    ws._emit("open");
    ws._emit(
      "message",
      msg({ type: "do:elevated_exec", commandId: "el-1", capability: "signed.jws.token" }),
    );
    await new Promise((r) => setTimeout(r, 0));

    expect(vi.mocked(executeElevatedCommand)).toHaveBeenCalledOnce();
    expect(vi.mocked(executeElevatedCommand).mock.calls[0]![0]).toBe("signed.jws.token");
    // Elevated must never leak into the ordinary (unprivileged) exec path.
    expect(executeCommand).not.toHaveBeenCalled();
    ws.close(1000, "ok");
  });

  it("passes commandId as the requestId to executeElevatedCommand", async () => {
    vi.mocked(executeElevatedCommand).mockReturnValue({ kill: vi.fn() });

    const { ws } = await connect();
    ws._emit("open");
    ws._emit(
      "message",
      msg({ type: "do:elevated_exec", commandId: "el-2", capability: "signed.jws.token" }),
    );
    await new Promise((r) => setTimeout(r, 0));

    // 1st arg = capability, 2nd arg = commandId (== signed requestId).
    expect(vi.mocked(executeElevatedCommand).mock.calls[0]![0]).toBe("signed.jws.token");
    expect(vi.mocked(executeElevatedCommand).mock.calls[0]![1]).toBe("el-2");
    ws.close(1000, "ok");
  });

  it("returns a no-op kill and never spawns from executeElevatedCommand (fail-closed)", async () => {
    const { executeElevatedCommand: realExec } = await vi.importActual<
      typeof import("../elevated-executor.js")
    >("../elevated-executor.js");

    const onOutput = vi.fn();
    const onDone = vi.fn();
    const onError = vi.fn();
    // endpoint: null forces the deterministic "no helper on this machine" path.
    const running = realExec("signed.jws.token", "el-3", { onOutput, onDone, onError }, { endpoint: null });

    // kill handle returned synchronously and is a safe no-op.
    expect(() => running.kill()).not.toThrow();
    // onError fires asynchronously (queueMicrotask); nothing else does.
    await new Promise((r) => setTimeout(r, 0));
    expect(onError).toHaveBeenCalledOnce();
    expect(onError.mock.calls[0]![0]).toMatch(/not available on this machine/);
    expect(onOutput).not.toHaveBeenCalled();
    expect(onDone).not.toHaveBeenCalled();
  });

  it("resolves cleanly on close code 1000", async () => {
    const { ws, promise } = await connect();
    ws._emit("open");
    ws.close(1000, "clean");

    // Should not throw
    await expect(Promise.race([promise, new Promise((_, r) => setTimeout(() => r(new Error("timeout")), 500))])).rejects.toThrow("timeout");
    // The loop keeps running (never resolves), but the inner connectAndServe resolved cleanly
  });

  it("terminates on ping timeout (90s)", async () => {
    vi.useFakeTimers();

    // Call runConnectionLoop directly (bypass connect() helper which uses setTimeout internally)
    const { runConnectionLoop } = await import("../connection.js");
    runConnectionLoop({
      serverUrl: "https://aic-worker.test",
      sessionCode: "AIC-WOLF-1234",
      agentToken: "test-token",
    }).catch(() => {});

    // Yield to microtask queue — WS constructor fires synchronously inside connectAndServe
    await flushTicketHandshake();

    const ws = latestWS();
    ws._emit("open"); // triggers 90s ping timeout

    await vi.advanceTimersByTimeAsync(89_000);
    expect(ws.terminated).toBe(false);

    await vi.advanceTimersByTimeAsync(2_000);
    expect(ws.terminated).toBe(true);

    vi.useRealTimers();
  }, 30_000);

  it("rotates the agent token while idle after reauthIntervalMs", async () => {
    vi.useFakeTimers();
    const reauth = vi.fn(async () => "rotated-token");
    const ac = new AbortController();
    const { runConnectionLoop } = await import("../connection.js");
    void runConnectionLoop({
      serverUrl: "https://aic-worker.test",
      sessionCode: "AIC-WOLF-1234",
      agentToken: "test-token",
      signal: ac.signal,
      reauthIntervalMs: 60_000,
      reauth,
    }).catch(() => {});

    await flushTicketHandshake();
    const ws1 = latestWS();
    expect(ws1.url).not.toContain("test-token");
    expect(ws1.options?.headers?.Authorization).toBe("Bearer test-token");
    ws1._emit("open"); // arms the reauth timer (idle)

    // After the interval, idle → clean close, reauth(), reconnect with new token.
    await vi.advanceTimersByTimeAsync(61_000);
    expect(reauth).toHaveBeenCalledTimes(1);
    await flushTicketHandshake();
    const ws2 = latestWS();
    expect(ws2).not.toBe(ws1);
    expect(ws2.url).not.toContain("rotated-token");
    expect(ws2.options?.headers?.Authorization).toBe("Bearer rotated-token");
    expect(ws2.url).not.toBe(ws1.url); // every reconnect receives a fresh one-use ticket

    ac.abort();
    vi.useRealTimers();
  }, 30_000);

  // ── Detached transfers stay reachable from teardown ───────────────────────
  //
  // A transfer outlives the frame that started it, which is exactly why losing
  // track of it matters: revoking access has to stop bytes that are already
  // moving, and rotating the token must not cut a transfer's reply off.
  describe("in-flight file transfers", () => {
    /** A transfer that never finishes on its own, handing back the signal it got. */
    function neverSettles(mock: typeof pullFileToRelay | typeof pushFileFromRelay) {
      const signals: AbortSignal[] = [];
      vi.mocked(mock).mockImplementation((req: { signal?: AbortSignal }) => {
        if (req.signal) signals.push(req.signal);
        return new Promise(() => undefined) as never;
      });
      return signals;
    }

    const PULL = {
      type: "do:file_pull",
      requestId: "req-pull",
      path: "/var/log/train.log",
      token: "blob-token",
      maxBytes: 1000,
      operator: { id: "u1", anonymous: false },
    };
    const PUSH = {
      type: "do:file_push",
      requestId: "req-push",
      destPath: "/data/model.ckpt",
      token: "blob-token",
      expectedBytes: 10,
      operator: { id: "u1", anonymous: false },
    };

    it("aborts an in-flight pull when the socket goes away", async () => {
      const signals = neverSettles(pullFileToRelay);
      const { ws } = await connect();
      ws._emit("open");
      ws._emit("message", msg(PULL));
      await new Promise((r) => setTimeout(r, 0));

      expect(signals).toHaveLength(1);
      expect(signals[0]!.aborted).toBe(false);

      ws.close(1000, "ok");
      await new Promise((r) => setTimeout(r, 0));
      // Untracked, this upload would have kept streaming the user's bytes long
      // after the connection carrying the authorisation for it was gone.
      expect(signals[0]!.aborted).toBe(true);
    });

    it("aborts an in-flight push when the agent is disabled", async () => {
      const signals = neverSettles(pushFileFromRelay);
      const ac = new AbortController();
      const { runConnectionLoop } = await import("../connection.js");
      void runConnectionLoop({
        serverUrl: "https://aic-worker.test",
        sessionCode: "AIC-WOLF-1234",
        agentToken: "test-token",
        signal: ac.signal,
      }).catch(() => undefined);
      await flushTicketHandshake();

      const ws = latestWS();
      ws._emit("open");
      ws._emit("message", msg(PUSH));
      await new Promise((r) => setTimeout(r, 0));
      expect(signals).toHaveLength(1);

      ac.abort();
      await new Promise((r) => setTimeout(r, 0));
      // Revocation has to reach the write BEFORE it lands on the destination —
      // otherwise disabling the agent still lets someone replace a file on it.
      expect(signals[0]!.aborted).toBe(true);
    });

    it("defers token rotation until the transfer is done", async () => {
      vi.useFakeTimers();
      let finish!: () => void;
      const done = new Promise<void>((resolve) => { finish = resolve; });
      vi.mocked(pullFileToRelay).mockImplementation(
        async () => { await done; return { ok: true, kind: "pulled", bytes: 1 }; },
      );

      const reauth = vi.fn(async () => "rotated-token");
      const ac = new AbortController();
      const { runConnectionLoop } = await import("../connection.js");
      void runConnectionLoop({
        serverUrl: "https://aic-worker.test",
        sessionCode: "AIC-WOLF-1234",
        agentToken: "test-token",
        signal: ac.signal,
        reauthIntervalMs: 60_000,
        reauth,
      }).catch(() => undefined);
      await flushTicketHandshake();

      const ws1 = latestWS();
      ws1._emit("open");
      ws1._emit("message", msg(PULL));
      await vi.advanceTimersByTimeAsync(0);

      // The rotation is due, but a transfer is a busy connection: closing the
      // socket now would leave the transfer running with nobody to report to.
      await vi.advanceTimersByTimeAsync(61_000);
      expect(reauth).not.toHaveBeenCalled();
      expect(latestWS()).toBe(ws1);

      // Keep the link alive across the second advance: the 90s ping watchdog would
      // otherwise terminate the socket and mask what is being measured here.
      ws1._emit("message", msg({ type: "do:ping", ts: 1 }));
      finish();
      await vi.advanceTimersByTimeAsync(31_000);
      expect(reauth).toHaveBeenCalledTimes(1);

      ac.abort();
      vi.useRealTimers();
    }, 30_000);
  });

  it("invokes onHeartbeat on open and on each server ping", async () => {
    let beats = 0;
    const { runConnectionLoop } = await import("../connection.js");
    runConnectionLoop({
      serverUrl: "https://aic-worker.test",
      sessionCode: "AIC-WOLF-1234",
      agentToken: "test-token",
      onHeartbeat: () => { beats++; },
    }).catch(() => {});
    await new Promise((r) => setTimeout(r, 0));

    const ws = latestWS();
    ws._emit("open"); // heartbeat #1
    ws._emit("message", msg({ type: "do:ping", ts: 1 })); // heartbeat #2
    ws._emit("message", msg({ type: "do:ping", ts: 2 })); // heartbeat #3
    await new Promise((r) => setTimeout(r, 0));

    expect(beats).toBeGreaterThanOrEqual(3);
    ws.close(1000, "ok");
  });

  it("emits agent:exec_idle when a command produces no output past the threshold", async () => {
    vi.useFakeTimers();
    // Long-running command: never calls onDone/onError so the idle timer can fire.
    vi.mocked(executeCommand).mockReturnValue({ kill: vi.fn() });

    const { runConnectionLoop } = await import("../connection.js");
    runConnectionLoop({
      serverUrl: "https://aic-worker.test",
      sessionCode: "AIC-WOLF-1234",
      agentToken: "test-token",
    }).catch(() => {});
    await flushTicketHandshake();

    const ws = latestWS();
    ws._emit("open");
    ws._emit("message", msg({ type: "do:exec", commandId: "cmd-1", command: "sleep 999" }));

    // Advance past the 5-min idle threshold while keeping the link alive with
    // server pings (idle is about command OUTPUT, not connection liveness).
    for (let t = 0; t < 320_000; t += 20_000) {
      ws._emit("message", msg({ type: "do:ping", ts: t }));
      await vi.advanceTimersByTimeAsync(20_000);
    }

    const idle = ws.sent.map((s) => JSON.parse(s)).find((m) => m.type === "agent:exec_idle");
    expect(idle).toBeTruthy();
    expect(idle.commandId).toBe("cmd-1");
    expect(idle.idleMs).toBeGreaterThanOrEqual(300_000);

    vi.useRealTimers();
  }, 30_000);
  // ── Screenshots ───────────────────────────────────────────────────────────
  //
  // The agent is the only layer that knows what was ACTUALLY captured, so these
  // cover both halves of that responsibility: forwarding the requested display
  // down to the provider, and echoing back the capture's own metadata rather than
  // the request's.

  function makeScreenShare(overrides: Record<string, unknown> = {}) {
    const capture = vi.fn(async () => ({
      data: Buffer.from("fake-png-bytes"),
      mimeType: "image/png",
      meta: { display: 0, displayCount: 3, width: 5760, height: 3240, scaled: false },
    }));
    return {
      capture,
      getState: vi.fn(
        (): Record<string, unknown> => ({
          capable: true,
          enabled: true,
          expiresAt: Date.now() + 60_000,
          ...overrides,
        }),
      ),
      on: vi.fn(),
      off: vi.fn(),
    };
  }

  async function requestShot(
    screenShare: ReturnType<typeof makeScreenShare>,
    display?: number | "all",
  ) {
    const { ws } = await connect({ screenShare });
    ws._emit("open");
    await new Promise((r) => setTimeout(r, 0));
    ws._emit(
      "message",
      msg({ type: "do:screenshot", requestId: "shot-1", ...(display !== undefined ? { display } : {}) }),
    );
    await new Promise((r) => setTimeout(r, 0));
    const sent = ws.sent.map((s) => JSON.parse(s));
    ws.close(1000, "ok");
    return sent;
  }

  it("forwards the requested display to the provider and echoes what came back", async () => {
    const screenShare = makeScreenShare();
    screenShare.capture.mockResolvedValueOnce({
      data: Buffer.from("fake-png-bytes"),
      mimeType: "image/png",
      meta: { display: 2, displayCount: 3, width: 2808, height: 4992, scaled: false },
    });
    const sent = await requestShot(screenShare, 2);
    expect(screenShare.capture).toHaveBeenCalledWith({ display: 2 });
    const done = sent.find((m) => m.type === "agent:screenshot_done");
    expect(done.meta.display).toBe(2);
    expect(done.meta.displayCount).toBe(3);
  });

  it("reports the capture's own display, NOT the one that was asked for", async () => {
    // A provider that ignores `display` must not produce a reply claiming the
    // request was honored — the relay trusts this echo, so it has to be the truth.
    const screenShare = makeScreenShare();
    const sent = await requestShot(screenShare, 2);
    const done = sent.find((m) => m.type === "agent:screenshot_done");
    expect(done.meta.display).toBe(0);
  });

  it("omits display entirely when none was requested (primary, as always)", async () => {
    const screenShare = makeScreenShare();
    await requestShot(screenShare);
    expect(screenShare.capture).toHaveBeenCalledWith({ display: undefined });
  });

  it.each([
    ["denied", /does not have the Screen Recording permission/],
    ["not-determined", /has not yet been asked for the Screen Recording permission/],
    ["restricted", /restricted on this machine/],
  ])("refuses to capture when the OS permission is %s", async (osPermission, expected) => {
    const screenShare = makeScreenShare({ osPermission });
    const sent = await requestShot(screenShare);
    const error = sent.find((m) => m.type === "agent:screenshot_error");
    expect(error.error).toMatch(expected);
    expect(error.error).toMatch(/System Settings/);
    // The point of the guard: no capture is attempted, so there is no black
    // image and no hang waiting on a prompt nobody can answer.
    expect(screenShare.capture).not.toHaveBeenCalled();
  });

  it("refuses when the grant landed after this process started", async () => {
    // macOS gives an app Screen Recording at launch; capturing here would return a
    // black image the caller would describe as if it were the screen.
    const screenShare = makeScreenShare({ osPermission: "granted-pending-restart" });
    const sent = await requestShot(screenShare);
    const error = sent.find((m) => m.type === "agent:screenshot_error");
    expect(error.error).toMatch(/granted after the app started/);
    expect(error.error).toMatch(/quit and reopen AI Commander/);
    expect(error.error).toMatch(/retrying before that changes nothing/i);
    expect(screenShare.capture).not.toHaveBeenCalled();
  });

  it.each(["granted", "unknown", undefined])(
    "still captures when the OS permission is %s",
    async (osPermission) => {
      // "unknown" is a failed QUERY, not a denial, and an older agent reports
      // nothing at all — neither may be turned into a blocker.
      const screenShare = makeScreenShare(
        osPermission === undefined ? {} : { osPermission },
      );
      const sent = await requestShot(screenShare);
      expect(screenShare.capture).toHaveBeenCalled();
      expect(sent.some((m) => m.type === "agent:screenshot_done")).toBe(true);
    },
  );

  it("reports the OS permission in agent:register", async () => {
    const screenShare = makeScreenShare({ osPermission: "denied" });
    const { ws } = await connect({ screenShare });
    ws._emit("open");
    await new Promise((r) => setTimeout(r, 0));
    const register = JSON.parse(ws.sent[0]!);
    expect(register.screenShare.osPermission).toBe("denied");
    ws.close(1000, "ok");
  });

  it("pushes a permission transition as agent:screen_state", async () => {
    // The relay caches this state; without the re-emit a machine stays reported
    // as unusable long after the human finally ticked the box.
    const screenShare = makeScreenShare({ osPermission: "not-determined" });
    const { ws } = await connect({ screenShare });
    ws._emit("open");
    await new Promise((r) => setTimeout(r, 0));

    const onChange = screenShare.on.mock.calls.find((c) => c[0] === "change")![1] as () => void;
    screenShare.getState.mockReturnValue({
      capable: true,
      enabled: true,
      expiresAt: Date.now() + 60_000,
      osPermission: "granted",
    });
    onChange();
    await new Promise((r) => setTimeout(r, 0));

    const push = ws.sent.map((s) => JSON.parse(s)).find((m) => m.type === "agent:screen_state");
    expect(push.screenShare.osPermission).toBe("granted");
    ws.close(1000, "ok");
  });
});
