// What the diagnostic log says about jobs, and what it refuses to say.
//
// Two questions the incident could not answer from the file: did a job START,
// and if it did not, WHY. A start that returns a refusal was recorded; a start
// that THROWS — which is what `job_script_removed` is, the antivirus taking the
// job's scripts between our write and the spawn — reached the relay and nothing
// else. The remote caller learned what happened, the file meant to be attached
// to the vendor submission did not.
//
// And one thing the log must never say: a relay frame's `jobId` verbatim. It is
// untrusted input on a line bound for someone else's inbox.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

interface MockWSInstance {
  sent: string[];
  _emit: (event: string, ...args: unknown[]) => void;
  close: (code: number, reason: string) => void;
}

vi.mock("ws", () => {
  const instances: MockWS[] = [];
  class MockWS {
    _handlers: Record<string, ((...args: unknown[]) => void)[]> = {};
    sent: string[] = [];
    constructor(public url: string, public options?: unknown) {
      instances.push(this);
    }
    on(event: string, cb: (...args: unknown[]) => void) {
      (this._handlers[event] ??= []).push(cb);
    }
    send(data: string) {
      this.sent.push(data);
    }
    terminate() {
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
vi.mock("../gpu.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../gpu.js")>()),
  probeGpuState: vi.fn(async () => ({ certainty: "unknown" })),
}));
vi.mock("../login-shell-path.js", () => ({
  startLoginShellPathProbe: vi.fn(async () => null),
  pendingLoginShellPath: vi.fn(() => null),
}));
vi.mock("../job-scope.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../job-scope.js")>()),
  startJobScopeProbe: vi.fn(async () => null),
  pendingJobScope: vi.fn(() => null),
}));
vi.mock("../installed-version.js", () => ({
  startInstalledVersionProbe: vi.fn(async () => undefined),
  installedVersionSnapshot: vi.fn(() => undefined),
}));
vi.mock("../elevated-executor.js", () => ({
  executeElevatedCommand: vi.fn(),
}));
// No privileged helper, stated as the reason rather than as silence — this suite
// is about job logging, so it just needs the register path to settle.
vi.mock("../elevated-availability.js", () => ({
  resolveElevatedAvailability: vi.fn(async () => ({
    available: false as const,
    reason: "platform_unsupported" as const,
  })),
  // The synchronous half the open-time register carries; nothing here turns on it.
  staticElevatedUnavailableReason: vi.fn(() => undefined),
}));
vi.mock("../file-transfer.js", () => ({
  pullFileToRelay: vi.fn(),
  pushFileFromRelay: vi.fn(),
}));

// The manager itself is covered in its own suites; what is under test here is
// the wiring between a start's OUTCOME and the line the log gets.
const jobs = vi.hoisted(() => ({
  start: null as null | (() => unknown),
  cancel: vi.fn(() => ({ ok: true, kind: "job", job: { jobId: "0123456789abcdef" } })),
}));
vi.mock("../job-manager.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../job-manager.js")>();
  return {
    ...actual,
    getJobManager: vi.fn(() => ({
      setKnownGpus: vi.fn(),
      start: vi.fn(async () => jobs.start?.()),
      list: vi.fn(),
      status: vi.fn(),
      logs: vi.fn(),
      cancel: jobs.cancel,
    })),
  };
});

import * as WsMod from "ws";
import { JOB_SCRIPT_REMOVED_ERROR } from "@aicommander/protocol";
import { JobError } from "../job-manager.js";
import { jobScriptRemovedMessage } from "../job-scripts.js";
import { runConnectionLoop } from "../connection.js";
import { closeDiagLog, initDiagLog } from "../diag-log.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const wsInstances: MockWSInstance[] = (WsMod as any).__instances;

let dir: string;
let ac: AbortController;
let loop: Promise<void>;

/**
 * Wait for one event to reach the file, then hand back everything in it.
 *
 * Nothing here flushes: the queue's own `setTimeout(…, 0)` is what production
 * relies on, so it is what these assertions wait for. The frame handler is
 * asynchronous (it awaits the PATH and scope probes before it starts a job), so
 * the wait polls rather than assuming one macrotask is enough.
 */
async function logText(event: string): Promise<string> {
  const file = path.join(dir, "worker.log");
  for (let i = 0; i < 100; i++) {
    await new Promise((resolve) => setTimeout(resolve, 5));
    try {
      const text = fs.readFileSync(file, "utf8");
      if (text.includes(event)) return text;
    } catch {
      // Not written yet.
    }
  }
  try {
    return fs.readFileSync(file, "utf8");
  } catch {
    return "";
  }
}

async function connect(): Promise<MockWSInstance> {
  ac = new AbortController();
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ ticket: "a".repeat(64) }),
      text: async () => "",
    })),
  );
  loop = runConnectionLoop({
    serverUrl: "https://aic-diag.test",
    sessionCode: "AIC-7K3P-WX9M-RTBN",
    agentToken: "b".repeat(48),
    signal: ac.signal,
    silent: true,
  });
  for (let i = 0; i < 12; i++) await Promise.resolve();
  const ws = wsInstances[wsInstances.length - 1]!;
  ws._emit("open");
  await new Promise((resolve) => setTimeout(resolve, 0));
  return ws;
}

beforeEach(() => {
  wsInstances.length = 0;
  jobs.start = null;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-diag-jobs-"));
  initDiagLog({ dir, role: "worker" });
  vi.spyOn(console, "log").mockImplementation(() => undefined);
  vi.spyOn(console, "error").mockImplementation(() => undefined);
});

afterEach(async () => {
  ac.abort();
  await loop.catch(() => undefined);
  closeDiagLog();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("the diagnostic log ↔ job wiring", () => {
  it("records a start that threw, with its cause and our own detail", async () => {
    const detail = "wrapper.cmd is gone";
    jobs.start = () => {
      throw new JobError(jobScriptRemovedMessage(detail), JOB_SCRIPT_REMOVED_ERROR, detail);
    };
    const ws = await connect();

    ws._emit(
      "message",
      JSON.stringify({ type: "do:job_start", requestId: "req-1", command: "python train.py" }),
    );
    const text = await logText("job.start_failed");

    expect(text).toContain("job.start_failed");
    expect(text).toContain(`code=${JOB_SCRIPT_REMOVED_ERROR}`);
    expect(text).toContain("wrapper.cmd is gone");
    // The caller is still told, in full — the log is the second record, never a
    // replacement for the reply.
    const reply = ws.sent.map((s) => JSON.parse(s)).find((m) => m.requestId === "req-1");
    expect(reply.type).toBe("agent:job_error");
    expect(reply.error).toContain(JOB_SCRIPT_REMOVED_ERROR);
    // …and the caller's command never reaches the file.
    expect(text).not.toContain("train.py");
  });

  it("does not claim a start for a job that was cancelled before it could run", async () => {
    // A cancel that lands inside the record→pid window is answered `ok` with a
    // TERMINAL job — the `unknown` the cancel settled it as — and no process of
    // that job ever existed. Logged as `job.start`, the file that goes to the
    // antivirus vendor asserted that a command started on a machine that can
    // prove none did.
    jobs.start = () => ({
      ok: true,
      kind: "job",
      job: { jobId: "0123456789abcdef", status: "unknown", exitCode: null, endedAt: Date.now() },
    });
    const ws = await connect();

    ws._emit(
      "message",
      JSON.stringify({ type: "do:job_start", requestId: "req-5", command: "python train.py" }),
    );
    // The reply still goes back in full: the caller learns its job is over.
    const reply = await (async () => {
      for (let i = 0; i < 100; i++) {
        await new Promise((resolve) => setTimeout(resolve, 5));
        const found = ws.sent.map((sent) => JSON.parse(sent)).find((msg) => msg.requestId === "req-5");
        if (found) return found;
      }
      return null;
    })();
    expect(reply?.type).toBe("agent:job_result");
    // And by then the log has had every chance to write the line it must not.
    const text = await logText("never-written");
    expect(text).not.toContain("job.start ");
  });

  it("records an unclassified start failure as an errno, never as a message", async () => {
    jobs.start = () => {
      const err: NodeJS.ErrnoException = new Error("ENOSPC: no space left on /home/alicja/jobs");
      err.code = "ENOSPC";
      err.syscall = "write";
      throw err;
    };
    const ws = await connect();

    ws._emit(
      "message",
      JSON.stringify({ type: "do:job_start", requestId: "req-2", command: "printf x" }),
    );
    const text = await logText("job.start_failed");

    expect(text).toContain("job.start_failed code=ENOSPC syscall=write");
    expect(text).not.toContain("alicja");
  });

  it("never writes an unvalidated jobId from a relay frame", async () => {
    const ws = await connect();

    ws._emit(
      "message",
      JSON.stringify({
        type: "do:job_cancel",
        requestId: "req-3",
        jobId: "; rm -rf /home/alicja #",
      }),
    );
    const text = await logText("job.cancel");

    expect(text).toContain("job.cancel jobId=invalid");
    expect(text).not.toContain("rm -rf");
    expect(text).not.toContain("alicja");
  });

  it("writes a real job id as itself", async () => {
    const ws = await connect();

    ws._emit(
      "message",
      JSON.stringify({ type: "do:job_cancel", requestId: "req-4", jobId: "0123456789abcdef" }),
    );

    expect(await logText("job.cancel")).toContain("job.cancel jobId=0123456789abcdef");
  });
});
