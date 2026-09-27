import { afterEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { JobManager } from "../job-manager.js";
import { JobStateReporter, lazyRunningJobCount } from "../job-state-reporter.js";
import { readProcIdentity } from "../proc-identity.js";
import { JobStore } from "../job-store.js";
import type { JobMeta } from "../job-types.js";

// Wrap the real probe so tests can prove the telemetry count never calls it.
vi.mock("../proc-identity.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../proc-identity.js")>();
  return { ...actual, readProcIdentity: vi.fn(actual.readProcIdentity) };
});

afterEach(() => {
  vi.useRealTimers();
});

describe("JobStateReporter", () => {
  it("sends on start even when unchanged, then only on change, and never garbage", async () => {
    vi.useFakeTimers();
    let count: number | null = 0;
    const sent: number[] = [];
    const r = new JobStateReporter({ count: () => count, send: (n) => sent.push(n), debounceMs: 10 });
    r.start();
    await vi.advanceTimersByTimeAsync(20);
    r.schedule();
    await vi.advanceTimersByTimeAsync(20);
    expect(sent).toEqual([0]);
    // A reconnect's start() re-sends the same value: the relay's snapshot is fresh.
    r.start();
    await vi.advanceTimersByTimeAsync(20);
    expect(sent).toEqual([0, 0]);
    count = null; // could not count: not news
    r.schedule();
    await vi.advanceTimersByTimeAsync(20);
    count = -3; // never on the wire
    r.schedule();
    await vi.advanceTimersByTimeAsync(20);
    expect(sent).toEqual([0, 0]);
    r.stop();
  });

  it("coalesces a burst into one recount and stops cleanly", async () => {
    vi.useFakeTimers();
    const count = vi.fn(() => 3);
    const sent: number[] = [];
    const r = new JobStateReporter({ count, send: (n) => sent.push(n), debounceMs: 10, pollMs: 1_000 });
    r.schedule();
    r.schedule();
    r.schedule();
    await vi.advanceTimersByTimeAsync(20);
    expect(count).toHaveBeenCalledTimes(1);
    expect(sent).toEqual([3]);
    r.stop();
    await vi.advanceTimersByTimeAsync(5_000);
    expect(count).toHaveBeenCalledTimes(1);
  });
});

describe("lazyRunningJobCount", () => {
  it("answers 0 without touching anything when no jobs directory exists", () => {
    const root = path.join(os.tmpdir(), "aic-no-such-dir-xyz");
    expect(lazyRunningJobCount(null, () => root)).toBe(0);
    expect(fs.existsSync(root)).toBe(false);
  });

  it("counts records on disk WITHOUT creating a manager, recovering, or probing", () => {
    const jobsRoot = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "aic-jobstate-")), "jobs");
    const store = new JobStore(jobsRoot);
    store.ensureRoot();
    const meta = (jobId: string, status: JobMeta["status"], pid: number | null): JobMeta => ({
      v: 1, jobId, name: jobId, command: "x", cwd: "/", status, exitCode: null,
      startedAt: Date.now(), endedAt: null, gpuIndex: null, pid, procIdentity: "stale", truncatedAt: null,
    });
    const write = (m: JobMeta) => { store.ensureJobDirs(m.jobId); expect(store.writeMeta(m)).toBe(true); };
    write(meta("0000000000000001", "running", process.pid)); // alive -> counted
    write(meta("0000000000000002", "running", process.pid)); // exit marker -> not counted
    fs.writeFileSync(store.exitPath("0000000000000002"), "0");
    write(meta("0000000000000003", "running", 2 ** 22 + 12345)); // ESRCH -> not counted
    write(meta("0000000000000004", "exited", process.pid)); // terminal -> not counted
    write(meta("0000000000000005", "running", null)); // no pid -> not counted

    const recover = vi.spyOn(JobManager.prototype, "recover");
    vi.mocked(readProcIdentity).mockClear();
    try {
      expect(lazyRunningJobCount(null, () => jobsRoot)).toBe(1);
      expect(recover).not.toHaveBeenCalled();
      expect(readProcIdentity).not.toHaveBeenCalled();
      // Records are left exactly as they were (nothing settled).
      expect(store.readMeta("0000000000000003")?.status).toBe("running");
    } finally {
      recover.mockRestore();
    }
  });

  it("asks an existing manager instead of reading disk", () => {
    const existing = { runningJobCount: vi.fn(() => 7) };
    expect(lazyRunningJobCount(existing as never, () => { throw new Error("must not resolve root"); })).toBe(7);
  });
});

describe.skipIf(process.platform === "win32")("JobManager running-change notifications", () => {
  it("notifies on start and on exit, and the count follows", async () => {
    const jobsRoot = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "aic-jobstate-")), "jobs");
    const manager = new JobManager({ jobsRoot });
    const listener = vi.fn();
    const off = manager.onRunningJobsChange(listener);
    const started = await manager.start({ command: "sleep 0.3" });
    expect(started.ok).toBe(true);
    expect(listener).toHaveBeenCalled();
    expect(manager.runningJobCount()).toBe(1);
    listener.mockClear();
    const deadline = Date.now() + 5_000;
    while (manager.runningJobCount() !== 0) {
      if (Date.now() > deadline) throw new Error("job never exited");
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(listener).toHaveBeenCalled();
    off();
  });

  it("notifies on cancel", async () => {
    const jobsRoot = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "aic-jobstate-")), "jobs");
    const manager = new JobManager({ jobsRoot });
    const started = await manager.start({ command: "sleep 30" });
    if (!started.ok || started.kind !== "job") throw new Error("start failed");
    const listener = vi.fn();
    manager.onRunningJobsChange(listener);
    manager.cancel({ jobId: started.job.jobId });
    const deadline = Date.now() + 10_000;
    // The count is probe-free and may reach 0 before the settle notification.
    while (manager.runningJobCount() !== 0 || listener.mock.calls.length === 0) {
      if (Date.now() > deadline) throw new Error("cancelled job never settled");
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(listener).toHaveBeenCalled();
  });
});

describe.skipIf(process.platform === "win32")("runningJobCount never probes synchronously", () => {
  it("counts a live job without readProcIdentity", async () => {
    const jobsRoot = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "aic-jobstate-")), "jobs");
    const manager = new JobManager({ jobsRoot });
    const started = await manager.start({ command: "sleep 30" });
    if (!started.ok || started.kind !== "job") throw new Error("start failed");
    vi.mocked(readProcIdentity).mockClear();
    expect(manager.runningJobCount()).toBe(1);
    expect(readProcIdentity).not.toHaveBeenCalled();
    manager.cancel({ jobId: started.job.jobId });
  });

  it("converges to 0 for a recovered job (no exit callback) without probing", async () => {
    const jobsRoot = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "aic-jobstate-")), "jobs");
    const first = new JobManager({ jobsRoot });
    const started = await first.start({ command: "sleep 0.3" });
    expect(started.ok).toBe(true);
    // A second manager over the same root has no child handle: like a restart.
    const recovered = new JobManager({ jobsRoot });
    vi.mocked(readProcIdentity).mockClear();
    const deadline = Date.now() + 5_000;
    while (recovered.runningJobCount() !== 0) {
      if (Date.now() > deadline) throw new Error("count never converged");
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(readProcIdentity).not.toHaveBeenCalled();
  });
});
