import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  JOB_ENDED_REPLAY_MAX,
  JOB_ENDED_RETRY_BASE_MS,
  JOB_ENDED_RETRY_MAX_MS,
  type AgentJobEndedMsg,
} from "@aicommander/protocol";
import { getJobManager, JobManager, resetJobManagerForTests } from "../job-manager.js";
import { JobEndedReporter, jobEndedRetryDelay } from "../job-ended-reporter.js";
import { STORE_ONLY_START_GRACE_MS } from "../job-ended-settle.js";
import { JobStore } from "../job-store.js";
import type { JobMeta } from "../job-types.js";
import { readProcIdentity } from "../proc-identity.js";

// Wrap the real probe so tests can prove the cheap path never calls it.
vi.mock("../proc-identity.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../proc-identity.js")>();
  return { ...actual, readProcIdentity: vi.fn(actual.readProcIdentity) };
});

const HOOK = "0123456789abcdef0123456789abcdef";
const hook = (n: number) => n.toString(16).padStart(32, "0");
const jid = (n: number) => n.toString(16).padStart(16, "0");

let jobsRoot: string;
let store: JobStore;

beforeEach(() => {
  jobsRoot = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "aic-jobended-")), "jobs");
  store = new JobStore(jobsRoot);
  store.ensureRoot();
  vi.mocked(readProcIdentity).mockClear();
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

function seed(over: Partial<JobMeta> & { jobId: string }): JobMeta {
  const meta: JobMeta = {
    v: 1, name: over.jobId, command: "x", cwd: "/", status: "running", exitCode: null,
    startedAt: 1_000, endedAt: null, gpuIndex: null, pid: null, procIdentity: null, truncatedAt: null,
    ...over,
  };
  store.ensureJobDirs(meta.jobId);
  expect(store.writeMeta(meta)).toBe(true);
  return meta;
}

function deadPid(): number {
  const pid = spawnSync(process.execPath, ["-e", ""]).pid;
  if (typeof pid !== "number") throw new Error("no pid");
  return pid;
}

function writeExit(jobId: string, code: number): void {
  fs.writeFileSync(store.exitPath(jobId), String(code));
}

function reporter(manager: () => JobManager | null = () => null, extra: Partial<ConstructorParameters<typeof JobEndedReporter>[0]> = {}) {
  const sent: AgentJobEndedMsg[] = [];
  const r = new JobEndedReporter({ manager, jobsRoot: () => jobsRoot, send: (m) => sent.push(m), ...extra });
  return { r, sent };
}

async function waitFor(what: string, predicate: () => boolean, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (predicate()) return;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

describe("settle() of a webhook job", () => {
  it("writes endedUnacked WITH the terminal state and sends exactly one event (instant job)", async () => {
    const manager = new JobManager({ jobsRoot, scopeLauncher: () => null });
    const { r, sent } = reporter(() => manager);
    const atSettle: JobMeta[] = [];
    // Read disk inside the settle notification, before any send: a crash here
    // must already find the flag next to the terminal state.
    manager.onJobEnded((m) => { atSettle.push(store.readMeta(m.jobId)!); r.onSettled(); });
    const res = await manager.start({ command: "exit 3", webhookId: HOOK });
    if (!res.ok || res.kind !== "job") throw new Error("start failed");
    await waitFor("event", () => sent.length > 0);
    expect(atSettle).toHaveLength(1);
    expect(atSettle[0]).toMatchObject({ status: "exited", exitCode: 3, endedUnacked: true, webhookId: HOOK });
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(sent).toEqual([
      { type: "agent:job_ended", webhookId: HOOK, jobId: res.job.jobId, status: "exited", exitCode: 3, endedAt: atSettle[0]!.endedAt },
    ]);
    r.ack(HOOK);
    expect(store.readMeta(res.job.jobId)!.endedUnacked).toBeUndefined();
    r.stop();
  });

  it("does nothing for jobs without (or with an invalid) webhookId", async () => {
    const manager = new JobManager({ jobsRoot, scopeLauncher: () => null });
    const ended = vi.fn();
    manager.onJobEnded(ended);
    const ids: string[] = [];
    for (const webhookId of [undefined, "NOT-A-HOOK"]) {
      const res = await manager.start({ command: "exit 0", ...(webhookId ? { webhookId } : {}) });
      if (!res.ok || res.kind !== "job") throw new Error("start failed");
      ids.push(res.job.jobId);
    }
    await waitFor("settle", () => ids.every((id) => manager.status({ jobId: id }).ok && store.readMeta(id)!.status !== "running"));
    for (const id of ids) {
      const meta = store.readMeta(id)!;
      expect(meta.webhookId).toBeUndefined();
      expect(meta.endedUnacked).toBeUndefined();
    }
    expect(ended).not.toHaveBeenCalled();
    const { r, sent } = reporter(() => manager);
    r.start();
    expect(sent).toEqual([]);
    r.stop();
  });
});

describe("replay", () => {
  it("replays on every connect until acked; ack is idempotent and ignores unknown ids", () => {
    seed({ jobId: jid(1), status: "unknown", endedAt: 5_000, endedAtApproximate: true, webhookId: HOOK, endedUnacked: true });
    const a = reporter();
    a.r.start();
    a.r.stop();
    expect(a.sent).toEqual([
      { type: "agent:job_ended", webhookId: HOOK, jobId: jid(1), status: "unknown", exitCode: null, endedAt: 5_000, endedAtApproximate: true },
    ]);
    const b = reporter();
    b.r.start();
    expect(b.sent).toHaveLength(1);
    b.r.ack(hook(999)); // unknown: no-op
    b.r.ack("garbage");
    expect(store.readMeta(jid(1))!.endedUnacked).toBe(true);
    b.r.ack(HOOK);
    b.r.ack(HOOK);
    b.r.stop();
    const c = reporter();
    c.r.start();
    expect(c.sent).toEqual([]);
    c.r.stop();
  });

  it("caps the replay at the newest JOB_ENDED_REPLAY_MAX and un-flags older ones", () => {
    const total = JOB_ENDED_REPLAY_MAX + 5;
    for (let i = 1; i <= total; i++) {
      seed({ jobId: jid(i), status: "exited", exitCode: 0, endedAt: 10_000 + i, webhookId: hook(i), endedUnacked: true });
    }
    const { r, sent } = reporter();
    r.start();
    r.stop();
    expect(sent).toHaveLength(JOB_ENDED_REPLAY_MAX);
    expect(sent[0]!.jobId).toBe(jid(total));
    for (let i = 1; i <= 5; i++) expect(store.readMeta(jid(i))!.endedUnacked).toBeUndefined();
    for (let i = 6; i <= total; i++) expect(store.readMeta(jid(i))!.endedUnacked).toBe(true);
  });

  it("backs off exponentially, capped, and stops when nothing is pending", async () => {
    vi.useFakeTimers();
    seed({ jobId: jid(1), status: "exited", exitCode: 1, endedAt: 5_000, webhookId: HOOK, endedUnacked: true });
    const { r, sent } = reporter(() => null, { random: () => 0, baseMs: 1_000, maxMs: 4_000 });
    r.start();
    expect(sent).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(999);
    expect(sent).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1); // +1000
    expect(sent).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(sent).toHaveLength(3);
    await vi.advanceTimersByTimeAsync(4_000);
    expect(sent).toHaveLength(4);
    await vi.advanceTimersByTimeAsync(4_000); // capped
    expect(sent).toHaveLength(5);
    r.ack(HOOK);
    await vi.advanceTimersByTimeAsync(4_000); // one last empty cycle, then no timer
    expect(vi.getTimerCount()).toBe(0);
    expect(sent).toHaveLength(5);
    r.stop();
  });

  it("jitter stays within [(1-J)·d, d] and the delay never exceeds the cap", () => {
    expect(jobEndedRetryDelay(0, () => 0)).toBe(JOB_ENDED_RETRY_BASE_MS);
    expect(jobEndedRetryDelay(0, () => 1)).toBe(JOB_ENDED_RETRY_BASE_MS * 0.8);
    expect(jobEndedRetryDelay(1, () => 0)).toBe(JOB_ENDED_RETRY_BASE_MS * 2);
    expect(jobEndedRetryDelay(50, () => 0)).toBe(JOB_ENDED_RETRY_MAX_MS);
    for (let i = 0; i < 100; i++) {
      const d = jobEndedRetryDelay(i % 12, Math.random);
      expect(d).toBeGreaterThanOrEqual(JOB_ENDED_RETRY_BASE_MS * 0.8);
      expect(d).toBeLessThanOrEqual(JOB_ENDED_RETRY_MAX_MS);
    }
  });
});

describe("cheap settle path (no RPC, no manager, no probe)", () => {
  it("restart scenario: the job ends after the restart and the event still goes out", () => {
    // Left by a previous agent process: running, webhook armed, process alive.
    seed({ jobId: jid(1), pid: process.pid, procIdentity: "stale", webhookId: HOOK });
    const { r, sent } = reporter();
    r.start();
    expect(sent).toEqual([]);
    expect(store.readMeta(jid(1))!.status).toBe("running"); // alive pid: untouched
    writeExit(jid(1), 7);
    r.poke(); // the agent:job_state recount
    expect(sent).toMatchObject([{ jobId: jid(1), status: "exited", exitCode: 7, webhookId: HOOK }]);
    expect(store.readMeta(jid(1))).toMatchObject({ status: "exited", exitCode: 7, endedUnacked: true });
    expect(readProcIdentity).not.toHaveBeenCalled();
    r.stop();
  });

  it("ESRCH with a marker appearing at the re-read settles as exited, not unknown", () => {
    seed({ jobId: jid(1), pid: deadPid(), webhookId: HOOK });
    const real = JobStore.prototype.readExit;
    let calls = 0;
    vi.spyOn(JobStore.prototype, "readExit").mockImplementation(function (this: JobStore, id: string) {
      calls++;
      if (calls === 1) return null; // the first look: the wrapper had not written it yet
      writeExit(id, 4);
      return real.call(this, id);
    });
    const { r, sent } = reporter();
    r.poke();
    r.stop();
    expect(sent).toMatchObject([{ status: "exited", exitCode: 4 }]);
  });

  it("ESRCH and no marker settles as unknown with an approximate end", () => {
    seed({ jobId: jid(1), pid: deadPid(), webhookId: HOOK });
    seed({ jobId: jid(2), pid: deadPid() }); // no webhook: not this path's business
    const { r, sent } = reporter();
    r.poke();
    r.stop();
    expect(sent).toEqual([
      expect.objectContaining({ jobId: jid(1), status: "unknown", exitCode: null, endedAtApproximate: true }),
    ]);
    expect(store.readMeta(jid(1))).toMatchObject({ status: "unknown", unknownReason: "undetermined", endedUnacked: true });
    expect(store.readMeta(jid(2))!.status).toBe("running");
  });

  it("with an un-recovered manager, settles through it without the identity probe", () => {
    seed({ jobId: jid(1), pid: deadPid(), procIdentity: "stale", webhookId: HOOK });
    const manager = new JobManager({ jobsRoot, scopeLauncher: () => null });
    const { r, sent } = reporter(() => manager);
    manager.onJobEnded(() => r.onSettled());
    r.poke();
    r.stop();
    expect(sent).toHaveLength(1);
    expect(store.readMeta(jid(1))).toMatchObject({ status: "unknown", endedUnacked: true });
    expect(readProcIdentity).not.toHaveBeenCalled();
  });
});

describe("retiring records (abandoned starts)", () => {
  it("store-only path discards a retiring record like discardRetired: no event, no endedUnacked", () => {
    // Left by a previous agent that crashed mid-retire: no exit marker, pid gone.
    seed({ jobId: jid(1), pid: deadPid(), webhookId: HOOK, retiring: true });
    const { r, sent } = reporter();
    r.start();
    r.poke();
    r.stop();
    expect(sent).toEqual([]);
    expect(store.readMeta(jid(1))).toBeNull();
    expect(fs.existsSync(path.join(jobsRoot, jid(1)))).toBe(false);
  });

  it("the manager path discards the same record the same way", () => {
    seed({ jobId: jid(1), pid: deadPid(), webhookId: HOOK, retiring: true });
    const manager = new JobManager({ jobsRoot, scopeLauncher: () => null });
    const { r, sent } = reporter(() => manager);
    r.attach(manager);
    r.poke();
    r.stop();
    expect(sent).toEqual([]);
    expect(store.readMeta(jid(1))).toBeNull();
  });
});

describe("poke cost and connect", () => {
  it("does no disk reads on recounts once a pass found nothing pending", () => {
    seed({ jobId: jid(1), pid: deadPid() }); // a non-webhook job
    const list = vi.spyOn(JobStore.prototype, "listJobIds");
    const read = vi.spyOn(JobStore.prototype, "readMeta");
    const { r, sent } = reporter();
    r.start();
    expect(list).toHaveBeenCalledTimes(1);
    list.mockClear();
    read.mockClear();
    for (let i = 0; i < 5; i++) r.poke();
    expect(list).not.toHaveBeenCalled();
    expect(read).not.toHaveBeenCalled();
    // A webhook job starting re-enables the scan.
    seed({ jobId: jid(2), pid: deadPid(), webhookId: HOOK });
    r.noteWebhookJob();
    r.poke();
    expect(list).toHaveBeenCalledTimes(1);
    expect(sent).toMatchObject([{ jobId: jid(2) }]);
    r.stop();
  });

  it("one directory pass per poke when records are pending", () => {
    seed({ jobId: jid(1), pid: process.pid, webhookId: HOOK });
    const list = vi.spyOn(JobStore.prototype, "listJobIds");
    const metas = vi.spyOn(JobStore.prototype, "listMetas");
    const { r } = reporter();
    r.poke();
    r.poke();
    r.stop();
    expect(list).toHaveBeenCalledTimes(2);
    expect(metas).not.toHaveBeenCalled();
  });

  it("a recount right before start() does not send the same event twice", () => {
    seed({ jobId: jid(1), status: "exited", exitCode: 0, endedAt: 2_000, webhookId: HOOK, endedUnacked: true });
    const { r, sent } = reporter();
    r.poke(); // jobState.start() → count() → poke()
    r.start(); // then jobEnded.start()
    r.stop();
    expect(sent).toHaveLength(1);
  });
});

describe("review fixes", () => {
  it("reconnect: a new connection uses the live singleton's start/retire windows (no premature event, no re-flag)", () => {
    vi.stubEnv("AICOMMANDER_CONFIG_DIR", path.dirname(jobsRoot));
    resetJobManagerForTests();
    try {
      const singleton = getJobManager();
      expect(singleton.jobsRoot).toBe(jobsRoot);
      // Seeded after recover(): old, pid-less (would look "vanished") and retiring.
      seed({ jobId: jid(1), pid: null, webhookId: hook(1) });
      seed({ jobId: jid(2), pid: deadPid(), webhookId: hook(2), retiring: true });
      const internals = singleton as unknown as { startingJobs: Map<string, unknown>; retiringJobs: Set<string> };
      internals.startingJobs.set(jid(1), { abort: null, erasing: false });
      internals.retiringJobs.add(jid(2));
      // The new connection's per-connection cache is still null.
      const { r, sent } = reporter(() => null);
      r.start();
      r.poke();
      r.stop();
      expect(sent).toEqual([]);
      expect(store.readMeta(jid(1))).toMatchObject({ status: "running" });
      expect(store.readMeta(jid(1))!.endedUnacked).toBeUndefined();
      expect(fs.existsSync(path.join(jobsRoot, jid(2)))).toBe(true);
      expect(store.readMeta(jid(2))!.endedUnacked).toBeUndefined();
    } finally {
      resetJobManagerForTests();
      vi.unstubAllEnvs();
    }
  });

  it("store-only path leaves a pid-less record in its start grace alone, settles an old one", () => {
    seed({ jobId: jid(1), pid: null, webhookId: hook(1), startedAt: Date.now() });
    seed({ jobId: jid(2), pid: null, webhookId: hook(2), startedAt: Date.now() - STORE_ONLY_START_GRACE_MS - 1 });
    const { r, sent } = reporter();
    r.start();
    r.stop();
    expect(sent.map((m) => m.jobId)).toEqual([jid(2)]);
    expect(store.readMeta(jid(1))).toMatchObject({ status: "running" });
  });

  it("a steady stream of new events never postpones the replay of an older unacked one", async () => {
    vi.useFakeTimers();
    const A = hook(0xa);
    seed({ jobId: jid(0xa), status: "exited", exitCode: 0, endedAt: 1_000, webhookId: A, endedUnacked: true });
    const { r, sent } = reporter(() => null, { random: () => 0 });
    r.start();
    for (let i = 1; i <= 20; i++) {
      await vi.advanceTimersByTimeAsync(30_000);
      seed({ jobId: jid(0x100 + i), status: "exited", exitCode: 0, endedAt: 2_000 + i, webhookId: hook(0x100 + i), endedUnacked: true });
      r.onSettled();
      await vi.advanceTimersByTimeAsync(0);
    }
    r.stop();
    // Sent at connect, then at BASE, 3·BASE and 7·BASE (60 s, 180 s, 420 s) within 10 minutes.
    expect(JOB_ENDED_RETRY_BASE_MS).toBe(60_000);
    expect(sent.filter((m) => m.webhookId === A)).toHaveLength(4);
  });

  it("ack reads and writes only the one acked record, never the whole store", () => {
    for (let i = 1; i <= JOB_ENDED_REPLAY_MAX; i++) {
      seed({ jobId: jid(i), status: "exited", exitCode: 0, endedAt: 1_000 + i, webhookId: hook(i), endedUnacked: true });
    }
    const { r, sent } = reporter();
    r.start();
    expect(sent).toHaveLength(JOB_ENDED_REPLAY_MAX);
    const metas = vi.spyOn(JobStore.prototype, "listMetas");
    const ids = vi.spyOn(JobStore.prototype, "listJobIds");
    const read = vi.spyOn(JobStore.prototype, "readMeta");
    const write = vi.spyOn(JobStore.prototype, "writeMeta");
    for (let i = 1; i <= JOB_ENDED_REPLAY_MAX; i++) r.ack(hook(i));
    r.ack(hook(0xfff)); // unknown: no-op, no disk
    for (let i = 1; i <= JOB_ENDED_REPLAY_MAX; i++) r.ack(hook(i)); // repeated: no-op
    r.stop();
    expect(metas).not.toHaveBeenCalled();
    expect(ids).not.toHaveBeenCalled();
    expect(read).toHaveBeenCalledTimes(JOB_ENDED_REPLAY_MAX);
    expect(write).toHaveBeenCalledTimes(JOB_ENDED_REPLAY_MAX);
    for (let i = 1; i <= JOB_ENDED_REPLAY_MAX; i++) expect(store.readMeta(jid(i))!.endedUnacked).toBeUndefined();
  });
});
