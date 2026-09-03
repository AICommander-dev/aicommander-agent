import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  JOB_ID_PATTERN,
  JOB_LIST_DEFAULT_ENTRIES,
  JOB_WIRE_MAX_LIST_ENTRIES,
} from "@aicommander/protocol";
import type { GpuDevice, JobRpcResult, JobStatus, JobSummary } from "@aicommander/protocol";
import { JobManager } from "../job-manager.js";

/**
 * The three job_start / job_list properties that are about WHAT WE TELL THE
 * CALLER rather than about running a process: which gpuIndex this machine will
 * accept, how much history one list reply carries, and how honest an `endedAt`
 * is. Plus the macOS PATH a job inherits, which is the same launchd problem
 * `do:exec` has.
 *
 * A separate file from job-manager.test.ts on purpose: that one is already past
 * 3000 lines. Most of what is here is seeded straight onto disk, so the state
 * machine can be driven to a branch (a vanished process, a full page) without
 * waiting for a real one to get there.
 */

/**
 * The macOS login-shell PATH probe, controllable and NEVER real: the actual one
 * spawns the developer's `zsh -l -i`, which is neither deterministic nor
 * something a unit test should wait 2 s for. `inject` is the PATH the resolved
 * probe would merge in; null keeps the production no-op ("not resolved yet").
 */
const loginShellPath = vi.hoisted(() => ({ inject: null as string | null }));
vi.mock("../login-shell-path.js", async () => {
  const actual =
    await vi.importActual<typeof import("../login-shell-path.js")>("../login-shell-path.js");
  return {
    ...actual,
    // Nothing to wait for: the memoized probe is what production defers to, and
    // a test that started it would spawn a login shell.
    pendingLoginShellPath: (): null => null,
    applyLoginShellPath: (env: NodeJS.ProcessEnv): void => {
      if (loginShellPath.inject === null) return;
      const inherited = env["PATH"] ?? "";
      env["PATH"] = inherited === "" ? loginShellPath.inject : `${loginShellPath.inject}:${inherited}`;
    },
  };
});

const describeOnPosix = describe.skipIf(process.platform === "win32");

/** A pid no live process can have, so a seeded job always reads as gone. */
const DEAD_PID = 4_194_305;

interface SeededMeta {
  v: 1;
  jobId: string;
  name: string;
  command: string;
  cwd: string;
  status: JobStatus;
  exitCode: number | null;
  startedAt: number;
  endedAt: number | null;
  endedAtApproximate?: boolean;
  gpuIndex: number | null;
  pid: number | null;
  procIdentity: string | null;
  truncatedAt: number | null;
}

let tmpBase: string;
let jobsRoot: string;
let manager: JobManager;
let startedJobs: Map<string, number>;

beforeEach(() => {
  loginShellPath.inject = null;
  tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), "aic-jobs-paging-"));
  jobsRoot = path.join(tmpBase, "jobs");
  manager = new JobManager({ jobsRoot });
  startedJobs = new Map();
});

afterEach(async () => {
  loginShellPath.inject = null;
  vi.restoreAllMocks();

  // `start()` deliberately detaches jobs, so a test ending does not mean the
  // corresponding shell (or its exit handler) has finished with the job
  // directory. Cancel every process this test actually started, then wait for
  // both the OS process and the manager's on-disk state to settle before rm.
  // Seeded records are not tracked here: several intentionally use this test
  // process' pid to model a live job and must never be signalled by teardown.
  for (const jobId of startedJobs.keys()) manager.cancel({ jobId });
  if (startedJobs.size > 0) {
    await waitFor("started jobs to stop", () =>
      [...startedJobs].every(([jobId, pid]) => {
        if (isProcessAlive(pid)) return false;
        const result = manager.status({ jobId });
        return !result.ok || result.kind !== "job" || result.job.status !== "running";
      }),
    );
    // ChildProcess exit callbacks run asynchronously after the pid disappears.
    // Drain that turn before deleting the files the callback reconciles.
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  fs.rmSync(tmpBase, { recursive: true, force: true });
});

// ── Helpers ──────────────────────────────────────────────────────────────────

function expectJob(result: JobRpcResult): JobSummary {
  if (!result.ok || result.kind !== "job") {
    throw new Error(`expected a job result, got ${JSON.stringify(result)}`);
  }
  return result.job;
}

function expectJobsReply(result: JobRpcResult): Extract<JobRpcResult, { kind: "jobs" }> {
  if (!result.ok || result.kind !== "jobs") {
    throw new Error(`expected a jobs result, got ${JSON.stringify(result)}`);
  }
  return result;
}

function expectRefusal(result: JobRpcResult): Extract<JobRpcResult, { ok: false }> {
  if (result.ok) throw new Error(`expected a refusal, got ${JSON.stringify(result)}`);
  return result;
}

/** Start a real job and retain exactly the lifecycle data teardown needs. */
async function startJob(req: Parameters<JobManager["start"]>[0]): Promise<JobSummary> {
  const job = expectJob(await manager.start(req));
  const meta = JSON.parse(
    fs.readFileSync(path.join(jobDir(job.jobId), "meta.json"), "utf8"),
  ) as { pid?: unknown };
  if (typeof meta.pid !== "number") throw new Error(`job ${job.jobId} has no recorded pid`);
  startedJobs.set(job.jobId, meta.pid);
  return job;
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

function jobDir(jobId: string): string {
  return path.join(jobsRoot, jobId);
}

function logPath(jobId: string): string {
  return path.join(jobDir(jobId), "output.log");
}

/** Write a job directory directly, so every branch here needs no real process. */
function seedJob(
  overrides: Partial<SeededMeta> & { log?: string; exit?: string } = {},
): string {
  const { log, exit, ...metaOverrides } = overrides;
  const jobId = randomBytes(8).toString("hex");
  const dir = jobDir(jobId);
  fs.mkdirSync(path.join(dir, "workspace"), { recursive: true });
  const meta: SeededMeta = {
    v: 1,
    jobId,
    name: `seeded-${jobId.slice(0, 6)}`,
    command: "seeded-command",
    cwd: path.join(dir, "workspace"),
    status: "running",
    exitCode: null,
    startedAt: Date.now() - 60_000,
    endedAt: null,
    gpuIndex: null,
    pid: DEAD_PID,
    procIdentity: null,
    truncatedAt: null,
    ...metaOverrides,
  };
  // The directory name is the id, whatever an override said.
  meta.jobId = jobId;
  fs.writeFileSync(path.join(dir, "meta.json"), JSON.stringify(meta, null, 2));
  if (log !== undefined) fs.writeFileSync(logPath(jobId), log);
  if (exit !== undefined) fs.writeFileSync(path.join(dir, "exit"), exit);
  return jobId;
}

/** An nvidia-smi row as gpu.ts would have parsed it. */
function device(index: number, name: string): GpuDevice {
  return { index, name, memoryTotalMiB: 16_384, memoryUsedMiB: 0, utilizationPct: 0 };
}

/** Read a job's log; jobs here run a real shell, so this is its output. */
function readLog(jobId: string): string {
  try {
    return fs.readFileSync(logPath(jobId), "utf8");
  } catch {
    return "";
  }
}

async function waitFor(what: string, predicate: () => boolean, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (predicate()) return;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

// ── gpuIndex against the machine's real cards ────────────────────────────────

describe("gpuIndex validation against known GPUs", () => {
  it("refuses an index the machine does not have, naming the cards it does", async () => {
    manager.setKnownGpus([device(0, "NVIDIA GeForce RTX 5080")]);

    const refusal = expectRefusal(await manager.start({ command: "printf x", gpuIndex: 7 }));
    // A request fault, not a machine fault: retrying it unchanged fails
    // identically, exactly like a relative cwd.
    expect(refusal.reason).toBe("invalid_request");
    // Modelled on the gpu_busy message: name the culprit, then the ways out.
    expect(refusal.message).toContain("no GPU 7");
    expect(refusal.message).toContain("[0] NVIDIA GeForce RTX 5080");
    expect(refusal.message).toContain("without gpu_index");
    // And nothing was started or reserved on the way.
    expect(fs.existsSync(jobsRoot) ? fs.readdirSync(jobsRoot) : []).toEqual([]);
  });

  it("says so plainly when the machine has no NVIDIA hardware at all", async () => {
    manager.setKnownGpus([]);

    const refusal = expectRefusal(await manager.start({ command: "printf x", gpuIndex: 3 }));
    expect(refusal.reason).toBe("invalid_request");
    expect(refusal.message).toContain("no NVIDIA GPU");
    expect(refusal.message).toContain("without gpu_index");
  });

  it("accepts an index the machine does have", async () => {
    manager.setKnownGpus([device(0, "RTX 5080"), device(1, "RTX 4090")]);

    const job = await startJob({ command: "printf x", gpuIndex: 1 });
    expect(job.gpuIndex).toBe(1);
  });

  it("stays permissive while the GPU list is UNKNOWN", async () => {
    // `undefined` is "we could not tell", and after the certainty rework that
    // covers nvidia-smi being absent or merely off the agent's minimal PATH too —
    // not just a wedged driver. Refusing on that would kill legitimate GPU jobs
    // on every box where the binary is installed but unreachable from a launchd
    // service, which is the regression the permissive branch exists to prevent.
    expect((await startJob({ command: "printf x", gpuIndex: 3 })).gpuIndex).toBe(3);

    manager.setKnownGpus([device(0, "RTX 5080")]);
    manager.setKnownGpus(undefined); // back to "we do not know"
    expect((await startJob({ command: "printf x", gpuIndex: 4 })).gpuIndex).toBe(4);
  });

  it("still refuses an index outside the lockfile namespace, list or no list", async () => {
    manager.setKnownGpus([device(0, "RTX 5080")]);
    for (const gpuIndex of [-1, 1.5, 4_096]) {
      expect(expectRefusal(await manager.start({ command: "printf x", gpuIndex })).reason).toBe(
        "invalid_request",
      );
    }
  });

  it("does not keep the caller's array alive as its own validation input", async () => {
    const cards = [device(0, "RTX 5080")];
    manager.setKnownGpus(cards);
    // The connection hands us the same array it publishes as telemetry.
    cards.push(device(1, "RTX 4090"));

    expect(expectRefusal(await manager.start({ command: "printf x", gpuIndex: 1 })).reason).toBe(
      "invalid_request",
    );
  });
});

// ── job_list paging ──────────────────────────────────────────────────────────

describe("job_list paging", () => {
  /** `count` jobs, oldest first in creation order, newest last. */
  function seedSeries(count: number): string[] {
    const base = Date.now() - count * 1_000;
    return Array.from({ length: count }, (_, i) =>
      seedJob({ status: "exited", exitCode: 0, startedAt: base + i * 1_000, endedAt: base + i * 1_000 }),
    );
  }

  it("returns the newest JOB_LIST_DEFAULT_ENTRIES and counts what it left out", () => {
    const ids = seedSeries(JOB_LIST_DEFAULT_ENTRIES + 5);

    const reply = expectJobsReply(manager.list({}));

    expect(reply.jobs).toHaveLength(JOB_LIST_DEFAULT_ENTRIES);
    // Newest first, and it really is the NEWEST slice — the tail of the series.
    expect(reply.jobs.map((job) => job.jobId)).toEqual(
      ids.slice(-JOB_LIST_DEFAULT_ENTRIES).reverse(),
    );
    expect(reply.omitted).toBe(5);
  });

  it("honours a smaller limit", () => {
    const ids = seedSeries(10);

    const reply = expectJobsReply(manager.list({ limit: 3 }));

    expect(reply.jobs.map((job) => job.jobId)).toEqual(ids.slice(-3).reverse());
    expect(reply.omitted).toBe(7);
  });

  it("omits the omitted count when nothing was left out", () => {
    seedSeries(3);

    const reply = expectJobsReply(manager.list({ limit: 10 }));

    expect(reply.jobs).toHaveLength(3);
    expect(reply.omitted).toBeUndefined();
  });

  it("clamps a limit to the wire page cap and ignores a nonsense one", () => {
    seedSeries(JOB_WIRE_MAX_LIST_ENTRIES + 3);

    expect(expectJobsReply(manager.list({ limit: 10_000 })).jobs).toHaveLength(
      JOB_WIRE_MAX_LIST_ENTRIES,
    );
    // Not a page size at all ⇒ the default, never an unbounded walk.
    for (const limit of [0, -5, Number.NaN, "20" as unknown as number]) {
      expect(expectJobsReply(manager.list({ limit })).jobs, `limit=${String(limit)}`).toHaveLength(
        JOB_LIST_DEFAULT_ENTRIES,
      );
    }
  });

  it("applies the limit AFTER the status filter, so a page is full of matches", () => {
    const base = Date.now() - 100_000;
    const running: string[] = [];
    for (let i = 0; i < 10; i++) {
      seedJob({ status: "exited", exitCode: 0, startedAt: base + i * 2_000, endedAt: base });
      running.push(seedJob({ status: "running", pid: process.pid, startedAt: base + i * 2_000 + 1_000 }));
    }

    const reply = expectJobsReply(manager.list({ status: "running", limit: 3 }));

    expect(reply.jobs.map((job) => job.jobId)).toEqual(running.slice(-3).reverse());
    // `omitted` counts RECORDS we never walked, not matches — under a filter it
    // is an upper bound, which is what the wire contract says.
    expect(reply.omitted).toBeGreaterThan(0);
  });
});

// ── When a vanished job ended ────────────────────────────────────────────────

describe("endedAt for a process that vanished without an exit marker", () => {
  /** Set a log's last-write time, which is the estimate's input. */
  function setLogMtime(jobId: string, at: number): void {
    fs.utimesSync(logPath(jobId), new Date(at), new Date(at));
  }

  it("estimates the ending from the log's last write, and says that it is an estimate", () => {
    const startedAt = Date.now() - 6 * 60 * 60 * 1_000;
    const lastWrite = Date.now() - 60 * 60 * 1_000;
    const jobId = seedJob({ status: "running", startedAt, log: "epoch 1/1 done\n" });
    setLogMtime(jobId, lastWrite);

    const job = expectJob(new JobManager({ jobsRoot }).status({ jobId }));

    expect(job.status).toBe("unknown");
    // Within a second of the last log write — NOT "when we noticed", which is now.
    expect(Math.abs((job.endedAt ?? 0) - lastWrite)).toBeLessThan(1_000);
    expect(job.endedAtApproximate).toBe(true);
    // Still a value the relay's validator accepts.
    expect(Number.isSafeInteger(job.endedAt)).toBe(true);
  });

  it("falls back to now for a SILENT job, rather than claiming it ended at its start", () => {
    const startedAt = Date.now() - 3 * 60 * 60 * 1_000;
    const before = Date.now();
    const jobId = seedJob({ status: "running", startedAt, log: "" });
    setLogMtime(jobId, startedAt);

    const job = expectJob(new JobManager({ jobsRoot }).status({ jobId }));

    // An empty log's mtime is the SPAWN, so believing it would report a
    // six-hour run as having ended the second it began.
    expect(job.endedAt).toBeGreaterThanOrEqual(before);
    expect(job.endedAtApproximate).toBe(true);
  });

  it("never reports an ending before the start or in the future", () => {
    const startedAt = Date.now() - 60_000;
    const jobId = seedJob({ status: "running", startedAt, log: "x\n" });
    // A copied job directory / a clock step: a log older than the job itself.
    setLogMtime(jobId, startedAt - 10 * 60_000);

    const job = expectJob(new JobManager({ jobsRoot }).status({ jobId }));

    expect(job.endedAt).toBe(startedAt);
    expect(job.endedAt).toBeLessThanOrEqual(Date.now());
  });

  it("leaves an EXITED job's observed timestamp alone and unmarked", () => {
    const jobId = seedJob({ status: "running", log: "done\n", exit: "0" });

    const job = expectJob(new JobManager({ jobsRoot }).status({ jobId }));

    expect(job.status).toBe("exited");
    expect(job.exitCode).toBe(0);
    // The exit file's mtime is the real instant; nothing here is an estimate.
    expect(job.endedAtApproximate).toBeUndefined();
  });

  it("reports the same estimate through job_list as through job_status", () => {
    const lastWrite = Date.now() - 30 * 60_000;
    const jobId = seedJob({ status: "running", startedAt: lastWrite - 60_000, log: "x\n" });
    setLogMtime(jobId, lastWrite);

    const restarted = new JobManager({ jobsRoot });
    const listed = expectJobsReply(restarted.list({})).jobs[0];
    const polled = expectJob(restarted.status({ jobId }));

    expect(listed?.endedAt).toBe(polled.endedAt);
    expect(listed?.endedAtApproximate).toBe(true);
    expect(polled.endedAtApproximate).toBe(true);
  });

  it("keeps the estimate across an agent restart, still marked as one", () => {
    const lastWrite = Date.now() - 45 * 60_000;
    const jobId = seedJob({ status: "running", startedAt: lastWrite - 60_000, log: "x\n" });
    setLogMtime(jobId, lastWrite);

    const settled = expectJob(new JobManager({ jobsRoot }).status({ jobId }));
    // A second manager reads the SETTLED record, not the running one.
    const reread = expectJob(new JobManager({ jobsRoot }).status({ jobId }));

    expect(reread.endedAt).toBe(settled.endedAt);
    expect(reread.endedAtApproximate).toBe(true);
  });
});

// ── The PATH a job inherits ──────────────────────────────────────────────────

describeOnPosix("job PATH", () => {
  /** Run a job that prints its own PATH and hand back what it printed. */
  async function jobPath(env?: Record<string, string>): Promise<string> {
    const job = await startJob({ command: 'printf %s "$PATH"', ...(env ? { env } : {}) });
    await waitFor(`job ${job.jobId} to print its PATH`, () => readLog(job.jobId).length > 0);
    return readLog(job.jobId).trim();
  }

  it("merges the login-shell PATH in, so a job sees what the user's terminal sees", async () => {
    // The macOS launchd problem `do:exec` has: the agent inherits
    // /usr/bin:/bin:/usr/sbin:/sbin, so homebrew/nvm/conda are invisible to a
    // job that runs fine when the user types it.
    loginShellPath.inject = "/opt/homebrew/bin";

    expect(await jobPath()).toContain("/opt/homebrew/bin");
  });

  it("still lets an explicit env.PATH win", async () => {
    // Applied BEFORE the caller's block, exactly like JOB_ENV_DEFAULTS: what the
    // caller asked for is never second-guessed.
    loginShellPath.inject = "/opt/homebrew/bin";

    expect(await jobPath({ PATH: "/usr/bin:/bin" })).toBe("/usr/bin:/bin");
  });

  it("changes nothing when the probe has not resolved", async () => {
    loginShellPath.inject = null;

    expect(await jobPath()).toBe(process.env["PATH"]);
  });
});

// ── The jobs root stays clean ────────────────────────────────────────────────

it("never leaves a directory behind for a refused gpuIndex", async () => {
  manager.setKnownGpus([device(0, "RTX 5080")]);
  expectRefusal(await manager.start({ command: "printf x", gpuIndex: 9 }));

  const entries = fs.existsSync(jobsRoot) ? fs.readdirSync(jobsRoot) : [];
  expect(entries.filter((entry) => JOB_ID_PATTERN.test(entry))).toEqual([]);
});
