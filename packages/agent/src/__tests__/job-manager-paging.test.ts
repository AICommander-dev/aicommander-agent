import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  JOB_ID_PATTERN,
  JOB_LIST_DEFAULT_ENTRIES,
  JOB_SCRIPT_REMOVED_ERROR,
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
  unknownReason?: string;
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

// ── Why a vanished job's outcome is unknown ──────────────────────────────────

describe("the reason recorded for a job that vanished without an exit marker", () => {
  // Windows and POSIX get different tokens for the same shape, because the set of
  // endings that are POSSIBLE differs and only the machine knows which one it is
  // (see JOB_UNKNOWN_REASONS). Derived from the real platform here for the same
  // reason.
  const NO_OUTPUT =
    process.platform === "win32" ? "vanished_no_output_windows" : "vanished_no_output_posix";
  const WITH_OUTPUT =
    process.platform === "win32" ? "vanished_with_output_windows" : "vanished_with_output_posix";

  /**
   * A vanished job's directory as the classifier will actually meet one HERE.
   *
   * On Windows the per-job `.cmd` files are part of a healthy job directory, and
   * their absence is a token of its own that is checked BEFORE the log's size — so
   * a fixture that omits them classifies as `job_script_removed` whatever the test
   * around it is called. The log-shape expectations below were unreachable on
   * win32 for exactly that reason (they never ran: this file is not in the narrow
   * Windows CI job either), and seeding the scripts is what makes them mean what
   * their names say on both platforms.
   */
  function seedVanished(overrides: Parameters<typeof seedJob>[0] = {}): string {
    const jobId = seedJob(overrides);
    if (process.platform === "win32") {
      for (const file of ["wrapper.cmd", "command.cmd"]) {
        fs.writeFileSync(path.join(jobDir(jobId), file), "@echo off\r\n");
      }
    }
    return jobId;
  }

  it("says NO OUTPUT for a job that never wrote a byte", () => {
    // `jobtest` from the incident: an empty log, no exit marker, scripts intact —
    // and, before this field, the identical bare `unknown` as the 180 KB job below.
    const jobId = seedVanished({ status: "running", log: "" });

    const job = expectJob(new JobManager({ jobsRoot }).status({ jobId }));

    expect(job.status).toBe("unknown");
    expect(job.unknownReason).toBe(NO_OUTPUT);
  });

  it("says it RAN AND VANISHED for a job that produced output and then disappeared", () => {
    // `train72`: 180 KB of output, no exit marker. The same status, a completely
    // different next step — and, deliberately, not a claim that anything killed it:
    // nothing watched this ending, so the token says only what the disk shows.
    const jobId = seedVanished({ status: "running", log: "x".repeat(180_845) });

    const job = expectJob(new JobManager({ jobsRoot }).status({ jobId }));

    expect(job.status).toBe("unknown");
    expect(job.unknownReason).toBe(WITH_OUTPUT);
    // The renamed vocabulary, stated as a rule rather than as one string: no token
    // this branch can produce may assert a cause it did not observe.
    expect(job.unknownReason).not.toContain("killed");
  });

  it.runIf(process.platform !== "win32")(
    "never invents the quarantined-scripts story on a platform that has no scripts",
    () => {
      // A POSIX job's wrapper is an argv, not a file, so a job directory without
      // wrapper.cmd is the NORMAL state there — reading it as security software
      // would send an operator to antivirus support over a healthy machine.
      const jobId = seedJob({ status: "running", log: "output\n" });
      expect(fs.existsSync(path.join(jobDir(jobId), "wrapper.cmd"))).toBe(false);

      const job = expectJob(new JobManager({ jobsRoot }).status({ jobId }));

      expect(job.unknownReason).toBe(WITH_OUTPUT);
    },
  );

  it.runIf(process.platform === "win32")(
    "names the removed scripts when a Windows job's .cmd files are gone",
    () => {
      // Removal AFTER the spawn, which verifyWindowsJobScripts cannot see: it
      // refuses the START and never looks again.
      const jobId = seedJob({ status: "running", log: "" });
      fs.writeFileSync(path.join(jobDir(jobId), "command.cmd"), "@echo off\r\n");

      const job = expectJob(new JobManager({ jobsRoot }).status({ jobId }));

      expect(job.unknownReason).toBe(JOB_SCRIPT_REMOVED_ERROR);
    },
  );

  it("says undetermined rather than guessing when it cannot read the job's log", () => {
    // The directory is gone under us: every file reads as missing, and the one
    // thing that must NOT come out of that is a named cause.
    const jobId = seedJob({ status: "running", log: "x\n" });
    fs.rmSync(logPath(jobId));

    const job = expectJob(new JobManager({ jobsRoot }).status({ jobId }));

    expect(job.status).toBe("unknown");
    expect(job.unknownReason).toBe("undetermined");
  });

  it("PERSISTS the reason, so it still describes the ending after the log is gone", () => {
    // The entire design point. The reason is observed at the settle and written to
    // meta.json; recomputing it lazily would describe the disk as it is when
    // someone ASKS. Here the log that proved "it produced output" is deleted after
    // the settle — a truncation or the retention window does the same in
    // production — and the answer must not change.
    const jobId = seedVanished({ status: "running", log: "x".repeat(4_096) });

    const settled = expectJob(new JobManager({ jobsRoot }).status({ jobId }));
    expect(settled.unknownReason).toBe(WITH_OUTPUT);
    fs.rmSync(logPath(jobId));

    // A fresh manager reads the SETTLED record, exactly as a restarted agent does.
    const reread = expectJob(new JobManager({ jobsRoot }).status({ jobId }));

    expect(reread.status).toBe("unknown");
    expect(reread.unknownReason).toBe(WITH_OUTPUT);
  });

  it("records it on disk, not only on the reply", () => {
    const jobId = seedVanished({ status: "running", log: "" });

    expectJob(new JobManager({ jobsRoot }).status({ jobId }));

    const meta = JSON.parse(
      fs.readFileSync(path.join(jobDir(jobId), "meta.json"), "utf8"),
    ) as Record<string, unknown>;
    expect(meta["unknownReason"]).toBe(NO_OUTPUT);
  });

  it("gives a job that EXITED no reason at all", () => {
    const jobId = seedJob({ status: "running", log: "done\n", exit: "0" });

    const job = expectJob(new JobManager({ jobsRoot }).status({ jobId }));

    expect(job.status).toBe("exited");
    // Never `undefined` on the wire, never "" — the field is simply absent, which
    // is what an older relay and an older agent both already render correctly.
    expect(job.unknownReason).toBeUndefined();
    expect(Object.keys(job)).not.toContain("unknownReason");
  });

  it("reports the same reason through job_list as through job_status", () => {
    const jobId = seedVanished({ status: "running", log: "x\n" });

    const restarted = new JobManager({ jobsRoot });
    const listed = expectJobsReply(restarted.list({})).jobs[0];
    const polled = expectJob(restarted.status({ jobId }));

    expect(listed?.unknownReason).toBe(WITH_OUTPUT);
    expect(polled.unknownReason).toBe(WITH_OUTPUT);
  });

  it("does not let a token from a newer agent reach the wire", () => {
    // A downgraded agent, or a copied jobs root: the record is perfectly good and
    // must keep listing, but a vocabulary this build cannot name must not be put in
    // front of an AI caller.
    const jobId = seedJob({
      status: "unknown",
      exitCode: null,
      endedAt: Date.now() - 1_000,
      unknownReason: "eaten_by_a_grue",
    });

    const job = expectJob(new JobManager({ jobsRoot }).status({ jobId }));

    expect(job.status).toBe("unknown");
    expect(job.unknownReason).toBeUndefined();
  });

  it("keeps a prototype key off the wire as firmly as an invented token", () => {
    // The gate is a membership test over the vocabulary, not an object lookup, and
    // this is why: a record holding `constructor` or `__proto__` — hand-edited, or
    // written by something that is not our agent at all — must be as silent as
    // `eaten_by_a_grue`. It is the agent-side half of the same hole the relay's
    // renderer had.
    for (const key of ["constructor", "toString", "__proto__"]) {
      const jobId = seedJob({
        status: "unknown",
        exitCode: null,
        endedAt: Date.now() - 1_000,
        unknownReason: key,
      });

      const job = expectJob(new JobManager({ jobsRoot }).status({ jobId }));

      // The record still lists — an unreadable reason costs the caller nothing.
      expect(job.status, key).toBe("unknown");
      expect(job.unknownReason, key).toBeUndefined();
      expect(Object.keys(job), key).not.toContain("unknownReason");
    }
  });

  // POSIX only: it needs a real signal delivered to a real process group, which is
  // the only way the child watcher is ever handed a `signal` at all (Windows
  // `taskkill /F` gives the terminated process an ordinary exit code instead).
  it.runIf(process.platform !== "win32")(
    "says KILLED BY SIGNAL only where the agent watched the shell die",
    async () => {
      // The one token backed by an observation rather than by a directory. The child
      // exit handler is handed `(code, signal)`; it used to drop the signal, which is
      // the single fact separating a kill the agent SAW from an ending nobody was
      // there for. A real job, a real SIGKILL to its process group.
      const job = await startJob({ command: "sleep 30" });
      const pid = startedJobs.get(job.jobId);
      if (pid === undefined) throw new Error("job has no pid");

      process.kill(-pid, "SIGKILL");
      await waitFor("the killed job to settle", () => {
        const result = manager.status({ jobId: job.jobId });
        return result.ok && result.kind === "job" && result.job.status !== "running";
      });

      const settled = expectJob(manager.status({ jobId: job.jobId }));
      expect(settled.status).toBe("unknown");
      expect(settled.unknownReason).toBe("killed_by_signal");
    },
  );
});

// ── A cancel that outlives the agent ─────────────────────────────────────────

describeOnPosix("the durable record that a cancel was requested", () => {
  /** The raw meta.json a seeded or settled job is holding right now. */
  function readMeta(jobId: string): Record<string, unknown> {
    return JSON.parse(
      fs.readFileSync(path.join(jobDir(jobId), "meta.json"), "utf8"),
    ) as Record<string, unknown>;
  }

  it("marks the record BEFORE the signal, so a restart cannot lose the cancel", async () => {
    const job = await startJob({ command: "sleep 30" });

    manager.cancel({ jobId: job.jobId });

    // Written by signalJob itself, not by the settle — the whole point is that it
    // exists while the process is still on its way down.
    expect(typeof readMeta(job.jobId)["cancelRequestedAt"]).toBe("number");
  });

  it("does not let a restarted agent report a cancelled job as exit code 0", async () => {
    // The pre-existing bug this closes, and it is not exotic: macOS `/bin/sh` is
    // bash, whose EXIT trap DOES run when the shell leaves on SIGTERM — so the
    // wrapper writes an exit marker of 0 for a job the caller cancelled. With the
    // note living only in memory, an agent restarted inside the kill window (a
    // self-update picks its own moment) read that marker and settled the job as
    // `exited 0`. Simulated here exactly as production does it: a SECOND manager,
    // with an empty in-memory set, reading the same directory.
    const job = await startJob({ command: "sleep 30" });
    manager.cancel({ jobId: job.jobId });
    // The wrapper's own marker, as bash writes it on the way out.
    fs.writeFileSync(path.join(jobDir(job.jobId), "exit"), "0");

    const restarted = expectJob(new JobManager({ jobsRoot }).status({ jobId: job.jobId }));

    expect(restarted.status).toBe("unknown");
    expect(restarted.exitCode).toBeNull();
    expect(restarted.unknownReason).toBe("cancelled");
  });

  it("records CANCELLED, not a filesystem story, after a restart", async () => {
    // The other half: no exit marker at all, so the restarted agent reaches
    // classifyVanishedJob. Without the durable mark it fell through to the log's
    // shape and PERMANENTLY wrote a "vanished" verdict about a job the caller had
    // itself cancelled — a wrong answer that no later read could correct.
    const job = await startJob({ command: "sleep 30" });
    manager.cancel({ jobId: job.jobId });
    await waitFor("the cancelled job's process to go", () => {
      const pid = startedJobs.get(job.jobId);
      return pid !== undefined && !isProcessAlive(pid);
    });
    fs.rmSync(path.join(jobDir(job.jobId), "exit"), { force: true });

    const restarted = expectJob(new JobManager({ jobsRoot }).status({ jobId: job.jobId }));

    expect(restarted.status).toBe("unknown");
    expect(restarted.unknownReason).toBe("cancelled");
  });

  it("says CANCELLED for a job cancelled during its start window", async () => {
    // The one cancellation path that never reaches classifyVanishedJob: the process
    // does not exist yet, so cancel() settles the record itself. settle() DELETES
    // the reason when it is not passed one, which made this the single cancellation
    // whose record said nothing about why it was `unknown` — permanently, since the
    // reason is written at the settle and never derived afterwards.
    // No race: `start()` creates the directory, writes meta.json and registers the
    // start window all BEFORE its first await, so everything below runs while the
    // window is provably open — no timer, no polling.
    const started = manager.start({ command: "sleep 30", name: "cancel-me" });
    const jobId = fs.readdirSync(jobsRoot).find((entry) => JOB_ID_PATTERN.test(entry));
    if (jobId === undefined) throw new Error("start() opened no job directory");

    const cancelled = expectJob(manager.cancel({ jobId }));
    await started.catch(() => undefined);

    expect(cancelled.status).toBe("unknown");
    expect(cancelled.unknownReason).toBe("cancelled");
    // And on the record, not only in the reply: the reason is written at the settle
    // and never derived, so a poll after a restart is the only thing that proves it
    // was actually persisted.
    const reread = expectJob(new JobManager({ jobsRoot }).status({ jobId }));
    expect(reread.status).toBe("unknown");
    expect(reread.unknownReason).toBe("cancelled");
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
