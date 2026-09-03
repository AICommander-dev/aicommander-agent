// The record→pid window: what the agent may be asked while a start is parked in
// an `await`, and what it must answer.
//
// The window exists because JobManager.start() is asynchronous. On Windows it
// writes the job's two script files and reads them back immediately before the
// spawn, and doing that synchronously would block Electron's main loop on a
// filesystem an on-access scanner is holding — the "Reconnecting…" stall this
// whole effort exists to prevent. The cost of that fix is a gap that could not
// previously exist: between the job's record landing on disk (pid: null) and its
// pid being written, another WebSocket frame CAN be handled.
//
// PLATFORM NOTE. The gap only opens on Windows — on POSIX a start that SUCCEEDS
// awaits nothing that yields to the event loop (a start that fails awaits its own
// cleanup on every platform) — and Windows is precisely where nobody can run
// this suite: the package's Windows CI job is deliberately narrow because the
// bulk of the agent's tests assume POSIX. So the Windows path is DRIVEN here,
// the way job-scripts.test.ts drives the scripts themselves: `process.platform`
// is pinned before job-manager.ts is imported (its `isWindows` is a module
// constant), the spawn boundary is a stand-in, and the pause that models a slow
// filesystem is injected around the real write and the real read-back.
//
// Five things are pinned, and each of them was, at some point, wrong:
//  - the read-back HAPPENS, before the spawn and after the write. Nothing else
//    asserts that: the fault test stages its fault at the spawn, so deleting the
//    whole `if (isWindows) { verify }` block leaves that suite green.
//  - a reader landing inside the window is not told the job is over.
//  - a cancel landing inside the window is TRUE: the job does not then start.
//  - a socket dying inside the window leaves no orphan behind.
//  - a filesystem that never answers fails the start with a named cause instead
//    of holding a GPU lock and a concurrency slot forever.

import { describe, it, expect, beforeEach, afterEach, beforeAll, afterAll, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { gpuLockFileName, JOB_SCRIPT_REMOVED_ERROR } from "@aicommander/protocol";

/**
 * The spawn boundary. `cmd /d /s /c` does not exist here, and is not the point.
 *
 * `files` records WHAT was spawned, because on this pinned platform the manager
 * stops a process by spawning `taskkill` — so "the process was stopped" is an
 * observation about this list, and `count` counts only the job launches.
 *
 * `duringSpawn` is the last instant a frame could possibly be handled: it runs
 * synchronously inside spawn(), i.e. after the process exists and before start()
 * has written its pid.
 */
const spawned = vi.hoisted(() => ({
  count: 0,
  files: [] as string[],
  duringSpawn: null as null | (() => void),
}));
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return {
    ...actual,
    spawn: (file: string) => {
      spawned.files.push(file);
      if (file === "taskkill") return { pid: 4321, on: () => undefined, unref: () => undefined };
      spawned.count += 1;
      hooks.order.push("spawn");
      spawned.duringSpawn?.();
      // A live pid, so every liveness check in start() answers honestly, and the
      // members the manager actually uses — including the two it reads before it
      // will signal a child it still holds (see signalSpawned).
      return {
        pid: process.pid,
        exitCode: null,
        signalCode: null,
        on: () => undefined,
        once: () => undefined,
        kill: () => true,
        unref: () => undefined,
      };
    },
  };
});

/**
 * The script write and read-back, wrapped rather than replaced.
 *
 * Wrapped is what makes this a mutation check: the calls are recorded in the
 * order they happen and the real implementations still run, so removing the
 * verify call from spawnJob — or moving it after the spawn — fails the first
 * test below, while a change to what the scripts CONTAIN does not.
 *
 * `pauseIn` is how a frame gets to arrive mid-start: the phase named there stops
 * after doing its real work and waits for the test to let go, which is exactly
 * the shape of a scanner holding the file.
 */
const hooks = vi.hoisted(() => ({
  order: [] as string[],
  pauseIn: null as null | "write" | "verify",
  entered: null as null | (() => void),
  gate: null as null | Promise<void>,
  // A refusal the write reports when it comes back — the shape a scanner that
  // took the file while we were parked produces, and the only way to stage a
  // fault and a cancel landing on the SAME start.
  writeFault: null as string | null,
}));
vi.mock("../job-scripts.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../job-scripts.js")>();
  const pause = async (phase: "write" | "verify"): Promise<void> => {
    if (hooks.pauseIn !== phase) return;
    hooks.entered?.();
    await hooks.gate;
  };
  return {
    ...actual,
    writeWindowsJobScripts: async (dir: string, command: string, timeoutMs?: number) => {
      hooks.order.push("write");
      const result = await actual.writeWindowsJobScripts(dir, command, timeoutMs);
      await pause("write");
      return hooks.writeFault ?? result;
    },
    verifyWindowsJobScripts: async (dir: string, command: string, timeoutMs?: number) => {
      hooks.order.push("verify");
      const result = await actual.verifyWindowsJobScripts(dir, command, timeoutMs);
      await pause("verify");
      return result;
    },
  };
});

/**
 * The write, with two kinds of filesystem available on demand:
 *  - `hang`: one that never answers at all;
 *  - `stall`: one that answers only when the test says so — a scanner that lets
 *    go LONG after the start gave up, which is when a write nobody is waiting
 *    for any more gets to touch the disk.
 */
const atomic = vi.hoisted(() => ({ hang: false, stall: null as null | Promise<void> }));
vi.mock("../atomic-file.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../atomic-file.js")>();
  return {
    ...actual,
    atomicWriteUtf8Async: async (
      dir: string,
      file: string,
      contents: string,
      giveUp?: import("../atomic-file.js").AsyncWriteAbandoned,
    ): Promise<void> => {
      if (atomic.hang) return new Promise<void>(() => undefined);
      // The real write, run after the stall — with the caller's own latch, which
      // is the whole point: by then it says the start is gone.
      if (atomic.stall) await atomic.stall;
      return actual.atomicWriteUtf8Async(dir, file, contents, giveUp);
    },
  };
});

/**
 * The identity probe, wrapped so the test can see WHEN it runs.
 *
 * It is the expensive half of what start() does after the spawn — a `ps`, or a
 * wmic/PowerShell call on Windows — and everything it delays is a stretch in
 * which the job's record exists with a null pid over a process that is already
 * alive. `pidOnDisk` records what meta.json said at that instant.
 */
const probe = vi.hoisted(() => ({ jobsRoot: "", pidOnDisk: undefined as unknown }));
vi.mock("../proc-identity.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../proc-identity.js")>();
  const nodeFs = (await import("node:fs")).default;
  const nodePath = (await import("node:path")).default;
  return {
    ...actual,
    readProcIdentity: (pid: number) => {
      const ids = nodeFs
        .readdirSync(probe.jobsRoot)
        .filter((entry) => /^[0-9a-f]{16}$/.test(entry));
      // The FIRST probe of a start only: verifyJobProcess probes again, by which
      // time the pid is on disk either way.
      if (ids.length === 1 && probe.pidOnDisk === undefined) {
        const record = nodeFs.readFileSync(
          nodePath.join(probe.jobsRoot, ids[0]!, "meta.json"),
          "utf8",
        );
        probe.pidOnDisk = (JSON.parse(record) as { pid: number | null }).pid;
      }
      return actual.readProcIdentity(pid);
    },
  };
});

type JobManagerModule = typeof import("../job-manager.js");
type Manager = InstanceType<JobManagerModule["JobManager"]>;

let jobManagerModule: JobManagerModule;
let scripts: typeof import("../job-scripts.js");
const realPlatform = process.platform;

beforeAll(async () => {
  // Before the import, not after: `isWindows` is read once, at module load.
  Object.defineProperty(process, "platform", { value: "win32", configurable: true });
  jobManagerModule = await import("../job-manager.js");
  scripts = await import("../job-scripts.js");
});

afterAll(() => {
  Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
});

let tmpBase: string;
let jobsRoot: string;
let manager: Manager;

beforeEach(() => {
  spawned.count = 0;
  spawned.files = [];
  spawned.duringSpawn = null;
  hooks.writeFault = null;
  hooks.order = [];
  hooks.pauseIn = null;
  hooks.entered = null;
  hooks.gate = null;
  atomic.hang = false;
  atomic.stall = null;
  tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), "aic-jobs-window-"));
  jobsRoot = path.join(tmpBase, "jobs");
  probe.jobsRoot = jobsRoot;
  probe.pidOnDisk = undefined;
  manager = new jobManagerModule.JobManager({ jobsRoot });
});

afterEach(() => {
  hooks.pauseIn = null;
  spawned.duringSpawn = null;
  atomic.hang = false;
  atomic.stall = null;
  vi.useRealTimers();
  jobManagerModule.resetJobManagerForTests();
  fs.rmSync(tmpBase, { recursive: true, force: true });
});

/** The one job id on disk — the record is written before the window opens. */
function recordedJobId(): string {
  const ids = fs.readdirSync(jobsRoot).filter((entry) => /^[0-9a-f]{16}$/.test(entry));
  expect(ids).toHaveLength(1);
  return ids[0]!;
}

function readRecord(jobId: string): { status: string; pid: number | null } {
  return JSON.parse(fs.readFileSync(path.join(jobsRoot, jobId, "meta.json"), "utf8")) as {
    status: string;
    pid: number | null;
  };
}

type Started = Promise<{ ok?: unknown; err?: unknown }>;

/**
 * Start a job and hand back control while it is INSIDE the window: its record is
 * on disk, its process does not exist, and the manager is parked in the named
 * phase's await until `release()`.
 */
async function startInsideWindow(
  req: Parameters<Manager["start"]>[0],
  phase: "write" | "verify" = "write",
): Promise<{ started: Started; release: () => void }> {
  let letGo!: () => void;
  hooks.gate = new Promise<void>((resolve) => {
    letGo = resolve;
  });
  const reached = new Promise<void>((resolve) => {
    hooks.entered = resolve;
  });
  hooks.pauseIn = phase;
  const started: Started = manager.start(req).then(
    (ok) => ({ ok }),
    (err) => ({ err }),
  );
  await reached;
  return {
    started,
    release: () => {
      hooks.pauseIn = null;
      letGo();
    },
  };
}

describe("the Windows read-back is on the start path", () => {
  it("writes the scripts, reads them back, and only then spawns", async () => {
    const result = await manager.start({ command: "echo hi" });

    expect(result.ok).toBe(true);
    // The whole assertion: verify sits between the write and the spawn. Delete
    // the `if (isWindows) { verifyWindowsJobScripts }` block in spawnJob and this
    // is ["write", "spawn"].
    expect(hooks.order).toEqual(["write", "verify", "spawn"]);
  });

  it("cleans up after a failed start without blocking the loop on the delete", async () => {
    // The failure path of the async conversion. A start fails HERE because the
    // filesystem an on-access scanner is holding refused the job's scripts —
    // and the undo used to be a SYNCHRONOUS recursive delete of that very
    // directory, i.e. the blocking call the conversion exists to remove, run on
    // Electron's main loop at the one moment the scanner is provably busy.
    const rmSync = vi.spyOn(fs, "rmSync");
    const { started, release } = await startInsideWindow({ command: "echo hi", gpuIndex: 0 });
    const jobId = recordedJobId();
    fs.writeFileSync(path.join(jobsRoot, jobId, scripts.WRAPPER_FILE), "");
    release();
    const { err } = await started;

    expect(err).toBeInstanceOf(jobManagerModule.JobError);
    // Gone — the undo still happened, just not on this thread.
    expect(fs.existsSync(path.join(jobsRoot, jobId))).toBe(false);
    expect(fs.existsSync(path.join(jobsRoot, gpuLockFileName(0)))).toBe(false);
    const syncRemovals = rmSync.mock.calls.filter(([target]) => String(target).includes(jobId));
    expect(syncRemovals).toEqual([]);
    rmSync.mockRestore();
  });

  it("refuses to spawn when the scripts did not survive the write", async () => {
    // The real read-back, against a real file a "scanner" emptied: no fault is
    // injected anywhere, which is what makes this a test OF the read-back.
    const { started, release } = await startInsideWindow({ command: "echo hi" });
    fs.writeFileSync(path.join(jobsRoot, recordedJobId(), "wrapper.cmd"), "");
    release();
    const { err } = await started;

    expect(err).toBeInstanceOf(jobManagerModule.JobError);
    expect((err as InstanceType<JobManagerModule["JobError"]>).code).toBe(JOB_SCRIPT_REMOVED_ERROR);
    expect(spawned.count).toBe(0);
  });
});

describe("a reader arriving inside the start window", () => {
  it("is told the job is running, not that it has ended", async () => {
    const { started, release } = await startInsideWindow({ command: "echo hi" });
    const jobId = recordedJobId();
    // The state that makes this hard: a record whose pid every branch of
    // refresh() would otherwise read as "the process is gone".
    expect(readRecord(jobId).pid).toBeNull();

    const status = manager.status({ jobId });
    const list = manager.list({});

    expect(status.ok && status.kind === "job" ? status.job.status : null).toBe("running");
    expect(list.ok && list.kind === "jobs" ? list.jobs.map((job) => job.status) : []).toEqual(["running"]);

    release();
    const { ok } = await started;
    expect((ok as { ok: boolean }).ok).toBe(true);
    // And the poll did not settle it out from under the spawn.
    expect(manager.status({ jobId })).toMatchObject({ ok: true, job: { status: "running" } });
  });
});

describe("a cancel arriving inside the start window", () => {
  it("stops the spawn and reports the job as ended, not as running", async () => {
    const { started, release } = await startInsideWindow({ command: "echo hi", gpuIndex: 0 });
    const jobId = recordedJobId();

    const cancelled = manager.cancel({ jobId });

    // The answer given while the job could still have been started. It used to
    // be `running`, with the process created moments later.
    expect(cancelled).toMatchObject({ ok: true, job: { jobId, status: "unknown", exitCode: null } });

    release();
    const { ok } = await started;

    // The promise the reply made, kept.
    expect(spawned.count).toBe(0);
    expect((ok as { ok: boolean; kind: string }).kind).toBe("job");
    expect(readRecord(jobId).status).toBe("unknown");
    expect(manager.status({ jobId })).toMatchObject({ ok: true, job: { status: "unknown" } });
    // And it surrendered what a running job holds: the card and the slot.
    expect(fs.existsSync(path.join(jobsRoot, gpuLockFileName(0)))).toBe(false);
    const next = await manager.start({ command: "echo again", gpuIndex: 0 });
    expect(next.ok).toBe(true);
  });

  it("is what every reader answers WHILE the start is still parked", async () => {
    // The half the reply used to promise and nothing kept. The cancel answers
    // "ended"; the start is still sitting in the scanner's write, and on Windows
    // that is up to JOB_SCRIPT_IO_TIMEOUT_MS. For all of that time `status` and
    // `list` went on saying `running`, and the card and the slot stayed taken —
    // the caller was told the job had ended and then watched it run.
    const { started, release } = await startInsideWindow({ command: "echo hi", gpuIndex: 0 });
    const jobId = recordedJobId();

    expect(manager.cancel({ jobId })).toMatchObject({ ok: true, job: { status: "unknown" } });

    // NOTHING has been released here yet: start() has not resumed, and will not
    // until `release()` below.
    expect(manager.status({ jobId })).toMatchObject({ ok: true, job: { status: "unknown" } });
    const listed = manager.list({});
    expect(listed.ok && listed.kind === "jobs" ? listed.jobs.map((job) => job.status) : []).toEqual(["unknown"]);
    // On disk too, so an agent restarted in this instant says the same thing.
    expect(readRecord(jobId).status).toBe("unknown");
    // And the reservations are already back: a replacement start gets the card
    // it was told was free.
    expect(fs.existsSync(path.join(jobsRoot, gpuLockFileName(0)))).toBe(false);

    release();
    await started;
    expect(spawned.count).toBe(0);
    expect(manager.status({ jobId })).toMatchObject({ ok: true, job: { status: "unknown" } });
  });

  it("keeps the record even when a script fault lands on the same start", async () => {
    // Both at once: a scanner takes the scripts while a cancel is in flight. The
    // fault used to win outright — abandonStart erased the directory the cancel
    // had just promised would stay pollable, and the next job_status answered
    // `not_found`. The caller was told the job ended, then told it never existed.
    const { started, release } = await startInsideWindow({ command: "echo hi", gpuIndex: 0 });
    const jobId = recordedJobId();

    expect(manager.cancel({ jobId })).toMatchObject({ ok: true, job: { status: "unknown" } });
    hooks.writeFault = `${scripts.WRAPPER_FILE} is gone`;
    release();
    const { err } = await started;

    // The fault still reaches the start's caller — it is the one thing that
    // names the cause, and it is what goes into the vendor submission.
    expect(err).toBeInstanceOf(jobManagerModule.JobError);
    expect((err as InstanceType<JobManagerModule["JobError"]>).code).toBe(JOB_SCRIPT_REMOVED_ERROR);
    expect(spawned.count).toBe(0);
    // And the record the CANCEL promised is still there, saying what the cancel
    // said it would.
    expect(manager.status({ jobId })).toMatchObject({ ok: true, job: { status: "unknown" } });
    expect(readRecord(jobId).status).toBe("unknown");
    expect(fs.existsSync(path.join(jobsRoot, gpuLockFileName(0)))).toBe(false);
  });

  it("is honoured at the last checkpoint too, during the read-back", async () => {
    const { started, release } = await startInsideWindow({ command: "echo hi" }, "verify");
    const jobId = recordedJobId();

    expect(manager.cancel({ jobId })).toMatchObject({ ok: true, job: { status: "unknown" } });
    release();
    await started;

    expect(spawned.count).toBe(0);
    expect(readRecord(jobId).status).toBe("unknown");
  });
});

describe("a cancel that lands at the very instant of the spawn", () => {
  it("stops the process it finds instead of returning it, and keeps the record", async () => {
    // The gap AFTER the spawn: the process exists, its pid is not yet on disk,
    // and start() has not resumed. Today's event loop cannot deliver a frame
    // there — resuming from `await spawnJob(…)` is a microtask and a relay frame
    // is a macrotask — so it is staged from INSIDE spawn(), which is strictly
    // later than any frame could arrive. What must not happen is what used to:
    // a terminal `ok` for a cancel while the process runs on, with the card
    // already handed back under it.
    spawned.duringSpawn = () => {
      manager.cancel({ jobId: recordedJobId() });
    };

    const failed = await manager.start({ command: "echo hi", gpuIndex: 0 }).then(
      () => null,
      (err: unknown) => err,
    );
    const jobId = recordedJobId();

    expect(failed).toBeInstanceOf(jobManagerModule.JobError);
    // The process that did get created is being stopped — on this platform, by
    // taskkill (see signalSpawned).
    expect(spawned.files).toContain("taskkill");
    // And the record still says exactly what the cancel answered: ended,
    // unknown, and still there to be polled.
    expect(readRecord(jobId).status).toBe("unknown");
    expect(manager.status({ jobId })).toMatchObject({ ok: true, job: { status: "unknown" } });
  });

  it("keeps the card reserved until the process it is killing is gone", async () => {
    // The half the record cannot cover. cancel() settled this job, and settling
    // RELEASES the GPU lock — while the process start() then discovered lives on
    // for up to KILL_ESCALATION_MS. For that stretch the branch left a live
    // training run on a card the next job_start could be granted: the exact
    // state its own comment forbids, and the one thing this whole file exists to
    // prevent. The signal is not the fix; holding the card until the child's
    // exit is (see holdCardUntilExit).
    spawned.duringSpawn = () => {
      manager.cancel({ jobId: recordedJobId() });
    };
    await manager.start({ command: "echo hi", gpuIndex: 0 }).then(
      () => null,
      () => null,
    );
    // The child handle here never emits `exit`, which is precisely the state
    // under test: the process has been signalled and has not died yet.
    const second = await manager.start({ command: "echo second", gpuIndex: 0 });

    expect(second).toMatchObject({ ok: false, reason: "gpu_busy" });
    // And nothing was launched for it: a refusal, not a second job on the card.
    expect(spawned.count).toBe(1);
  });
});

describe("a socket that dies at the very instant of the spawn", () => {
  it("stops the process and lets no surface name the job it retired", async () => {
    // The `abandoned` twin of the cancel above, and until now the only branch of
    // the post-spawn race with no test at all. Nobody can ever be told this id —
    // the socket that would have carried it back is gone — so the process is
    // stopped and the job is retired, and while that is happening every reader
    // has to agree about it: cancel() has always answered `not_found` for a
    // retiring job, and status()/list() used to answer `running` for the same id.
    const socketGone = new AbortController();
    spawned.duringSpawn = () => socketGone.abort();

    const failed = await manager
      .start({ command: "echo hi", gpuIndex: 0, signal: socketGone.signal })
      .then(
        () => null,
        (err: unknown) => err,
      );
    const jobId = recordedJobId();

    expect(failed).toBeInstanceOf(jobManagerModule.JobError);
    expect(spawned.files).toContain("taskkill");
    // The durable note, so an agent that dies mid-escalation still finds it.
    expect(
      (JSON.parse(fs.readFileSync(path.join(jobsRoot, jobId, "meta.json"), "utf8")) as {
        retiring?: boolean;
      }).retiring,
    ).toBe(true);
    // One id, one answer — from every surface that can be asked about it.
    expect(manager.cancel({ jobId })).toMatchObject({ ok: false, reason: "not_found" });
    expect(manager.status({ jobId })).toMatchObject({ ok: false, reason: "not_found" });
    expect(manager.list({})).toMatchObject({ ok: true, jobs: [] });
    // And the card stays reserved until the process is confirmed gone.
    expect(await manager.start({ command: "echo second", gpuIndex: 0 })).toMatchObject({
      ok: false,
      reason: "gpu_busy",
    });
  });
});

describe("the pid reaches the disk before anything else the start still has to do", () => {
  it("is already recorded when the identity probe runs", async () => {
    // A `running` record with a null pid is the one record no recovery can read
    // honestly: refresh() calls a null pid `gone`, settles the job and hands its
    // GPU lock back — under a process that is still training. The record is
    // written before the spawn on purpose (a process with no record is the
    // unrecoverable direction), so the gap is the stretch AFTER the spawn and
    // before the pid is written down, and an agent killed inside it orphans a
    // live process.
    //
    // The identity probe used to sit in that stretch — a `ps`, or wmic on
    // Windows, i.e. tens to hundreds of milliseconds on the loaded box this
    // matters on. Now it runs after the pid is on disk, which is what this pins.
    const result = await manager.start({ command: "echo hi" });

    expect(result.ok).toBe(true);
    expect(probe.pidOnDisk).toBe(process.pid);
  });
});

describe("a cancel arriving while a failed start is being ERASED", () => {
  it("is answered not_found instead of settling the record being deleted", async () => {
    // The window the async removal opened, and the one the existing tests here
    // could not see: they poll after the start has resolved, and this one closes
    // when it does. A start that failed erases itself — and the erase is now an
    // `await` (removeJobDirAsync), with the id deliberately left in the start
    // window for its whole duration. So a `do:job_cancel` frame can land INSIDE
    // it, take cancel()'s starting-job branch, and settle the job — whose
    // meta.json write re-creates, through ensurePrivateDir, the very directory
    // being deleted. Both outcomes of that race are wrong: a phantom terminal
    // directory nobody asked for, or the record the cancel just promised would
    // stay pollable, deleted a moment later.
    //
    // The id is obtainable throughout: job_list reports the job as `running` for
    // the whole start window AND for the duration of the erase.
    const realRm = fs.promises.rm;
    let cancelled: unknown = null;
    const rm = vi.spyOn(fs.promises, "rm").mockImplementation(async (target, options) => {
      const id = path.basename(String(target));
      // Staged at the START of the erase: the record is still on disk, so a
      // cancel that means to settle it can, and the deletion is still to come.
      if (cancelled === null && /^[0-9a-f]{16}$/.test(id)) {
        cancelled = manager.cancel({ jobId: id });
      }
      return realRm(target, options);
    });

    const { started, release } = await startInsideWindow({ command: "echo hi", gpuIndex: 0 });
    const jobId = recordedJobId();
    // A scanner empties the wrapper: the script fault that sends this start down
    // the erase path.
    fs.writeFileSync(path.join(jobsRoot, jobId, scripts.WRAPPER_FILE), "");
    release();
    const { err } = await started;
    rm.mockRestore();

    expect(err).toBeInstanceOf(jobManagerModule.JobError);
    expect(cancelled).not.toBeNull();
    // The only answer that stays true: the job is on its way out, and no reader
    // after this moment will ever say otherwise.
    expect(cancelled).toMatchObject({ ok: false, reason: "not_found" });
    // Not re-created behind the erase, and not left for the retention sweep.
    expect(fs.existsSync(path.join(jobsRoot, jobId))).toBe(false);
    expect(manager.status({ jobId })).toMatchObject({ ok: false, reason: "not_found" });
    expect(manager.list({})).toMatchObject({ ok: true, jobs: [] });
    expect(fs.existsSync(path.join(jobsRoot, gpuLockFileName(0)))).toBe(false);
    expect(spawned.count).toBe(0);
  });
});

describe("a socket that dies inside the start window", () => {
  it("drops the start and leaves nothing behind", async () => {
    const socketGone = new AbortController();
    const { started, release } = await startInsideWindow({
      command: "echo hi",
      gpuIndex: 0,
      signal: socketGone.signal,
    });
    const jobId = recordedJobId();

    // The connection settles: whatever this start produced could never be
    // reported back, because the reply has nowhere to go.
    socketGone.abort();
    release();
    const { err } = await started;

    expect(err).toBeInstanceOf(jobManagerModule.JobError);
    expect(spawned.count).toBe(0);
    // No record, no directory, no reservation — an unreachable job is litter.
    expect(fs.existsSync(path.join(jobsRoot, jobId))).toBe(false);
    expect(fs.existsSync(path.join(jobsRoot, gpuLockFileName(0)))).toBe(false);
    expect(manager.list({})).toMatchObject({ ok: true, jobs: [] });
  });
});

describe("a filesystem that answers long after we gave up", () => {
  it("leaves nothing behind when the scanner finally lets go", async () => {
    // Giving up on a write does not stop it: no fs API revokes a request a
    // filter driver is sitting on. The start fails, the job's directory is
    // deleted — and then, minutes later, the abandoned write resumes. Its first
    // step is `mkdir(recursive)`, so it used to RE-CREATE the id-shaped
    // directory and drop a wrapper.cmd (or a `.tmp`) into it: a directory with
    // no meta.json, which pruneUnreadable then keeps for the whole retention
    // window.
    let letGo!: () => void;
    atomic.stall = new Promise<void>((resolve) => {
      letGo = resolve;
    });
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

    const started: Started = manager.start({ command: "echo hi", gpuIndex: 0 }).then(
      (ok) => ({ ok }),
      (err) => ({ err }),
    );
    await vi.advanceTimersByTimeAsync(scripts.JOB_SCRIPT_IO_TIMEOUT_MS + 1_000);
    const { err } = await started;
    expect(err).toBeInstanceOf(jobManagerModule.JobError);
    vi.useRealTimers();

    const idsNow = (): string[] => fs.readdirSync(jobsRoot).filter((entry) => /^[0-9a-f]{16}$/.test(entry));
    expect(idsNow()).toEqual([]);

    // The scanner lets go. Everything the abandoned write does from here happens
    // after the job it belonged to stopped existing.
    letGo();
    atomic.stall = null;
    // Two macrotask turns: enough for the whole mkdir → write → rename chain to
    // run to completion (or to undo itself).
    await new Promise((resolve) => setTimeout(resolve, 20));

    expect(idsNow()).toEqual([]);
    expect(manager.list({})).toMatchObject({ ok: true, jobs: [] });
  });
});

describe("a filesystem that never answers", () => {
  it("fails the start with the named cause instead of wedging the window", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    atomic.hang = true;

    const started: Started = manager.start({ command: "echo hi", gpuIndex: 0 }).then(
      (ok) => ({ ok }),
      (err) => ({ err }),
    );
    await vi.advanceTimersByTimeAsync(scripts.JOB_SCRIPT_IO_TIMEOUT_MS + 1_000);
    const { err } = await started;

    // Same family as a refused write, because it is the same event: an on-access
    // scanner holding our file open, told a moment earlier.
    expect(err).toBeInstanceOf(jobManagerModule.JobError);
    const failure = err as InstanceType<JobManagerModule["JobError"]>;
    expect(failure.code).toBe(JOB_SCRIPT_REMOVED_ERROR);
    expect(failure.detail).toContain("timed out");
    expect(spawned.count).toBe(0);

    vi.useRealTimers();
    atomic.hang = false;
    // The two things an unbounded hang would have kept forever.
    expect(fs.existsSync(path.join(jobsRoot, gpuLockFileName(0)))).toBe(false);
    expect(manager.list({})).toMatchObject({ ok: true, jobs: [] });
    expect((await manager.start({ command: "echo again", gpuIndex: 0 })).ok).toBe(true);
  });
});
