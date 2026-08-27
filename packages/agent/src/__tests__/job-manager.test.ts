import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  gpuLockFileName,
  JOB_ID_PATTERN,
  JOB_LIST_DEFAULT_ENTRIES,
  JOB_LOGS_DEFAULT_TAIL_LINES,
  JOB_LOGS_MAX_SLICE_BYTES,
  JOB_MAX_CONCURRENT,
  JOB_MAX_GPU_INDEX,
  JOB_MAX_LOG_BYTES,
  JOB_RETENTION_MS,
  JOB_WIRE_MAX_COMMAND_CHARS,
  JOB_WIRE_MAX_LIST_ENTRIES,
  JOB_WIRE_MAX_NAME_CHARS,
  KILL_ESCALATION_MS,
  MAX_EPOCH_MS,
} from "@aicommander/protocol";
import type { JobLogs, JobRpcResult, JobStatus, JobSummary } from "@aicommander/protocol";

/**
 * The only way to make a meta.json write fail on demand. Everything else in
 * atomic-file.ts stays real — the point is a disk that rejects OUR record, not a
 * different write path. `fail` returns true for the writes that should throw.
 */
const metaWrite = vi.hoisted(() => ({
  fail: null as null | ((dir: string, fileName: string) => boolean),
  /**
   * A side effect to run BEFORE a write, for the one thing no test can otherwise
   * reach: the window inside start() between the cwd check and the spawn. Both
   * happen in one synchronous call, so a test cannot get in between from outside
   * — but every job's script files are written in that window, which makes this
   * the real interception point rather than a simulation of one. Distinct from
   * `fail` on purpose: this observes and disturbs the world, it does not make the
   * write itself fail.
   */
  before: null as null | ((dir: string, fileName: string) => void),
}));
vi.mock("../atomic-file.js", async () => {
  const actual = await vi.importActual<typeof import("../atomic-file.js")>("../atomic-file.js");
  return {
    ...actual,
    atomicWriteUtf8: (dir: string, fileName: string, contents: string): void => {
      metaWrite.before?.(dir, fileName);
      if (metaWrite.fail?.(dir, fileName)) throw new Error("read-only file system");
      actual.atomicWriteUtf8(dir, fileName, contents);
    },
  };
});

/**
 * The TERM fill, OBSERVED rather than inferred from what a job printed.
 *
 * Inferring it is impossible on this path, and the way it fails is a trap worth
 * naming: /bin/sh on macOS is bash, and bash sets `TERM=dumb` itself when it
 * starts with none — so a job asked what TERM it saw answers "dumb" whether or
 * not buildEnv filled anything, even with the runner's own TERM removed first.
 * (Under vitest it never is removed anyway: the runner exports TERM=dumb, and
 * the job inherits it.) The env HANDED TO THE SPAWN is the only place the
 * difference is visible, so that is what this wrapper captures: the real
 * function still runs, and the object it mutated — the same one `spawn` receives
 * — is kept for the assertion.
 *
 * The rest of login-shell-path.js stays real; PATH and locale are asserted
 * through actual jobs elsewhere in this file.
 */
const termFill = vi.hoisted(() => ({ envs: [] as NodeJS.ProcessEnv[] }));
vi.mock("../login-shell-path.js", async () => {
  const actual =
    await vi.importActual<typeof import("../login-shell-path.js")>("../login-shell-path.js");
  return {
    ...actual,
    applyNonInteractiveTerm: (env: NodeJS.ProcessEnv): void => {
      actual.applyNonInteractiveTerm(env);
      termFill.envs.push(env);
    },
  };
});

/**
 * The identity probe, with its two real-world failure shapes available on
 * demand: it can come back empty (a momentarily unreadable /proc, a `ps` that
 * could not fork) and it can take a while (a loaded box, or the timeout in
 * proc-identity.ts running out). Off by default, so every other test drives the
 * real probe unchanged.
 */
const procIdentity = vi.hoisted(() => ({
  fail: false,
  delayMs: 0,
  /**
   * A fixed answer for the probe, for tests that need a SPECIFIC token (the
   * errno-routing group compares against seeded identities on pids no real
   * probe could read). Null keeps the real/fail behaviour below.
   */
  override: null as null | ((pid: number) => string | null),
}));
vi.mock("../proc-identity.js", async () => {
  const actual = await vi.importActual<typeof import("../proc-identity.js")>("../proc-identity.js");
  return {
    ...actual,
    readProcIdentity: (pid: number): string | null => {
      // Synchronous on purpose: the real probe blocks the calling thread too.
      if (procIdentity.delayMs > 0) {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, procIdentity.delayMs);
      }
      if (procIdentity.override) return procIdentity.override(pid);
      return procIdentity.fail ? null : actual.readProcIdentity(pid);
    },
  };
});

import {
  JOB_COMMAND_ENV,
  JOB_CWD_ENV,
  JOB_EXIT_PATH_ENV,
  JOB_LOG_PATH_ENV,
  JobError,
  JobManager,
  buildWindowsJobCommandScript,
  WINDOWS_JOB_WRAPPER,
  buildJobScript,
  getJobManager,
  resetJobManagerForTests,
  resolveJobsRoot,
} from "../job-manager.js";

// Like executor.test.ts, the job tests drive a REAL shell: the wrapper script,
// the detached process group and the `exit` file are the feature, so mocking the
// process boundary away would test nothing. That makes the shell-dependent
// groups POSIX-only — buildJobScript is the POSIX wrapper and nothing else runs
// it, while Windows has a wrapper of its own (the WINDOWS_JOB_WRAPPER +
// WINDOWS_JOB_COMMAND_SCRIPT pair) and taskkill — so those groups are skipped
// with a reason rather than asserted falsely. Windows coverage belongs in
// describeOnWindows below, against that pair; buildJobScript is not the Windows
// implementation and asserting on it proves nothing about Windows.
const describeOnPosix = describe.skipIf(process.platform === "win32");
/**
 * The mirror of describeOnPosix, for the assertions that are only meaningful
 * when the Windows wrapper actually RUNS: nested `cmd.exe`, a detached start and
 * the shell's own `>>` redirect are the mechanism under test, and none of them
 * can be exercised by comparing a built command string.
 *
 * Stated plainly because it matters: this block is SKIPPED on macOS and Linux,
 * so a green macOS run says NOTHING about it. What executes it is the
 * `test-windows` job in .github/workflows/ci.yml (added in 6efee15), which runs
 * this whole file on windows-latest — so every Windows behaviour that must not
 * regress belongs in HERE rather than under a string assertion that would pass
 * on any platform. The first Windows defect survived exactly that mistake: its
 * assertions sat in a POSIX-gated group and never ran anywhere.
 */
const describeOnWindows = describe.runIf(process.platform === "win32");
// For a single assertion inside an otherwise platform-neutral group — POSIX
// process-group signalling is the one that has no Windows equivalent to assert.
const itOnPosix = it.skipIf(process.platform === "win32");
// resolveJobHome only decides anything for a ROOT agent; a suite running as root
// would take a different branch than the one these tests describe.
const itUnlessRoot = it.skipIf(typeof process.getuid === "function" && process.getuid() === 0);

/**
 * A pid that can never name a live process: Linux caps pid_max at 2^22
 * (4,194,304) and macOS stops far lower, so `process.kill(DEAD_PID, 0)` always
 * throws. Using a constant out-of-range pid instead of a recently-exited one
 * keeps the "process is gone" branch free of any pid-reuse race.
 */
const DEAD_PID = 4_194_305;

/** A job that stays alive for the whole test but costs one sleeping process. */
const LONG_RUNNING = "sleep 30";

/** Mirrors the private on-disk record so tests can seed state without spawning. */
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
  gpuIndex: number | null;
  pid: number | null;
  procIdentity: string | null;
  /** Agent-local; absent on every ordinary job. See JobMeta.retiring. */
  retiring?: boolean;
  truncatedAt: number | null;
}

const ENV_DIR_VAR = "AICOMMANDER_CONFIG_DIR";
let savedEnvDir: string | undefined;
let tmpBase: string;
let jobsRoot: string;
let manager: JobManager;

beforeEach(() => {
  metaWrite.fail = null;
  metaWrite.before = null;
  procIdentity.fail = false;
  procIdentity.delayMs = 0;
  procIdentity.override = null;
  // resolveJobsRoot() consults AICOMMANDER_CONFIG_DIR, so a value inherited from
  // the developer's shell would silently redirect the default-path tests.
  savedEnvDir = process.env[ENV_DIR_VAR];
  delete process.env[ENV_DIR_VAR];
  tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), "aic-jobs-"));
  jobsRoot = path.join(tmpBase, "jobs");
  manager = new JobManager({ jobsRoot });
});

afterEach(async () => {
  metaWrite.fail = null;
  metaWrite.before = null;
  procIdentity.fail = false;
  procIdentity.delayMs = 0;
  procIdentity.override = null;
  vi.useRealTimers();
  vi.restoreAllMocks();
  resetJobManagerForTests();
  killAllJobProcesses(jobsRoot);
  // A dying job's `exit` handler re-writes meta.json (and re-creates its
  // directory on the way), so give the reaper a tick before removing the tree.
  await new Promise((resolve) => setTimeout(resolve, 25));
  if (savedEnvDir === undefined) delete process.env[ENV_DIR_VAR];
  else process.env[ENV_DIR_VAR] = savedEnvDir;
  fs.rmSync(tmpBase, { recursive: true, force: true });
});

// ── Helpers ──────────────────────────────────────────────────────────────────

function expectJob(result: JobRpcResult): JobSummary {
  if (!result.ok || result.kind !== "job") {
    throw new Error(`expected a job result, got ${JSON.stringify(result)}`);
  }
  return result.job;
}

function expectJobs(result: JobRpcResult): JobSummary[] {
  if (!result.ok || result.kind !== "jobs") {
    throw new Error(`expected a jobs result, got ${JSON.stringify(result)}`);
  }
  return result.jobs;
}

function expectLogs(result: JobRpcResult): JobLogs {
  if (!result.ok || result.kind !== "logs") {
    throw new Error(`expected a logs result, got ${JSON.stringify(result)}`);
  }
  return result.logs;
}

function expectRefusal(result: JobRpcResult): Extract<JobRpcResult, { ok: false }> {
  if (result.ok) throw new Error(`expected a refusal, got ${JSON.stringify(result)}`);
  return result;
}

function startJob(req: Parameters<JobManager["start"]>[0]): JobSummary {
  return expectJob(manager.start(req));
}

function jobDir(jobId: string): string {
  return path.join(jobsRoot, jobId);
}

/**
 * A syntactically VALID identity token that names a DIFFERENT process: same
 * canonical kind as the real one, different value. Recycled-pid tests must use
 * this rather than an arbitrary string — an unparseable token is the LEGACY
 * case, which deliberately reads "unverifiable" (hold), not "gone".
 */
function foreignIdentity(token: string): string {
  const instant = /^(epoch|utc):(\d+)$/.exec(token);
  if (instant) return `${instant[1]}:${Number(instant[2]) + 1}`;
  if (/^\d+$/.test(token)) return String(Number(token) + 1);
  throw new Error(`unrecognised canonical identity token: ${token}`);
}

function readMetaFile(jobId: string): SeededMeta {
  return JSON.parse(fs.readFileSync(path.join(jobDir(jobId), "meta.json"), "utf8")) as SeededMeta;
}

function logPath(jobId: string): string {
  return path.join(jobDir(jobId), "output.log");
}

function exitPath(jobId: string): string {
  return path.join(jobDir(jobId), "exit");
}

function readLog(jobId: string): string {
  try {
    return fs.readFileSync(logPath(jobId), "utf8");
  } catch {
    return "";
  }
}

/** Read a window of a file without pulling the whole (possibly huge) thing in. */
function readAt(target: string, position: number, length: number): string {
  const fd = fs.openSync(target, "r");
  try {
    const buffer = Buffer.alloc(length);
    const read = fs.readSync(fd, buffer, 0, length, position);
    return buffer.subarray(0, read).toString("utf8");
  } finally {
    fs.closeSync(fd);
  }
}

function fileSize(target: string): number {
  try {
    return fs.statSync(target).size;
  } catch {
    return 0;
  }
}

/**
 * Reach a log size the cap cares about without writing that many bytes:
 * ftruncate extends the file SPARSELY, so `statSync().size` — the only thing the
 * cap check looks at — is where we want it while no blocks are allocated.
 */
function inflateLog(jobId: string, bytes: number): void {
  fs.truncateSync(logPath(jobId), bytes);
  expect(fileSize(logPath(jobId))).toBe(bytes);
}

/**
 * Longest the truncation notice may be. The cut-off is the cap plus that one
 * notice, and the tests assert the bound rather than duplicating the exact
 * wording — the promise is "never materially past 256 MiB", not a byte count.
 */
const MAX_NOTICE_BYTES = 512;

/** What a caller may ever page through: the cap, plus at most the notice. */
function expectServedWithinCap(logBytes: number): void {
  expect(logBytes).toBeGreaterThan(JOB_MAX_LOG_BYTES);
  expect(logBytes).toBeLessThanOrEqual(JOB_MAX_LOG_BYTES + MAX_NOTICE_BYTES);
}

/** Poll a synchronous condition instead of sleeping for a fixed worst case. */
async function waitFor(what: string, predicate: () => boolean, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (predicate()) return;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

/**
 * Waits for an exit file the manager will actually ACCEPT, not merely one that
 * exists: the wrapper's `> "$exit"` creates the file empty and only then writes
 * the code into it, so existence alone leaves a window in which readExitFile
 * still returns null and refresh keeps calling the job `running`. Narrow, but a
 * loaded CI box widens it — matching the same shape readExitFile requires closes
 * it for every caller here.
 */
function waitForExit(jobId: string): Promise<void> {
  return waitFor(`job ${jobId} to write its exit file`, () =>
    /^-?\d{1,5}$/.test(readTrimmed(exitPath(jobId))),
  );
}

/** File contents with surrounding whitespace gone; "" when it is not readable. */
function readTrimmed(target: string): string {
  try {
    return fs.readFileSync(target, "utf8").trim();
  } catch {
    return "";
  }
}

/** Write a job directory directly, so recovery/limit branches need no processes. */
function seedJob(overrides: Partial<SeededMeta> & { log?: string | Buffer; exit?: string } = {}): string {
  const { log, exit, ...metaOverrides } = overrides;
  const jobId = metaOverrides.jobId ?? randomBytes(8).toString("hex");
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
    startedAt: Date.now() - 1_000,
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
  if (exit !== undefined) fs.writeFileSync(exitPath(jobId), exit);
  return jobId;
}

/** SIGKILL every recorded job's process GROUP so no test leaks a background loop. */
function killAllJobProcesses(root: string): void {
  let entries: string[];
  try {
    entries = fs.readdirSync(root);
  } catch {
    return;
  }
  for (const entry of entries) {
    try {
      const meta = JSON.parse(
        fs.readFileSync(path.join(root, entry, "meta.json"), "utf8"),
      ) as { pid?: number | null };
      if (typeof meta.pid !== "number" || meta.pid === DEAD_PID) continue;
      try {
        process.kill(-meta.pid, "SIGKILL");
      } catch {
        // Already gone.
      }
    } catch {
      // Not a job directory.
    }
  }
}

// Built with the protocol's own name builder, not a `gpu-${index}.lock` template:
// gpuLockFileName is documented as the ONLY place a lock name is built, and a
// test that mints lock names its own way stops testing the names the agent mints.
function gpuLockPath(index: number): string {
  return path.join(jobsRoot, gpuLockFileName(index));
}

/** Every job directory currently in the jobs root, ignoring locks and `home`. */
function jobDirNames(): string[] {
  try {
    return fs.readdirSync(jobsRoot).filter((entry) => JOB_ID_PATTERN.test(entry));
  } catch {
    return [];
  }
}

// ── resolveJobsRoot / getJobManager ──────────────────────────────────────────

describe("resolveJobsRoot", () => {
  it("puts jobs under an explicitly supplied config directory", () => {
    expect(resolveJobsRoot("/opt/aic-data")).toBe(path.join("/opt/aic-data", "jobs"));
  });

  it("honours AICOMMANDER_CONFIG_DIR when no config directory is passed", () => {
    const durable = path.join(tmpBase, "durable");
    process.env[ENV_DIR_VAR] = durable;
    expect(resolveJobsRoot()).toBe(path.join(durable, "jobs"));
  });

  it("returns an absolute per-machine path with no override at all", () => {
    // The exact default differs per platform/uid; what matters is that it is
    // absolute and namespaced, since it is used verbatim in path joins.
    const root = resolveJobsRoot();
    expect(path.isAbsolute(root)).toBe(true);
    expect(root.endsWith(path.join("aicommander", "jobs"))).toBe(true);
  });
});

describe("getJobManager", () => {
  it("returns the same instance for the same root and a new one after reset", () => {
    const configDir = path.join(tmpBase, "shared");
    const first = getJobManager(configDir);
    expect(getJobManager(configDir)).toBe(first);
    resetJobManagerForTests();
    expect(getJobManager(configDir)).not.toBe(first);
  });

  it("recovers the jobs root on first use", () => {
    const configDir = path.join(tmpBase, "recovered");
    const created = getJobManager(configDir);
    expect(fs.statSync(created.jobsRoot).isDirectory()).toBe(true);
  });
});

// ── Lifecycle ────────────────────────────────────────────────────────────────

describeOnPosix("job lifecycle", () => {
  it("runs a job to completion and reports exit code 0", async () => {
    const started = startJob({ command: "printf 'lifecycle-output'" });
    expect(started.status).toBe("running");
    expect(started.exitCode).toBeNull();
    expect(started.endedAt).toBeNull();

    await waitForExit(started.jobId);
    const settled = expectJob(manager.status({ jobId: started.jobId }));
    expect(settled.status).toBe("exited");
    expect(settled.exitCode).toBe(0);
    expect(settled.endedAt).not.toBeNull();
    expect(readLog(started.jobId)).toContain("lifecycle-output");
  });

  it("reports a non-zero exit code", async () => {
    // `(exit 7)` runs in a subshell so the wrapper survives to record $?.
    const started = startJob({ command: "printf 'failing' >&2; (exit 7)" });
    await waitForExit(started.jobId);
    const settled = expectJob(manager.status({ jobId: started.jobId }));
    expect(settled.status).toBe("exited");
    expect(settled.exitCode).toBe(7);
  });

  it("interleaves stdout and stderr into one output.log", async () => {
    const started = startJob({ command: "printf 'to-out'; printf 'to-err' >&2" });
    await waitForExit(started.jobId);
    const log = readLog(started.jobId);
    expect(log).toContain("to-out");
    expect(log).toContain("to-err");
  });

  it("runs in a per-job workspace when no cwd was given", async () => {
    const started = startJob({ command: "pwd" });
    await waitForExit(started.jobId);
    // macOS resolves the temp dir through a symlink, so compare real paths.
    const workspace = fs.realpathSync(path.join(jobDir(started.jobId), "workspace"));
    expect(readLog(started.jobId).trim()).toBe(workspace);
  });

  it("runs in a caller-supplied cwd", async () => {
    const elsewhere = path.join(tmpBase, "elsewhere");
    fs.mkdirSync(elsewhere);
    const started = startJob({ command: "pwd", cwd: elsewhere });
    await waitForExit(started.jobId);
    expect(readLog(started.jobId).trim()).toBe(fs.realpathSync(elsewhere));
  });

  it("passes caller environment through to the job", async () => {
    const started = startJob({
      command: 'printf %s "$AIC_JOB_SENTINEL"',
      env: { AIC_JOB_SENTINEL: "job-env-value" },
    });
    await waitForExit(started.jobId);
    expect(readLog(started.jobId)).toBe("job-env-value");
  });

  it("lists jobs newest first and filters by status", async () => {
    const finished = startJob({ command: "printf done" });
    await waitForExit(finished.jobId);
    const running = startJob({ command: LONG_RUNNING });

    const all = expectJobs(manager.list({}));
    expect(all.map((job) => job.jobId)).toEqual([running.jobId, finished.jobId]);

    const exited = expectJobs(manager.list({ status: "exited" }));
    expect(exited.map((job) => job.jobId)).toEqual([finished.jobId]);
    expect(exited[0].exitCode).toBe(0);
  });

  it("reports logBytes so a caller can page without a probe read", async () => {
    const started = startJob({ command: "printf '0123456789'" });
    await waitForExit(started.jobId);
    const settled = expectJob(manager.status({ jobId: started.jobId }));
    expect(settled.logBytes).toBe(10);
    expect(settled.truncated).toBe(false);
  });

  it("normalizes the job name and falls back to a stable default", () => {
    // A name is echoed back to the caller (and thence to an LLM), so control
    // characters are flattened to spaces rather than passed through verbatim.
    const named = startJob({ command: "printf x", name: "\ttrain\nrun " });
    expect(named.name).toBe("train run");

    const long = startJob({ command: "printf x", name: "n".repeat(200) });
    expect(long.name).toHaveLength(64);

    const unnamed = startJob({ command: "printf x" });
    expect(unnamed.name).toBe(`job-${unnamed.jobId.slice(0, 8)}`);
  });

  it("refuses a request that is malformed IN ITSELF with invalid_request", () => {
    // These faults are decided from the request alone — no machine state is
    // involved and no machine could accept them. They must therefore come back on
    // the REFUSAL channel (which the relay maps to 400 "fix the request"), not as
    // a JobError, which the relay can only report as "the machine failed" (502)
    // and which invites a retry that can never succeed.
    const cases: Array<[Parameters<JobManager["start"]>[0], RegExp]> = [
      [{ command: "   " }, /non-empty command/i],
      [{ command: "x".repeat(70_000) }, /too long/i],
      [{ command: "printf x", cwd: "relative/path" }, /absolute path/i],
    ];
    for (const [req, message] of cases) {
      const refusal = expectRefusal(manager.start(req));
      expect(refusal.reason, JSON.stringify(Object.keys(req))).toBe("invalid_request");
      expect(refusal.message).toMatch(message);
    }
    // Every refusal above must clean up its half-created directory.
    expect(expectJobs(manager.list({}))).toHaveLength(0);
  });

  it("keeps a cwd that is missing on THIS machine a machine fault, not a caller fault", () => {
    // Deliberately NOT invalid_request: the same request succeeds once the volume
    // is mounted, and the check also fails for a directory that exists but the
    // agent's user cannot stat. Calling that a malformed request would tell the
    // operator to fix a path that is already correct.
    expect(() => manager.start({ command: "printf x", cwd: path.join(tmpBase, "nope") })).toThrow(
      JobError,
    );
    expect(expectJobs(manager.list({}))).toHaveLength(0);
  });
});

// ── HOME ─────────────────────────────────────────────────────────────────────

describeOnPosix("job HOME", () => {
  itUnlessRoot("leaves HOME alone for a non-root agent, whatever cwd says", async () => {
    // The owner-derived HOME exists only for a ROOT agent putting model caches
    // somewhere a user can find them. A non-root agent already runs as the right
    // user, so a relay-supplied cwd must change nothing at all.
    const elsewhere = path.join(tmpBase, "someone-elses-tree");
    fs.mkdirSync(elsewhere);
    const started = startJob({ command: 'printf %s "$HOME"', cwd: elsewhere });
    await waitForExit(started.jobId);
    expect(readLog(started.jobId)).toBe(process.env["HOME"]);
  });

  it("lets an explicit caller HOME win", async () => {
    const chosen = path.join(tmpBase, "chosen-home");
    fs.mkdirSync(chosen);
    const started = startJob({ command: 'printf %s "$HOME"', env: { HOME: chosen } });
    await waitForExit(started.jobId);
    expect(readLog(started.jobId)).toBe(chosen);
  });

  it("keeps the exit-marker path out of a caller's reach", async () => {
    // A relay message must never steer where a root process writes: our value is
    // applied after the caller's, so the marker lands in the job directory.
    const decoy = path.join(tmpBase, "decoy-exit");
    const started = startJob({ command: "exit 2", env: { [JOB_EXIT_PATH_ENV]: decoy } });
    await waitForExit(started.jobId);
    expect(fs.existsSync(decoy)).toBe(false);
    expect(expectJob(manager.status({ jobId: started.jobId })).exitCode).toBe(2);
  });
});

// ── Restart recovery ─────────────────────────────────────────────────────────

describeOnPosix("restart recovery", () => {
  it("(a) settles a job from its exit file when the agent was down", () => {
    const jobId = seedJob({ status: "running", exit: "3" });

    const restarted = new JobManager({ jobsRoot });
    restarted.recover();

    expect(readMetaFile(jobId).status).toBe("exited");
    const summary = expectJob(restarted.status({ jobId }));
    expect(summary.status).toBe("exited");
    expect(summary.exitCode).toBe(3);
    expect(summary.endedAt).not.toBeNull();
  });

  it("(a) accepts a negative exit code and ignores a garbage exit file", () => {
    const negative = seedJob({ status: "running", exit: "-1" });
    const garbage = seedJob({ status: "running", exit: "not-a-code" });

    const restarted = new JobManager({ jobsRoot });
    restarted.recover();

    expect(expectJob(restarted.status({ jobId: negative })).exitCode).toBe(-1);
    // An unparseable exit file is no evidence at all: the pid is gone, so the
    // job is `unknown`, never a fabricated success.
    const bad = expectJob(restarted.status({ jobId: garbage }));
    expect(bad.status).toBe("unknown");
    expect(bad.exitCode).toBeNull();
  });

  it("(b) adopts a job whose pid is still alive as running", async () => {
    const started = startJob({ command: LONG_RUNNING });

    // A fresh manager on the same root is exactly what an agent restart sees.
    const restarted = new JobManager({ jobsRoot });
    restarted.recover();

    const adopted = expectJob(restarted.status({ jobId: started.jobId }));
    expect(adopted.status).toBe("running");
    expect(adopted.exitCode).toBeNull();
    expect(adopted.endedAt).toBeNull();
    // And it is genuinely the process we started, not a stale record.
    expect(() => process.kill(readMetaFile(started.jobId).pid as number, 0)).not.toThrow();
  });

  it("(c) reports a job with no exit file and a dead pid as unknown, never as success", () => {
    const jobId = seedJob({ status: "running" }); // pid = DEAD_PID, no exit file

    const restarted = new JobManager({ jobsRoot });
    restarted.recover();

    const summary = expectJob(restarted.status({ jobId }));
    expect(summary.status).toBe("unknown");
    expect(summary.status).not.toBe("exited");
    expect(summary.exitCode).toBeNull();
    expect(summary.endedAt).not.toBeNull();
  });

  it("(b) rejects a recycled pid via the recorded process start time", () => {
    // Every POSIX platform records an identity now: Linux from /proc, macOS from
    // `ps -o lstart=`. Before that, macOS accepted ANY live pid, so a recycled
    // one was adopted as the job.
    const started = startJob({ command: LONG_RUNNING });
    const meta = readMetaFile(started.jobId);
    expect(meta.procIdentity).toBeTruthy();

    // Same live pid, a VALID start time that is not ours ⇒ someone else's
    // process. Valid on purpose: only a parseable token may ever mean "gone".
    fs.writeFileSync(
      path.join(jobDir(started.jobId), "meta.json"),
      JSON.stringify({ ...meta, procIdentity: foreignIdentity(meta.procIdentity as string) }, null, 2),
    );

    const restarted = new JobManager({ jobsRoot });
    const summary = expectJob(restarted.status({ jobId: started.jobId }));
    expect(summary.status).toBe("unknown");
    expect(summary.exitCode).toBeNull();
  });

  it("(b) holds a live pid it cannot corroborate instead of declaring it finished", () => {
    // A live pid we cannot corroborate must fail closed — and for a READ, failing
    // closed is holding, not settling: kill(pid, 0) succeeded, so a process IS
    // there, and calling that job finished would release its card and make it
    // uncancellable. The record keeps saying `running` until the pid is gone,
    // which is the one thing about it that is decidable.
    const started = startJob({ command: LONG_RUNNING });
    const meta = readMetaFile(started.jobId);
    fs.writeFileSync(
      path.join(jobDir(started.jobId), "meta.json"),
      JSON.stringify({ ...meta, procIdentity: null }, null, 2),
    );
    const summary = expectJob(new JobManager({ jobsRoot }).status({ jobId: started.jobId }));
    expect(summary.status).toBe("running");
    // What it must never be is a success, or over: no exit code was observed.
    expect(summary.exitCode).toBeNull();
    expect(summary.endedAt).toBeNull();
  });

  it("(b) holds a live pid whose recorded identity is a LEGACY token, keeping its GPU lock", () => {
    // Records written by the pre-canonical agent hold the probe's raw rendering
    // (macOS lstart text, wmic's CIM form). The current probe now answers in
    // the canonical form, so raw-string comparison reads "different process" —
    // a confident, false "gone" — for a job that is alive and on its card. A
    // legacy token must instead be the OPEN question it is: the job stays
    // running and the lock stays held until the pid itself dies.
    const gpuIndex = 3;
    const jobId = seedJob({
      status: "running",
      pid: process.pid, // provably alive, and the probe CAN describe it
      procIdentity: "Tue Aug 4 22:36:20 2026", // pre-canonical macOS rendering
      gpuIndex,
    });
    const lockPath = gpuLockPath(gpuIndex);
    fs.writeFileSync(lockPath, jobId);

    const summary = expectJob(new JobManager({ jobsRoot }).status({ jobId }));
    expect(summary.status).toBe("running");
    expect(summary.endedAt).toBeNull();
    // The defect's payload: settling on a format mismatch released the card
    // under a live training run, letting a second job collide onto it.
    expect(fs.existsSync(lockPath)).toBe(true);
  });

  it("(b) holds a live pid whose recorded identity is a locally-parsed epoch token, keeping its GPU lock", () => {
    // Defect path 4's upgrade population. Every macOS record written before the
    // zone fix holds `epoch:<ms>` minted by inverting ps's LOCAL rendering with
    // the runtime's cached zone — a value that is shifted from the truth exactly
    // when a zone change or DST-ambiguous hour was in play. The probe now
    // answers in the zone-free `utc:` kind, so on macOS a fresh check of the
    // SAME live process can no longer confirm such a token — and before the
    // kind split it would have CONTRADICTED it: two parseable epochs, different
    // values, a confident "mismatch" → "gone" that settled every running job on
    // the first upgraded poll and released its card. The kind split makes it the
    // open question it is: held, lock kept, until the pid itself dies. (On
    // Linux the probe answers ticks, which lands in the same cross-kind hold;
    // the settle-on-mismatch half is exercised on macOS, where the probe mints
    // an instant token.)
    const gpuIndex = 13;
    const jobId = seedJob({
      status: "running",
      pid: process.pid, // provably alive, and the probe CAN describe it
      procIdentity: `epoch:${Date.UTC(2026, 0, 1)}`, // legacy local inversion; not this process's start
      gpuIndex,
    });
    const lockPath = gpuLockPath(gpuIndex);
    fs.writeFileSync(lockPath, jobId);

    const summary = expectJob(new JobManager({ jobsRoot }).status({ jobId }));
    expect(summary.status).toBe("running");
    expect(summary.exitCode).toBeNull();
    expect(summary.endedAt).toBeNull();
    // The payload assertion: the live job kept its reservation.
    expect(fs.existsSync(lockPath)).toBe(true);
    expect(fs.readFileSync(lockPath, "utf8")).toBe(jobId);
  });

  it("never signals a pid it cannot confirm is ours", async () => {
    // The dangerous half of pid reuse: cancel signals a process GROUP, as root.
    // A recycled pid must cost an uncancellable job, never a foreign process
    // tree. (Before the fix, macOS killed whatever now held the pid.)
    const tickFile = path.join(tmpBase, "ticks-foreign");
    fs.writeFileSync(tickFile, "");
    const started = startJob({
      command: 'while :; do printf x >> "$AIC_JOB_TICK"; sleep 0.05; done',
      env: { AIC_JOB_TICK: tickFile },
    });
    await waitFor("the ticker to start writing", () => fileSize(tickFile) > 0);

    const meta = readMetaFile(started.jobId);
    fs.writeFileSync(
      path.join(jobDir(started.jobId), "meta.json"),
      JSON.stringify({ ...meta, procIdentity: foreignIdentity(meta.procIdentity as string) }, null, 2),
    );

    expect(expectJob(manager.cancel({ jobId: started.jobId })).status).toBe("unknown");

    // The process behind that pid is untouched — which is the point.
    await new Promise((resolve) => setTimeout(resolve, 250));
    const before = fileSize(tickFile);
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(fileSize(tickFile)).toBeGreaterThan(before);

    // Clean up by hand: the meta the reaper reads no longer identifies the job.
    process.kill(-(meta.pid as number), "SIGKILL");
  });

  it("deletes job directories older than the retention window and keeps recent ones", () => {
    const stale = seedJob({
      status: "exited",
      exitCode: 0,
      endedAt: Date.now() - JOB_RETENTION_MS - 60_000,
    });
    const recent = seedJob({ status: "exited", exitCode: 0, endedAt: Date.now() });

    new JobManager({ jobsRoot }).recover();

    expect(fs.existsSync(jobDir(stale))).toBe(false);
    expect(fs.existsSync(jobDir(recent))).toBe(true);
  });

  it("keeps an unreadable job directory until it is older than the retention window", () => {
    const fresh = randomBytes(8).toString("hex");
    const ancient = randomBytes(8).toString("hex");
    for (const id of [fresh, ancient]) {
      fs.mkdirSync(jobDir(id), { recursive: true });
      fs.writeFileSync(path.join(jobDir(id), "meta.json"), "{ truncated json");
    }
    const old = new Date(Date.now() - JOB_RETENTION_MS - 60_000);
    fs.utimesSync(jobDir(ancient), old, old);

    new JobManager({ jobsRoot }).recover();

    // A half-created directory cannot be classified, so it survives until it is
    // far too old to be a job still being set up.
    expect(fs.existsSync(jobDir(fresh))).toBe(true);
    expect(fs.existsSync(jobDir(ancient))).toBe(false);
  });

  it("ignores directories and files that are not job ids", () => {
    fs.mkdirSync(path.join(jobsRoot, "not-a-job-id"), { recursive: true });
    fs.mkdirSync(path.join(jobsRoot, "home"), { recursive: true });
    const kept = seedJob({ status: "exited", exitCode: 0, endedAt: Date.now() });

    const restarted = new JobManager({ jobsRoot });
    restarted.recover();

    expect(fs.existsSync(path.join(jobsRoot, "not-a-job-id"))).toBe(true);
    expect(expectJobs(restarted.list({})).map((job) => job.jobId)).toEqual([kept]);
  });

  it("never throws when the jobs root is unusable", () => {
    const asFile = path.join(tmpBase, "root-is-a-file");
    fs.writeFileSync(asFile, "not a directory");
    const broken = new JobManager({ jobsRoot: asFile });
    expect(() => broken.recover()).not.toThrow();
    expect(expectJobs(broken.list({}))).toEqual([]);
  });
});

// ── Retention on a long-lived agent ──────────────────────────────────────────

describe("retention", () => {
  /** Pretend the agent has been up for `ms` — the NAS/GPU-box case. */
  function ageTheAgentBy(ms: number): void {
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + ms });
  }

  const PAST_RETENTION = JOB_RETENTION_MS + 60 * 60 * 1000 + 60_000;

  it("reclaims expired jobs while it is running, not only at startup", () => {
    const live = new JobManager({ jobsRoot });
    live.recover(); // the only prune the agent ever used to run
    const stale = seedJob({ status: "exited", exitCode: 0, endedAt: Date.now() });

    ageTheAgentBy(PAST_RETENTION);
    // Seeded after the clock moved, so it is inside the window.
    const recent = seedJob({ status: "exited", exitCode: 0, endedAt: Date.now() });

    expectJobs(live.list({}));

    expect(fs.existsSync(jobDir(stale))).toBe(false);
    expect(fs.existsSync(jobDir(recent))).toBe(true);
  });

  it("reclaims expired jobs when the next job starts", () => {
    const live = new JobManager({ jobsRoot });
    live.recover();
    const stale = seedJob({ status: "exited", exitCode: 0, endedAt: Date.now() });

    ageTheAgentBy(PAST_RETENTION);
    expectJob(live.start({ command: "printf x" }));

    expect(fs.existsSync(jobDir(stale))).toBe(false);
  });

  it("keeps a job that ended but has not been settled yet", () => {
    // endedAt is null until someone looks, and a prune must never guess: a job
    // whose meta still says "running" survives until a read settles it.
    const unsettled = seedJob({ status: "running", exit: "0" });
    fs.utimesSync(jobDir(unsettled), new Date(0), new Date(0));

    const live = new JobManager({ jobsRoot });
    ageTheAgentBy(PAST_RETENTION);
    expectJobs(live.list({}));

    expect(fs.existsSync(jobDir(unsettled))).toBe(true);
    expect(expectJob(live.status({ jobId: unsettled })).exitCode).toBe(0);
  });

  it("does not scan the jobs root at all on the polling calls", () => {
    // status/logs/cancel are what a caller tailing a training run hits every few
    // seconds, on the thread that must still answer do:ping — so the retention
    // sweep must never land there.
    const jobId = seedJob({ status: "exited", exitCode: 0, endedAt: Date.now(), log: "x" });
    const readdir = vi.spyOn(fs, "readdirSync");

    manager.status({ jobId });
    manager.logs({ jobId });
    manager.cancel({ jobId });

    expect(readdir).not.toHaveBeenCalled();
  });
});

// ── Scaling of the walking RPCs ──────────────────────────────────────────────

describeOnPosix("cost of a full jobs root", () => {
  it("refreshes at most the page it returns", () => {
    // Liveness is the expensive part of a refresh (a stat, a kill(0) and a
    // start-time probe per job). A machine holding a retention window of jobs
    // must pay it for the entries it hands back, not for every directory.
    const overflow = 40;
    for (let i = 0; i < JOB_WIRE_MAX_LIST_ENTRIES + overflow; i++) {
      seedJob({ status: "running" }); // pid = DEAD_PID ⇒ each refresh probes it
    }
    const kill = vi.spyOn(process, "kill");

    // Asking for the largest page a caller may ask for; the clamp is what makes
    // that the wire cap and not the 240 seeded here (the DEFAULT page is far
    // smaller — see the paging tests in job-manager-paging.test.ts).
    expect(
      expectJobs(manager.list({ limit: JOB_WIRE_MAX_LIST_ENTRIES })),
    ).toHaveLength(JOB_WIRE_MAX_LIST_ENTRIES);

    expect(kill.mock.calls.length).toBeLessThanOrEqual(JOB_WIRE_MAX_LIST_ENTRIES);
  });

  it("refreshes at most the DEFAULT page when the caller named no limit", () => {
    // The page a caller actually gets when it does not ask: `list({})` walks 20,
    // not the 240 on disk. This is the case the wire default exists for, so it
    // is the one measured here — the explicit-limit case above proves the clamp.
    const seeded = JOB_LIST_DEFAULT_ENTRIES + 40;
    for (let i = 0; i < seeded; i++) {
      seedJob({ status: "running" }); // pid = DEAD_PID ⇒ each refresh probes it
    }
    const kill = vi.spyOn(process, "kill");

    const reply = manager.list({});

    expect(expectJobs(reply)).toHaveLength(JOB_LIST_DEFAULT_ENTRIES);
    expect(reply.ok && reply.kind === "jobs" ? reply.omitted : undefined).toBe(
      seeded - JOB_LIST_DEFAULT_ENTRIES,
    );
    expect(kill.mock.calls.length).toBeLessThanOrEqual(JOB_LIST_DEFAULT_ENTRIES);
  });

  it("does not re-read finished jobs on every start once a walk has covered them", () => {
    for (let i = 0; i < 50; i++) {
      seedJob({ status: "exited", exitCode: 0, endedAt: Date.now() });
    }
    // One walk observes them all as terminal; a terminal status is final, so the
    // concurrency count never needs to open those records again. The explicit
    // limit is what makes the walk cover all 50 — the default page stops at 20,
    // which is the case the test below measures.
    expectJobs(manager.list({ limit: JOB_WIRE_MAX_LIST_ENTRIES }));

    const readFileSync = vi.spyOn(fs, "readFileSync");
    startJob({ command: "printf x" });

    const reread = readFileSync.mock.calls
      .map((args) => String(args[0]))
      .filter((target) => target.endsWith("meta.json"));
    expect(reread).toEqual([]);
  });

  it("re-opens exactly the records the default page left unsettled", () => {
    // The honest cost of the 20-record default: records outside the page are
    // never settled by the walk, so the next start's concurrency count must open
    // them itself — every one of them, and on a fresh agent the whole retention
    // window. Asserted as an exact SET (not a bound) so a regression that either
    // re-opens the settled page or silently stops counting the rest is caught.
    const ids: string[] = [];
    for (let i = 0; i < JOB_LIST_DEFAULT_ENTRIES + 10; i++) {
      ids.push(seedJob({ status: "exited", exitCode: 0, endedAt: Date.now() - (100 - i) }));
    }
    // Newest-first page ⇒ the tail of the series settles, the head does not.
    const paged = expectJobs(manager.list({})).map((job) => job.jobId);
    expect(paged).toHaveLength(JOB_LIST_DEFAULT_ENTRIES);
    const unsettled = ids.filter((jobId) => !paged.includes(jobId));
    expect(unsettled).toHaveLength(10);

    // Which of the SEEDED records a start had to open. (The jobs the test itself
    // starts are alive and legitimately counted, so they are not the subject.)
    const seedsReadBy = (act: () => void): string[] => {
      const readFileSync = vi.spyOn(fs, "readFileSync");
      try {
        act();
        const read = readFileSync.mock.calls
          .map((args) => String(args[0]))
          .filter((target) => target.endsWith("meta.json"))
          .map((target) => path.basename(path.dirname(target)))
          .filter((jobId) => ids.includes(jobId));
        // De-duplicated: a start may open one record twice (the retention sweep
        // and then the concurrency count). WHICH records it had to open is the
        // question here, not how many reads each cost.
        return [...new Set(read)].sort();
      } finally {
        readFileSync.mockRestore();
      }
    };

    // The first start after a default page pays for exactly the records the page
    // did not reach — no more (the 20 it settled are skipped) and no fewer.
    expect(seedsReadBy(() => startJob({ command: "printf x" }))).toEqual([...unsettled].sort());
    // That start settled them too (countRunningJobs refreshes what it opens), so
    // the cost is paid ONCE per manager, not per start — which is the invariant
    // the explicit-limit test above protects, reached here from the default path.
    expect(seedsReadBy(() => startJob({ command: "printf x" }))).toEqual([]);

    // A fresh manager — an agent restart — starts from an empty in-memory note
    // and pays for the whole retention window again on its first start, whatever
    // any previous process had walked. That is the standing cost of the 20-record
    // default, and it is bounded by retention, not by the page.
    const restarted = new JobManager({ jobsRoot });
    const afterRestart = seedsReadBy(() => expectJob(restarted.start({ command: "printf x" })));
    expect(afterRestart).toEqual([...ids].sort());
  });
});

// ── The exit marker ──────────────────────────────────────────────────────────

describeOnPosix("exit marker", () => {
  /**
   * Run the wrapper the way a shell does, with NO agent around. This is what
   * proves the marker survives an agent restart: nothing here can fall back to
   * the child-exit handler in spawnJob.
   */
  function runWrapper(command: string): { exitCode: string | null; log: string } {
    const dir = fs.mkdtempSync(path.join(tmpBase, "wrapper-"));
    const marker = path.join(dir, "exit");
    const log = path.join(dir, "output.log");
    try {
      execFileSync("/bin/sh", ["-c", buildJobScript(command)], {
        cwd: dir,
        env: { ...process.env, [JOB_EXIT_PATH_ENV]: marker, [JOB_LOG_PATH_ENV]: log },
        // Deliberately NO usable stdout/stderr: the wrapper redirects to the log
        // itself, so capture must not depend on the handles it was started with.
        stdio: "ignore",
      });
    } catch {
      // A job that fails is the interesting case here, not an error: what the
      // wrapper RECORDED is the assertion.
    }
    return {
      exitCode: fs.existsSync(marker) ? fs.readFileSync(marker, "utf8").trim() : null,
      log: fs.existsSync(log) ? fs.readFileSync(log, "utf8") : "",
    };
  }

  it("records the code for a command that exits the shell", () => {
    expect(runWrapper("printf work; exit 5").exitCode).toBe("5");
  });

  it("records the code for a set -e abort", () => {
    expect(runWrapper("set -e\nfalse\nprintf 'never runs'").exitCode).toBe("1");
  });

  it("records the code for a command ending in a comment or a continuation", () => {
    expect(runWrapper("printf ok # trailing comment").exitCode).toBe("0");
    expect(runWrapper("printf ok \\").exitCode).toBe("0");
  });

  it("still records a plain success and a plain failure", () => {
    expect(runWrapper("printf ok").exitCode).toBe("0");
    expect(runWrapper("exit 3").exitCode).toBe("3");
  });

  // ── Capture does not depend on the handles the job was started with ────────
  //
  // The Windows defect these cover: a detached start whose command ran to
  // completion and wrote its exit marker while output.log stayed at 0 bytes,
  // because the inherited standard handles never reached the command. The
  // wrapper redirects itself, so `stdio: "ignore"` above is the same situation
  // and the assertion is platform-independent.

  it("captures stdout and stderr with no usable handles inherited", () => {
    const { exitCode, log } = runWrapper("printf out; printf err 1>&2; exit 7");
    expect(exitCode).toBe("7");
    // One stream, interleaved, exactly as a terminal would show it.
    expect(log).toBe("outerr");
  });

  it("captures the output of processes the command starts", () => {
    // A training run is never a single process; the redirect binds to the shell,
    // so everything it forks inherits it.
    expect(runWrapper("sh -c 'printf child'").log).toBe("child");
  });

  it("appends to an existing log rather than truncating it", () => {
    // Recovery re-opens a log another reader may already hold an offset into.
    const dir = fs.mkdtempSync(path.join(tmpBase, "wrapper-"));
    const log = path.join(dir, "output.log");
    fs.writeFileSync(log, "earlier\n");
    execFileSync("/bin/sh", ["-c", buildJobScript("printf later")], {
      cwd: dir,
      env: {
        ...process.env,
        [JOB_EXIT_PATH_ENV]: path.join(dir, "exit"),
        [JOB_LOG_PATH_ENV]: log,
      },
      stdio: "ignore",
    });
    expect(fs.readFileSync(log, "utf8")).toBe("earlier\nlater");
  });

  it("still records an exit code when the log cannot be opened", () => {
    // The trap is installed before the redirect precisely so that a full or
    // read-only volume costs the OUTPUT, never the outcome.
    const dir = fs.mkdtempSync(path.join(tmpBase, "wrapper-"));
    const marker = path.join(dir, "exit");
    try {
      execFileSync("/bin/sh", ["-c", buildJobScript("printf ok")], {
        cwd: dir,
        // A directory is never openable for writing, on any POSIX system.
        env: { ...process.env, [JOB_EXIT_PATH_ENV]: marker, [JOB_LOG_PATH_ENV]: dir },
        stdio: "ignore",
      });
    } catch {
      // The failure is the point.
    }
    expect(fs.existsSync(marker)).toBe(true);
  });

  it("reports the exit code of a job that exits the shell", async () => {
    const started = startJob({ command: "printf 'before exit'; exit 5" });
    await waitForExit(started.jobId);
    const settled = expectJob(manager.status({ jobId: started.jobId }));
    expect(settled.status).toBe("exited");
    expect(settled.exitCode).toBe(5);
    expect(readLog(started.jobId)).toContain("before exit");
  });

  it("reports the exit code of a set -e job that fails", async () => {
    const started = startJob({ command: "set -e\nfalse\nprintf 'never runs'" });
    await waitForExit(started.jobId);
    const settled = expectJob(manager.status({ jobId: started.jobId }));
    expect(settled.status).toBe("exited");
    expect(settled.exitCode).toBe(1);
    expect(readLog(started.jobId)).not.toContain("never runs");
  });

  it("reports the exit code of a job that replaces the shell with exec", async () => {
    // Nothing inside the shell can survive an exec, so this one is recorded by
    // the agent watching the process it spawned.
    const started = startJob({ command: "exec sh -c 'printf execed; exit 4'" });
    await waitForExit(started.jobId);
    const settled = expectJob(manager.status({ jobId: started.jobId }));
    expect(settled.status).toBe("exited");
    expect(settled.exitCode).toBe(4);
    expect(readLog(started.jobId)).toContain("execed");
  });

  it("reports the exit code of a job that installs its own EXIT trap", async () => {
    const started = startJob({ command: "trap 'printf cleanup' EXIT; exit 6" });
    await waitForExit(started.jobId);
    const settled = expectJob(manager.status({ jobId: started.jobId }));
    expect(settled.exitCode).toBe(6);
    expect(readLog(started.jobId)).toContain("cleanup");
  });

  it("never overwrites an exit code that is already recorded", async () => {
    // The wrapper ran in the process that ran the command, so its value is the
    // authoritative one; the agent's observation is only a backstop and must
    // lose every race with it. `exec` is used so nothing in the shell competes
    // with the marker planted here.
    const started = startJob({ command: "exec sh -c 'sleep 0.4; exit 4'" });
    fs.writeFileSync(exitPath(started.jobId), "9");

    await new Promise((resolve) => setTimeout(resolve, 800));
    expect(fs.readFileSync(exitPath(started.jobId), "utf8").trim()).toBe("9");
    expect(expectJob(manager.status({ jobId: started.jobId })).exitCode).toBe(9);
  });

  it("keeps the command last in the POSIX wrapper", () => {
    const posix = buildJobScript("train.py --flag \"x\"");
    // Our text is entirely BEFORE the command, so nothing the command's own text
    // does — a comment, a `\` continuation, an exit — can swallow it.
    expect(posix.startsWith("trap ")).toBe(true);
    expect(posix.trimEnd().endsWith('train.py --flag "x"')).toBe(true);
    // The paths travel in the environment, never quoted into the script.
    expect(posix).toContain(`"$${JOB_EXIT_PATH_ENV}"`);
    expect(posix).toContain(`"$${JOB_LOG_PATH_ENV}"`);
    // The trap is installed before the redirect: an unopenable log must still
    // leave an outcome behind.
    expect(posix.indexOf("trap ")).toBeLessThan(posix.indexOf("exec "));
  });

  it("keeps every varying value of OURS out of the Windows wrapper", () => {
    // Our paths travel in the environment so a jobs root containing a literal
    // `%…%` cannot be re-expanded into something else. The caller's command is
    // the deliberate exception: it is written into the command file precisely so
    // that its own `%FOO%` DOES expand, once, like `$FOO` in sh.
    expect(WINDOWS_JOB_WRAPPER).toContain(`"%${JOB_LOG_PATH_ENV}%"`);
    expect(WINDOWS_JOB_WRAPPER).toContain(`"%${JOB_EXIT_PATH_ENV}%"`);
    expect(buildWindowsJobCommandScript("whoami")).toContain(`cd /d "%${JOB_CWD_ENV}%"`);
    // cmd has no EXIT trap, so the command gets its own shell to terminate, and
    // the redirect binds to THAT shell — it captures the command and its tree.
    expect(WINDOWS_JOB_WRAPPER).toContain(
      `cmd /d /s /c .\\command.cmd >> "%${JOB_LOG_PATH_ENV}%" 2>&1`,
    );
    // No caret escaping anywhere: there is no outer shell left to escape from.
    expect(WINDOWS_JOB_WRAPPER).not.toContain("^");
    expect(buildWindowsJobCommandScript("whoami")).not.toContain("^");
  });

  it("never passes the command through the job's environment", () => {
    // It used to arrive as %AIC_JOB_COMMAND% and be reached with `call`. That
    // indirection is what broke the expansion contract — `call` re-parses only
    // the command it invokes, so anything after the first `&` kept its `%FOO%`
    // literally (measured on a real box). It also put the command string in an
    // environment every child process inherits.
    const script = buildWindowsJobCommandScript("echo A=%FOO% & echo B=%FOO%");
    expect(script).not.toContain(JOB_COMMAND_ENV);
    expect(script).not.toContain("call ");
  });

  it("puts nothing of ours on the Windows command's own line", () => {
    // The macOS-assertable half of the metacharacter defect (the executing half
    // is in the Windows group below). cmd scans a whole line for operators
    // before it starts anything, tracking quote state as it goes — so wrapping
    // the command in OUR quotes on a line that also carries `>>` let the
    // command's own first quote close ours, and a `|` or `&` after it became an
    // operator. The invariant that removes the hole is structural: the command
    // is the WHOLE last line, unquoted, sharing it with nothing of ours.
    const command = 'python.exe -c "print(\'a\', \'| b\')"';
    const lines = buildWindowsJobCommandScript(command).split("\r\n");
    expect(lines[lines.length - 2]).toBe(command);

    // …and no line that carries an operator carries user text. Over BOTH files:
    // the line that actually carries `>>` and `2>&1` lives in the wrapper, and it
    // must never grow a reference to the command. The non-empty check keeps the
    // loop honest — a filter that stops matching must fail here rather than pass
    // by finding nothing to check.
    const ourLines = [
      ...WINDOWS_JOB_WRAPPER.split("\r\n"),
      ...lines.slice(0, -2), // everything except the command's own line
    ];
    const operatorLines = ourLines.filter((line) => /[|&<>]/.test(line));
    expect(operatorLines.length).toBeGreaterThan(0);
    for (const line of operatorLines) expect(line).not.toContain("python.exe");
  });

  it("still accepts a multi-line command on POSIX", async () => {
    // The other half of the platform divergence the Windows group pins: there a
    // newline would turn the command's tail into further lines of OUR batch file
    // and is refused; here the command is embedded in a script where a newline is
    // an ordinary statement separator, callers already send small here-scripts
    // that way, and refusing them would break working jobs.
    const started = startJob({ command: "printf first\nprintf second" });
    await waitForExit(started.jobId);

    expect(expectJob(manager.status({ jobId: started.jobId })).exitCode).toBe(0);
    expect(readLog(started.jobId)).toBe("firstsecond");
  });

  it("drops ERRORLEVEL from the caller's env in either case", async () => {
    // The POSIX-observable half of the Windows forgery fix: on Windows an
    // ERRORLEVEL supplied in `env` makes the wrapper's `echo %ERRORLEVEL%` record
    // that value instead of the job's real exit code (measured), so buildEnv drops the
    // name — case-insensitively, because Windows env lookup ignores case — and
    // does so on every platform, so one request cannot mean two things. Asserted
    // by having the job PRINT what it got, which is the only way to see the env a
    // detached process was actually handed.
    const started = startJob({
      command: 'printf "[$ERRORLEVEL][$errorlevel][$AIC_KEPT]"',
      env: { ERRORLEVEL: "0", errorlevel: "0", AIC_KEPT: "kept" },
    });
    await waitForExit(started.jobId);

    // The unrelated key proves the scrub is narrow: `env` still works.
    expect(readLog(started.jobId)).toBe("[][][kept]");
  });

  it("drops an ERRORLEVEL the agent itself inherited", async () => {
    // The other source, and the worse one: `env` forges ONE job's exit code,
    // while an ERRORLEVEL in the AGENT's own environment — from a service
    // wrapper, a parent shell, an operator's `set` — would be copied into every
    // job on the machine and make `echo %ERRORLEVEL%` record that one constant as
    // every outcome. The scrub used to run only over the caller's block, so this
    // source passed through untouched. Asserted the same way, by having the job
    // print what it was handed, and on POSIX because that is where the suite can
    // read a real job's environment back.
    const saved = process.env["ERRORLEVEL"];
    process.env["ERRORLEVEL"] = "0";
    try {
      const started = startJob({
        command: 'printf "[$ERRORLEVEL][$AIC_KEPT]"',
        env: { AIC_KEPT: "kept" },
      });
      await waitForExit(started.jobId);

      // The kept key is the positive counterpart: an empty first field on its own
      // could equally mean the job never ran or printed nothing at all.
      expect(readLog(started.jobId)).toBe("[][kept]");
    } finally {
      if (saved === undefined) delete process.env["ERRORLEVEL"];
      else process.env["ERRORLEVEL"] = saved;
    }
  });

  it("keeps the command last in the Windows command script", () => {
    // The same rule buildJobScript states for POSIX, and the one the Windows
    // script used to break: a command ending in an unquoted `^` swallowed the
    // `exit /b %ERRORLEVEL%` that followed it, execution fell through into the
    // missing-cwd branch, and a job that had run fine reported a cwd it could not
    // enter (measured on the real box, agent 1.0.40). Nothing of ours may follow
    // the command reference — hence the missing-cwd branch ABOVE it, jumped over,
    // and nothing of ours after it: falling off the end of a batch propagates the
    // last errorlevel out of `cmd /c` by itself, which is what the wrapper reads.
    const lines = buildWindowsJobCommandScript("printf-like-command").split("\r\n").filter((line) => line !== "");
    expect(lines.length).toBeGreaterThan(0);
    expect(lines.at(-1)).toBe("printf-like-command");
    // The cwd check still happens, and still happens BEFORE the command.
    expect(lines.indexOf(`cd /d "%${JOB_CWD_ENV}%"`)).toBeGreaterThanOrEqual(0);
    expect(lines.indexOf(`cd /d "%${JOB_CWD_ENV}%"`)).toBeLessThan(lines.length - 1);
    // …and the exit line the caret ATE is the one that must not come back: it is
    // the specific text that used to follow the command. `exit /b 1` inside the
    // branch is a different line in a different place and is required — below.
    expect(buildWindowsJobCommandScript("whoami")).not.toContain("exit /b %ERRORLEVEL%");
  });

  it("keeps the missing-cwd branch terminal in the Windows command script", () => {
    // The exposure the layout above CREATED, and the reason it needs its own
    // assertion: the branch used to sit at the end of the file and was terminal
    // by position, whereas now `:aic_run` follows it. Its `exit /b 1` is the only
    // thing between a cwd that could not be entered and the command running in
    // the JOB directory — logging the failure and then reporting the command's
    // own exit code as the job's. Two tests guard it and NEITHER covers the
    // other's platform: the executing one in describeOnWindows proves the command
    // does not run, but only on windows-latest; this one inspects the script text
    // and lives in describeOnPosix, so it is what a macOS/Linux run has — the
    // usual case locally and in the main CI job, where the Windows test is
    // skipped. Deleting either leaves the invariant unasserted on that platform.
    const lines = buildWindowsJobCommandScript("whoami").split("\r\n").filter((line) => line !== "");
    const guardIdx = lines.indexOf("if not errorlevel 1 goto aic_run");
    const noticeIdx = lines.findIndex((line) => line.includes("could not be entered"));
    const exitIdx = lines.indexOf("exit /b 1");
    const labelIdx = lines.indexOf(":aic_run");
    // Every line named above must actually be there — a findIndex of -1 would
    // otherwise satisfy some of the orderings below by absence.
    expect(guardIdx).toBeGreaterThanOrEqual(0);
    expect(noticeIdx).toBeGreaterThanOrEqual(0);
    expect(exitIdx).toBeGreaterThanOrEqual(0);
    expect(labelIdx).toBeGreaterThanOrEqual(0);
    // The guard jumps over the branch, the branch says why, and it STOPS.
    expect(guardIdx).toBeLessThan(noticeIdx);
    expect(noticeIdx).toBeLessThan(exitIdx);
    expect(exitIdx).toBeLessThan(labelIdx);
    // The sharp form: whatever else the branch grows, the last line before the
    // label is the one that leaves the script. Anything else there falls through.
    expect(lines[labelIdx - 1]).toBe("exit /b 1");
    // …and the label is followed only by the command, so nothing can be inserted
    // between the jump target and the thing it exists to reach.
    expect(lines[labelIdx + 1]).toBe("whoami");
  });

  it("captures a job's output without the caller ever asking for it", async () => {
    // The end-to-end shape of the Windows defect, asserted through the manager:
    // a job that runs to completion must leave BYTES behind, and job_logs must
    // be able to page them.
    const started = startJob({ command: "printf 'hello from the job'; printf oops 1>&2" });
    await waitForExit(started.jobId);

    const settled = expectJob(manager.status({ jobId: started.jobId }));
    expect(settled.status).toBe("exited");
    expect(settled.logBytes).toBeGreaterThan(0);
    const logs = expectLogs(manager.logs({ jobId: started.jobId }));
    expect(Buffer.from(logs.chunk, "base64").toString("utf8")).toBe("hello from the joboops");
  });
});

// ── The Windows wrapper, actually executed ───────────────────────────────────
//
// Everything else about the Windows path is asserted as a STRING (the
// WINDOWS_JOB_WRAPPER case above), which cannot fail for the reasons the Windows
// path keeps failing for: a detached, console-less shell that hands its
// redirected stdout to nobody, a handle of ours that denies the wrapper's `>>`,
// a parse pass too many chewing on the command's own quoting, and a line whose
// own quoting let cmd split it at a `|` the command meant literally — that last
// one shipped in 1.0.40 past a wrapper text that read correctly by inspection.
// Only running it can. Skipped off Windows — see describeOnWindows — so on a macOS/Linux CI
// these tests report as skipped rather than passing vacuously.
//
// Every case here uses a REAL child process wherever it can: `cmd` builtins
// write to the log even in the broken arrangements, which is exactly how an
// earlier probe of this mechanism looked healthy while every actual job was
// losing its output.

describeOnWindows("Windows job capture", () => {
  it("runs a job through the real spawn path and captures its output", async () => {
    const started = startJob({ command: "node -e \"console.log('hello-from-the-job')\"" });
    await waitForExit(started.jobId);

    const settled = expectJob(manager.status({ jobId: started.jobId }));
    expect(settled.status).toBe("exited");
    expect(settled.exitCode).toBe(0);
    // The assertion the string comparison cannot make: BYTES landed in the file.
    expect(settled.logBytes).toBeGreaterThan(0);
    expect(readLog(started.jobId)).toContain("hello-from-the-job");
    // …and a caller can page them back out without asking for anything special.
    const logs = expectLogs(manager.logs({ jobId: started.jobId }));
    expect(Buffer.from(logs.chunk, "base64").toString("utf8")).toContain("hello-from-the-job");
  });

  it("captures stderr and the command's own exit code", async () => {
    // `2>&1` in the wrapper is what folds the two streams into one file, and the
    // `echo %ERRORLEVEL%` after it records the outcome of the NESTED cmd — the
    // one the command's own `exit /b` ends — rather than of the redirect.
    const started = startJob({ command: "echo to-stderr 1>&2 & exit /b 3" });
    await waitForExit(started.jobId);

    const settled = expectJob(manager.status({ jobId: started.jobId }));
    expect(settled.status).toBe("exited");
    expect(settled.exitCode).toBe(3);
    expect(readLog(started.jobId)).toContain("to-stderr");
  });

  it("captures the output of processes the job starts", async () => {
    // A real job is never one process, and this is the case a console-less
    // detached shell silently loses: the wrapper must be the one redirecting.
    // One level deeper than the tests above — the job's own shell starts a shell.
    const started = startJob({ command: 'cmd /d /s /c "echo from-a-child"' });
    await waitForExit(started.jobId);

    expect(expectJob(manager.status({ jobId: started.jobId })).status).toBe("exited");
    expect(readLog(started.jobId)).toContain("from-a-child");
  });

  it("delivers a quoted argument to the program as one argument", async () => {
    // Quoting that MATTERS: `a b` is one argv entry only if the command's own
    // quotes survive to the shell that runs it. A layer that strips or re-parses
    // them prints "a" and fails here — which a command whose quotes are
    // decorative could not detect.
    const started = startJob({
      command: 'node -e "console.log(process.argv[1])" "a b"',
    });
    await waitForExit(started.jobId);

    expect(expectJob(manager.status({ jobId: started.jobId })).exitCode).toBe(0);
    expect(readLog(started.jobId).trim()).toBe("a b");
  });

  it("delivers a quoted argument holding `|` and `&` as one argument", async () => {
    // The defect this pair pins, measured on the real box with 1.0.40: a job
    // whose command carried a metacharacter INSIDE its own quotes died with
    // `'b')""' is not recognized as an internal or external command`, while the
    // identical text through do:exec ran. cmd scans a line for operators before
    // it starts anything, so our quotes around the command let the command's own
    // first quote close ours, and the `|` after it became a pipe — splitting the
    // line and handing its right-hand half to the shell as a program name.
    //
    // A real child process, because that is what the argument has to reach; and
    // the control below differs ONLY in the metacharacters, so a failure here
    // cannot be blamed on the quoting of the probe itself.
    const control = startJob({ command: 'node -e "console.log(process.argv[1])" "a b c"' });
    await waitForExit(control.jobId);
    expect(expectJob(manager.status({ jobId: control.jobId })).exitCode).toBe(0);
    expect(readLog(control.jobId).trim()).toBe("a b c");

    const started = startJob({ command: 'node -e "console.log(process.argv[1])" "a | b & c"' });
    await waitForExit(started.jobId);

    const settled = expectJob(manager.status({ jobId: started.jobId }));
    expect(settled.status).toBe("exited");
    // Asserted before the output, because THIS is what the caller of
    // remote_job_start never sees: a job that reported a jobId and started
    // nothing looks identical from outside until someone reads the log.
    expect(settled.exitCode).toBe(0);
    expect(readLog(started.jobId).trim()).toBe("a | b & c");
    expect(readLog(started.jobId)).not.toContain("is not recognized");
  });

  it("still runs a pipeline the job actually meant", async () => {
    // The other side of the same line: a metacharacter the command means as an
    // operator must keep working, and every stage's output must still land in
    // the log (they inherit the redirected handle from the shell above them).
    const started = startJob({
      command: "node -e \"console.log('piped-through')\" | findstr piped",
    });
    await waitForExit(started.jobId);

    expect(expectJob(manager.status({ jobId: started.jobId })).exitCode).toBe(0);
    expect(readLog(started.jobId)).toContain("piped-through");
  });

  it("resolves an undefined percent reference to nothing, as sh does", async () => {
    // Deliberately POSIX-shaped: `sh -c 'echo $NOPE'` prints an empty line, and a
    // job command means the same thing on both platforms or it means nothing.
    // Reaching the program as the literal `%AIC_NO_SUCH_VARIABLE%` would be the
    // OTHER design — no expansion at all — under which the documented `env`
    // parameter could not be referenced from a Windows command at all.
    const started = startJob({
      command: 'node -e "console.log(JSON.stringify(process.argv[1]))" %AIC_NO_SUCH_VARIABLE%',
    });
    await waitForExit(started.jobId);

    expect(expectJob(manager.status({ jobId: started.jobId })).exitCode).toBe(0);
    expect(readLog(started.jobId).trim()).toBe("undefined");
  });

  it("expands a variable the caller passed in `env`", async () => {
    // The point of the round: `env` is a documented parameter, so a command must
    // be able to READ what it set — the POSIX side has always been able to.
    const started = startJob({
      command: 'node -e "console.log(process.argv[1])" %AIC_FROM_ENV%',
      env: { AIC_FROM_ENV: "value-from-env" },
    });
    await waitForExit(started.jobId);

    expect(expectJob(manager.status({ jobId: started.jobId })).exitCode).toBe(0);
    expect(readLog(started.jobId).trim()).toBe("value-from-env");
  });

  it("expands the command's percent references exactly once", async () => {
    // The sharp version of the case above, which an undefined variable cannot
    // detect: AIC_PROBE's VALUE is the text `%AIC_INNER%`. One expansion prints
    // that text. A second — one hidden parse pass too many, the regression this
    // wrapper exists to remove — prints `boom` instead, silently and plausibly.
    const started = startJob({
      command: 'node -e "console.log(process.argv[1])" %AIC_PROBE%',
      env: { AIC_PROBE: "%AIC_INNER%", AIC_INNER: "boom" },
    });
    await waitForExit(started.jobId);

    expect(expectJob(manager.status({ jobId: started.jobId })).exitCode).toBe(0);
    expect(readLog(started.jobId).trim()).toBe("%AIC_INNER%");
  });

  it("expands ONCE inside a pipeline too", async () => {
    // This test used to pin the opposite, as a measured limit of `call`: a
    // pipeline side got a fresh `cmd /S /D /c` and therefore a SECOND percent
    // phase, so this probe printed `boom` instead of `%AIC_INNER%`. Its own
    // comment said that if the extra round ever disappeared, the answer would
    // become `%AIC_INNER%` and the documentation should be corrected. It did, and
    // it has: with the command written into the command file, the one round is
    // the batch parser's own, applied to the whole line before any pipeline
    // child exists — so one round now really means one, everywhere.
    const started = startJob({
      command: 'node -e "console.log(process.argv[1])" %AIC_PROBE% | findstr /r "."',
      env: { AIC_PROBE: "%AIC_INNER%", AIC_INNER: "boom" },
    });
    await waitForExit(started.jobId);

    expect(readLog(started.jobId).trim()).toBe("%AIC_INNER%");
  });

  it("leaves a caret inside the command's own quotes alone", async () => {
    // Also inherited from `call`: its re-parse escaped batch's escape character a
    // second time, so `"a^b"` reached the program as `a^^b`. The old comment
    // called it unfixable — "removing it means removing `call`, and with it the
    // round that lets a command read the `env` the caller passed". That premise
    // was wrong: writing the command into the file keeps the round AND drops the
    // doubling, because there is now one parse rather than a parse plus a
    // re-parse. A real child process, because the whole question is what the
    // PROGRAM receives.
    const started = startJob({
      command: 'node -e "console.log(process.argv[1])" "a^b"',
    });
    await waitForExit(started.jobId);

    expect(expectJob(manager.status({ jobId: started.jobId })).exitCode).toBe(0);
    expect(readLog(started.jobId).trim()).toBe("a^b");
  });

  it("propagates the exit code of a child that never exits the shell itself", async () => {
    // The propagation path proper, which `echo x & exit /b 3` does NOT exercise:
    // an `&` splits the line before `call` ever applies, and the `exit /b` then
    // sets the shell's code by hand. Here a real child exits 7 and says nothing
    // about the shell, so the 7 can only arrive by falling off the end of the
    // command script and out of the nested `cmd /c` — the mechanism that
    // replaced the `exit /b %ERRORLEVEL%` line. Reintroduce anything of ours
    // after the command, or lose the fall-through, and this reports 0 or 1.
    const started = startJob({ command: 'node -e "process.exit(7)"' });
    await waitForExit(started.jobId);

    const settled = expectJob(manager.status({ jobId: started.jobId }));
    expect(settled.status).toBe("exited");
    expect(settled.exitCode).toBe(7);
  });

  it("runs a command ending in a caret without swallowing the script's own tail", async () => {
    // Measured on the real box with 1.0.40: a command ending in an unquoted `^`
    // ate the `exit /b %ERRORLEVEL%` line that followed it as a continuation,
    // execution fell through into the missing-cwd label, and a job that had just
    // run reported a working directory it could not enter. The command is now the
    // LAST line, so a trailing caret has nothing of ours left to eat. If anything
    // of ours is ever put back after it, the misleading message returns here.
    const started = startJob({ command: "node -e \"console.log('caret-tail')\" ^" });
    await waitForExit(started.jobId);

    expect(readLog(started.jobId)).toContain("caret-tail");
    expect(readLog(started.jobId)).not.toContain("working directory could not be entered");
  });

  it("cannot have its exit code forged by ERRORLEVEL in the caller's env", async () => {
    // Measured: cmd resolves `%ERRORLEVEL%` from the ENVIRONMENT when a variable
    // of that name is there, in preference to the real status — so the identical
    // job whose child exits 5 recorded 0 with `ERRORLEVEL=0` in `env`. The `env`
    // parameter comes from a relay message, and a job's exit code is the one
    // thing a caller must not be able to write. Lowercase deliberately: Windows
    // looks environment variables up without regard to case, so a scrub that only
    // dropped the uppercase spelling would leave the hole open.
    const started = startJob({
      command: 'node -e "process.exit(5)"',
      env: { errorlevel: "0", ERRORLEVEL: "0" },
    });
    await waitForExit(started.jobId);

    expect(expectJob(manager.status({ jobId: started.jobId })).exitCode).toBe(5);
  });

  it("refuses a command containing a line break", () => {
    // Windows only, and refused rather than escaped: the command becomes the last
    // LINE of a batch file, so an embedded newline turns its tail into further
    // lines of OUR script — a different program from the one the caller wrote.
    // POSIX accepts the same request (see the POSIX case), which is why this
    // assertion lives in the group that actually runs on Windows.
    //
    // All three spellings, because the guard says `\r` OR `\n` and cmd ends a
    // line at either: a probe set that only ever carried `\n` would stay green
    // while a guard narrowed to `\n` alone let the bare-CR form through.
    const refusal = expectRefusal(manager.start({ command: "echo one\r\necho two" }));
    expect(refusal.reason).toBe("invalid_request");
    expect(expectRefusal(manager.start({ command: "echo one\necho two" })).reason).toBe(
      "invalid_request",
    );
    expect(expectRefusal(manager.start({ command: "echo one\recho two" })).reason).toBe(
      "invalid_request",
    );
    // Nothing was started and nothing was left behind by the refusal.
    expect(jobDirNames()).toEqual([]);
  });

  it("does not run the command when the cwd vanished before the spawn", async () => {
    // The branch `exit /b 1` exists for, and the only test that executes it. The
    // cwd is checked in start() and entered by `cd /d` in command.cmd, so between
    // the two it can disappear — a network share dropping, a workspace deleted
    // out from under a queued start. Staged rather than raced: both halves are in
    // one synchronous start() call, so the directory is removed from INSIDE the
    // write of command.cmd, which happens after the check and immediately before
    // the spawn. To the running script that is indistinguishable from the real
    // thing — it simply finds no cwd.
    //
    // The load-bearing assertion is that the command did NOT run. Measured on the
    // real box (Windows 10.0.26200) by running this exact script pair against a
    // missing AIC_JOB_CWD, once as shipped and once with the `exit /b 1` line
    // deleted:
    //
    //   as shipped : exit file `1`, notice in the log, command did NOT run
    //   deleted    : exit file `0`, THE SAME notice in the log, command RAN
    //
    // So the log line is identical in both, and it is the sentinel and the exit
    // code that tell them apart. A test that only looked for the notice would pass
    // with the guard gone — which is exactly the hole this closes.
    const vanishing = path.join(tmpBase, "vanishing-cwd");
    // Absolute, so the sentinel does not depend on where the command ends up
    // running: the whole question is whether it runs ANYWHERE.
    const sentinel = path.join(tmpBase, "the-command-ran");
    const command = `node -e "require('fs').writeFileSync(process.argv[1], 'ran')" "${sentinel}"`;

    // The positive counterpart first, with the cwd left alone: the same command
    // in the same shape DOES leave the sentinel behind, so its absence below
    // means the guard stopped it rather than that the probe never worked.
    fs.mkdirSync(vanishing);
    const control = startJob({ command, cwd: vanishing });
    await waitForExit(control.jobId);
    expect(expectJob(manager.status({ jobId: control.jobId })).exitCode).toBe(0);
    expect(fs.existsSync(sentinel)).toBe(true);
    fs.rmSync(sentinel);

    let removals = 0;
    metaWrite.before = (_dir, fileName) => {
      if (fileName !== "command.cmd" || !fs.existsSync(vanishing)) return;
      fs.rmSync(vanishing, { recursive: true, force: true });
      removals += 1;
    };
    const started = startJob({ command, cwd: vanishing });
    await waitForExit(started.jobId);
    // The staging actually happened — otherwise everything below would be
    // asserting about an ordinary job whose directory was still there.
    expect(removals).toBe(1);
    expect(fs.existsSync(vanishing)).toBe(false);

    const settled = expectJob(manager.status({ jobId: started.jobId }));
    expect(settled.status).toBe("exited");
    // The job FAILED, with the branch's own code rather than the command's.
    expect(settled.exitCode).toBe(1);
    expect(readLog(started.jobId)).toContain("working directory could not be entered");
    // …and the command never ran, anywhere.
    expect(fs.existsSync(sentinel)).toBe(false);
  });

  it("captures a job whose jobs root contains a percent pair", async () => {
    // resolveJobsRoot derives the Windows root from LOCALAPPDATA / the home
    // directory — i.e. from a username — or from AICOMMANDER_CONFIG_DIR, so a
    // path holding a literal `%…%` pair is a real shape. It must reach the
    // wrapper as text, never as something a shell expanded on the way.
    const pctRoot = path.join(tmpBase, "root-%USERNAME%-here", "jobs");
    const pctManager = new JobManager({ jobsRoot: pctRoot });
    const started = expectJob(pctManager.start({ command: "node -e \"console.log('pct-ok')\"" }));
    await waitFor("the job in a percent-named root to write its exit file", () =>
      fs.existsSync(path.join(pctRoot, started.jobId, "exit")),
    );

    const settled = expectJob(pctManager.status({ jobId: started.jobId }));
    expect(settled.status).toBe("exited");
    expect(settled.exitCode).toBe(0);
    expect(fs.readFileSync(path.join(pctRoot, started.jobId, "output.log"), "utf8")).toContain(
      "pct-ok",
    );
  });
});

// ── A job is never running without a record ──────────────────────────────────

describeOnPosix("durable record", () => {
  it("starts nothing when the record cannot be written", async () => {
    const sentinel = path.join(tmpBase, "should-not-exist");
    metaWrite.fail = (_dir, fileName) => fileName === "meta.json";

    expect(() =>
      manager.start({ command: `printf x > ${sentinel}`, gpuIndex: 6 }),
    ).toThrow(JobError);

    // No process (so nothing invisible is running), no lock (so the card is not
    // wedged by a job that does not exist), no directory.
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(fs.existsSync(sentinel)).toBe(false);
    expect(fs.existsSync(gpuLockPath(6))).toBe(false);
    expect(jobDirNames()).toEqual([]);
  });

  it("stops a job whose pid it could not record", async () => {
    const tickFile = path.join(tmpBase, "ticks-unrecorded");
    fs.writeFileSync(tickFile, "");
    // The record lands, the pid update does not — the moment where a process
    // exists that nothing could ever find or cancel.
    let writes = 0;
    metaWrite.fail = (_dir, fileName) => fileName === "meta.json" && ++writes > 1;

    expect(() =>
      manager.start({
        command: 'while :; do printf x >> "$AIC_JOB_TICK"; sleep 0.05; done',
        env: { AIC_JOB_TICK: tickFile },
      }),
    ).toThrow(JobError);

    await new Promise((resolve) => setTimeout(resolve, 400));
    const settled = fileSize(tickFile);
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(fileSize(tickFile)).toBe(settled);
    const leftovers = jobDirNames().map(
      (entry) => `${entry}: ${fs.readdirSync(path.join(jobsRoot, entry)).join(",")}`,
    );
    expect(leftovers).toEqual([]);
  });

  it("leaves a recoverable record when the process never starts", () => {
    // The other ordering: a record whose spawn failed is settled as `unknown` by
    // the next reader, which is why writing first is the safe direction.
    const jobId = seedJob({ status: "running" });
    const summary = expectJob(manager.status({ jobId }));
    expect(summary.status).toBe("unknown");
  });
});

// ── A start that cannot own the process it started ───────────────────────────

describeOnPosix("a start that cannot own its process", () => {
  /**
   * A command that reports its own process-GROUP leader pid, then ignores
   * SIGTERM and keeps writing. Both properties are needed here: the test has to
   * prove the process is genuinely alive DURING the teardown window (so it must
   * survive the SIGTERM the teardown opens with), and it has to be able to kill
   * it by hand afterwards without waiting out KILL_ESCALATION_MS.
   */
  const STUBBORN_TICKER =
    `printf %s "$$" > "$AIC_JOB_PIDFILE"; trap '' TERM; ` +
    `while :; do printf x >> "$AIC_JOB_TICK"; sleep 0.05; done`;

  let tickFile: string;
  let pidFile: string;

  beforeEach(() => {
    tickFile = path.join(tmpBase, "ticks-unowned");
    pidFile = path.join(tmpBase, "pid-unowned");
    fs.writeFileSync(tickFile, "");
    fs.writeFileSync(pidFile, "");
    // The identity probe is the only thing between the spawn and the teardown's
    // first SIGTERM, so a probe that returns instantly would have the signal
    // reach the shell before it has run a single line — and the test would be
    // racing sh's startup instead of exercising the teardown. A probe that takes
    // a realistic moment (see the mock) removes the race without touching the
    // behaviour under test: the teardown still signals as soon as it decides to.
    procIdentity.delayMs = 250;
  });

  /** The pid the stubborn ticker wrote down, once it is up. */
  async function orphanPid(): Promise<number> {
    await waitFor("the orphaned process to report its pid", () => fileSize(pidFile) > 0);
    const pid = Number(fs.readFileSync(pidFile, "utf8").trim());
    expect(Number.isInteger(pid) && pid > 1).toBe(true);
    return pid;
  }

  /** It is not a zombie: it is still doing work, so its card is still in use. */
  async function expectStillRunning(): Promise<void> {
    const before = fileSize(tickFile);
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(fileSize(tickFile)).toBeGreaterThan(before);
  }

  it("keeps the card reserved when the process identity cannot be captured", async () => {
    // The regression this pins: a null procIdentity used to be persisted while
    // the start REPORTED SUCCESS. On POSIX the very next refresh reads a live pid
    // with no identity as `unverifiable`, settles the job — and settling RELEASES
    // ITS GPU LOCK. A transient /proc or `ps` failure therefore produced an
    // uncancellable orphan AND freed the card, so the next job_start put a second
    // training run on it: the exact OOM the lock exists to prevent.
    procIdentity.fail = true;

    expect(() =>
      manager.start({
        command: STUBBORN_TICKER,
        gpuIndex: 7,
        env: { AIC_JOB_TICK: tickFile, AIC_JOB_PIDFILE: pidFile },
      }),
    ).toThrow(/identify/i);

    // The probe recovers immediately — the point is that the START does not.
    procIdentity.fail = false;
    const pid = await orphanPid();
    await expectStillRunning();

    // The card stays reserved for as long as that process lives…
    expect(fs.existsSync(gpuLockPath(7))).toBe(true);
    expect(jobDirNames()).toHaveLength(1);
    const refusal = expectRefusal(manager.start({ command: "printf second", gpuIndex: 7 }));
    expect(refusal.reason).toBe("gpu_busy");
    expect(refusal.heldBy).toBe(fs.readFileSync(gpuLockPath(7), "utf8"));
    await expectStillRunning();

    // …and only until it is gone: the reservation is held, not leaked.
    process.kill(-pid, "SIGKILL");
    await waitFor("the card to be released once the process is gone", () => !fs.existsSync(gpuLockPath(7)));
    await waitFor("the job directory to be cleaned up", () => jobDirNames().length === 0);
  });

  it("holds the record and the card until a process it could not record is gone", async () => {
    // The other half of the same question. When the post-spawn pid write fails
    // the process is signalled, but signalling is not instantaneous — a job that
    // ignores SIGTERM lives until the KILL_ESCALATION_MS escalation. Releasing
    // the lock and deleting the directory at signal time left a live process with
    // NEITHER a record NOR a reservation, so a concurrent job_start could take the
    // same card out from under it.
    let writes = 0;
    metaWrite.fail = (_dir, fileName) => fileName === "meta.json" && ++writes > 1;

    expect(() =>
      manager.start({
        command: STUBBORN_TICKER,
        gpuIndex: 8,
        env: { AIC_JOB_TICK: tickFile, AIC_JOB_PIDFILE: pidFile },
      }),
    ).toThrow(JobError);
    // The disk is healthy again; the process from the failed start is not.
    metaWrite.fail = null;

    const pid = await orphanPid();
    await expectStillRunning();

    expect(jobDirNames()).toHaveLength(1);
    expect(fs.existsSync(gpuLockPath(8))).toBe(true);
    const refusal = expectRefusal(manager.start({ command: "printf second", gpuIndex: 8 }));
    expect(refusal.reason).toBe("gpu_busy");
    await expectStillRunning();

    process.kill(-pid, "SIGKILL");
    await waitFor("the card to be released once the process is gone", () => !fs.existsSync(gpuLockPath(8)));
    await waitFor("the job directory to be cleaned up", () => jobDirNames().length === 0);
  });

  it("keeps a mid-retirement process's card across an agent RESTART", async () => {
    // Mechanism B: retiringJobs is memory, and the escalation it guards outlives
    // this process. An agent restarted between the SIGTERM and the child's exit
    // used to read a record saying `running` with `pid: null` — the pid write is
    // exactly what failed — settle it `unknown` and release the card while the
    // child was still ignoring SIGTERM. Same double-booked GPU as mechanism A,
    // reached from the other end.
    //
    // One failed write, not a dead disk: the retirement path gets to write the
    // pid and its marker down, which is what makes the fact survive us.
    let writes = 0;
    metaWrite.fail = (_dir, fileName) => fileName === "meta.json" && ++writes === 2;

    expect(() =>
      manager.start({
        command: STUBBORN_TICKER,
        gpuIndex: 11,
        env: { AIC_JOB_TICK: tickFile, AIC_JOB_PIDFILE: pidFile },
      }),
    ).toThrow(JobError);
    metaWrite.fail = null;

    const pid = await orphanPid();
    await expectStillRunning();

    // The durable half of retiringJobs: the fact, and the pid that makes it
    // checkable by an agent that never saw the spawn.
    const [jobId] = jobDirNames();
    expect(jobId).toBeTruthy();
    const persisted = readMetaFile(jobId);
    expect(persisted.retiring).toBe(true);
    expect(persisted.pid).toBe(pid);

    // The restart itself: a fresh manager over the same root, with no child
    // handle and an empty retiringJobs.
    const restarted = new JobManager({ jobsRoot });
    restarted.recover();

    expect(fs.existsSync(jobDir(jobId))).toBe(true);
    expect(fs.existsSync(gpuLockPath(11))).toBe(true);
    const refusal = expectRefusal(restarted.start({ command: "printf second", gpuIndex: 11 }));
    expect(refusal.reason).toBe("gpu_busy");
    await expectStillRunning();

    process.kill(-pid, "SIGKILL");
    await waitFor("the card to be released once the process is gone", () => {
      expectJobs(restarted.list({}));
      return !fs.existsSync(gpuLockPath(11));
    });
  });

  it("still starts normally when the process ended before we could write it down", async () => {
    // `gone` is not `unverifiable`: a job that finished during the start leaves
    // nothing running and no card held, so it must still be a successful start
    // that settles from its exit file — not a retired orphan.
    const started = startJob({ command: "printf quick", gpuIndex: 9 });
    await waitForExit(started.jobId);
    const settled = expectJob(manager.status({ jobId: started.jobId }));
    expect(settled.status).toBe("exited");
    expect(settled.exitCode).toBe(0);
    expect(fs.existsSync(gpuLockPath(9))).toBe(false);
  });
});

// ── A live process we cannot vouch for ───────────────────────────────────────

describeOnPosix("a live process we cannot vouch for", () => {
  /** Ticks while it lives and dies on SIGTERM, so cancel can be observed working. */
  const TICKER = 'while :; do printf x >> "$AIC_JOB_TICK"; sleep 0.05; done';

  let tickFile: string;

  beforeEach(() => {
    tickFile = path.join(tmpBase, "ticks-unvouched");
    fs.writeFileSync(tickFile, "");
  });

  /** It is not a zombie: it is still doing work, so its card is still in use. */
  async function expectStillTicking(): Promise<void> {
    const before = fileSize(tickFile);
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(fileSize(tickFile)).toBeGreaterThan(before);
  }

  it("holds a running job whose identity probe fails transiently", async () => {
    // Mechanism A. `verifyJobProcess` has three answers and `unverifiable` used
    // to be folded into the terminal one on POSIX: kill(pid, 0) succeeds, the
    // start-time probe momentarily does not (EMFILE, a fork that failed, a /proc
    // or `ps` hiccup — what a loaded GPU box produces), and refresh settled the
    // job. Settling releases the GPU lock, so an ordinary job_status poll freed
    // the card under a live training run, the next job_start was granted the same
    // GPU, and two runs collided in the OOM the lock exists to prevent. The job
    // was also terminal by then, so cancel would not signal it: the first run
    // could no longer be stopped through the API either.
    const started = startJob({ command: TICKER, gpuIndex: 10, env: { AIC_JOB_TICK: tickFile } });
    await waitFor("the ticker to start writing", () => fileSize(tickFile) > 0);
    // Captured at spawn, so this job IS identifiable — until the probe goes dark.
    expect(readMetaFile(started.jobId).procIdentity).toBeTruthy();

    procIdentity.fail = true;

    // Poll it exactly as a caller tailing a training run does.
    const polled = expectJob(manager.status({ jobId: started.jobId }));
    expect(polled.status).toBe("running");
    expect(polled.exitCode).toBeNull();
    expect(polled.endedAt).toBeNull();
    expect(expectJobs(manager.list({ status: "running" })).map((job) => job.jobId)).toEqual([
      started.jobId,
    ]);
    // Nothing was written down as finished, either.
    expect(readMetaFile(started.jobId).status).toBe("running");
    expect(readMetaFile(started.jobId).endedAt).toBeNull();

    // The card is still ours, so nothing else can be put on it.
    expect(fs.existsSync(gpuLockPath(10))).toBe(true);
    const refusal = expectRefusal(manager.start({ command: "printf second", gpuIndex: 10 }));
    expect(refusal.reason).toBe("gpu_busy");
    expect(refusal.heldBy).toBe(started.jobId);
    await expectStillTicking();

    // And the job is still cancellable — the half a settled record destroyed,
    // since cancel does not signal a job it has already called terminal.
    procIdentity.fail = false;
    expect(expectJob(manager.cancel({ jobId: started.jobId })).status).toBe("running");
    await waitFor(
      "the cancelled job to reach a terminal state",
      () => expectJob(manager.status({ jobId: started.jobId })).status !== "running",
    );
    const atCancel = fileSize(tickFile);
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(fileSize(tickFile)).toBe(atCancel);

    // The hold ends the moment the pid does: the card is not stranded.
    expect(fs.existsSync(gpuLockPath(10))).toBe(false);
  });

  it("releases a retired job's card once its process is gone, with no handle to watch it", async () => {
    // The exit from the durable hold of mechanism B, on the side where nothing
    // can be observed directly: this is what an agent that restarted mid-stop
    // sees — a `retiring` record, a pid it never spawned, and no identity to
    // compare (the case that made us retire in the first place). It must hold the
    // card while that pid is alive and let go the moment it is not, or the
    // fail-closed answer would be a card stranded forever.
    const orphan = spawn("sleep", ["30"], { detached: true, stdio: "ignore" });
    orphan.unref();
    const pid = orphan.pid as number;
    expect(Number.isInteger(pid)).toBe(true);

    const jobId = seedJob({ status: "running", retiring: true, pid, procIdentity: null, gpuIndex: 12 });
    fs.writeFileSync(gpuLockPath(12), jobId);

    const restarted = new JobManager({ jobsRoot });
    restarted.recover();

    // Held: a live pid we cannot name is not an ended job, and recovery's stale
    // lock reaper must not take the card either.
    expect(expectJob(restarted.status({ jobId })).status).toBe("running");
    expect(fs.existsSync(gpuLockPath(12))).toBe(true);

    orphan.kill("SIGKILL");
    await waitFor("the orphan to be gone", () => {
      try {
        process.kill(pid, 0);
        return false;
      } catch {
        return true;
      }
    });

    // Now it is decidable — and a retired start is not a job that ended: its
    // caller was already told the start failed, so the record goes with the card
    // rather than lingering as a phantom nobody ever started.
    expect(expectJob(restarted.status({ jobId })).status).not.toBe("running");
    expect(fs.existsSync(gpuLockPath(12))).toBe(false);
    expect(fs.existsSync(jobDir(jobId))).toBe(false);
  });
});

// ── Liveness-probe errno routing ─────────────────────────────────────────────

describe("liveness-probe errno routing", () => {
  // The regression this group pins: verifyJobProcess's kill(pid, 0) catch used
  // to return a confident "gone" for EVERY errno. Right for ESRCH; wrong for
  // EPERM, which means the process EXISTS and we merely may not signal it — the
  // shape an agent started as a lesser user against a root service's jobs root
  // sees for every live root-owned job. "gone" settles the job, and settling
  // releases its GPU lock, so a second training run could take a card the first
  // was still on. The kill is only a liveness gate; the identity comparison is
  // the authority — so EPERM must fall through to it, and an errno that proves
  // neither presence nor absence must hold, never guess.
  //
  // Everything here is simulated: the errno is thrown by a mock (so no test
  // depends on the running user or platform being able to provoke a real
  // EPERM), the pid can never name a live process, and identities are seeded
  // canonical tokens compared by pure code.

  /** A ticks-kind canonical token, valid on every platform's comparator. */
  const OUR_IDENTITY = "424242";

  /** The GPU index every seeded job in this group reserves. */
  const GPU = 3;

  /**
   * Make kill(<pid>, 0) throw the given errno, shaped exactly as Node throws
   * it — an Error carrying `code`/`errno`/`syscall` (verified against a real
   * ESRCH and a real EPERM), or a bare Error when `code` is null. Every other
   * (pid, signal) pair falls through to the real kill, so cleanup and any
   * unrelated process traffic stay untouched. Returns the spy so a test can
   * assert what WAS signalled.
   */
  function mockKillErrno(pid: number, code: string | null) {
    const realKill = process.kill.bind(process);
    return vi.spyOn(process, "kill").mockImplementation(((
      target: number,
      signal?: string | number,
    ): true => {
      if (target === pid && signal === 0) {
        const err = new Error(code === null ? "kill failed" : `kill ${code}`);
        if (code !== null) Object.assign(err, { code, errno: -1, syscall: "kill" });
        throw err;
      }
      return realKill(target, signal as NodeJS.Signals);
    }) as typeof process.kill);
  }

  /** Seed a running job holding GPU `GPU`, lock file and all. */
  function seedGpuJob(overrides: Partial<SeededMeta> = {}): string {
    const jobId = seedJob({
      status: "running",
      gpuIndex: GPU,
      pid: DEAD_PID,
      procIdentity: OUR_IDENTITY,
      ...overrides,
    });
    fs.writeFileSync(gpuLockPath(GPU), jobId);
    return jobId;
  }

  it("EPERM on a pid whose identity still matches holds the job and its lock", () => {
    procIdentity.override = () => OUR_IDENTITY;
    const jobId = seedGpuJob();
    mockKillErrno(DEAD_PID, "EPERM");

    // Poll it exactly as a caller tailing a training run does.
    const polled = expectJob(manager.status({ jobId }));
    expect(polled.status).toBe("running");
    expect(polled.endedAt).toBeNull();
    // Nothing was written down as finished, either.
    expect(readMetaFile(jobId).status).toBe("running");

    // The lock FILE is the thing that matters: settling deletes it, and then a
    // second job_start is granted the same card under a live run.
    expect(fs.existsSync(gpuLockPath(GPU))).toBe(true);
    const refusal = expectRefusal(manager.start({ command: "printf second", gpuIndex: GPU }));
    expect(refusal.reason).toBe("gpu_busy");
    expect(refusal.heldBy).toBe(jobId);
  });

  // The proof that the verdict is `ours` and not the weaker `unverifiable` hold
  // is what cancel SIGNALS, and that is the one assertion in this group whose
  // shape is platform-specific: POSIX signals the process GROUP (negative pid)
  // through process.kill, which the spy sees, while Windows shells out to
  // taskkill, which it cannot. Hence the guard — the rest of the group stays
  // platform-neutral by design.
  itOnPosix("EPERM on a matching identity keeps the job cancellable", () => {
    procIdentity.override = () => OUR_IDENTITY;
    const jobId = seedGpuJob();
    const kill = mockKillErrno(DEAD_PID, "EPERM");

    expect(expectJob(manager.status({ jobId })).status).toBe("running");
    expectJob(manager.cancel({ jobId }));
    expect(kill.mock.calls.some(([pid, signal]) => pid === -DEAD_PID && signal === "SIGTERM")).toBe(
      true,
    );
  });

  it("EPERM on a pid recycled onto someone else's process still settles and frees the card", () => {
    // The direction that must not over-tighten: EPERM establishes only
    // LIVENESS, and the identity check keeps its authority to say this live
    // process is not ours — a genuinely stale record must not strand its card.
    procIdentity.override = () => foreignIdentity(OUR_IDENTITY);
    const jobId = seedGpuJob();
    mockKillErrno(DEAD_PID, "EPERM");

    expect(expectJob(manager.status({ jobId })).status).toBe("unknown");
    expect(fs.existsSync(gpuLockPath(GPU))).toBe(false);
  });

  it("EPERM with an identity probe that cannot answer holds the job and the lock", () => {
    // A live pid we may not signal AND cannot read (Windows without query
    // rights on another user's process) is an open question, and open
    // questions hold — the posture refresh takes for every live pid.
    procIdentity.fail = true;
    const jobId = seedGpuJob();
    mockKillErrno(DEAD_PID, "EPERM");

    expect(expectJob(manager.status({ jobId })).status).toBe("running");
    expect(fs.existsSync(gpuLockPath(GPU))).toBe(true);
  });

  it("ESRCH still ends the job and releases the card", () => {
    // Absence is the one thing the gate may conclude alone; routing it into a
    // hold would strand every dead job's card behind an unanswerable question.
    const jobId = seedGpuJob();
    mockKillErrno(DEAD_PID, "ESRCH");

    expect(expectJob(manager.status({ jobId })).status).toBe("unknown");
    expect(fs.existsSync(gpuLockPath(GPU))).toBe(false);
  });

  it("an unknown errno holds rather than settling", () => {
    // EINVAL proves neither presence nor absence, so it must not become the
    // "gone" that releases a lock — nor is it the EPERM that proves liveness.
    const jobId = seedGpuJob();
    mockKillErrno(DEAD_PID, "EINVAL");

    expect(expectJob(manager.status({ jobId })).status).toBe("running");
    expect(fs.existsSync(gpuLockPath(GPU))).toBe(true);
  });

  it("an error with no usable code holds rather than settling", () => {
    const jobId = seedGpuJob();
    mockKillErrno(DEAD_PID, null);

    expect(expectJob(manager.status({ jobId })).status).toBe("running");
    expect(fs.existsSync(gpuLockPath(GPU))).toBe(true);
  });
});

// ── jobId validation ─────────────────────────────────────────────────────────

describe("jobId validation", () => {
  const BAD_IDS = [
    "../../etc/passwd",
    "..",
    "../",
    "",
    "/etc/passwd",
    path.join(os.tmpdir(), "escape"),
    "0123456789abcde", // 15 chars
    "0123456789abcdef0", // 17 chars
    "0123456789ABCDEF", // uppercase is not our alphabet
    "0123456789abcde/",
    "00000000000000zz",
    "..%2f..%2fetc%2fpasswd",
  ];

  it("refuses every non-16-hex jobId as not_found rather than throwing", () => {
    for (const jobId of BAD_IDS) {
      for (const call of [
        () => manager.status({ jobId }),
        () => manager.logs({ jobId }),
        () => manager.cancel({ jobId }),
      ]) {
        expect(call).not.toThrow();
        const refusal = expectRefusal(call());
        expect(refusal.reason).toBe("not_found");
        // The caller's id is never echoed back — it is untrusted text heading
        // for an LLM's context — and the reply is byte-identical for every bad id.
        expect(refusal.message).toBe("No such job on this machine.");
        if (jobId !== "") expect(JSON.stringify(refusal)).not.toContain(jobId);
      }
    }
  });

  it("refuses a jobId that is not a string at all", () => {
    const notStrings: unknown[] = [undefined, null, 42, { jobId: "x" }, ["0123456789abcdef"]];
    for (const jobId of notStrings) {
      const refusal = expectRefusal(manager.status({ jobId } as { jobId: string }));
      expect(refusal.reason).toBe("not_found");
    }
  });

  it("gives an unknown-but-well-formed jobId the same answer as a malformed one", () => {
    const unknown = expectRefusal(manager.status({ jobId: "0123456789abcdef" }));
    const malformed = expectRefusal(manager.status({ jobId: "../../etc/passwd" }));
    expect(unknown).toEqual(malformed);
  });

  it("never touches the filesystem outside the jobs root for a traversal attempt", () => {
    const readFileSync = vi.spyOn(fs, "readFileSync");
    const statSync = vi.spyOn(fs, "statSync");
    const openSync = vi.spyOn(fs, "openSync");

    // Synchronous throughout, so nothing else can interleave into the spies.
    for (const jobId of BAD_IDS) {
      manager.status({ jobId });
      manager.logs({ jobId, offsetBytes: 0 });
      manager.cancel({ jobId });
    }

    const touched = [...readFileSync.mock.calls, ...statSync.mock.calls, ...openSync.mock.calls]
      .map((args) => args[0])
      .filter((target): target is string => typeof target === "string");
    // Validation happens BEFORE any path join, so there should be no filesystem
    // traffic at all; assert the escape explicitly so a future refactor that
    // reorders the check fails here.
    expect(touched).toEqual([]);
    expect(touched.some((target) => target.includes("passwd"))).toBe(false);
  });

  it("ignores a meta.json whose recorded jobId does not match its directory", () => {
    const jobId = seedJob({ status: "exited", exitCode: 0, endedAt: Date.now() });
    const meta = readMetaFile(jobId);
    fs.writeFileSync(
      path.join(jobDir(jobId), "meta.json"),
      JSON.stringify({ ...meta, jobId: "ffffffffffffffff" }, null, 2),
    );
    expect(expectRefusal(manager.status({ jobId })).reason).toBe("not_found");
  });
});

// ── GPU lock ─────────────────────────────────────────────────────────────────

describeOnPosix("GPU lock", () => {
  it("reserves the card and exposes it to the job as CUDA_VISIBLE_DEVICES", async () => {
    const started = startJob({ command: 'printf %s "$CUDA_VISIBLE_DEVICES"', gpuIndex: 2 });
    expect(started.gpuIndex).toBe(2);
    expect(fs.readFileSync(gpuLockPath(2), "utf8")).toBe(started.jobId);

    await waitForExit(started.jobId);
    expect(readLog(started.jobId)).toBe("2");
  });

  it("overrides a caller-supplied CUDA_VISIBLE_DEVICES with the reserved card", async () => {
    const started = startJob({
      command: 'printf %s "$CUDA_VISIBLE_DEVICES"',
      gpuIndex: 1,
      env: { CUDA_VISIBLE_DEVICES: "7" },
    });
    await waitForExit(started.jobId);
    // The lock is what makes exclusivity meaningful, so it wins.
    expect(readLog(started.jobId)).toBe("1");
  });

  it("refuses a second job on the same card with gpu_busy and the holder's id", () => {
    const holder = startJob({ command: LONG_RUNNING, gpuIndex: 0 });
    const before = fs.readdirSync(jobsRoot).length;

    const refusal = expectRefusal(manager.start({ command: "printf second", gpuIndex: 0 }));
    expect(refusal.reason).toBe("gpu_busy");
    expect(refusal.heldBy).toBe(holder.jobId);
    // The refused start must not leave a job directory behind.
    expect(fs.readdirSync(jobsRoot).length).toBe(before);
    expect(expectJobs(manager.list({}))).toHaveLength(1);
  });

  it("allows a different card while one is held", () => {
    startJob({ command: LONG_RUNNING, gpuIndex: 0 });
    const other = startJob({ command: LONG_RUNNING, gpuIndex: 1 });
    expect(other.gpuIndex).toBe(1);
    expect(fs.existsSync(gpuLockPath(1))).toBe(true);
  });

  it("releases the lock as soon as the job is observed to have ended", async () => {
    const started = startJob({ command: "printf done", gpuIndex: 3 });
    expect(fs.existsSync(gpuLockPath(3))).toBe(true);

    await waitForExit(started.jobId);
    expect(expectJob(manager.status({ jobId: started.jobId })).status).toBe("exited");
    expect(fs.existsSync(gpuLockPath(3))).toBe(false);
  });

  it("frees the card on cancel, without waiting for anyone to poll the job", async () => {
    // A cancelled training run must not hold a GPU hostage until some later
    // status call happens to settle it — the next job asks for the same card.
    const started = startJob({ command: LONG_RUNNING, gpuIndex: 2 });
    expect(fs.existsSync(gpuLockPath(2))).toBe(true);

    manager.cancel({ jobId: started.jobId });

    await waitFor("the cancelled job's card to be released", () => !fs.existsSync(gpuLockPath(2)));
    // And it really is free: the same card can be reserved again straight away.
    expect(startJob({ command: LONG_RUNNING, gpuIndex: 2 }).gpuIndex).toBe(2);
  });

  it("reaps a stale lock during startup recovery but keeps a live holder's", () => {
    const live = startJob({ command: LONG_RUNNING, gpuIndex: 0 });
    // Holder finished while the agent was down.
    const finished = seedJob({ status: "running", gpuIndex: 1, exit: "0" });
    fs.writeFileSync(gpuLockPath(1), finished);
    // Holder's directory is gone entirely (pruned, or a truncated write).
    fs.writeFileSync(gpuLockPath(2), "aaaaaaaaaaaaaaaa");
    // Not even a job id.
    fs.writeFileSync(gpuLockPath(3), "garbage");

    new JobManager({ jobsRoot }).recover();

    expect(fs.existsSync(gpuLockPath(0))).toBe(true);
    expect(fs.readFileSync(gpuLockPath(0), "utf8")).toBe(live.jobId);
    expect(fs.existsSync(gpuLockPath(1))).toBe(false);
    expect(fs.existsSync(gpuLockPath(2))).toBe(false);
    expect(fs.existsSync(gpuLockPath(3))).toBe(false);
  });

  it("reaps a stale lock on acquisition so one crash cannot wedge a card", () => {
    // No recovery pass — a lock left by a job that no longer exists must not
    // block the very next start.
    fs.mkdirSync(jobsRoot, { recursive: true });
    fs.writeFileSync(gpuLockPath(4), "bbbbbbbbbbbbbbbb");

    const started = startJob({ command: LONG_RUNNING, gpuIndex: 4 });
    expect(fs.readFileSync(gpuLockPath(4), "utf8")).toBe(started.jobId);
  });

  it("never steals a lock held by another job when settling", async () => {
    const first = startJob({ command: "printf done", gpuIndex: 5 });
    // Simulate a hand-off: someone else now holds the card.
    fs.writeFileSync(gpuLockPath(5), "cccccccccccccccc");

    await waitForExit(first.jobId);
    expect(expectJob(manager.status({ jobId: first.jobId })).status).toBe("exited");
    expect(fs.readFileSync(gpuLockPath(5), "utf8")).toBe("cccccccccccccccc");
  });

  it("refuses an implausible gpuIndex as invalid_request, never dropping the field", () => {
    // An index that cannot name a card is a fault in the request, so it comes back
    // structured (→ 400) rather than as a machine error. What must NOT happen is
    // the field being silently dropped: that would start an unreserved GPU job,
    // the exact OOM collision the lock exists to prevent.
    for (const gpuIndex of [-1, 1.5, 4_096, Number.NaN, Number.POSITIVE_INFINITY]) {
      const refusal = expectRefusal(manager.start({ command: "printf x", gpuIndex }));
      expect(refusal.reason, `gpuIndex=${gpuIndex}`).toBe("invalid_request");
      expect(refusal.message).toMatch(/gpu_index/);
    }
    expect(
      expectRefusal(manager.start({ command: "printf x", gpuIndex: "0" as unknown as number }))
        .reason,
    ).toBe("invalid_request");
    // A rejected index must not create a lock file namespace entry.
    expect(fs.existsSync(jobsRoot) ? fs.readdirSync(jobsRoot) : []).toEqual([]);
  });
});

// ── GPU lock reaping when the disk will not answer ───────────────────────────

describeOnPosix("GPU lock reaping when the disk will not answer", () => {
  /** The failure shape of a loaded box: the file is there, the read is refused. */
  function emfile(): NodeJS.ErrnoException {
    return Object.assign(new Error("EMFILE: too many open files"), { code: "EMFILE" });
  }

  /** Make reads of paths containing `needle` fail like a loaded box; pass the rest through. */
  function failReadsOf(needle: string): void {
    const realRead = fs.readFileSync.bind(fs) as typeof fs.readFileSync;
    vi.spyOn(fs, "readFileSync").mockImplementation(((target: unknown, ...rest: unknown[]) => {
      if (typeof target === "string" && target.includes(needle)) throw emfile();
      return realRead(target as never, ...(rest as never[]));
    }) as never);
  }

  it("does not reap a holder whose record EXISTS but cannot be read — while still reaping a provably absent one", () => {
    // Defect path 5. Lock reaping never goes through settle(), so none of the
    // fail-closed guards there cover it: it used to fold ANY readMeta failure
    // into "the holder is not running" and take the card. An EMFILE or EIO on a
    // loaded box — precisely when a training run is on the GPU — therefore
    // freed a live job's lock and double-booked the card. The two misses are
    // now distinct: a record that provably is not there is evidence (reap, or
    // one crash strands a card forever), a record that would not READ is not
    // (hold, and re-ask on the next recovery).
    const holder = seedJob({ status: "running", pid: process.pid, gpuIndex: 14 });
    fs.writeFileSync(gpuLockPath(14), holder);
    // A lock whose holder's directory is genuinely gone (pruned, or a crash
    // before the record landed) — the reap that must KEEP working.
    fs.writeFileSync(gpuLockPath(15), "aaaaaaaaaaaaaaaa");

    failReadsOf(path.join(holder, "meta.json"));
    new JobManager({ jobsRoot }).recover();

    expect(fs.existsSync(gpuLockPath(14))).toBe(true);
    expect(fs.readFileSync(gpuLockPath(14), "utf8")).toBe(holder);
    expect(fs.existsSync(gpuLockPath(15))).toBe(false);
  });

  it("answers gpu_busy instead of stealing the lock when the holder's record cannot be read", () => {
    // The same third answer on the acquisition path: a start racing the failure
    // used to reap the unreadable holder's lock, retry, WIN the card, and put a
    // second run on it. It must refuse instead — the caller polls and retries,
    // which is exactly what gpu_busy means.
    const holder = seedJob({ status: "running", pid: process.pid, gpuIndex: 14 });
    fs.writeFileSync(gpuLockPath(14), holder);

    failReadsOf(path.join(holder, "meta.json"));
    const refusal = expectRefusal(manager.start({ command: "printf second", gpuIndex: 14 }));

    expect(refusal.reason).toBe("gpu_busy");
    expect(refusal.heldBy).toBe(holder);
    expect(fs.readFileSync(gpuLockPath(14), "utf8")).toBe(holder);
    // And the refused start left nothing behind.
    expect(jobDirNames()).toEqual([holder]);
  });

  it("holds a lock FILE that itself cannot be read, on recovery and on acquisition", () => {
    // The same class one layer down: the lock's own read failing says nothing
    // about the reservation it records, so neither the startup reaper nor a
    // racing start may treat it as free.
    const holder = seedJob({ status: "running", pid: process.pid, gpuIndex: 16 });
    fs.writeFileSync(gpuLockPath(16), holder);

    failReadsOf("gpu-16.lock");
    new JobManager({ jobsRoot }).recover();
    expect(fs.existsSync(gpuLockPath(16))).toBe(true);

    const refusal = expectRefusal(manager.start({ command: "printf second", gpuIndex: 16 }));
    expect(refusal.reason).toBe("gpu_busy");
    expect(fs.existsSync(gpuLockPath(16))).toBe(true);
  });
});

// ── Log slicing ──────────────────────────────────────────────────────────────

describe("log slicing", () => {
  /** A settled job with an exact log body — no process, so no timing at all. */
  function seedLoggedJob(log: string | Buffer, extra: Partial<SeededMeta> = {}): string {
    return seedJob({ status: "exited", exitCode: 0, endedAt: Date.now(), log, ...extra });
  }

  function lines(count: number): string {
    return Array.from({ length: count }, (_, i) => `line-${i}`).join("\n") + "\n";
  }

  function decode(logs: JobLogs): string {
    return Buffer.from(logs.chunk, "base64").toString("utf8");
  }

  it("tails JOB_LOGS_DEFAULT_TAIL_LINES lines when no range is given", () => {
    const body = lines(500);
    const jobId = seedLoggedJob(body);

    const logs = expectLogs(manager.logs({ jobId }));
    const text = decode(logs);
    const returned = text.split("\n").filter((line) => line !== "");
    expect(returned).toHaveLength(JOB_LOGS_DEFAULT_TAIL_LINES);
    expect(returned[0]).toBe(`line-${500 - JOB_LOGS_DEFAULT_TAIL_LINES}`);
    expect(returned[returned.length - 1]).toBe("line-499");
    expect(logs.offsetBytes).toBe(Buffer.byteLength(body) - Buffer.byteLength(text));
    expect(logs.eof).toBe(true);
    expect(logs.truncated).toBe(false);
    expect(logs.jobId).toBe(jobId);
  });

  it("honours an explicit tailLines", () => {
    const jobId = seedLoggedJob(lines(50));
    const text = decode(expectLogs(manager.logs({ jobId, tailLines: 3 })));
    expect(text).toBe("line-47\nline-48\nline-49\n");
  });

  it("returns the whole log when it holds fewer lines than requested", () => {
    const body = lines(4);
    const jobId = seedLoggedJob(body);
    const logs = expectLogs(manager.logs({ jobId, tailLines: 999 }));
    expect(decode(logs)).toBe(body);
    expect(logs.offsetBytes).toBe(0);
    expect(logs.eof).toBe(true);
  });

  it("falls back to the default tail for a nonsensical tailLines", () => {
    const jobId = seedLoggedJob(lines(500));
    for (const tailLines of [0, -5, Number.NaN, 1.5]) {
      const returned = decode(expectLogs(manager.logs({ jobId, tailLines })))
        .split("\n")
        .filter((line) => line !== "");
      // 1.5 floors to 1; the rest are unusable and fall back to the default.
      expect(returned.length).toBe(tailLines === 1.5 ? 1 : JOB_LOGS_DEFAULT_TAIL_LINES);
    }
  });

  it("pages forward through a log with offsetBytes/nextOffsetBytes", () => {
    const body = lines(200);
    const jobId = seedLoggedJob(body);
    const total = Buffer.byteLength(body);

    let offset = 0;
    let assembled = "";
    let pages = 0;
    for (;;) {
      const logs = expectLogs(manager.logs({ jobId, offsetBytes: offset, maxBytes: 100 }));
      expect(logs.offsetBytes).toBe(offset);
      assembled += decode(logs);
      pages++;
      if (logs.eof) {
        expect(logs.nextOffsetBytes).toBe(total);
        break;
      }
      expect(logs.nextOffsetBytes).toBeGreaterThan(offset);
      offset = logs.nextOffsetBytes;
      if (pages > 200) throw new Error("pagination did not terminate");
    }
    expect(assembled).toBe(body);
    expect(pages).toBeGreaterThan(1); // it really did paginate
  });

  it("reports eof only once the reader has caught up with the end", () => {
    const jobId = seedLoggedJob("a".repeat(1_000));
    const first = expectLogs(manager.logs({ jobId, offsetBytes: 0, maxBytes: 400 }));
    expect(first.eof).toBe(false);
    expect(first.nextOffsetBytes).toBe(400);
    const last = expectLogs(manager.logs({ jobId, offsetBytes: 600, maxBytes: 400 }));
    expect(last.eof).toBe(true);
    expect(last.nextOffsetBytes).toBe(1_000);
  });

  it("clamps a slice to JOB_LOGS_MAX_SLICE_BYTES however large maxBytes is", () => {
    const body = Buffer.alloc(JOB_LOGS_MAX_SLICE_BYTES + 50_000, 0x61);
    const jobId = seedLoggedJob(body);

    const logs = expectLogs(manager.logs({ jobId, offsetBytes: 0, maxBytes: 10_000_000 }));
    expect(Buffer.from(logs.chunk, "base64")).toHaveLength(JOB_LOGS_MAX_SLICE_BYTES);
    expect(logs.eof).toBe(false);
    expect(logs.nextOffsetBytes).toBe(JOB_LOGS_MAX_SLICE_BYTES);
  });

  it("clamps a tail-mode slice too, even for one enormous line", () => {
    // A single line longer than the slice cap must still return a slice-sized
    // tail rather than nothing.
    const body = Buffer.alloc(JOB_LOGS_MAX_SLICE_BYTES + 50_000, 0x62);
    const jobId = seedLoggedJob(body);
    const logs = expectLogs(manager.logs({ jobId }));
    expect(Buffer.from(logs.chunk, "base64")).toHaveLength(JOB_LOGS_MAX_SLICE_BYTES);
    expect(logs.eof).toBe(true);
  });

  it("lets maxBytes only shrink the slice", () => {
    const jobId = seedLoggedJob("x".repeat(5_000));
    expect(Buffer.from(expectLogs(manager.logs({ jobId, offsetBytes: 0, maxBytes: 64 })).chunk, "base64"))
      .toHaveLength(64);
  });

  it("round-trips arbitrary bytes through base64", () => {
    const binary = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
    const jobId = seedLoggedJob(binary);
    const logs = expectLogs(manager.logs({ jobId, offsetBytes: 0 }));
    expect(Buffer.from(logs.chunk, "base64").equals(binary)).toBe(true);
  });

  it("clamps an offset past the end to the end and reports eof", () => {
    const jobId = seedLoggedJob("12345");
    const logs = expectLogs(manager.logs({ jobId, offsetBytes: 10_000 }));
    expect(logs.chunk).toBe("");
    expect(logs.offsetBytes).toBe(5);
    expect(logs.nextOffsetBytes).toBe(5);
    expect(logs.eof).toBe(true);
  });

  it("returns an empty slice for a job that produced no output at all", () => {
    const jobId = seedJob({ status: "exited", exitCode: 0, endedAt: Date.now() });
    const logs = expectLogs(manager.logs({ jobId }));
    expect(logs.chunk).toBe("");
    expect(logs.offsetBytes).toBe(0);
    expect(logs.eof).toBe(true);
  });

  it("follows a growing log across calls", () => {
    const jobId = seedLoggedJob("first\n");
    const first = expectLogs(manager.logs({ jobId, offsetBytes: 0 }));
    expect(first.eof).toBe(true);

    fs.appendFileSync(logPath(jobId), "second\n");
    const next = expectLogs(manager.logs({ jobId, offsetBytes: first.nextOffsetBytes }));
    expect(decode(next)).toBe("second\n");
    expect(next.eof).toBe(true);
  });
});

// ── Log cap ──────────────────────────────────────────────────────────────────

describeOnPosix("log cap", () => {
  async function startCappedJob(): Promise<JobSummary> {
    const started = startJob({ command: LONG_RUNNING });
    await waitFor("the job's log file to exist", () => fs.existsSync(logPath(started.jobId)));
    inflateLog(started.jobId, JOB_MAX_LOG_BYTES);
    return started;
  }

  /**
   * A job that runs until the test lets it finish, so its exit happens at a
   * moment the test chooses rather than one the machine's speed chooses. Writes
   * nothing, so it cannot move the log out from under inflateLog.
   */
  const GATED = "until [ -f release ]; do sleep 0.02; done";

  /** Let a GATED job end. The marker lands in the job's own workspace, its cwd. */
  function releaseGatedJob(jobId: string): void {
    fs.writeFileSync(path.join(jobDir(jobId), "workspace", "release"), "");
  }

  it("appends a truncation notice, marks the job truncated, and does NOT kill it", async () => {
    const started = await startCappedJob();
    const pid = readMetaFile(started.jobId).pid as number;

    const capped = expectJob(manager.status({ jobId: started.jobId }));

    // The whole point of jobs: a chatty 5-hour run is not killed for its output.
    expect(capped.status).toBe("running");
    expect(() => process.kill(pid, 0)).not.toThrow();
    expect(fs.existsSync(exitPath(started.jobId))).toBe(false);
    // …and it is still alive a moment later, so an ASYNC kill would be caught
    // too rather than hiding behind a not-yet-reaped pid.
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(expectJob(manager.status({ jobId: started.jobId })).status).toBe("running");
    expect(fs.existsSync(exitPath(started.jobId))).toBe(false);

    expect(capped.truncated).toBe(true);
    // The file was exactly AT the cap when we noticed, so the notice lands
    // inside the served range and is the last thing a reader paging to eof
    // sees. Read only that window: the file is a 256 MiB sparse one.
    expect(readAt(logPath(started.jobId), JOB_MAX_LOG_BYTES, 512)).toContain("reached its size limit");
    expect(capped.logBytes).toBe(fileSize(logPath(started.jobId)));
    expectServedWithinCap(capped.logBytes);
  });

  it("clamps the cut-off to the cap when the file had ALREADY overshot", async () => {
    // The defect: the cut-off was the size we happened to OBSERVE, so a job that
    // wrote a gigabyte between two polls got a gigabyte cut-off — and every reply
    // about it then served far past the 256 MiB this agent advertises. Nothing
    // here can stop those bytes landing on disk; what it can do is refuse to
    // pretend they are inside a cap that says otherwise.
    const started = startJob({ command: LONG_RUNNING });
    await waitFor("the job's log file to exist", () => fs.existsSync(logPath(started.jobId)));
    const overshoot = JOB_MAX_LOG_BYTES + 64 * 1024 * 1024;
    inflateLog(started.jobId, overshoot);

    const capped = expectJob(manager.status({ jobId: started.jobId }));
    expect(capped.truncated).toBe(true);
    expectServedWithinCap(capped.logBytes);
    expect(readMetaFile(started.jobId).truncatedAt).toBe(capped.logBytes);
    // The bytes past the cut-off are on disk — and stay there — but no caller can
    // reach them: paging stops at the cut-off and reports eof there.
    const logs = expectLogs(
      manager.logs({ jobId: started.jobId, offsetBytes: capped.logBytes - 10, maxBytes: 10_000 }),
    );
    expect(logs.nextOffsetBytes).toBe(capped.logBytes);
    expect(logs.eof).toBe(true);
    expect(fileSize(logPath(started.jobId))).toBeGreaterThan(overshoot - 1);
  });

  it("cannot stop the WRITER, so the file really does outgrow the cap", async () => {
    // The reader-side assertions above are satisfied by a file that never grows.
    // This is the other half, and the honest one: the job's own shell appends to
    // the same path with its own handle, so ITS writes land past the cut-off, on
    // disk, while the job runs. Nothing reclaims that until the directory ages
    // out of JOB_RETENTION_MS — which is why the retention prune has to run on a
    // long-lived agent for checkLogCap's trade-off to hold at all.
    const started = startJob({ command: "while :; do printf 'chatty-output'; sleep 0.02; done" });
    await waitFor("the job's log file to exist", () => fs.existsSync(logPath(started.jobId)));
    inflateLog(started.jobId, JOB_MAX_LOG_BYTES);

    const capped = expectJob(manager.status({ jobId: started.jobId }));
    expect(capped.truncated).toBe(true);
    const cutOff = capped.logBytes;
    expectServedWithinCap(cutOff);

    await waitFor(
      "the job to write past the cut-off with its own handle",
      () => fileSize(logPath(started.jobId)) > cutOff,
    );

    // The overshoot is invisible to every caller: what we serve stays capped…
    const again = expectJob(manager.status({ jobId: started.jobId }));
    expect(again.logBytes).toBe(cutOff);
    expect(again.status).toBe("running");
    const logs = expectLogs(
      manager.logs({ jobId: started.jobId, offsetBytes: cutOff - 10, maxBytes: 10_000 }),
    );
    expect(logs.nextOffsetBytes).toBe(cutOff);
    expect(logs.eof).toBe(true);
    // …and the notice is still written exactly once, however much lands after it.
    expect(readMetaFile(started.jobId).truncatedAt).toBe(cutOff);
  });

  it("stops appending and stops serving past the cut-off once capped", async () => {
    const started = await startCappedJob();
    const capped = expectJob(manager.status({ jobId: started.jobId }));
    const cutOff = capped.logBytes;

    // The job still writes to the same file, so more bytes CAN land on disk.
    fs.appendFileSync(logPath(started.jobId), "z".repeat(4_096));
    const grown = fileSize(logPath(started.jobId));
    expect(grown).toBeGreaterThan(cutOff);

    const again = expectJob(manager.status({ jobId: started.jobId }));
    // The notice is appended exactly once, and the cut-off never moves.
    expect(fileSize(logPath(started.jobId))).toBe(grown);
    expect(again.logBytes).toBe(cutOff);
    expect(again.truncated).toBe(true);
    expect(readMetaFile(started.jobId).truncatedAt).toBe(cutOff);

    // Reads stop at the cut-off, so paging always reaches eof.
    const logs = expectLogs(
      manager.logs({ jobId: started.jobId, offsetBytes: cutOff - 20, maxBytes: 10_000 }),
    );
    expect(Buffer.from(logs.chunk, "base64")).toHaveLength(20);
    expect(logs.nextOffsetBytes).toBe(cutOff);
    expect(logs.eof).toBe(true);
    expect(logs.truncated).toBe(true);
  });

  it("caps a job that exits before it is ever polled", async () => {
    // The bypass: checkLogCap used to run only on refresh's "still running"
    // branch, so a job that ran and exited between two calls — the ordinary
    // fire-and-forget case — reached its terminal record without the cap ever
    // being evaluated. `truncated` then said false forever and every read served
    // the whole file, however large it had grown.
    //
    // The log is oversized BEFORE the process ends, which is what makes this
    // deterministic: TWO callers can settle this job — the status() call below
    // and spawnJob's own `exit` handler, which calls refresh() itself — and
    // whichever gets there first is the one that weighs the cap, once. Growing
    // the log after the exit would test only the ordering of that race (and lose
    // it on a fast machine, where the handler settles a still-tiny log). A real
    // job's log cannot grow after it exits anyway; being already over the cap
    // when it does is the state this test is actually about.
    const started = startJob({ command: GATED });
    await waitFor("the job's log file to exist", () => fs.existsSync(logPath(started.jobId)));
    inflateLog(started.jobId, JOB_MAX_LOG_BYTES + 1024);
    releaseGatedJob(started.jobId);
    await waitForExit(started.jobId);

    // Whoever settled it, the record a caller is served has to be the capped one.
    const settled = expectJob(manager.status({ jobId: started.jobId }));
    expect(settled.status).toBe("exited");
    expect(settled.truncated).toBe(true);
    expectServedWithinCap(settled.logBytes);
    expect(readMetaFile(started.jobId).truncatedAt).toBe(settled.logBytes);
    expect(expectLogs(manager.logs({ jobId: started.jobId, offsetBytes: 0 })).truncated).toBe(true);
  });

  it("caps a job that was already terminal on disk when this agent found it", () => {
    // The other way in: a record settled by a previous agent life never passes
    // through settle() again, so the terminal branch of refresh has to weigh the
    // cap itself or an oversized log survives every restart uncapped.
    const jobId = seedJob({ status: "exited", exitCode: 0, endedAt: Date.now(), log: "" });
    inflateLog(jobId, JOB_MAX_LOG_BYTES + 1024);

    const summary = expectJob(manager.status({ jobId }));
    expect(summary.truncated).toBe(true);
    expectServedWithinCap(summary.logBytes);
    expect(readMetaFile(jobId).truncatedAt).toBe(summary.logBytes);
    // And it is decided once: a second read neither moves the cut-off nor
    // appends a second notice.
    const size = fileSize(logPath(jobId));
    expect(expectJob(manager.status({ jobId })).logBytes).toBe(summary.logBytes);
    expect(fileSize(logPath(jobId))).toBe(size);
  });
});

// ── Concurrency rail ─────────────────────────────────────────────────────────

describeOnPosix("concurrency limit", () => {
  it("refuses a start beyond JOB_MAX_CONCURRENT running jobs", () => {
    for (let i = 0; i < JOB_MAX_CONCURRENT; i++) {
      startJob({ command: LONG_RUNNING });
    }
    const before = fs.readdirSync(jobsRoot).length;

    const refusal = expectRefusal(manager.start({ command: "printf over-the-limit" }));
    expect(refusal.reason).toBe("too_many_jobs");
    expect(refusal.message).toContain(String(JOB_MAX_CONCURRENT));
    // A refused start creates nothing.
    expect(fs.readdirSync(jobsRoot).length).toBe(before);
  });

  it("counts from live state, not from stale 'running' records on disk", () => {
    // A full machine's worth of jobs that ended while the agent was down: half
    // wrote an exit file, half were killed outright. None is running now, so the
    // rail must not wedge job_start until someone happens to call job_list.
    for (let i = 0; i < JOB_MAX_CONCURRENT; i++) {
      seedJob(i % 2 === 0 ? { status: "running", exit: "0" } : { status: "running" });
    }
    const started = startJob({ command: "printf accepted" });
    expect(started.status).toBe("running");
  });
});

// ── Cancel ───────────────────────────────────────────────────────────────────

describeOnPosix("cancel", () => {
  /** A job whose background grandchild appends to `tickFile` on a loop. */
  async function startTicker(tickFile: string, trapTerm: boolean): Promise<JobSummary> {
    fs.writeFileSync(tickFile, "");
    const loop = 'while :; do printf x >> "$AIC_JOB_TICK"; sleep 0.05; done';
    const command = trapTerm
      ? `trap '' TERM; ${loop} & printf 'ready\\n'; wait`
      : `${loop} & printf 'ready\\n'; wait`;
    const started = startJob({ command, env: { AIC_JOB_TICK: tickFile } });
    await waitFor("the ticker to start writing", () => fileSize(tickFile) > 0);
    return started;
  }

  it("refuses to cancel a job that does not exist", () => {
    expect(expectRefusal(manager.cancel({ jobId: "0123456789abcdef" })).reason).toBe("not_found");
  });

  it("signals the whole process group so grandchildren die too", async () => {
    const tickFile = path.join(tmpBase, "ticks-group");
    const started = await startTicker(tickFile, false);

    manager.cancel({ jobId: started.jobId });

    // Assert no further growth rather than probing the pid: a SIGKILLed leaf
    // lingers as a zombie that still answers signal 0 (same reasoning as
    // executor.test.ts).
    await new Promise((resolve) => setTimeout(resolve, 250));
    const settledSize = fileSize(tickFile);
    expect(settledSize).toBeGreaterThan(0); // the grandchild really did run
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(fileSize(tickFile)).toBe(settledSize);
  });

  it("does not lose a job that ignores SIGTERM before the grace period is up", async () => {
    const tickFile = path.join(tmpBase, "ticks-term");
    const started = await startTicker(tickFile, true);

    // Fake timers so the escalation this cancel arms is discarded with them,
    // leaving only the SIGTERM whose effect (none) we want to observe.
    vi.useFakeTimers({ toFake: ["setTimeout"] });
    manager.cancel({ jobId: started.jobId });
    vi.useRealTimers();

    const sizeAtTerm = fileSize(tickFile);
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(fileSize(tickFile)).toBeGreaterThan(sizeAtTerm);
  });

  it("escalates to SIGKILL after KILL_ESCALATION_MS", async () => {
    const tickFile = path.join(tmpBase, "ticks-kill");
    const started = await startTicker(tickFile, true);

    vi.useFakeTimers({ toFake: ["setTimeout"] });
    manager.cancel({ jobId: started.jobId }); // SIGTERM, ignored by the job
    vi.advanceTimersByTime(KILL_ESCALATION_MS + 10); // → SIGKILL, synchronously
    vi.useRealTimers();

    await new Promise((resolve) => setTimeout(resolve, 250));
    const settledSize = fileSize(tickFile);
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(fileSize(tickFile)).toBe(settledSize);
    // A SIGKILLed wrapper never gets to write its exit code.
    expect(fs.existsSync(exitPath(started.jobId))).toBe(false);
  });

  it("reports a killed job as unknown rather than a success", async () => {
    const started = startJob({ command: LONG_RUNNING });
    const pid = readMetaFile(started.jobId).pid as number;
    process.kill(-pid, "SIGKILL");

    await waitFor("the killed job to be reaped", () => {
      const summary = expectJob(manager.status({ jobId: started.jobId }));
      return summary.status !== "running";
    });
    const summary = expectJob(manager.status({ jobId: started.jobId }));
    expect(summary.status).toBe("unknown");
    expect(summary.exitCode).toBeNull();
  });

  it("cancelling an already-finished job returns its terminal state, not an error", async () => {
    const started = startJob({ command: "printf done" });
    await waitForExit(started.jobId);

    const cancelled = expectJob(manager.cancel({ jobId: started.jobId }));
    expect(cancelled.status).toBe("exited");
    expect(cancelled.exitCode).toBe(0);
  });

  it("never reports a cancelled job as 'exited 0' when its shell leaves cleanly", async () => {
    // Measured on a real Mac (2026-08-10): a job cancelled at tick 45 of 300 came
    // back as `exited, exit code 0` — indistinguishable from success, and the one
    // thing every description of this tool promises never to say. The cause is a
    // shell that HANDLES SIGTERM: macOS /bin/sh is bash, which runs the wrapper's
    // EXIT trap and then leaves normally, so Node sees `code: 0, signal: null` and
    // the "was it killed?" test based on `signal` passes it straight through.
    // Linux dash dies OF the signal, which is why it was correct there and only
    // there. Windows arrives the same way: taskkill /F hands the process an
    // ordinary code.
    //
    // The trap below reproduces that shape on ANY platform, which is the point:
    // the fix cannot be "trust the signal", it has to be "we know we cancelled".
    const started = startJob({ command: "trap 'exit 0' TERM; while :; do sleep 0.05; done" });
    await waitFor("the job to be running", () => expectJob(manager.status({ jobId: started.jobId })).status === "running");

    manager.cancel({ jobId: started.jobId });
    await waitFor(
      "the cancelled job to settle",
      () => expectJob(manager.status({ jobId: started.jobId })).status !== "running",
    );

    const settled = expectJob(manager.status({ jobId: started.jobId }));
    expect(settled.status).toBe("unknown");
    expect(settled.exitCode).toBeNull();
  });

  it("still keeps a real exit code the wrapper recorded before the cancel landed", async () => {
    // The guard must not swallow genuine outcomes: a job that finished on its own
    // has its code written by the process that actually ran the command, and that
    // value outranks anything we observe or assume.
    const started = startJob({ command: "printf done; exit 7" });
    await waitForExit(started.jobId);

    const cancelled = expectJob(manager.cancel({ jobId: started.jobId }));
    expect(cancelled.status).toBe("exited");
    expect(cancelled.exitCode).toBe(7);
  });
});

// ── Refusal / payload discipline ─────────────────────────────────────────────

describeOnPosix("refusal and payload discipline", () => {
  const SENTINEL = "AIC-CMD-SENTINEL-9f3a";
  // `:` ignores its arguments, so the sentinel is in the COMMAND but never in
  // the job's output — any reply carrying it leaked the command string.
  const SENTINEL_COMMAND = `: ${SENTINEL}; printf 'safe-output'`;

  it("returns gpu_busy as a structured result instead of throwing", () => {
    startJob({ command: LONG_RUNNING, gpuIndex: 0 });
    let result: JobRpcResult | undefined;
    expect(() => {
      result = manager.start({ command: SENTINEL_COMMAND, gpuIndex: 0 });
    }).not.toThrow();
    const refusal = expectRefusal(result as JobRpcResult);
    expect(refusal.reason).toBe("gpu_busy");
    expect(JSON.stringify(refusal)).not.toContain(SENTINEL);
  });

  it("returns too_many_jobs as a structured result instead of throwing", () => {
    for (let i = 0; i < JOB_MAX_CONCURRENT; i++) {
      startJob({ command: LONG_RUNNING });
    }
    const refusal = expectRefusal(manager.start({ command: SENTINEL_COMMAND }));
    expect(refusal.reason).toBe("too_many_jobs");
    expect(JSON.stringify(refusal)).not.toContain(SENTINEL);
  });

  it("returns not_found as a structured result instead of throwing", () => {
    const refusal = expectRefusal(manager.status({ jobId: "0123456789abcdef" }));
    expect(refusal.reason).toBe("not_found");
    expect(refusal.heldBy).toBeUndefined();
    expect(refusal.message).toBeTruthy();
  });

  it("keeps the command out of every reply that did not ask for it", async () => {
    const started = startJob({ command: SENTINEL_COMMAND, name: "sentinel-job" });
    await waitForExit(started.jobId);

    const replies: JobRpcResult[] = [
      manager.status({ jobId: started.jobId }),
      manager.status({ jobId: started.jobId, includeCommand: false }),
      manager.list({}),
      manager.list({ includeCommand: false }),
      manager.cancel({ jobId: started.jobId }),
      manager.logs({ jobId: started.jobId }),
    ];
    for (const reply of replies) {
      expect(JSON.stringify(reply)).not.toContain(SENTINEL);
    }
    expect(expectJob(replies[0]).command).toBeUndefined();
    expect(expectJobs(replies[2])[0].command).toBeUndefined();
    // The start reply is likewise command-free (there is no way to ask there).
    expect(started.command).toBeUndefined();
  });

  it("returns the command only when the caller explicitly asked for it", async () => {
    const started = startJob({ command: SENTINEL_COMMAND });
    await waitForExit(started.jobId);

    expect(expectJob(manager.status({ jobId: started.jobId, includeCommand: true })).command).toBe(
      SENTINEL_COMMAND,
    );
    expect(expectJobs(manager.list({ includeCommand: true }))[0].command).toBe(SENTINEL_COMMAND);
  });
});

// ── Every summary must survive the relay's validator ─────────────────────────
//
// The relay revalidates each JobSummary and rejects a record (and, before the
// per-record skip existed, the WHOLE reply) on the first field that does not
// match — so a summary that is merely plausible here is a caller who gets no
// answer at all. The checks below mirror packages/worker/src/jobs-relay.ts's
// validJobSummary deliberately: restating them is how the agent side notices when
// it stops meeting the contract.
//
// The BOUNDS, though, are imported rather than restated. An earlier copy of this
// block hardcoded a gpu ceiling of 4096 — the relay's value, which the agent's own
// code never used — so the test asserted a limit its subject did not have. That is
// the drift these constants exist to remove; the worker's separate, deliberately
// looser string bounds are held >= these by jobs-wire-contract.test.ts there.

/** Exactly the relay's check, applied to what actually goes over the wire. */
function assertValidSummary(summary: JobSummary): void {
  // The round-trip is load-bearing: JSON.stringify DELETES an `undefined` field,
  // and the validator demands a literal `null` — so a field that is undefined
  // here simply vanishes and fails on the far side, invisible to a plain
  // in-memory assertion.
  const j = JSON.parse(JSON.stringify(summary)) as Record<string, unknown>;
  // The relay matches the id's exact SHAPE, not merely its length — it echoes ids
  // into caller-visible text — so a non-empty id is not enough to pass over there.
  expect(typeof j["jobId"]).toBe("string");
  expect(JOB_ID_PATTERN.test(j["jobId"] as string)).toBe(true);
  expect(typeof j["name"]).toBe("string");
  expect((j["name"] as string).length).toBeLessThanOrEqual(JOB_WIRE_MAX_NAME_CHARS);
  expect(["running", "exited", "unknown"]).toContain(j["status"]);
  expect(j["exitCode"] === null || Number.isSafeInteger(j["exitCode"])).toBe(true);
  expect(Number.isSafeInteger(j["startedAt"]) && Math.abs(j["startedAt"] as number) <= MAX_EPOCH_MS).toBe(
    true,
  );
  expect(
    j["endedAt"] === null ||
      (Number.isSafeInteger(j["endedAt"]) && Math.abs(j["endedAt"] as number) <= MAX_EPOCH_MS),
  ).toBe(true);
  expect(
    j["gpuIndex"] === null ||
      (Number.isSafeInteger(j["gpuIndex"]) &&
        (j["gpuIndex"] as number) >= 0 &&
        (j["gpuIndex"] as number) <= JOB_MAX_GPU_INDEX),
  ).toBe(true);
  expect(Number.isSafeInteger(j["logBytes"]) && (j["logBytes"] as number) >= 0).toBe(true);
  expect(typeof j["truncated"]).toBe("boolean");
  expect(j["command"] === undefined || typeof j["command"] === "string").toBe(true);
  expect(j["command"] === undefined || (j["command"] as string).length <= JOB_WIRE_MAX_COMMAND_CHARS).toBe(
    true,
  );
}

describeOnPosix("wire shape of a job summary", () => {
  it("keeps an exited job's endedAt a whole number of milliseconds", async () => {
    // The defect: endedAt came straight from the exit file's mtimeMs, which
    // carries the filesystem's sub-millisecond precision and is therefore almost
    // never an integer — so EVERY reply describing an exited job was rejected,
    // while the same job read fine while it was still running.
    const started = startJob({ command: "printf done" });
    await waitForExit(started.jobId);

    const settled = expectJob(manager.status({ jobId: started.jobId }));
    expect(settled.status).toBe("exited");
    expect(Number.isSafeInteger(settled.endedAt)).toBe(true);
    assertValidSummary(settled);
    // And on disk too, so a restarted agent re-reads an honest record.
    expect(Number.isSafeInteger(readMetaFile(started.jobId).endedAt)).toBe(true);
  });

  it("validates for a running job, a cancelled one, and a whole list", async () => {
    const running = startJob({ command: LONG_RUNNING, gpuIndex: 3 });
    const exited = startJob({ command: "exit 2" });
    await waitForExit(exited.jobId);

    assertValidSummary(running);
    assertValidSummary(expectJob(manager.status({ jobId: running.jobId, includeCommand: true })));
    assertValidSummary(expectJob(manager.cancel({ jobId: running.jobId })));
    assertValidSummary(expectJob(manager.cancel({ jobId: exited.jobId })));
    for (const summary of expectJobs(manager.list({}))) assertValidSummary(summary);
  });

  it("validates for a job whose log file is missing entirely", () => {
    // Bug B's blast radius: a job with no output.log at all must still describe
    // itself, or one broken capture takes job_list down with it.
    const jobId = seedJob({ status: "exited", exitCode: 0, endedAt: Date.now() });
    expect(fs.existsSync(logPath(jobId))).toBe(false);

    const summary = expectJob(manager.status({ jobId }));
    expect(summary.logBytes).toBe(0);
    assertValidSummary(summary);
  });

  it("normalises the fields a corrupt-but-readable record could poison", () => {
    // isJobMeta accepts any `number`, which includes the values that are NOT
    // representable on the wire. Normalising at the single serialization
    // boundary is what makes the summary incapable of being invalid, rather
    // than each of these being a separate patch.
    const jobId = seedJob({
      status: "exited",
      exitCode: 1.5,
      startedAt: Date.now() + 0.25,
      endedAt: Number.NaN,
      gpuIndex: 99_999,
    });

    const summary = expectJob(manager.status({ jobId }));
    assertValidSummary(summary);
    expect(summary.exitCode).toBeNull();
    expect(summary.endedAt).toBeNull();
    expect(summary.gpuIndex).toBeNull();
  });

  it("truncates a name and a command the relay would reject as over-long", () => {
    // The LENGTH bounds are enforced exactly as hard as the type checks on the
    // far side: an over-long `name` fails validJobSummary, and for a `kind:"job"`
    // reply that is a 502 with no job in it. Nothing this agent STARTS can get
    // near them (names are cut to 64 chars, commands refused past 64 KiB) — but
    // isJobMeta only asks whether the field is a string, so a hand-edited or
    // half-corrupted meta.json can, and that record must still describe itself.
    const jobId = seedJob({
      status: "exited",
      exitCode: 0,
      endedAt: Date.now(),
      name: "n".repeat(JOB_WIRE_MAX_NAME_CHARS + 100),
      command: "c".repeat(JOB_WIRE_MAX_COMMAND_CHARS + 100),
    });

    const summary = expectJob(manager.status({ jobId, includeCommand: true }));
    assertValidSummary(summary);
    expect(summary.name).toHaveLength(JOB_WIRE_MAX_NAME_CHARS);
    expect(summary.command).toHaveLength(JOB_WIRE_MAX_COMMAND_CHARS);
    // The cut is at the WIRE only: the record on disk is left exactly as found.
    expect(readMetaFile(jobId).name).toHaveLength(JOB_WIRE_MAX_NAME_CHARS + 100);
    // …and a list of such records still answers, rather than costing the caller
    // every other job on the machine.
    for (const listed of expectJobs(manager.list({ includeCommand: true }))) assertValidSummary(listed);
  });

  it("never leaves half a surrogate pair at the cut", () => {
    // The bound is counted in UTF-16 code units, so the cut can fall between the
    // halves of an emoji in a job name. A lone surrogate is not text: it survives
    // the length check and then confuses everything downstream that renders it.
    const jobId = seedJob({
      status: "exited",
      exitCode: 0,
      endedAt: Date.now(),
      name: `${"n".repeat(JOB_WIRE_MAX_NAME_CHARS - 1)}😀tail`,
    });

    const summary = expectJob(manager.status({ jobId }));
    assertValidSummary(summary);
    expect(summary.name).toHaveLength(JOB_WIRE_MAX_NAME_CHARS - 1);
    expect(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/.test(summary.name)).toBe(false);
  });
});

// ── The job environment ──────────────────────────────────────────────────────

describeOnPosix("job environment", () => {
  /** What the job actually saw, captured by the job itself. */
  async function envOf(name: string, req: Partial<Parameters<JobManager["start"]>[0]> = {}) {
    const started = startJob({ command: `printf %s "$${name}"`, ...req });
    await waitForExit(started.jobId);
    return readLog(started.jobId);
  }

  it("defaults PYTHONUNBUFFERED so a training log arrives as it is produced", async () => {
    // Python block-buffers ~4-8 KiB whenever stdout is not a terminal, and a
    // job's stdout is always a file — so without this a "live" log is a burst
    // every few minutes, which reads exactly like no output at all.
    expect(await envOf("PYTHONUNBUFFERED")).toBe("1");
  });

  it("lets a caller-supplied env win over the default", async () => {
    expect(await envOf("PYTHONUNBUFFERED", { env: { PYTHONUNBUFFERED: "0" } })).toBe("0");
  });

  // The locale fill-in is macOS-only by construction: Linux agents inherit a
  // LANG from systemd/the login session and Windows does not use the variable,
  // so only here is there a hole to fill — and only here can the fix be shown.
  // A green Linux run says nothing about this pair; the darwin CI job is what
  // executes it.
  const itOnMacOS = it.runIf(process.platform === "darwin");

  itOnMacOS("gives a macOS job a real locale instead of launchd's empty LANG", async () => {
    // Reproduce the launchd situation the fix exists for: the app is started
    // with no environment at all, so the runner's own LANG must not stand in
    // for one — with it inherited, applyLoginShellLocale correctly leaves it
    // alone and the test would pass without the fix.
    const inherited = process.env["LANG"];
    delete process.env["LANG"];
    try {
      const lang = await envOf("LANG");
      // The exact value depends on the box (the login shell's own LANG when it
      // reports one, the UTF-8 fallback when it does not), so assert the
      // property that matters to a CLI tool handling Polish or Japanese text:
      // some locale, and a UTF-8 one — not the C locale an empty LANG means.
      expect(lang).not.toBe("");
      expect(lang).toMatch(/UTF-8$/i);
    } finally {
      if (inherited === undefined) delete process.env["LANG"];
      else process.env["LANG"] = inherited;
    }
  });

  itOnMacOS("lets a caller-supplied LANG win over the one we fill in", async () => {
    // Same precedence as PATH and JOB_ENV_DEFAULTS: what we resolve is applied
    // BEFORE the caller's block, so an explicit request still decides. A caller
    // asking for the C locale on purpose must get it.
    const inherited = process.env["LANG"];
    delete process.env["LANG"];
    try {
      expect(await envOf("LANG", { env: { LANG: "C" } })).toBe("C");
    } finally {
      if (inherited === undefined) delete process.env["LANG"];
      else process.env["LANG"] = inherited;
    }
  });

  describeOnPosix("TERM", () => {
    // buildEnv calls applyNonInteractiveTerm so a job is never left with TERM
    // unset: a job writes the longest logs on the machine and remote_job_logs
    // pages them back to a model, which should not have to read the escape
    // sequences a colour-capable TERM invites.
    //
    // login-shell-path.test.ts proves the HELPER fills an absent TERM, and
    // executor.ts's own suite proves `do:exec` calls it. Neither proves this
    // file does — and that is the gap that matters, because deleting the call
    // from buildEnv breaks jobs under launchd/systemd (no TERM at all) while
    // every other test stays green: vitest runs with TERM=dumb, so a job that
    // merely INHERITS the runner's environment already looks correct.
    //
    // And asking the JOB what TERM it saw cannot prove it either — that was the
    // first attempt, and it passed with the production call commented out. See
    // the termFill mock at the top of this file: /bin/sh is bash on macOS and
    // sets TERM=dumb for itself when it starts with none, so the job answers
    // "dumb" no matter what we hand it. The ENV THE JOB IS SPAWNED WITH is the
    // only place the difference is visible, so that is what these two assert:
    // deleting `applyNonInteractiveTerm(env)` from buildEnv fails them.
    it("fills TERM in the env a job is spawned with — the launchd/systemd case", async () => {
      const inherited = process.env["TERM"];
      // Reproduce the shipped situation: launchd and systemd hand the agent no
      // TERM at all. With the runner's own TERM left in place the fill is a
      // no-op and the assertion would be about the runner, not the fix.
      delete process.env["TERM"];
      termFill.envs.length = 0;
      try {
        const started = startJob({ command: "true" });
        await waitForExit(started.jobId);
        // Once per job start, on the environment that spawn() receives.
        expect(termFill.envs).toHaveLength(1);
        const spawnedWith = termFill.envs[0]!;
        // It really is buildEnv's environment — JOB_ENV_DEFAULTS was applied to
        // this same object a few lines earlier — and not some other caller's.
        expect(spawnedWith["PYTHONUNBUFFERED"]).toBe("1");
        // "dumb" is applyNonInteractiveTerm's value: a terminal name every
        // terminfo has and that advertises no colour, so a multi-hour log stays
        // readable when remote_job_logs pages it back to a model.
        expect(spawnedWith["TERM"]).toBe("dumb");
      } finally {
        if (inherited === undefined) delete process.env["TERM"];
        else process.env["TERM"] = inherited;
      }
    });

    // The wiring's precedence, which the helper's own unit test cannot see: what
    // we fill is applied BEFORE the caller's env block, so an explicit value
    // still decides what the job is spawned with.
    it("lets a caller-supplied TERM win over the one we fill in", async () => {
      const inherited = process.env["TERM"];
      delete process.env["TERM"];
      termFill.envs.length = 0;
      try {
        const started = startJob({ command: "true", env: { TERM: "xterm-256color" } });
        await waitForExit(started.jobId);
        expect(termFill.envs[0]?.["TERM"]).toBe("xterm-256color");
      } finally {
        if (inherited === undefined) delete process.env["TERM"];
        else process.env["TERM"] = inherited;
      }
    });
  });

  it("points the log path at the job's own output.log, past any caller override", async () => {
    const started = startJob({
      command: `printf %s "$${JOB_LOG_PATH_ENV}"`,
      env: { [JOB_LOG_PATH_ENV]: "/tmp/somewhere-else" },
    });
    await waitForExit(started.jobId);
    // The redirect happened before the printf, so the log holds its own path.
    expect(readLog(started.jobId)).toBe(logPath(started.jobId));
  });
});
