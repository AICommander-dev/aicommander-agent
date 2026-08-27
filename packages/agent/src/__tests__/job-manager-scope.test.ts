// Jobs launched THROUGH a scope wrapper, executed for real.
//
// job-scope.test.ts pins the decision and the argv; this file pins what the
// wrapper must not disturb. `systemd-run --scope` execs the command in place,
// and the entire design rests on that: the pid stays the job's shell, the log fd
// survives, the cwd survives, the environment survives, and the exit is observed
// by the same handler as before. A stand-in that behaves the way exec-in-place
// behaves is enough to hold every one of those to account on a box with no
// systemd, which is every developer machine and most of CI.
//
// What it CANNOT show is the cgroup itself — that a scope is created outside the
// service's control group, and that the job then survives
// `systemctl restart aicommander-agent`. Both were measured by hand on Ubuntu
// 24.04.4 / systemd 255 (scoped job in `0::/system.slice/aic-job-<id>.scope`, a
// plain-spawn control in `0::/system.slice/aicommander-agent.service`; the
// restart killed the control at that exact second and the scoped job's log ran
// straight through it) — see job-scope.ts, where the full list is written down.
// No test in this repository can re-run that: it needs root, systemd, and a
// restart of the agent under test.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { JobRpcResult, JobStatus, JobSummary } from "@aicommander/protocol";

/**
 * The spawn boundary, observed rather than replaced: the real child still runs
 * (these tests execute jobs), and the argv it was given is kept so the fallback
 * test can assert that a machine without a launcher spawns a bare `/bin/sh -c`
 * and nothing else.
 */
const spawns = vi.hoisted(() => ({ calls: [] as { file: string; args: readonly string[] }[] }));
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return {
    ...actual,
    spawn: (file: string, args: readonly string[], opts: unknown) => {
      spawns.calls.push({ file, args });
      return (actual.spawn as unknown as (...a: unknown[]) => unknown)(file, args, opts);
    },
  };
});

/**
 * The systemctl call that empties a scope's cgroup, observed instead of made.
 *
 * job-scope-probe.test.ts pins what killJobScope RUNS; what matters here is
 * WHEN the manager reaches for it — and the real one would aim a root
 * `systemctl kill` at a unit on the developer's own box.
 */
const scopeKills = vi.hoisted(() => ({ units: [] as string[] }));
vi.mock("../job-scope.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../job-scope.js")>();
  return { ...actual, killJobScope: (unit: string) => void scopeKills.units.push(unit) };
});

/**
 * A meta.json write that fails on demand — the only way to reach the retirement
 * path (a process that is already running when the start fails), which is where
 * the second scope escalation lives.
 */
const metaWrite = vi.hoisted(() => ({ fail: null as null | ((fileName: string) => boolean) }));
vi.mock("../atomic-file.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../atomic-file.js")>();
  return {
    ...actual,
    atomicWriteUtf8: (dir: string, fileName: string, contents: string): void => {
      if (metaWrite.fail?.(fileName)) throw new Error("read-only file system");
      actual.atomicWriteUtf8(dir, fileName, contents);
    },
  };
});

import { KILL_ESCALATION_MS } from "@aicommander/protocol";
import { JobManager, resetJobManagerForTests } from "../job-manager.js";
import {
  jobScopeUnitName,
  resetJobScopeLauncherForTests,
  setSystemctlForTests,
} from "../job-scope.js";

// Every assertion here runs a real POSIX shell through the real spawn path, and
// the Windows job path deliberately does not use scopes at all (see spawnJob).
const describeOnPosix = describe.skipIf(process.platform === "win32");

/**
 * A stand-in for `systemd-run --scope` that reproduces the ONE property the job
 * machinery depends on: it drops its own options, then `exec`s the command in
 * place, so the pid, the process group, the inherited fds, the cwd and the
 * environment all carry straight through to the job's shell.
 *
 * Deliberately written as a shell script rather than faked in JS: the real thing
 * is an execvp, and anything that forks instead would quietly pass tests that
 * the real mechanism would fail.
 */
function writeFakeSystemdRun(dir: string): string {
  const target = path.join(dir, "fake-systemd-run");
  fs.writeFileSync(
    target,
    "#!/bin/sh\n" +
      "while [ \"$#\" -gt 0 ]; do\n" +
      "  case \"$1\" in\n" +
      "    --) shift; break ;;\n" +
      "    --*) shift ;;\n" +
      "    *) break ;;\n" +
      "  esac\n" +
      "done\n" +
      "exec \"$@\"\n",
    { mode: 0o755 },
  );
  return target;
}

/**
 * A stand-in for systemctl that RECORDS instead of killing, and answers
 * `list-units` from a file the test controls.
 *
 * Written as a real script, like the systemd-run stand-in above and for the same
 * reason: the sweep resolves a path and execs it, so anything faked in JS would
 * pass on argv the real binary would reject. It is also the only safe way to
 * exercise this on a CI runner that HAS a real systemctl — the sweep must never
 * be allowed to aim one at that box.
 */
function writeFakeSystemctl(dir: string): string {
  const target = path.join(dir, "fake-systemctl");
  fs.writeFileSync(
    target,
    "#!/bin/sh\n" +
      `printf '%s\\n' "$*" >> ${JSON.stringify(systemctlLog(dir))}\n` +
      `if [ "$1" = "list-units" ]; then cat ${JSON.stringify(liveScopesFile(dir))} 2>/dev/null; fi\n` +
      "exit 0\n",
    { mode: 0o755 },
  );
  return target;
}

function systemctlLog(dir: string): string {
  return path.join(dir, "systemctl-calls.log");
}

function liveScopesFile(dir: string): string {
  return path.join(dir, "live-scopes.txt");
}

/** Every systemctl command line the sweep has run so far, in order. */
function systemctlCalls(): string[] {
  try {
    return fs
      .readFileSync(systemctlLog(tmpBase), "utf8")
      .split("\n")
      .filter((line) => line.length > 0);
  } catch {
    return [];
  }
}

/** Make `units` look alive to `list-units`, in that command's output shape. */
function declareLiveScopes(units: readonly string[]): void {
  fs.writeFileSync(
    liveScopesFile(tmpBase),
    units.map((u) => `${u} loaded active running AI Commander job\n`).join(""),
  );
}

const ENV_DIR_VAR = "AICOMMANDER_CONFIG_DIR";
let savedEnvDir: string | undefined;
let tmpBase: string;
let jobsRoot: string;
let workDir: string;
let systemdRun: string;

beforeEach(() => {
  spawns.calls = [];
  scopeKills.units = [];
  metaWrite.fail = null;
  savedEnvDir = process.env[ENV_DIR_VAR];
  delete process.env[ENV_DIR_VAR];
  tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), "aic-scope-"));
  jobsRoot = path.join(tmpBase, "jobs");
  workDir = path.join(tmpBase, "work");
  fs.mkdirSync(workDir);
  systemdRun = writeFakeSystemdRun(tmpBase);
  // Clears the memoized systemctl path AND any sweep left pending by the
  // previous test, then points the sweep at the stand-in above.
  resetJobScopeLauncherForTests();
  setSystemctlForTests(writeFakeSystemctl(tmpBase));
});

afterEach(async () => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  resetJobManagerForTests();
  resetJobScopeLauncherForTests();
  // A dying job's exit handler re-writes meta.json on its way out.
  await new Promise((resolve) => setTimeout(resolve, 25));
  if (savedEnvDir === undefined) delete process.env[ENV_DIR_VAR];
  else process.env[ENV_DIR_VAR] = savedEnvDir;
  fs.rmSync(tmpBase, { recursive: true, force: true });
});

interface OnDiskMeta {
  jobId: string;
  status: JobStatus;
  exitCode: number | null;
  cwd: string;
  pid: number | null;
  procIdentity: string | null;
  /** Present only when the job really was launched into a scope. */
  scope?: string;
}

function scopedManager(): JobManager {
  return new JobManager({ jobsRoot, scopeLauncher: () => ({ systemdRun }) });
}

function unscopedManager(): JobManager {
  return new JobManager({ jobsRoot, scopeLauncher: () => null });
}

function expectJob(result: JobRpcResult): JobSummary {
  if (!result.ok || result.kind !== "job") {
    throw new Error(`expected a job result, got ${JSON.stringify(result)}`);
  }
  return result.job;
}

function readMetaFile(jobId: string): OnDiskMeta {
  return JSON.parse(
    fs.readFileSync(path.join(jobsRoot, jobId, "meta.json"), "utf8"),
  ) as OnDiskMeta;
}

function readLog(jobId: string): string {
  try {
    return fs.readFileSync(path.join(jobsRoot, jobId, "output.log"), "utf8");
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

/** The manager only settles a record when someone asks, so ask. */
function settle(manager: JobManager, jobId: string): JobSummary {
  return expectJob(manager.status({ jobId }));
}

async function runToCompletion(
  manager: JobManager,
  req: Parameters<JobManager["start"]>[0],
): Promise<{ jobId: string; summary: JobSummary }> {
  const started = expectJob(manager.start(req));
  await waitFor(`job ${started.jobId} to write its exit file`, () => {
    try {
      return /^-?\d{1,5}$/.test(
        fs.readFileSync(path.join(jobsRoot, started.jobId, "exit"), "utf8").trim(),
      );
    } catch {
      return false;
    }
  });
  return { jobId: started.jobId, summary: settle(manager, started.jobId) };
}

describeOnPosix("a job launched through a scope wrapper", () => {
  it("runs to completion and records the exit code the wrapper wrote", async () => {
    const manager = scopedManager();
    const { summary } = await runToCompletion(manager, { command: "exit 0", cwd: workDir });
    expect(summary.status).toBe("exited");
    expect(summary.exitCode).toBe(0);
  });

  it("records a NON-zero exit code just as an unwrapped job does", async () => {
    // The exit trap lives in the job's own shell, which the wrapper execs INTO —
    // if the wrapper were a fork instead, this would report the wrapper's code.
    const manager = scopedManager();
    const { summary } = await runToCompletion(manager, { command: "exit 7", cwd: workDir });
    expect(summary.exitCode).toBe(7);
  });

  it("keeps the inherited log fd: stdout AND stderr still land in output.log", async () => {
    const manager = scopedManager();
    const { jobId } = await runToCompletion(manager, {
      command: "echo to-stdout; echo to-stderr 1>&2",
      cwd: workDir,
    });
    await waitFor("both streams in the log", () => /to-stderr/.test(readLog(jobId)));
    const log = readLog(jobId);
    expect(log).toContain("to-stdout");
    expect(log).toContain("to-stderr");
    // Nothing of the wrapper's own is in there. On the real systemd-run that is
    // what --quiet buys: "Running scope as unit …" goes to stderr, which IS this
    // file, and would otherwise be the first line of every Linux job ever run.
    expect(log).not.toMatch(/Running scope as unit/);
  });

  it("honours the caller's cwd — scope mode does not chdir", async () => {
    // Confirmed against the real systemd-run too (Ubuntu 24.04 / systemd 255):
    // the job printed the cwd handed to spawn(), unchanged.
    const manager = scopedManager();
    const { jobId } = await runToCompletion(manager, { command: "pwd", cwd: workDir });
    await waitFor("pwd output", () => readLog(jobId).trim().length > 0);
    // fs.realpathSync: macOS hands out /var/folders/… temp dirs behind a symlink.
    expect(readLog(jobId).trim()).toBe(fs.realpathSync(workDir));
  });

  it("hands the caller's environment through untouched", async () => {
    const manager = scopedManager();
    const { jobId } = await runToCompletion(manager, {
      command: 'printf %s "$AIC_SCOPE_TEST"',
      cwd: workDir,
      env: { AIC_SCOPE_TEST: "carried through" },
    });
    await waitFor("env output", () => readLog(jobId).length > 0);
    expect(readLog(jobId)).toContain("carried through");
  });

  it("still captures a process identity for the pid it was handed", async () => {
    // The pid is the job's own shell (exec does not change it), and on Linux the
    // identity is /proc/<pid>/stat start-ticks, which exec does not change
    // either — so the token captured right after the spawn stays valid. Measured
    // against the real systemd-run: the starttime read while the process was
    // still systemd-run equalled the one read later, as the job shell.
    const manager = scopedManager();
    const started = expectJob(manager.start({ command: "sleep 5", cwd: workDir }));
    const meta = readMetaFile(started.jobId);
    expect(meta.pid).toBeGreaterThan(0);
    expect(meta.procIdentity).toBeTruthy();
    expect(() => process.kill(meta.pid as number, 0)).not.toThrow();
    manager.cancel({ jobId: started.jobId });
  });

  it("still signals the whole process GROUP on cancel", async () => {
    // exec preserves the process group, and the group is what a training run's
    // children live in. Signals are independent of cgroups, so this is unchanged
    // by the scope — which is exactly the claim worth pinning.
    const manager = scopedManager();
    const started = expectJob(manager.start({ command: "sleep 30", cwd: workDir }));
    const pid = readMetaFile(started.jobId).pid as number;
    manager.cancel({ jobId: started.jobId });
    await waitFor("the process group to be gone", () => {
      try {
        process.kill(-pid, 0);
        return false;
      } catch {
        return true;
      }
    });
  });

  it("writes the scope's unit name into meta.json", async () => {
    // Nothing else on disk can answer "will this job survive the next upgrade?",
    // and by the time an operator asks, the process that decided is long gone.
    const manager = scopedManager();
    const { jobId } = await runToCompletion(manager, { command: "exit 0", cwd: workDir });
    expect(readMetaFile(jobId).scope).toBe(jobScopeUnitName(jobId));
  });

  it("puts the wrapper in front of the job's own shell, with nothing re-quoted", async () => {
    const manager = scopedManager();
    const command = "echo 'quoted $NOT_EXPANDED'";
    const { jobId } = await runToCompletion(manager, { command, cwd: workDir });
    const call = spawns.calls.find((c) => c.file === systemdRun);
    expect(call).toBeDefined();
    expect(call!.args.slice(0, 6)).toEqual([
      "--scope",
      "--quiet",
      "--collect",
      `--unit=${jobScopeUnitName(jobId)}`,
      `--description=AI Commander job ${jobId}`,
      "--",
    ]);
    // The command reaches exactly ONE shell — the job wrapper's own `/bin/sh -c`
    // — and the script text is the last argv element, unquoted and unescaped.
    expect(call!.args[6]).toBe("/bin/sh");
    expect(call!.args[7]).toBe("-c");
    expect(call!.args[8]).toContain(command);
    await waitFor("the echo output", () => readLog(jobId).length > 0);
    expect(readLog(jobId)).toContain("quoted $NOT_EXPANDED");
  });
});

describeOnPosix("a job on a machine with no scope launcher", () => {
  it("falls back to a plain detached /bin/sh -c, silently", async () => {
    // The fallback has to stay silent and complete: refusing to run jobs on a
    // machine without systemd would be a far larger regression than the one the
    // scope fixes.
    const manager = unscopedManager();
    const { summary } = await runToCompletion(manager, { command: "exit 0", cwd: workDir });
    expect(summary.status).toBe("exited");
    expect(summary.exitCode).toBe(0);
    expect(spawns.calls).toHaveLength(1);
    expect(spawns.calls[0]!.file).toBe("/bin/sh");
    expect(spawns.calls[0]!.args[0]).toBe("-c");
    expect(spawns.calls[0]!.args).toHaveLength(2);
  });

  it("leaves `scope` absent from meta.json", async () => {
    // Absent, not empty: absence is what says "this job is in the agent's own
    // cgroup", and it is also what every pre-upgrade record looks like.
    const manager = unscopedManager();
    const { jobId } = await runToCompletion(manager, { command: "exit 0", cwd: workDir });
    const meta = readMetaFile(jobId);
    expect(meta.scope).toBeUndefined();
    expect("scope" in meta).toBe(false);
  });

  it("behaves identically otherwise: cwd, env, streams and exit code", async () => {
    const manager = unscopedManager();
    const { jobId, summary } = await runToCompletion(manager, {
      command: 'pwd; printf %s "$AIC_SCOPE_TEST" 1>&2; exit 5',
      cwd: workDir,
      env: { AIC_SCOPE_TEST: "carried through" },
    });
    expect(summary.exitCode).toBe(5);
    await waitFor("both streams in the log", () => /carried through/.test(readLog(jobId)));
    expect(readLog(jobId)).toContain(fs.realpathSync(workDir));
  });
});

/**
 * Every scope this manager creates has to be emptied again, and the half that
 * matters is not cancel.
 *
 * A job that ENDS ON ITS OWN while a descendant that called `setsid` keeps
 * running leaves the wrapper gone and the descendant alive: refresh() settles
 * the job and releases its GPU lock at that moment, so the card and the
 * concurrency slot go to the next job while a live root process is still on the
 * card. Before scopes, `KillMode=control-group` reaped that descendant at the
 * next agent restart; inside its own scope nothing ever would.
 */
function killsOf(unit: string): string[] {
  // Filtered by unit rather than counted outright: a previous test's escalation
  // timer is unref'd and may still be pending, and every job id is distinct.
  return scopeKills.units.filter((u) => u === unit);
}

describeOnPosix("reaping a job's scope", () => {
  it("empties the scope when the job reaches a terminal state on its own", async () => {
    const manager = scopedManager();
    const { jobId, summary } = await runToCompletion(manager, { command: "exit 0", cwd: workDir });
    expect(summary.status).toBe("exited");
    // The settle is where the card is handed on, so it is where a survivor has
    // to be ended. (Normally the scope went with the job and systemd already
    // collected it — `Unit not loaded`, a silent no-op.)
    expect(killsOf(jobScopeUnitName(jobId))).toEqual([jobScopeUnitName(jobId)]);
  });

  it("fires on the TRANSITION only — status and list must not kill per poll", async () => {
    const manager = scopedManager();
    const { jobId } = await runToCompletion(manager, { command: "exit 0", cwd: workDir });
    for (let i = 0; i < 5; i++) {
      manager.status({ jobId });
      manager.list({});
    }
    expect(killsOf(jobScopeUnitName(jobId))).toHaveLength(1);
  });

  it("never touches the scope of a job that is still running", async () => {
    const manager = scopedManager();
    const started = expectJob(manager.start({ command: "sleep 30", cwd: workDir }));
    for (let i = 0; i < 3; i++) {
      expect(settle(manager, started.jobId).status).toBe("running");
      manager.list({});
    }
    expect(killsOf(jobScopeUnitName(started.jobId))).toEqual([]);
    manager.cancel({ jobId: started.jobId });
  });

  it("says nothing to systemctl for a job that never got a scope", async () => {
    // macOS, Windows and every non-systemd Linux box: absent `scope` means the
    // job is in the agent's own cgroup, and their behaviour must not change.
    const manager = unscopedManager();
    const { jobId } = await runToCompletion(manager, { command: "exit 0", cwd: workDir });
    manager.status({ jobId });
    expect(scopeKills.units).toEqual([]);
  });

  it("reaps a record found already terminal on disk through the sweep, not per job", async () => {
    // The agent-restart case: the job ended while we were down, and a scope
    // survives an agent restart by design — so it may still be holding a
    // descendant on a card the recovered agent is about to hand out. It is
    // reached through the deferred sweep rather than an immediate kill, so the
    // startup pass costs one systemctl however many records it walks.
    const { jobId } = await runToCompletion(scopedManager(), { command: "exit 0", cwd: workDir });
    scopeKills.units = [];

    const restarted = new JobManager({ jobsRoot, scopeLauncher: () => ({ systemdRun }) });
    restarted.status({ jobId });
    restarted.status({ jobId });
    expect(killsOf(jobScopeUnitName(jobId))).toEqual([]);
    await waitFor("the sweep to ask systemd", () => systemctlCalls().length > 0);
    // Nothing was declared alive, so the query is the whole cost: no kill.
    expect(systemctlCalls()).toHaveLength(1);
    expect(systemctlCalls()[0]).toContain("list-units");
  });

  it("empties the scope on the cancel escalation too", async () => {
    // SIGKILL to the process GROUP does not reach a descendant that called
    // setsid; the unit is what does.
    const manager = scopedManager();
    const started = expectJob(manager.start({ command: "sleep 30", cwd: workDir }));
    const unit = jobScopeUnitName(started.jobId);
    vi.useFakeTimers();
    manager.cancel({ jobId: started.jobId });
    // SIGTERM first, and nothing else: a job that leaves on its own gets the
    // reap at its settle, not a root systemctl call while it is shutting down.
    expect(killsOf(unit)).toEqual([]);
    vi.advanceTimersByTime(KILL_ESCALATION_MS + 10);
    expect(killsOf(unit)).toEqual([unit]);
    vi.useRealTimers();
  });

  it("empties the scope on the escalation of a start that could not be recorded", async () => {
    // retireStartedProcess: the process is already running and we cannot own it,
    // so it is stopped and its card surrendered — the same shape as a cancel,
    // and the same escaped descendant.
    let writes = 0;
    // The record BEFORE the spawn must succeed; the one after it is what fails.
    metaWrite.fail = (fileName) => fileName === "meta.json" && ++writes === 2;
    const manager = scopedManager();
    vi.useFakeTimers();
    expect(() => manager.start({ command: "sleep 30", cwd: workDir })).toThrow(/being stopped/);
    const unitArg = spawns.calls
      .flatMap((c) => c.args)
      .find((a) => typeof a === "string" && a.startsWith("--unit="));
    expect(unitArg).toBeDefined();
    const unit = unitArg!.slice("--unit=".length);
    expect(killsOf(unit)).toEqual([]);
    vi.advanceTimersByTime(KILL_ESCALATION_MS + 10);
    expect(killsOf(unit)).toEqual([unit]);
    vi.useRealTimers();
  });
});

/**
 * The startup pass over everything a previous agent left behind.
 *
 * recover() refreshes every job directory inside the retention window, so a
 * machine holding a week of finished scoped jobs walks hundreds of records that
 * are already terminal on disk. Hanging a kill off each one fired a root
 * `systemctl kill` per retained job, synchronously — and on the desktop path
 * recover() is reached lazily from the first `do:job_*` frame, so that burst
 * landed on the frame handler's thread. It has been introduced and removed once
 * already; these assertions are what stop it coming back a third time.
 */
function seedRetainedScopedJobs(template: string, count: number): string[] {
  const meta = JSON.parse(
    fs.readFileSync(path.join(jobsRoot, template, "meta.json"), "utf8"),
  ) as Record<string, unknown>;
  const ids: string[] = [];
  for (let i = 1; i <= count; i++) {
    const jobId = i.toString(16).padStart(16, "0");
    fs.mkdirSync(path.join(jobsRoot, jobId), { recursive: true });
    fs.writeFileSync(
      path.join(jobsRoot, jobId, "meta.json"),
      JSON.stringify({ ...meta, jobId, scope: jobScopeUnitName(jobId) }),
    );
    ids.push(jobId);
  }
  return ids;
}

describeOnPosix("recovering a machine full of retained scoped jobs", () => {
  it("asks systemd ONCE for the whole pass, not once per retained job", async () => {
    const { jobId: template } = await runToCompletion(scopedManager(), {
      command: "exit 0",
      cwd: workDir,
    });
    const ids = seedRetainedScopedJobs(template, 40);
    scopeKills.units = [];

    const restarted = new JobManager({ jobsRoot, scopeLauncher: () => ({ systemdRun }) });
    restarted.recover();

    // Not one immediate kill anywhere in the pass — that was the burst.
    expect(scopeKills.units).toEqual([]);
    await waitFor("the sweep to ask systemd", () => systemctlCalls().length > 0);
    // Settle: anything per-job would keep arriving after the first call.
    await new Promise((resolve) => setTimeout(resolve, 50));
    // One `list-units`, and nothing else: none of the 41 scopes is alive, so
    // there is nothing to kill and no second spawn.
    expect(systemctlCalls()).toHaveLength(1);
    expect(systemctlCalls()[0]).toContain("list-units");
    expect(ids).toHaveLength(40);
  });

  it("still kills a leftover scope that is genuinely alive, in one batched call", async () => {
    // The one case the process-group cancel can never cover: the job ended while
    // the agent was down, a `setsid` descendant is still in its scope, and the
    // scope outlived the restart by design.
    const { jobId: template } = await runToCompletion(scopedManager(), {
      command: "exit 0",
      cwd: workDir,
    });
    const ids = seedRetainedScopedJobs(template, 40);
    const alive = [jobScopeUnitName(ids[7]!), jobScopeUnitName(ids[23]!)];
    declareLiveScopes(alive);
    scopeKills.units = [];

    const restarted = new JobManager({ jobsRoot, scopeLauncher: () => ({ systemdRun }) });
    restarted.recover();

    await waitFor("the sweep to kill", () => systemctlCalls().length > 1);
    await new Promise((resolve) => setTimeout(resolve, 50));
    // The query, then ONE kill naming both live units — evidence first, and the
    // 39 scopes that provably no longer exist cost nothing at all.
    expect(systemctlCalls()).toHaveLength(2);
    const kill = systemctlCalls()[1]!;
    expect(kill).toContain("kill --kill-who=all --signal=SIGKILL");
    for (const unit of alive) expect(kill).toContain(unit);
    expect(kill).not.toContain(jobScopeUnitName(ids[0]!));
  });

  it("keeps the transition reap immediate — a settle must not wait for a sweep", async () => {
    // The settle is the instant the GPU lock is released and the card is handed
    // on, so that one still kills right there, exactly once, with no query.
    const manager = scopedManager();
    const { jobId } = await runToCompletion(manager, { command: "exit 0", cwd: workDir });
    expect(killsOf(jobScopeUnitName(jobId))).toEqual([jobScopeUnitName(jobId)]);
    expect(systemctlCalls()).toEqual([]);
  });
});
