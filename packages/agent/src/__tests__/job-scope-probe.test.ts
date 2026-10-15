// The IMPURE half of job-scope.ts: the capability probe, what is memoized out of
// its answer, the journal lines an operator reads it through, and the systemctl
// call that empties a scope's cgroup on a cancel escalation.
//
// job-scope.test.ts covers the pure decisions beside these; job-manager-scope.ts
// covers what the wrapper must not disturb. What none of them can show is the
// cgroup itself — that needs root, systemd and a real bus. The two behaviours
// that MATTER here were measured by hand on Ubuntu 24.04.4 / systemd 255 (a
// scoped probe returning in milliseconds; `systemctl kill --kill-who=all
// --signal=SIGKILL <unit>` returning in 0.01 s and emptying the cgroup a
// setsid'd runaway had survived in), so what is held to account below is the
// POLICY around them: run once on success, retry on failure but not per job,
// speak only on transitions, and aim the kill at nothing but our own units.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("node:child_process", () => ({ execFile: vi.fn() }));

import fs from "node:fs";

import { execFile } from "node:child_process";
import {
  buildJobScopeKillArgv,
  buildJobScopeKillManyArgv,
  buildJobScopeListArgv,
  parseJobScopeUnits,
  reapLeftoverJobScope,
  setSystemctlForTests,
  jobScopeLauncher,
  jobScopeUnitName,
  killJobScope,
  pendingJobScope,
  probeScopeWorks,
  resetJobScopeLauncherForTests,
  resolveSystemctl,
  startJobScopeProbe,
  JOB_SCOPE_KILL_BATCH_MAX,
  JOB_SCOPE_KILL_TIMEOUT_MS,
  JOB_SCOPE_LIST_TIMEOUT_MS,
  JOB_SCOPE_PROBE_TIMEOUT_MS,
  JOB_SCOPE_REPROBE_INTERVAL_MS,
  SYSTEMCTL_PATHS,
  type JobScopeEnv,
} from "../job-scope.js";

const JOB_ID = "0123456789abcdef";
const UNIT = jobScopeUnitName(JOB_ID);
const SYSTEMCTL = "/usr/bin/systemctl";

const linuxRoot = (over: Partial<JobScopeEnv> = {}): JobScopeEnv => ({
  platform: "linux",
  uid: 0,
  systemdRun: "/usr/bin/systemd-run",
  hasSystemd: true,
  ...over,
});

/** Everything the agent printed to the journal (stderr) during one test. */
let logged: string[];

beforeEach(() => {
  resetJobScopeLauncherForTests();
  vi.mocked(execFile).mockReset();
  // execFile's return value is only ever used to attach an 'error' listener.
  vi.mocked(execFile).mockReturnValue({ on: vi.fn() } as never);
  logged = [];
  vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    logged.push(args.join(" "));
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  resetJobScopeLauncherForTests();
});

describe("startJobScopeProbe — success", () => {
  it("probes ONCE however many callers ask, and memoizes the launcher", async () => {
    const runProbe = vi.fn(async () => true);
    const deps = { env: () => linuxRoot(), runProbe };

    const first = await startJobScopeProbe(deps);
    expect(first).toEqual({ systemdRun: "/usr/bin/systemd-run" });
    for (let i = 0; i < 5; i++) await startJobScopeProbe(deps);

    // A machine that just created a scope will create the next one, and the
    // probe must never be paid per job start.
    expect(runProbe).toHaveBeenCalledTimes(1);
    expect(runProbe).toHaveBeenCalledWith("/usr/bin/systemd-run");
  });

  it("shares ONE in-flight probe between concurrent callers", async () => {
    let settle!: (works: boolean) => void;
    const runProbe = vi.fn(() => new Promise<boolean>((r) => { settle = r; }));
    const deps = { env: () => linuxRoot(), runProbe };

    const all = Promise.all([startJobScopeProbe(deps), startJobScopeProbe(deps), startJobScopeProbe(deps)]);
    settle(true);
    const results = await all;

    expect(runProbe).toHaveBeenCalledTimes(1);
    expect(results.every((r) => r?.systemdRun === "/usr/bin/systemd-run")).toBe(true);
  });

  it("says so once, at startup, and never again", async () => {
    const deps = { env: () => linuxRoot(), runProbe: async () => true };
    await startJobScopeProbe(deps);
    await startJobScopeProbe(deps);
    expect(logged).toEqual([
      "[AIC] Jobs run in their own systemd scope (/usr/bin/systemd-run).",
    ]);
  });

  it("reads back synchronously only ONCE settled — spawnJob falls back until then", async () => {
    // start() is synchronous by contract, so spawnJob cannot wait: an unsettled
    // probe means "launch it unscoped", which is exactly how jobs ran before
    // scopes existed. The window is closed in practice by do:job_start awaiting
    // pendingJobScope(), not by blocking here.
    let settle!: (works: boolean) => void;
    const pending = startJobScopeProbe({
      env: () => linuxRoot(),
      runProbe: () => new Promise<boolean>((r) => { settle = r; }),
    });
    expect(jobScopeLauncher()).toBeNull();
    settle(true);
    await pending;
    expect(jobScopeLauncher()).toEqual({ systemdRun: "/usr/bin/systemd-run" });
    // Nothing left to wait for, so the job_start path costs nothing per job.
    expect(pendingJobScope()).toBeNull();
  });
});

describe("startJobScopeProbe — a machine that can never have scopes", () => {
  it("never runs the probe, and states the reason once on Linux", async () => {
    const runProbe = vi.fn(async () => true);
    const deps = { env: () => linuxRoot({ uid: 1000 }), runProbe };

    expect(await startJobScopeProbe(deps)).toBeNull();
    await startJobScopeProbe(deps);

    expect(runProbe).not.toHaveBeenCalled();
    expect(logged).toHaveLength(1);
    expect(logged[0]).toMatch(/without a systemd scope/);
    expect(logged[0]).toMatch(/not root/);
    // The static half is memoized forever — there is nothing left to wait for.
    expect(pendingJobScope()).toBeNull();
  });

  it("stays silent off Linux, where a job already outlives the agent", async () => {
    expect(await startJobScopeProbe({ env: () => linuxRoot({ platform: "darwin" }) })).toBeNull();
    expect(logged).toEqual([]);
  });
});

describe("startJobScopeProbe — a FAILURE is not permanent", () => {
  it("retries after the floor, not per job start", async () => {
    // The bug this replaces: one transient failure — D-Bus not up yet, which is
    // precisely when a Restart=always agent starts — downgraded every job for
    // the machine's whole uptime.
    let now = 1_000_000;
    const runProbe = vi.fn(async () => false);
    const deps = { env: () => linuxRoot(), runProbe, now: () => now };

    expect(await startJobScopeProbe(deps)).toBeNull();
    expect(runProbe).toHaveBeenCalledTimes(1);

    // Inside the floor: answered from the last failure, no new probe.
    for (let i = 0; i < 5; i++) {
      now += JOB_SCOPE_REPROBE_INTERVAL_MS / 10;
      expect(await startJobScopeProbe(deps)).toBeNull();
    }
    expect(runProbe).toHaveBeenCalledTimes(1);

    now += JOB_SCOPE_REPROBE_INTERVAL_MS;
    expect(await startJobScopeProbe(deps)).toBeNull();
    expect(runProbe).toHaveBeenCalledTimes(2);
  });

  it("logs the first failure and then keeps quiet — one retry, one line", async () => {
    let now = 0;
    const deps = { env: () => linuxRoot(), runProbe: async () => false, now: () => now };
    await startJobScopeProbe(deps);
    now += JOB_SCOPE_REPROBE_INTERVAL_MS * 2;
    await startJobScopeProbe(deps);
    now += JOB_SCOPE_REPROBE_INTERVAL_MS * 2;
    await startJobScopeProbe(deps);

    // Transitions only: a broken box retried forever must not bury the journal.
    expect(logged).toHaveLength(1);
    expect(logged[0]).toMatch(/could not create one/);
  });

  it("picks the capability up when the bus comes back, and says so", async () => {
    let now = 0;
    let works = false;
    const deps = { env: () => linuxRoot(), runProbe: async () => works, now: () => now };

    expect(await startJobScopeProbe(deps)).toBeNull();
    works = true;
    now += JOB_SCOPE_REPROBE_INTERVAL_MS;
    expect(await startJobScopeProbe(deps)).toEqual({ systemdRun: "/usr/bin/systemd-run" });
    expect(jobScopeLauncher()).toEqual({ systemdRun: "/usr/bin/systemd-run" });

    // Both transitions are visible: the operator sees the downgrade AND the
    // recovery, and nothing in between.
    expect(logged).toHaveLength(2);
    expect(logged[0]).toMatch(/could not create one/);
    expect(logged[1]).toMatch(/in their own systemd scope/);
  });
});

/**
 * The bounded attempt itself, driven through the `exec` seam.
 *
 * Reaching it any other way is not possible off a Linux root box with systemd:
 * startJobScopeProbe answers from the static decision long before it would run,
 * which is what left the argv and the timeout — the two things that decide
 * whether the probe measures the real path at all — unasserted.
 */
type ExecCall = { file: string; args: readonly string[]; options: { timeout?: number } };

type ProbeOutcome = "ok" | "exit-nonzero" | "timeout" | "spawn-error" | "throws";

function fakeExec(outcome: ProbeOutcome, seen: ExecCall[]): typeof execFile {
  return ((file: string, args: readonly string[], options: { timeout?: number }, cb: (e: Error | null) => void) => {
    seen.push({ file, args, options });
    if (outcome === "throws") throw new Error("ENOENT");
    const child = {
      on: (event: string, handler: (e: Error) => void) => {
        // Node hands a spawn failure to the callback too, but an 'error'
        // listener must exist or it is thrown at the process instead.
        if (event === "error" && outcome === "spawn-error") handler(new Error("EACCES"));
      },
    };
    if (outcome === "ok") cb(null);
    // What `timeout:` produces: the child is killed and the callback gets the
    // error, exactly as a non-zero exit does.
    if (outcome === "exit-nonzero") cb(new Error("Command failed: exit 1"));
    if (outcome === "timeout") cb(Object.assign(new Error("timeout"), { killed: true, signal: "SIGTERM" }));
    return child;
  }) as unknown as typeof execFile;
}

describe("probeScopeWorks", () => {
  it("runs the cheapest command that exercises the whole path, bounded", async () => {
    // Bus, polkit, unit creation, exec and teardown in one call — and no
    // `--unit=`, so it can collide with nothing and systemd names it itself.
    const seen: ExecCall[] = [];
    expect(await probeScopeWorks("/usr/bin/systemd-run", fakeExec("ok", seen))).toBe(true);
    expect(seen).toHaveLength(1);
    expect(seen[0]!.file).toBe("/usr/bin/systemd-run");
    expect(seen[0]!.args).toEqual(["--scope", "--quiet", "--collect", "--", "/bin/sh", "-c", "exit 0"]);
    expect(seen[0]!.args.some((a) => a.startsWith("--unit"))).toBe(false);
    // Unbounded, this would hang the startup path on the very machines the probe
    // exists to detect: a wedged system bus, a polkit that never answers.
    expect(seen[0]!.options).toMatchObject({ timeout: JOB_SCOPE_PROBE_TIMEOUT_MS });
  });

  it("turns every failure into `false`, and never rejects", async () => {
    for (const outcome of ["exit-nonzero", "timeout", "spawn-error", "throws"] as const) {
      expect(await probeScopeWorks("/usr/bin/systemd-run", fakeExec(outcome, []))).toBe(false);
    }
  });
});

describe("startJobScopeProbe — with the real probe wired up", () => {
  /** The module-level node:child_process mock IS the execFile probeScopeWorks uses. */
  function mockExecFile(outcome: ProbeOutcome, seen: ExecCall[]): void {
    vi.mocked(execFile).mockImplementation(fakeExec(outcome, seen) as never);
  }

  it("probes the systemd-run the static decision chose, and memoizes success", async () => {
    const seen: ExecCall[] = [];
    mockExecFile("ok", seen);

    expect(await startJobScopeProbe({ env: () => linuxRoot() })).toEqual({
      systemdRun: "/usr/bin/systemd-run",
    });

    expect(seen).toHaveLength(1);
    expect(seen[0]!.file).toBe("/usr/bin/systemd-run");
    expect(seen[0]!.options).toMatchObject({ timeout: JOB_SCOPE_PROBE_TIMEOUT_MS });
    // Settled, so spawnJob can read it back synchronously and nothing waits.
    expect(jobScopeLauncher()).toEqual({ systemdRun: "/usr/bin/systemd-run" });
    expect(pendingJobScope()).toBeNull();
    expect(logged).toEqual(["[AIC] Jobs run in their own systemd scope (/usr/bin/systemd-run)."]);
  });

  it("a probe that times out downgrades the machine, once, without crashing", async () => {
    const seen: ExecCall[] = [];
    mockExecFile("timeout", seen);

    expect(await startJobScopeProbe({ env: () => linuxRoot(), now: () => 0 })).toBeNull();

    expect(seen).toHaveLength(1);
    expect(jobScopeLauncher()).toBeNull();
    expect(logged).toHaveLength(1);
    expect(logged[0]).toMatch(/could not create one/);
    expect(logged[0]).toMatch(/may end running jobs/);
  });
});

describe("pendingJobScope", () => {
  it("starts the probe as a side effect of asking, and settles it", async () => {
    // This is what connection.ts's do:job_start awaits before dispatching, and
    // nothing else need have run first — the startup call is a warm-up, not a
    // precondition.
    vi.mocked(execFile).mockImplementation(((_f: unknown, _a: unknown, _o: unknown, cb: unknown) => {
      (cb as (e: null) => void)(null);
      return { on: vi.fn() };
    }) as never);

    const pending = pendingJobScope();
    expect(pending).not.toBeNull();
    await pending;

    // Settled either way: a machine that can have scopes memoized its launcher,
    // and one that cannot memoized the static "never". Both mean the next job
    // start waits for nothing.
    expect(pendingJobScope()).toBeNull();
  });
});

describe("buildJobScopeKillArgv", () => {
  it("is `kill`, never `stop`", () => {
    // `systemctl stop` waits for the unit's stop job (DefaultTimeoutStopSec, 90 s
    // by default) and would hang the cancel; `kill` only sends signals and
    // returns — 0.01 s, measured on Ubuntu 24.04.4 / systemd 255.
    const { args } = buildJobScopeKillArgv({ systemctl: SYSTEMCTL, unit: UNIT });
    expect(args[0]).toBe("kill");
    expect(args).not.toContain("stop");
  });

  it("uses --kill-who, the spelling that works on every systemd", () => {
    // --kill-whom only exists on systemd >= 252; both work on 255.
    const { file, args } = buildJobScopeKillArgv({ systemctl: SYSTEMCTL, unit: UNIT });
    expect(file).toBe(SYSTEMCTL);
    expect(args).toEqual(["kill", "--kill-who=all", "--signal=SIGKILL", UNIT]);
    expect(args.some((a) => a.startsWith("--kill-whom"))).toBe(false);
  });

  it("refuses any unit name that is not one of ours", () => {
    // A root `systemctl kill` — the name decides what dies, so it is re-validated
    // here exactly as jobScopeUnitName re-validates the job id.
    for (const unit of ["aicommander-agent.service", "aic-job-.scope", "aic-job-*.scope", "-.mount"]) {
      expect(() => buildJobScopeKillArgv({ systemctl: SYSTEMCTL, unit })).toThrow();
    }
  });
});

describe("killJobScope", () => {
  it("runs the built argv, bounded", () => {
    killJobScope(UNIT, SYSTEMCTL);
    expect(execFile).toHaveBeenCalledTimes(1);
    const [file, args, opts] = vi.mocked(execFile).mock.calls[0]!;
    expect(file).toBe(SYSTEMCTL);
    expect(args).toEqual(["kill", "--kill-who=all", "--signal=SIGKILL", UNIT]);
    expect(opts).toMatchObject({ timeout: JOB_SCOPE_KILL_TIMEOUT_MS });
  });

  it("treats an already-collected unit as a no-op success", () => {
    // `Failed to kill unit …: Unit … not loaded.`, rc != 0, is the NORMAL case:
    // the job ended and systemd collected its scope. A cancel must not be turned
    // into an error by it.
    killJobScope(UNIT, SYSTEMCTL);
    const done = vi.mocked(execFile).mock.calls[0]![3] as unknown as (e: Error) => void;
    expect(() => done(new Error("Failed to kill unit aic-job-….scope: Unit not loaded."))).not.toThrow();
    expect(logged).toEqual([]);
  });

  it("never throws, and never aims at a foreign unit", () => {
    expect(() => killJobScope("aicommander-agent.service", SYSTEMCTL)).not.toThrow();
    expect(execFile).not.toHaveBeenCalled();

    // No systemctl on this box (a non-systemd host that somehow recorded a
    // scope): the process-group signal was the whole cancel.
    expect(() => killJobScope(UNIT, null)).not.toThrow();
    expect(execFile).not.toHaveBeenCalled();

    vi.mocked(execFile).mockImplementationOnce(() => { throw new Error("ENOENT"); });
    expect(() => killJobScope(UNIT, SYSTEMCTL)).not.toThrow();
  });
});

describe("resolveSystemctl", () => {
  it("probes absolute paths only, in order, and never PATH", () => {
    // Same reasoning as SYSTEMD_RUN_PATHS, and stronger: this one runs as root
    // and kills things, so the binary must not be chosen by an env var.
    expect([...SYSTEMCTL_PATHS].every((p) => p.startsWith("/"))).toBe(true);
    expect(resolveSystemctl(() => true)).toBe(SYSTEMCTL_PATHS[0]);
    expect(resolveSystemctl((p) => p === SYSTEMCTL_PATHS[1])).toBe(SYSTEMCTL_PATHS[1]);
    expect(resolveSystemctl(() => false)).toBeNull();
    expect(resolveSystemctl(() => { throw new Error("EACCES"); })).toBeNull();
  });
});

/**
 * The startup sweep: ask once, kill only what exists.
 *
 * Hanging a plain killJobScope off refresh()'s "already terminal on disk" branch
 * fired one root `systemctl kill` per RETAINED job at startup — hundreds of
 * spawns against units that ended days ago, on the thread that has to answer the
 * next frame. That has now been introduced and removed once; what is pinned here
 * is the property that stops it returning: N leftovers cost one query, and the
 * only thing that is ever killed is a unit systemd itself just named.
 */
const unitOf = (n: number): string => jobScopeUnitName(n.toString(16).padStart(16, "0"));

/** The sweep is deferred by one turn of the event loop, deliberately. */
const afterSweep = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));

describe("buildJobScopeListArgv / parseJobScopeUnits", () => {
  it("asks for our scopes only, header- and bullet-free", () => {
    const { file, args } = buildJobScopeListArgv(SYSTEMCTL);
    expect(file).toBe(SYSTEMCTL);
    // --all so a loaded-but-dead scope still answers (existence, not activity),
    // --plain so the unit name is the first field rather than a `●` column.
    expect(args).toEqual([
      "list-units",
      "--type=scope",
      "--all",
      "--no-legend",
      "--plain",
      "aic-job-*.scope",
    ]);
  });

  it("reads the first field, and trusts nothing that is not one of ours", () => {
    const live = parseJobScopeUnits(
      `${UNIT} loaded active running AI Commander job ${JOB_ID}\n` +
        "session-3.scope loaded active running Session 3 of user root\n" +
        "aic-job-nothex.scope loaded active running forged\n" +
        "\n",
    );
    expect([...live]).toEqual([UNIT]);
  });

  it("finds nothing in an empty or garbled answer", () => {
    // The set decides what a root kill is aimed at: no answer must mean "kill
    // nothing", never "kill something else".
    expect(parseJobScopeUnits("").size).toBe(0);
    expect(parseJobScopeUnits("0 loaded units listed.\n").size).toBe(0);
  });
});

describe("buildJobScopeKillManyArgv", () => {
  it("names every unit on one command line, with the same flags", () => {
    const units = [unitOf(1), unitOf(2), unitOf(3)];
    const { file, args } = buildJobScopeKillManyArgv({ systemctl: SYSTEMCTL, units });
    expect(file).toBe(SYSTEMCTL);
    expect(args).toEqual(["kill", "--kill-who=all", "--signal=SIGKILL", ...units]);
  });

  it("re-validates EVERY name, not just the first", () => {
    expect(() =>
      buildJobScopeKillManyArgv({ systemctl: SYSTEMCTL, units: [UNIT, "-.mount"] }),
    ).toThrow();
    expect(() => buildJobScopeKillManyArgv({ systemctl: SYSTEMCTL, units: [] })).toThrow();
  });
});

describe("reapLeftoverJobScope", () => {
  beforeEach(() => setSystemctlForTests(SYSTEMCTL));

  it("spawns NOTHING when it is called, however many times", async () => {
    for (let i = 1; i <= 200; i++) reapLeftoverJobScope(unitOf(i));
    // The burst that was removed: this is where 200 root kills used to be.
    expect(execFile).not.toHaveBeenCalled();
    await afterSweep();
    // One query for all 200, and no kill until systemd has answered.
    expect(execFile).toHaveBeenCalledTimes(1);
    const [file, args, opts] = vi.mocked(execFile).mock.calls[0]!;
    expect(file).toBe(SYSTEMCTL);
    expect(args).toEqual(buildJobScopeListArgv(SYSTEMCTL).args);
    expect(opts).toMatchObject({ timeout: JOB_SCOPE_LIST_TIMEOUT_MS });
  });

  it("kills only the units systemd says exist, in one batched call", async () => {
    for (let i = 1; i <= 200; i++) reapLeftoverJobScope(unitOf(i));
    await afterSweep();
    const done = vi.mocked(execFile).mock.calls[0]![3] as unknown as (
      e: Error | null,
      out: string,
    ) => void;
    done(null, `${unitOf(7)} loaded active running x\n${unitOf(23)} loaded active running x\n`);
    expect(execFile).toHaveBeenCalledTimes(2);
    const [file, args, opts] = vi.mocked(execFile).mock.calls[1]!;
    expect(file).toBe(SYSTEMCTL);
    expect(args).toEqual([
      "kill",
      "--kill-who=all",
      "--signal=SIGKILL",
      unitOf(7),
      unitOf(23),
    ]);
    expect(opts).toMatchObject({ timeout: JOB_SCOPE_KILL_TIMEOUT_MS });
  });

  it("chunks a very long list rather than growing one unbounded argv", async () => {
    const many = Array.from({ length: JOB_SCOPE_KILL_BATCH_MAX + 1 }, (_, i) => unitOf(i + 1));
    for (const unit of many) reapLeftoverJobScope(unit);
    await afterSweep();
    const done = vi.mocked(execFile).mock.calls[0]![3] as unknown as (
      e: Error | null,
      out: string,
    ) => void;
    done(null, many.map((u) => `${u} loaded active running x\n`).join(""));
    // Two kills, not 65 — and nothing dropped.
    expect(execFile).toHaveBeenCalledTimes(3);
    const named = [1, 2].flatMap((i) => vi.mocked(execFile).mock.calls[i]![1] as string[]).filter(
      (a) => a.startsWith("aic-job-"),
    );
    expect(new Set(named)).toEqual(new Set(many));
  });

  it("kills nothing when the query fails, and never throws", async () => {
    // A query that failed is not evidence that anything is alive, and this is a
    // root kill: no answer means kill nothing.
    reapLeftoverJobScope(UNIT);
    await afterSweep();
    const done = vi.mocked(execFile).mock.calls[0]![3] as unknown as (
      e: Error | null,
      out: string,
    ) => void;
    expect(() => done(new Error("Failed to connect to bus"), "")).not.toThrow();
    expect(execFile).toHaveBeenCalledTimes(1);
    expect(logged).toEqual([]);
  });

  it("says nothing to systemctl for a foreign name, or a box without systemctl", async () => {
    reapLeftoverJobScope("aicommander-agent.service");
    await afterSweep();
    expect(execFile).not.toHaveBeenCalled();

    setSystemctlForTests(null);
    reapLeftoverJobScope(UNIT);
    await afterSweep();
    expect(execFile).not.toHaveBeenCalled();
  });

  it("resolves systemctl ONCE per process, not once per reap", () => {
    // It used to sit as a default argument, i.e. an existsSync probe per call.
    setSystemctlForTests(null);
    resetJobScopeLauncherForTests();
    const exists = vi.spyOn(fs, "existsSync").mockReturnValue(true);
    for (let i = 1; i <= 20; i++) reapLeftoverJobScope(unitOf(i));
    killJobScope(UNIT);
    killJobScope(UNIT);
    expect(exists.mock.calls.filter(([p]) => String(p).endsWith("systemctl"))).toHaveLength(1);
  });
});
