import { execFile } from "node:child_process";
import fs from "node:fs";
import { JOB_ID_PATTERN } from "@aicommander/protocol";

/**
 * Linux only: put every detached job in its OWN transient systemd scope, so that
 * restarting the agent does not kill the jobs it started.
 *
 * THE FAILURE THIS FIXES. The unit install.ts writes is an ordinary
 * `Type=simple` service with systemd's default `KillMode=control-group`. Every
 * process the agent forks stays in the service's cgroup, so `systemctl restart
 * aicommander-agent` — which install.ts performs deliberately, and which
 * self-update.ts performs on every upgrade — takes the whole cgroup down with
 * it, jobs included. A twelve-hour training run died because the agent under it
 * was upgraded. Linux was the ONLY platform where that happened: on macOS the
 * job is a plain orphan of a launchd-managed process and on Windows it is a
 * detached console-less child, and neither is torn down with its parent.
 *
 * WHY `--scope` AND NOT A TRANSIENT SERVICE. `systemd-run --scope` registers the
 * transient unit with its OWN pid and then `execvp()`s the command in place — it
 * BECOMES the job's shell. Every property the surrounding job machinery already
 * depends on therefore survives untouched. All of the following were MEASURED on
 * Ubuntu 24.04.4 / systemd 255, launching the exact spawnJob argv from inside a
 * running agent's cgroup, with a plain-spawn job as the control:
 *
 *  - the pid `spawn()` returns is still the job's `/bin/sh` (the shell's own
 *    `$$` equalled it), and still the process-GROUP leader (`pgid == sid == pid`
 *    from `detached: true`), so `process.kill(-pid, …)` still signals the whole
 *    tree on cancel — verified from a process OUTSIDE the scope, and the scope
 *    was auto-collected afterwards. Cancel needs no systemctl;
 *  - `procIdentity` on Linux is `/proc/<pid>/stat` start-ticks, which `exec`
 *    does not change: the value read IMMEDIATELY after spawn (while the process
 *    was still systemd-run) equalled the value read later, once it was the job
 *    shell. So capturing the token right after the spawn stays valid;
 *  - the inherited log fd, the cwd and the environment pass straight through:
 *    scope mode does not touch stdio, does not chdir and does not scrub the env;
 *  - `child.on("exit")` still observes the real job shell leaving, and the
 *    wrapper's EXIT trap still records the code (a job exiting 3 wrote `3`);
 *  - the job's own children land in the same scope cgroup, not the agent's.
 *
 * And the thing all of it is for: with a scoped and a plain job running side by
 * side, `systemctl restart aicommander-agent` killed the PLAIN job at that exact
 * second (no exit file) while the scoped one ran straight through it with a
 * gapless log. The scoped job's cgroup was `0::/system.slice/aic-job-<id>.scope`;
 * the plain job's was `0::/system.slice/aicommander-agent.service`.
 *
 * A transient SERVICE (`systemd-run` with no `--scope`, which self-update.ts
 * uses — correctly, for its own purpose: it wants to survive its own parent
 * being replaced) would break every one of those. systemd-run would fork the
 * work to PID 1 and exit immediately, so our pid would name a process that is
 * already gone, our identity token would describe it, our log fd would go
 * nowhere and the output would land in the journal instead of output.log.
 */

/** The unit name a job's scope gets. Enumerated by uninstall — see the pattern below. */
const SCOPE_PREFIX = "aic-job-";
const SCOPE_SUFFIX = ".scope";

/**
 * The glob that matches every scope this agent creates, and NOTHING else.
 *
 * Exported because ctl/commands/uninstall.ts has to find the leftover scopes
 * before it deletes the jobs roots, and a second copy of this string living
 * there is exactly the kind of duplicated constant that drifts: rename the
 * prefix here and the uninstall would silently stop finding anything, leaving
 * live root jobs whose output.log was just deleted underneath them.
 */
export const JOB_SCOPE_UNIT_GLOB = `${SCOPE_PREFIX}*${SCOPE_SUFFIX}`;

/**
 * The unit name for a job, e.g. `aic-job-3f2a…c1.scope`.
 *
 * The id is re-validated here rather than trusted, even though every caller
 * already generated or validated it: a unit name is a string systemd parses,
 * and it is the one place where a job id would leave our own file-path handling
 * and become part of a command line. JOB_ID_PATTERN is 16 hex characters, so a
 * value that passes it cannot carry a separator, a glob character or a
 * template's `@`. Throwing is right — a caller with a malformed id has a bug,
 * and the alternative (a sanitised fallback name) would let two jobs share one
 * unit.
 */
export function jobScopeUnitName(jobId: string): string {
  if (!JOB_ID_PATTERN.test(jobId)) {
    throw new Error(`refusing to build a systemd unit name from ${JSON.stringify(jobId)}`);
  }
  return `${SCOPE_PREFIX}${jobId}${SCOPE_SUFFIX}`;
}

/**
 * Whether a unit name is one of OURS, exactly — the same shape jobScopeUnitName
 * builds, job id and all.
 *
 * The uninstall path stops units by name, and the names it stops come out of
 * `systemctl list-units`' text output. Re-checking each one here is what keeps a
 * mis-parsed line (a column shift, a localised header a `--no-legend` did not
 * suppress, a bullet glyph) from turning into a `systemctl stop` aimed at some
 * other unit on the machine.
 */
export function isJobScopeUnitName(unit: string): boolean {
  if (!unit.startsWith(SCOPE_PREFIX) || !unit.endsWith(SCOPE_SUFFIX)) return false;
  return JOB_ID_PATTERN.test(unit.slice(SCOPE_PREFIX.length, unit.length - SCOPE_SUFFIX.length));
}

/**
 * The absolute paths systemd-run is installed at, in the order they are probed.
 *
 * Deliberately NOT a PATH lookup. This process runs as root, and resolving a
 * bare program name through PATH means the binary we execute is chosen by an
 * environment variable — a hijack surface a root service has no business
 * offering for a convenience feature. Both entries are root-owned system
 * directories on every distribution that ships systemd (usr-merged systems make
 * the second a symlink to the first).
 */
export const SYSTEMD_RUN_PATHS = ["/usr/bin/systemd-run", "/bin/systemd-run"] as const;

/**
 * The first systemd-run that exists, or null. `exists` is injectable so the
 * decision can be unit-tested on a box that has neither path.
 */
export function resolveSystemdRun(exists: (p: string) => boolean = fs.existsSync): string | null {
  for (const candidate of SYSTEMD_RUN_PATHS) {
    try {
      if (exists(candidate)) return candidate;
    } catch {
      // An unreadable path prefix is not a systemd-run; keep looking.
    }
  }
  return null;
}

/** What the decision function is told about the machine. All four are required. */
export interface JobScopeEnv {
  platform: NodeJS.Platform;
  /** `process.getuid?.()` — undefined on Windows, where there is no such call. */
  uid: number | undefined;
  /** The result of resolveSystemdRun(), or null. */
  systemdRun: string | null;
  /** Whether /run/systemd/system exists, i.e. whether systemd is the init here. */
  hasSystemd: boolean;
}

export type JobScopeDecision =
  | { supported: true; systemdRun: string }
  | { supported: false; reason: string };

/**
 * Whether this machine can launch jobs into scopes — pure, so the whole matrix
 * is testable, and so the reason an operator sees is the same string the logic
 * actually decided on.
 *
 * All four conditions are required, and the uid one is the one most likely to be
 * "fixed" by someone who has not thought it through:
 *
 * SYSTEM MODE ONLY, ON PURPOSE. A non-root agent cannot create a system scope at
 * all — measured on Ubuntu 24.04 / systemd 255, the attempt is refused with
 * `Failed to start transient scope unit: Interactive authentication required.`
 * — and `systemd-run --user --scope` is NOT the answer to that. It would be a
 * REGRESSION: a user-mode scope is created under `user@<uid>.service`, inside
 * the login session's cgroup, which systemd tears down when the session ends
 * (and, with `KillUserProcesses=yes` or a plain logout, sooner than that), while
 * today's plain detached child at least survives as an orphan of PID 1. It also
 * simply does not work where the agent actually runs: from a non-session context
 * it fails with `Failed to connect to bus: No medium found`. So a non-root agent
 * keeps the fallback rather than being moved into a cgroup with a NEW way to die.
 */
export function jobScopeDecision(env: JobScopeEnv): JobScopeDecision {
  if (env.platform !== "linux") {
    return { supported: false, reason: `not Linux (${env.platform}) — no systemd cgroups here` };
  }
  if (env.uid !== 0) {
    return {
      supported: false,
      reason: "the agent is not root, and a --user scope dies with the login session",
    };
  }
  if (!env.hasSystemd) {
    // The same signal self-update.ts's preflight uses (PreflightEnv.hasSystemd):
    // the systemd-run BINARY is present in plenty of images whose PID 1 is
    // something else entirely, and asking it for a scope there only fails.
    return { supported: false, reason: "no systemd manager (/run/systemd/system is absent)" };
  }
  if (env.systemdRun === null) {
    return { supported: false, reason: `no systemd-run at ${SYSTEMD_RUN_PATHS.join(" or ")}` };
  }
  return { supported: true, systemdRun: env.systemdRun };
}

/** What a job's spawn actually runs, once the scope wrapper is in front of it. */
export interface JobScopeArgv {
  file: string;
  args: string[];
}

/**
 * The systemd-run command line, built rather than written out, so the ONE place
 * that decides the flag order is also the place the tests read.
 *
 * Every flag earns its place:
 *  - `--scope`, for the exec-in-place semantics the whole design rests on;
 *  - `--quiet`, because systemd-run otherwise prints "Running scope as unit …"
 *    on stderr — which is the job's output.log — and that line would become the
 *    first thing every job on Linux ever printed;
 *  - `--collect`, so a scope that FAILED is reaped instead of lingering as a
 *    failed unit that a later `--unit=` of the same name would refuse to reuse.
 *    Be precise about what it does not cover: `--collect` reaps inactive and
 *    failed units, never a LIVE one, so it is no defence against a name that is
 *    still loaded — that case is `Failed to start transient scope unit: Unit
 *    aic-job-….scope was already loaded or has a fragment file.` on stderr,
 *    rc=1 (measured). It stays a non-issue for a different reason: a scope
 *    disappears the instant its process tree ends (`LoadState=not-found`), and
 *    job ids are 64 random bits;
 *  - `--unit=`, so `systemctl list-units 'aic-job-*.scope'` finds our scopes and
 *    only ours — that is what makes the uninstall able to stop them;
 *  - `--description=`, which names the JOB ID and nothing else. The job's `name`
 *    is caller payload and would end up in `systemctl status` output and the
 *    journal; the id is validated, unique, and enough to find the record with.
 *  - `--`, so that neither our own description nor anything the caller supplied
 *    can be read back as an option by systemd-run's own parser.
 *
 * No quoting happens here, and none is needed: these are argv elements handed to
 * `execvp`, so `file`/`args` reach systemd-run byte for byte and it passes them
 * on the same way.
 */
export function buildJobScopeArgv(opts: {
  systemdRun: string;
  unit: string;
  description: string;
  file: string;
  args: readonly string[];
}): JobScopeArgv {
  return {
    file: opts.systemdRun,
    args: [
      "--scope",
      "--quiet",
      "--collect",
      `--unit=${opts.unit}`,
      `--description=${opts.description}`,
      "--",
      opts.file,
      ...opts.args,
    ],
  };
}

/** The `--description=` a job's scope carries. No caller payload — see above. */
export function jobScopeDescription(jobId: string): string {
  return `AI Commander job ${jobId}`;
}

/** What spawnJob needs to wrap a command, or null when this machine cannot. */
export interface JobScopeLauncher {
  systemdRun: string;
}


/**
 * The probe that turns "the binary is there" into "a scope actually gets
 * created here", bounded and run OFF the frame handler's thread.
 *
 * The difference is not academic: systemd-run needs to reach the system bus and
 * be allowed by polkit to create a transient unit, and `--collect` needs systemd
 * ≥ 236. A container with /run/systemd/system bind-mounted in, a locked-down
 * polkit, or an ancient distribution all pass every static check above and then
 * fail at spawn time — where the failure would land in a real job's output.log
 * instead of being noticed once at startup.
 *
 * `/bin/sh -c 'exit 0'` is the cheapest thing that exercises the whole path
 * (bus, polkit, unit creation, exec, teardown), and it returns 0 on the shape we
 * ship to (measured, Ubuntu 24.04.4 / systemd 255, where it costs milliseconds).
 * It is deliberately given no `--unit=`, so it cannot collide with anything and
 * systemd names it itself.
 *
 * ASYNC, AND THAT IS LOAD-BEARING. This used to be an `execFileSync` bounded at
 * five seconds, reached lazily from spawnJob — i.e. from inside the synchronous
 * JobManager.start(), i.e. on the WS frame handler's own thread. On exactly the
 * machines the probe exists to detect (a wedged system bus, a polkit that never
 * answers) the first job start then stalled the agent's entire loop for up to
 * those five seconds: `do:ping` unanswered until the relay declares the machine
 * dead, every concurrent `do:exec` stuck behind it. It is now the same shape
 * login-shell-path.ts uses for the macOS PATH probe, wired the same way and for
 * the same reason: started on the agent's startup path (runConnectionLoop and
 * JobManager.recover()), AWAITED by connection.ts's do:job_start handler, and
 * read back SYNCHRONOUSLY by spawnJob out of the settled memo — which is also
 * what makes the documented "the agent logs which it got, once, at startup"
 * true, instead of a line that appeared on the first job start and never at all
 * on a machine that started none.
 */
export const JOB_SCOPE_PROBE_TIMEOUT_MS = 5_000;

/**
 * The floor between two probe attempts once one has FAILED.
 *
 * A probe failure is not permanent, and memoizing it as though it were was a
 * real bug. The STATIC half of the decision — platform, uid,
 * /run/systemd/system, the systemd-run binary — genuinely cannot change under a
 * running process, and is still memoized forever below. What the probe measures
 * cannot make that claim: bus reachability, polkit's answer and the machine's
 * load all change while we run. The agent's unit is `Restart=always` and these
 * boxes stay up for weeks, and the single likeliest moment for the probe to fail
 * is the one right after boot, when D-Bus may not be up yet and a
 * `Restart=always` agent is already running. Caching that answer silently
 * downgraded every job for the machine's whole uptime, with the one journal line
 * that explained it scrolled away days earlier.
 *
 * Five minutes, so that a genuinely broken box pays at most one bounded probe
 * per five minutes however many jobs are started against it (a failing probe
 * costs up to JOB_SCOPE_PROBE_TIMEOUT_MS, and do:job_start waits for it), while
 * a bus that comes up seconds after the agent is picked up long before the
 * operator's first long run.
 */
export const JOB_SCOPE_REPROBE_INTERVAL_MS = 5 * 60_000;

/**
 * Seams, and ONLY seams: production passes none of these. The scope path needs
 * root, systemd and a reachable system bus, none of which a test box has, so
 * without them a whole platform's behaviour would be code nothing ever executes.
 */
export interface JobScopeProbeDeps {
  /** What the machine looks like. Default: this process, read once. */
  env?: () => JobScopeEnv;
  /** Runs the bounded probe. Default: probeScopeWorks below. */
  runProbe?: (systemdRun: string) => Promise<boolean>;
  /** The clock the re-probe floor is measured on. Default: Date.now. */
  now?: () => number;
}

function readJobScopeEnv(): JobScopeEnv {
  return {
    platform: process.platform,
    uid: process.getuid?.(),
    systemdRun: resolveSystemdRun(),
    hasSystemd: fs.existsSync("/run/systemd/system"),
  };
}

/**
 * One bounded attempt. Never throws and never rejects — every failure is `false`.
 *
 * `exec` is a seam, and ONLY a seam — production passes nothing, exactly as with
 * `resolveSystemdRun(exists)`. It is what makes the two things that decide
 * whether this measures the real path — the argv and the timeout — assertable
 * against the function the agent actually runs, on a box that is not Linux, not
 * root, or has no systemd, i.e. on every developer machine and every CI runner
 * we have. Without it the whole function is code nothing ever executes.
 */
export function probeScopeWorks(
  systemdRun: string,
  exec: typeof execFile = execFile,
): Promise<boolean> {
  return new Promise((resolve) => {
    try {
      const child = exec(
        systemdRun,
        ["--scope", "--quiet", "--collect", "--", "/bin/sh", "-c", "exit 0"],
        { timeout: JOB_SCOPE_PROBE_TIMEOUT_MS },
        (err) => resolve(err === null),
      );
      // A spawn failure reaches the callback too, but an 'error' listener must
      // exist or Node throws it at the process instead.
      child.on("error", () => resolve(false));
    } catch {
      resolve(false);
    }
  });
}

/** The static half of the decision, memoized FOREVER — it cannot change. */
let staticDecision: JobScopeDecision | undefined;
/** Whether that decision was taken on Linux, i.e. whether an absence is worth saying. */
let staticIsLinux = false;
/** `undefined` = the probe has not settled yet; `null` = settled, "no scopes". */
let launcher: JobScopeLauncher | null | undefined;
/** The in-flight probe, so N concurrent callers share exactly one. */
let inFlight: Promise<JobScopeLauncher | null> | null = null;
/** When the last probe failed, for the re-probe floor above. */
let failedAt: number | null = null;
/** What the journal has already been told, so only TRANSITIONS are logged. */
let loggedState: "scoped" | "unscoped" | undefined;

/**
 * The agent's stderr is the journal, and these two lines are what an operator
 * reads when they ask "did my job get its own scope, or is the next upgrade
 * going to kill it?" — a question that is otherwise unanswerable from outside,
 * since a job that gets no scope behaves identically until the restart that ends
 * it. Logged on TRANSITIONS only: with the re-probe above, a broken box would
 * otherwise emit the same line every five minutes forever and bury everything
 * else in the journal. The first failure and any later recovery are each said
 * exactly once.
 */
function logScopeState(state: "scoped" | "unscoped", message: string): void {
  if (loggedState === state) return;
  loggedState = state;
  console.error(message);
}

const NO_SCOPE_CONSEQUENCE =
  "Restarting the agent (including an upgrade) may end running jobs.";

/**
 * Start (or reuse) the capability probe for this machine. Called at process
 * start from the agent's two startup paths, and again from do:job_start, which
 * awaits it.
 *
 * SUCCESS is memoized for the life of the process — a machine that just created
 * a scope will create the next one, and the probe must not be paid per job.
 * FAILURE is not: it is retried, no more often than JOB_SCOPE_REPROBE_INTERVAL_MS.
 */
export function startJobScopeProbe(
  deps: JobScopeProbeDeps = {},
): Promise<JobScopeLauncher | null> {
  if (launcher) return Promise.resolve(launcher);
  if (inFlight) return inFlight;

  if (staticDecision === undefined) {
    const env = (deps.env ?? readJobScopeEnv)();
    staticIsLinux = env.platform === "linux";
    staticDecision = jobScopeDecision(env);
  }
  const decision = staticDecision;
  if (!decision.supported) {
    // Silent off Linux, and deliberately so: there is no scope to want there,
    // and a job on macOS or Windows already outlives the agent, so a line saying
    // it did not get one would be noise that also implied a risk it does not
    // carry. On Linux the same absence IS the risk, so it is always said.
    if (staticIsLinux) {
      logScopeState(
        "unscoped",
        `[AIC] Jobs run without a systemd scope: ${decision.reason}. ${NO_SCOPE_CONSEQUENCE}`,
      );
    }
    launcher = null;
    return Promise.resolve(null);
  }

  const now = deps.now ?? Date.now;
  if (failedAt !== null && now() - failedAt < JOB_SCOPE_REPROBE_INTERVAL_MS) {
    // Inside the floor: answer from the last failure rather than spending
    // another bounded probe (and another do:job_start's wait) on a box that is
    // very likely still broken.
    return Promise.resolve(null);
  }

  const systemdRun = decision.systemdRun;
  inFlight = (deps.runProbe ?? probeScopeWorks)(systemdRun).then((works) => {
    inFlight = null;
    if (!works) {
      failedAt = now();
      launcher = null;
      logScopeState(
        "unscoped",
        `[AIC] Jobs run without a systemd scope: ${systemdRun} could not create one ` +
          "(no system bus, polkit, or a systemd too old for --collect). " +
          NO_SCOPE_CONSEQUENCE,
      );
      return null;
    }
    failedAt = null;
    launcher = { systemdRun };
    logScopeState("scoped", `[AIC] Jobs run in their own systemd scope (${systemdRun}).`);
    return launcher;
  });
  return inFlight;
}

/**
 * The promise a caller must await before starting a job, or null when there is
 * nothing to wait for (this machine can never have scopes, or the answer is
 * already settled). Exactly pendingLoginShellPath()'s contract, and awaited in
 * exactly the same place for the same reason — see connection.ts's do:job_start.
 */
export function pendingJobScope(): Promise<unknown> | null {
  if (launcher) return null;
  if (staticDecision !== undefined && !staticDecision.supported) return null;
  return startJobScopeProbe();
}

/**
 * The launcher for this machine, read SYNCHRONOUSLY — this is what spawnJob
 * calls, from inside the synchronous JobManager.start().
 *
 * Null means "launch this job unscoped", and it covers two cases deliberately
 * folded together: the machine cannot have scopes, and the probe has not settled
 * yet. Falling back rather than blocking is the whole point of the async rework
 * above — a job started in the probe's first few milliseconds runs exactly as it
 * did before this feature existed, which is a far smaller cost than stalling the
 * frame handler. In practice the window is empty: the probe starts at process
 * startup and do:job_start awaits it.
 */
export function jobScopeLauncher(): JobScopeLauncher | null {
  return launcher ?? null;
}

/**
 * Test helper: pin the memoized systemctl path, so the sweep can be pointed at a
 * stand-in. Production never calls this — it would aim a root kill by hand.
 */
export function setSystemctlForTests(systemctl: string | null): void {
  systemctlPath = systemctl;
}

/** Test helper: forget the memoized decision so another environment can be set up. */
export function resetJobScopeLauncherForTests(): void {
  systemctlPath = undefined;
  pendingLeftoverScopes.clear();
  if (leftoverSweep !== null) clearTimeout(leftoverSweep);
  leftoverSweep = null;
  staticDecision = undefined;
  staticIsLinux = false;
  launcher = undefined;
  inFlight = null;
  failedAt = null;
  loggedState = undefined;
}

// ── Tearing a scope down ─────────────────────────────────────────────────────

/**
 * The absolute paths systemctl is installed at, probed in order — the same
 * no-PATH-lookup reasoning as SYSTEMD_RUN_PATHS, and for the stronger reason:
 * this one runs as root and kills things.
 *
 * DELIBERATELY NOT ctl/systemctl.ts. That module is the CLI layer — it drives
 * the agent's OWN unit for install/uninstall, prints to a human's terminal, and
 * may block for a stop timeout; core must not depend on it. The two modules
 * therefore both invoke systemctl, at different layers and for different verbs,
 * on purpose.
 */
export const SYSTEMCTL_PATHS = ["/usr/bin/systemctl", "/bin/systemctl"] as const;

/** The first systemctl that exists, or null. `exists` is injectable, as above. */
export function resolveSystemctl(exists: (p: string) => boolean = fs.existsSync): string | null {
  for (const candidate of SYSTEMCTL_PATHS) {
    try {
      if (exists(candidate)) return candidate;
    } catch {
      // An unreadable path prefix is not a systemctl; keep looking.
    }
  }
  return null;
}

/** The memoized answer, or `undefined` while it has never been asked. */
let systemctlPath: string | null | undefined;

/**
 * resolveSystemctl(), asked ONCE per process.
 *
 * It used to sit as a DEFAULT ARGUMENT on killJobScope, which meant one or two
 * existsSync calls on every single reap — per cancel escalation, per settle, and
 * (before the sweep below existed) per retained job at startup. The paths are
 * two root-owned absolute names in system directories: a systemctl that appears
 * or disappears under a running root service is not a case worth paying a
 * syscall per call to catch. Cleared by resetJobScopeLauncherForTests.
 */
function cachedSystemctl(): string | null {
  if (systemctlPath === undefined) systemctlPath = resolveSystemctl();
  return systemctlPath;
}

/** A safety net only — the measured call returns in 0.01 s. */
export const JOB_SCOPE_KILL_TIMEOUT_MS = 5_000;

/**
 * The command that empties a job's scope cgroup, built rather than written out,
 * so the flags the tests read are the flags that run.
 *
 * `kill`, NOT `stop`, and this is the part someone will want to "simplify":
 * `systemctl stop` waits for the unit's stop job to finish, i.e. up to
 * DefaultTimeoutStopSec (90 s), which is precisely what a cancel must not do.
 * `kill` only sends signals and returns — measured at 0.01 s on Ubuntu 24.04.4 /
 * systemd 255, after which the scope was `inactive`/`not-found`, its cgroup was
 * empty and the runaway's log stopped growing.
 *
 * `--kill-who=all`, NOT `--kill-whom`: the newer spelling only exists on systemd
 * ≥ 252 (both work on 255, the older one works everywhere), and this feature
 * targets every systemd that can create a scope. `all` rather than the default
 * `main` is the entire point — the process we cannot reach is by definition not
 * the main one.
 *
 * The unit name is re-validated for the same reason jobScopeUnitName validates
 * the id: this is a root `systemctl kill` and the name decides what dies.
 */
export function buildJobScopeKillArgv(opts: { systemctl: string; unit: string }): JobScopeArgv {
  if (!isJobScopeUnitName(opts.unit)) {
    throw new Error(`refusing to kill ${JSON.stringify(opts.unit)}: not one of our job scopes`);
  }
  return { file: opts.systemctl, args: ["kill", "--kill-who=all", "--signal=SIGKILL", opts.unit] };
}

/**
 * Tear down a job's scope cgroup. Fire-and-forget by construction: it NEVER
 * throws and never reports, so a failure here can never turn a successful cancel
 * into an error for the caller.
 *
 * WHY IT EXISTS. Scopes made one case worse, and it was measured. Before them a
 * descendant that called `setsid` escaped `kill(-pgid)` but stayed in the
 * agent's service cgroup, so the next `systemctl restart` reaped it. With a
 * scope it sits in the job's own unit and survives BOTH cancel and restarts,
 * while refresh() sees the wrapper pid gone, settles the job and releases its
 * GPU lock — putting the next job on a card a runaway is still using, the exact
 * OOM the lock exists to prevent. Measured on Ubuntu 24.04.4 / systemd 255: with
 * a scoped job whose child called `setsid`, `kill -TERM -<pgid>` killed the
 * wrapper while the runaway kept running and kept writing to its log (25 → 27
 * lines) with the scope still `active`; the command above then emptied it.
 *
 * A unit that is already gone answers `Failed to kill unit …: Unit … not
 * loaded.` with a non-zero exit. That is the NORMAL case — the job ended and
 * systemd collected its scope — so it is a no-op success, never an error worth
 * surfacing.
 */
export function killJobScope(
  unit: string,
  systemctl: string | null = cachedSystemctl(),
): void {
  if (systemctl === null) return;
  let argv: JobScopeArgv;
  try {
    argv = buildJobScopeKillArgv({ systemctl, unit });
  } catch {
    // A name that is not ours: nothing to kill, and nothing else may be killed.
    return;
  }
  try {
    const child = execFile(argv.file, argv.args, { timeout: JOB_SCOPE_KILL_TIMEOUT_MS }, () => {
      // Both outcomes are fine: the scope was emptied, or it was already gone.
    });
    child.on("error", () => undefined);
  } catch {
    // No systemctl to run after all — the process group signal was the cancel.
  }
}

// ── Sweeping up scopes left behind by a previous agent ───────────────────────

/**
 * A scope SURVIVES an agent restart by design — that is the whole point of the
 * feature — so a job that ended while the agent was down may still be holding a
 * `setsid`-escaped descendant in its unit. refresh() finds exactly those records
 * (terminal on disk, never seen by this process) and they are the ONE case the
 * process-group cancel can never cover, so they must still be reaped.
 *
 * THE FAILURE THIS FIXES, which has now been introduced and removed once — do
 * not reintroduce it a third time. Hanging a plain killJobScope off that branch
 * fires a root `systemctl kill` per retained record: recover() refreshes every
 * job directory inside the retention window, so an agent restarting on a machine
 * holding a week of finished scoped jobs spawned one systemctl per job, in a
 * synchronous loop, against units that ended days ago and provably no longer
 * exist. On the desktop path recover() is reached lazily from the first
 * `do:job_*` frame, so that burst landed on the frame handler's thread — the
 * exact invariant the async capability probe above was reworked to protect.
 *
 * So: EVIDENCE, NOT EXIT CODES, the same principle the uninstall teardown
 * follows. Ask systemd ONCE which of our scopes are actually alive, kill only
 * those, and skip the rest without spawning anything. Deferred and coalesced, so
 * the whole recovery pass costs one bounded child process — and zero when there
 * is nothing to ask about.
 */
export const JOB_SCOPE_LIST_TIMEOUT_MS = 5_000;

/**
 * The command that answers "which of our job scopes exist right now".
 *
 * `--type=scope` plus the unit glob narrows the answer to units this agent
 * created and could name itself; `--all` keeps loaded-but-inactive ones (a scope
 * whose last process died but which systemd has not collected) so the answer is
 * about existence rather than activity; `--no-legend` drops the header and the
 * "N loaded units listed" footer, and `--plain` drops the leading `●` status
 * column so the unit name really is the first field of every line.
 */
export function buildJobScopeListArgv(systemctl: string): JobScopeArgv {
  return {
    file: systemctl,
    args: ["list-units", "--type=scope", "--all", "--no-legend", "--plain", JOB_SCOPE_UNIT_GLOB],
  };
}

/**
 * The unit names in a `list-units` answer. Anything that is not one of OUR scope
 * names is dropped rather than trusted: the set this returns decides what a root
 * `systemctl kill` is aimed at, and an empty or garbled answer must mean "kill
 * nothing", never "kill something else".
 */
export function parseJobScopeUnits(stdout: string): Set<string> {
  const live = new Set<string>();
  for (const line of stdout.split("\n")) {
    const unit = line.trim().split(/\s+/)[0];
    if (unit !== undefined && isJobScopeUnitName(unit)) live.add(unit);
  }
  return live;
}

/**
 * How many units one `systemctl kill` may name.
 *
 * `kill` takes any number of units, and the sweep exists precisely so that N
 * leftovers cost one spawn — but an argv is not unbounded, and this one is built
 * from names read off disk. Past the bound the list is simply chunked: 65 live
 * leftovers cost two spawns rather than 65, and none is skipped. In practice the
 * intersection is empty or has one element; a machine with 64 simultaneously
 * live orphaned scopes has a much larger problem than this argv.
 */
export const JOB_SCOPE_KILL_BATCH_MAX = 64;

/**
 * buildJobScopeKillArgv for several units at once — same flags, same reasons,
 * and EVERY name re-validated, not just the first: this is a root kill and the
 * names decide what dies.
 */
export function buildJobScopeKillManyArgv(opts: {
  systemctl: string;
  units: readonly string[];
}): JobScopeArgv {
  for (const unit of opts.units) {
    if (!isJobScopeUnitName(unit)) {
      throw new Error(`refusing to kill ${JSON.stringify(unit)}: not one of our job scopes`);
    }
  }
  if (opts.units.length === 0) throw new Error("refusing to kill nothing");
  return {
    file: opts.systemctl,
    args: ["kill", "--kill-who=all", "--signal=SIGKILL", ...opts.units],
  };
}

/** Units awaiting the next sweep, deduplicated. Emptied by every flush. */
const pendingLeftoverScopes = new Set<string>();
/** The one coalescing timer, or null when no sweep is scheduled. */
let leftoverSweep: NodeJS.Timeout | null = null;

/**
 * Queue the scope of a record found ALREADY TERMINAL on disk for the next sweep.
 *
 * Costs nothing but a Set insert: no probing, no spawn, nothing synchronous.
 * recover() may call this once per retained job; they all coalesce into the
 * single deferred flush below, because recover() is synchronous and the timer
 * cannot fire until it has finished.
 *
 * Deliberately NOT used for the running→terminal TRANSITION, which keeps its
 * immediate killJobScope: that is the instant the GPU lock is released and the
 * card is handed to the next job, so the survivor has to be ended THEN, not one
 * turn of the event loop later.
 */
export function reapLeftoverJobScope(unit: string): void {
  if (!isJobScopeUnitName(unit)) return;
  pendingLeftoverScopes.add(unit);
  if (leftoverSweep !== null) return;
  leftoverSweep = setTimeout(() => {
    leftoverSweep = null;
    flushLeftoverJobScopes();
  }, 0);
  // A pending sweep must never hold the process open.
  leftoverSweep.unref?.();
}

/**
 * Ask once, kill only what exists. Fire-and-forget by construction, exactly as
 * killJobScope is: it never throws and never reports, so it can never turn a
 * status or a list into an error.
 */
function flushLeftoverJobScopes(): void {
  const wanted = [...pendingLeftoverScopes];
  pendingLeftoverScopes.clear();
  if (wanted.length === 0) return;
  const systemctl = cachedSystemctl();
  if (systemctl === null) return;
  const argv = buildJobScopeListArgv(systemctl);
  try {
    const child = execFile(
      argv.file,
      argv.args,
      { timeout: JOB_SCOPE_LIST_TIMEOUT_MS },
      (err, stdout) => {
        // A query that failed is not evidence that anything is alive, and this
        // is a root kill: no answer means kill nothing. The records stay
        // terminal, and the worst case is a leftover that outlives us — which is
        // exactly where we stood before scopes existed.
        if (err !== null) return;
        const live = parseJobScopeUnits(stdout);
        const doomed = wanted.filter((unit) => live.has(unit));
        for (let i = 0; i < doomed.length; i += JOB_SCOPE_KILL_BATCH_MAX) {
          killJobScopes(doomed.slice(i, i + JOB_SCOPE_KILL_BATCH_MAX), systemctl);
        }
      },
    );
    child.on("error", () => undefined);
  } catch {
    // No systemctl to run after all.
  }
}

/** killJobScope for a batch: one spawn for the whole chunk. Never throws. */
function killJobScopes(units: readonly string[], systemctl: string): void {
  if (units.length === 0) return;
  let argv: JobScopeArgv;
  try {
    argv = buildJobScopeKillManyArgv({ systemctl, units });
  } catch {
    // A name that is not ours got this far: kill nothing rather than guess.
    return;
  }
  try {
    const child = execFile(argv.file, argv.args, { timeout: JOB_SCOPE_KILL_TIMEOUT_MS }, () => {
      // Both outcomes are fine, as in killJobScope.
    });
    child.on("error", () => undefined);
  } catch {
    // Nothing to run.
  }
}
