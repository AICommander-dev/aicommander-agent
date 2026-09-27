import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { JOB_SCRIPT_REMOVED_ERROR } from "@aicommander/protocol";
import { ensurePrivateDir, PRIVATE_FILE_MODE } from "./atomic-file.js";
import {
  applyLoginShellLocale,
  applyLoginShellPath,
  applyNonInteractiveTerm,
  pendingLoginShellPath,
} from "./login-shell-path.js";
import {
  buildJobScopeArgv,
  jobScopeDescription,
  jobScopeUnitName,
  type JobScopeLauncher,
} from "./job-scope.js";
import { compareProcIdentity, readProcIdentity } from "./proc-identity.js";
import {
  buildJobScript,
  JOB_CWD_ENV,
  JOB_EXIT_PATH_ENV,
  JOB_LOG_PATH_ENV,
  jobScriptRemovedMessage,
  verifyWindowsJobScripts,
  windowsJobLaunch,
  writeWindowsJobScripts,
} from "./job-scripts.js";
import { EXIT_FILE, isDirectory, isWindows, LOG_FILE, SHARED_HOME_DIR } from "./job-store.js";
import { JobError, StartAborted } from "./job-types.js";
import { boundedJobOperator, setJobNoticeEnv } from "./job-notice.js";
import type { JobMeta, StartAbortReason } from "./job-types.js";

const JOB_ENV_DEFAULTS: Readonly<Record<string, string>> = { PYTHONUNBUFFERED: "1" };

type ProcessVerdict = "ours" | "gone" | "unverifiable";

export interface SpawnJobOptions {
  jobsRoot: string;
  meta: JobMeta;
  callerEnv: Record<string, string> | undefined;
  resolveOperator?: () => Promise<string>;
  scopeLauncher: () => JobScopeLauncher | null;
  abortedStart: () => StartAbortReason | null;
  onExit: (code: number | null, signal: NodeJS.Signals | null) => void;
}

export async function spawnJob(
  opts: SpawnJobOptions,
): Promise<{ child: ChildProcess; pid: number; scope?: string }> {
  const { jobsRoot, meta } = opts;
  const dir = path.join(jobsRoot, meta.jobId);
  const operator = isWindows ? await boundedJobOperator(opts.resolveOperator) : "";
  throwIfAborted(opts.abortedStart());

  if (isWindows) {
    const refused = await writeWindowsJobScripts(dir, meta.command);
    if (refused !== null) {
      throw new JobError(jobScriptRemovedMessage(refused), JOB_SCRIPT_REMOVED_ERROR, refused);
    }
    throwIfAborted(opts.abortedStart());
  }

  const launch: { file: string; args: string[] } = isWindows
    ? windowsJobLaunch()
    : { file: "/bin/sh", args: ["-c", buildJobScript(meta.command)] };
  const launcher = isWindows ? null : opts.scopeLauncher();
  let scope: string | undefined;
  if (launcher) {
    scope = jobScopeUnitName(meta.jobId);
    const wrapped = buildJobScopeArgv({
      systemdRun: launcher.systemdRun,
      unit: scope,
      description: jobScopeDescription(meta.jobId),
      file: launch.file,
      args: launch.args,
    });
    launch.file = wrapped.file;
    launch.args = wrapped.args;
  }

  let logFd: number | null = fs.openSync(path.join(dir, LOG_FILE), "a", PRIVATE_FILE_MODE);
  if (isWindows) {
    fs.closeSync(logFd);
    logFd = null;
  }
  try {
    if (isWindows) {
      const fault = await verifyWindowsJobScripts(dir, meta.command);
      if (fault !== null) {
        throw new JobError(jobScriptRemovedMessage(fault), JOB_SCRIPT_REMOVED_ERROR, fault);
      }
    }
    // This remains the last observation before spawn; there is no await after it.
    throwIfAborted(opts.abortedStart());
    const child = spawn(launch.file, launch.args, {
      shell: isWindows,
      cwd: isWindows ? dir : meta.cwd,
      env: buildJobEnv(meta, jobsRoot, opts.callerEnv, operator),
      stdio: logFd === null ? ["ignore", "ignore", "ignore"] : ["ignore", logFd, logFd],
      detached: true,
      windowsHide: true,
    });
    if (child.pid === undefined) throw new Error("the shell did not start");

    // Listeners must exist before unref so prompt settlement cannot be missed.
    child.on("exit", opts.onExit);
    child.on("error", () => undefined);
    child.unref();
    return { child, pid: child.pid, scope };
  } finally {
    if (logFd !== null) fs.closeSync(logFd);
  }
}

function throwIfAborted(reason: StartAbortReason | null): void {
  if (reason !== null) throw new StartAborted(reason);
}

function buildJobEnv(
  meta: JobMeta,
  jobsRoot: string,
  callerEnv: Record<string, string> | undefined,
  operator: string,
): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, ...JOB_ENV_DEFAULTS };
  void pendingLoginShellPath();
  applyLoginShellPath(env);
  applyLoginShellLocale(env);
  applyNonInteractiveTerm(env);
  if (callerEnv && typeof callerEnv === "object") {
    for (const [key, value] of Object.entries(callerEnv)) {
      if (typeof key === "string" && key !== "" && typeof value === "string") env[key] = value;
    }
  }
  // cmd resolves ERRORLEVEL from the environment before the real exit status.
  for (const key of Object.keys(env)) {
    if (key.toUpperCase() === "ERRORLEVEL") delete env[key];
  }
  const home = resolveJobHome(jobsRoot, meta.cwd, typeof callerEnv?.["HOME"] === "string");
  if (home) env["HOME"] = home;
  if (meta.gpuIndex !== null) env["CUDA_VISIBLE_DEVICES"] = String(meta.gpuIndex);
  env[JOB_EXIT_PATH_ENV] = path.join(jobsRoot, meta.jobId, EXIT_FILE);
  env[JOB_LOG_PATH_ENV] = path.join(jobsRoot, meta.jobId, LOG_FILE);
  if (isWindows) {
    env[JOB_CWD_ENV] = meta.cwd;
    setJobNoticeEnv(env, meta.jobId, operator, meta.startedAt);
  }
  return env;
}

function resolveJobHome(
  jobsRoot: string,
  cwd: string,
  callerSetHome: boolean,
): string | undefined {
  if (callerSetHome || isWindows) return undefined;
  if (typeof process.getuid !== "function" || process.getuid() !== 0) return undefined;
  const ownerHome = homeOfPathOwner(cwd);
  if (ownerHome) return ownerHome;
  const shared = path.join(jobsRoot, SHARED_HOME_DIR);
  try {
    ensurePrivateDir(shared);
    return shared;
  } catch {
    return undefined;
  }
}

function homeOfPathOwner(target: string): string | undefined {
  try {
    const uid = fs.statSync(target).uid;
    if (uid === 0) return undefined;
    const passwd = fs.readFileSync("/etc/passwd", "utf8");
    for (const line of passwd.split("\n")) {
      const fields = line.split(":");
      if (fields.length < 6 || Number(fields[2]) !== uid) continue;
      const home = fields[5];
      if (home && path.isAbsolute(home) && isDirectory(home) && ownerUid(home) === uid) return home;
      return undefined;
    }
  } catch {
    // Containers and hardened systems may not expose passwd or the cwd owner.
  }
  return undefined;
}

function ownerUid(target: string): number | null {
  try {
    return fs.statSync(target).uid;
  } catch {
    return null;
  }
}

/** Retry once because a transient identity miss otherwise rejects the whole start. */
export function captureProcIdentity(pid: number): string | null {
  return readProcIdentity(pid) ?? readProcIdentity(pid);
}

/**
 * Distinguishes proof of ownership, proof of absence, and an inconclusive hold.
 * A null pid is gone because failed or unrecorded starts leave nothing to probe;
 * ESRCH also proves absence. EPERM still permits an identity probe, while a
 * missing, legacy, or unparseable identity remains unverifiable.
 */
export function verifyJobProcess(meta: JobMeta): ProcessVerdict {
  if (meta.pid === null) return "gone";
  try {
    process.kill(meta.pid, 0);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ESRCH") return "gone";
    if (code !== "EPERM") return "unverifiable";
  }
  const identity = readProcIdentity(meta.pid);
  if (identity === null || meta.procIdentity === null) return "unverifiable";
  switch (compareProcIdentity(meta.procIdentity, identity)) {
    case "match":
      return "ours";
    case "mismatch":
      return "gone";
    default:
      return "unverifiable";
  }
}

export function signalSpawned(
  child: ChildProcess,
  pid: number,
  signal: "SIGTERM" | "SIGKILL",
): void {
  if (child.exitCode !== null || child.signalCode !== null) return;
  signalProcessTree(pid, signal);
}

export function signalProcessTree(pid: number, signal: "SIGTERM" | "SIGKILL"): void {
  try {
    if (isWindows) {
      spawn("taskkill", ["/pid", String(pid), "/T", "/F"], {
        stdio: "ignore",
        windowsHide: true,
      });
    } else {
      process.kill(-pid, signal);
    }
  } catch {
    // The process may have exited between verification and signalling.
  }
}
