import type { ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import path from "node:path";
import {
  JOB_ID_PATTERN,
  JOB_MAX_CONCURRENT,
  JOB_RETENTION_MS,
  JOB_SCRIPT_REMOVED_ERROR,
  KILL_ESCALATION_MS,
} from "@aicommander/protocol";
import type {
  GpuDevice,
  JobRpcResult,
  JobStatus,
  JobSummary,
  JobUnknownReason,
} from "@aicommander/protocol";
import { diag } from "./diag-log.js";
import { decideGpuIndex, type KnownGpus } from "./job-gpu-index.js";
import { pendingLoginShellPath } from "./login-shell-path.js";
import { checkLogCap, clampListLimit, normalizeName, readJobLogs, toSummary } from "./job-output.js";
import {
  captureProcIdentity,
  signalProcessTree,
  signalSpawned,
  spawnJob,
  verifyJobProcess,
} from "./job-process.js";
import {
  jobScopeLauncher,
  killJobScope,
  pendingJobScope,
  reapLeftoverJobScope,
  type JobScopeLauncher,
} from "./job-scope.js";
import { COMMAND_FILE, WRAPPER_FILE } from "./job-scripts.js";
import { isDirectory, isWindows, JobStore, LOG_FILE, resolveJobsRoot } from "./job-store.js";
import { errText, invalidRequest, JobError, notFound, StartAborted } from "./job-types.js";
import type {
  JobCancelRequest,
  JobListRequest,
  JobLogsRequest,
  JobMeta,
  JobStartRequest,
  JobStatusRequest,
  StartWindow,
} from "./job-types.js";

const MAX_COMMAND_BYTES = 65_536;
const PRUNE_INTERVAL_MS = 60 * 60 * 1000;
export {
  buildJobScript,
  buildWindowsJobCommandScript,
  JOB_COMMAND_ENV,
  JOB_CWD_ENV,
  JOB_EXIT_PATH_ENV,
  JOB_LOG_PATH_ENV,
  WINDOWS_JOB_WRAPPER,
} from "./job-scripts.js";
export { JobError, resolveJobsRoot };
export type {
  JobCancelRequest,
  JobListRequest,
  JobLogsRequest,
  JobStartRequest,
  JobStatusRequest,
};

/**
 * Coordinates job lifecycle. Disk is authoritative; memory only guards active
 * start/retirement windows and avoids repeated work on settled records.
 */
export class JobManager {
  readonly jobsRoot: string;

  private lastPruneAt = 0;
  /** Terminal observations used only to avoid repeat work, never to answer status. */
  private readonly settledJobs = new Set<string>();
  /** Failed starts whose spawned process is still being stopped. */
  private readonly retiringJobs = new Set<string>();
  /** GPU reservations retained while a late-started cancelled process dies. */
  private readonly cardsHeldByDyingProcess = new Map<number, string>();
  /** Interruptible record-to-process windows; readers must not settle them. */
  private readonly startingJobs = new Map<string, StartWindow>();
  /** In-memory companion to the durable cancelRequestedAt marker. */
  private readonly cancelledJobs = new Set<string>();
  /** Signal evidence consumed by the exit classification callback. */
  private readonly signalledJobs = new Set<string>();

  private knownGpus: KnownGpus = null;

  private readonly store: JobStore;

  private readonly scopeLauncher: () => JobScopeLauncher | null;

  constructor(opts?: {
    jobsRoot?: string;
    configDir?: string;
    scopeLauncher?: () => JobScopeLauncher | null;
  }) {
    this.jobsRoot = opts?.jobsRoot ?? resolveJobsRoot(opts?.configDir);
    this.store = new JobStore(this.jobsRoot);
    this.scopeLauncher = opts?.scopeLauncher ?? jobScopeLauncher;
  }

  setKnownGpus(gpus: readonly GpuDevice[] | undefined): void {
    this.knownGpus = gpus === undefined ? null : gpus.slice();
  }

  recover(): void {
    void pendingLoginShellPath();
    void pendingJobScope();
    try {
      this.store.ensureRoot();
    } catch {
      // Job RPCs fail individually; recovery must not keep the agent offline.
      return;
    }
    for (const jobId of this.store.listJobIds()) {
      try {
        const meta = this.store.readMeta(jobId);
        if (meta) this.refresh(meta);
      } catch {
        // One damaged job directory must not abort recovery of the rest.
      }
    }
    this.pruneExpired(Date.now());
    this.reapGpuLocks();
  }

  private pruneExpired(now: number): void {
    this.lastPruneAt = now;
    for (const jobId of this.store.listJobIds()) {
      try {
        const meta = this.store.readMeta(jobId);
        if (!meta) {
          this.pruneUnreadable(jobId, now);
          continue;
        }
        if (meta.endedAt !== null && now - meta.endedAt > JOB_RETENTION_MS) {
          this.removeJobDir(jobId);
        }
      } catch {
        // One damaged job directory must not abort the retention sweep.
      }
    }
  }

  private maybePrune(): void {
    const now = Date.now();
    if (now - this.lastPruneAt < PRUNE_INTERVAL_MS) return;
    this.pruneExpired(now);
  }

  async start(req: JobStartRequest): Promise<JobRpcResult> {
    // Validate request-only fields before changing disk state.
    const command = req.command;
    if (typeof command !== "string" || command.trim() === "") {
      return invalidRequest("A job requires a non-empty command.");
    }
    if (Buffer.byteLength(command, "utf8") > MAX_COMMAND_BYTES) {
      return invalidRequest("The command is too long to run as a job.");
    }
    if (isWindows && /[\r\n]/.test(command)) {
      return invalidRequest(
        "A job command cannot contain a line break on Windows: it would be read as further lines of the wrapper script. Join the steps with `&&` instead.",
      );
    }
    const gpu = decideGpuIndex(req.gpuIndex, this.knownGpus);
    if ("invalid" in gpu) return invalidRequest(gpu.invalid);
    const gpuIndex = gpu.gpuIndex;

    try {
      this.store.ensureRoot();
    } catch (err) {
      throw new JobError(`The jobs directory is not usable: ${errText(err)}`);
    }

    // Retention and capacity policy stay coordinated with fresh disk state.
    this.maybePrune();
    const running = this.countRunningJobs();
    if (running >= JOB_MAX_CONCURRENT) {
      return {
        ok: false,
        reason: "too_many_jobs",
        message: `This machine already has ${running} jobs running (limit ${JOB_MAX_CONCURRENT}).`,
      };
    }

    const jobId = randomBytes(8).toString("hex");
    const workspace = this.store.workspaceDir(jobId);
    try {
      this.store.ensureJobDirs(jobId);
    } catch (err) {
      throw new JobError(`Could not create the job directory: ${errText(err)}`);
    }
    let cwd = workspace;
    if (req.cwd !== undefined) {
      if (typeof req.cwd !== "string" || !path.isAbsolute(req.cwd)) {
        this.removeJobDir(jobId);
        return invalidRequest("cwd must be an absolute path.");
      }
      if (!isDirectory(req.cwd)) {
        this.removeJobDir(jobId);
        throw new JobError("cwd does not exist on this machine.");
      }
      cwd = req.cwd;
    }

    // Reserve the GPU before exposing a running record.
    if (gpuIndex !== null) {
      const heldBy = this.acquireGpuLock(gpuIndex, jobId);
      if (heldBy !== null) {
        this.removeJobDir(jobId);
        return {
          ok: false,
          reason: "gpu_busy",
          heldBy,
          message: `GPU ${gpuIndex} is reserved by job ${heldBy}.`,
        };
      }
    }

    const meta: JobMeta = {
      v: 1,
      jobId,
      name: normalizeName(req.name, jobId),
      command,
      cwd,
      status: "running",
      exitCode: null,
      startedAt: Date.now(),
      endedAt: null,
      gpuIndex,
      pid: null,
      procIdentity: null,
      truncatedAt: null,
    };

    // The record precedes spawn; startingJobs protects the pid-less await window.
    if (!this.store.writeMeta(meta)) {
      this.abandonStart(jobId, gpuIndex);
      throw new JobError("Could not record the job on disk.");
    }
    const window: StartWindow = { abort: null, erasing: false };
    this.startingJobs.set(jobId, window);
    let child: ChildProcess;
    let pid: number;
    let scope: string | undefined;
    try {
      ({ child, pid, scope } = await spawnJob({
        jobsRoot: this.jobsRoot,
        meta,
        callerEnv: req.env,
        scopeLauncher: this.scopeLauncher,
        abortedStart: () => window.abort ?? (req.signal?.aborted === true ? "abandoned" : null),
        onExit: (code, signal) => this.handleChildExit(meta.jobId, code, signal),
      }));
    } catch (err) {
      if (window.abort === "cancelled") {
        this.startingJobs.delete(jobId);
        if (err instanceof StartAborted && err.reason === "cancelled") {
          const settled = this.store.readMeta(jobId) ?? {
            ...meta,
            status: "unknown",
            exitCode: null,
            endedAt: Date.now(),
          };
          return { ok: true, kind: "job", job: toSummary(this.store, settled, false) };
        }
        throw err instanceof JobError ? err : new JobError(`Could not start the job: ${errText(err)}`);
      }
      window.erasing = true;
      await this.abandonStartAsync(jobId, gpuIndex);
      this.startingJobs.delete(jobId);
      if (err instanceof StartAborted) {
        throw new JobError("The connection was lost before the job could be started, so nothing was started.");
      }
      throw err instanceof JobError ? err : new JobError(`Could not start the job: ${errText(err)}`);
    }

    meta.pid = pid;
    if (scope !== undefined) meta.scope = scope;
    const raced = window.abort ?? (req.signal?.aborted === true ? "abandoned" : null);
    if (raced !== null) {
      this.startingJobs.delete(jobId);
      if (raced === "cancelled") {
        this.holdCardUntilExit(meta, child);
        this.cancelledJobs.add(jobId);
        child.once("exit", () => this.cancelledJobs.delete(jobId));
        signalSpawned(child, pid, "SIGTERM");
        const escalation = setTimeout(() => {
          signalSpawned(child, pid, "SIGKILL");
          if (meta.scope !== undefined) killJobScope(meta.scope);
        }, KILL_ESCALATION_MS);
        escalation.unref?.();
        throw new JobError("The job was cancelled while it was being started; its process is being stopped.");
      }
      this.retireStartedProcess(meta, child);
      throw new JobError("The connection was lost while the job was being started; the process is being stopped.");
    }

    // Persist the pid before the slower identity probe to reduce the crash window.
    const pidRecorded = this.store.writeMeta(meta);
    meta.procIdentity = captureProcIdentity(pid);
    const recorded = pidRecorded && (meta.procIdentity === null || this.store.writeMeta(meta));
    this.startingJobs.delete(jobId);
    const verdict = verifyJobProcess(meta);
    // Windows may lack an identity probe; POSIX starts require a verifiable owner.
    const unidentified = verdict === "unverifiable" && !isWindows;
    if (!recorded || unidentified) {
      this.retireStartedProcess(meta, child);
      throw new JobError(
        recorded
          ? "Could not identify the job's process; it is being stopped."
          : "Could not record the job on disk; the process is being stopped.",
      );
    }
    return { ok: true, kind: "job", job: toSummary(this.store, meta, false) };
  }

  private abandonStart(jobId: string, gpuIndex: number | null): void {
    if (gpuIndex !== null) this.releaseGpuLock(gpuIndex, jobId);
    this.removeJobDir(jobId);
  }

  private async abandonStartAsync(jobId: string, gpuIndex: number | null): Promise<void> {
    if (gpuIndex !== null) this.releaseGpuLock(gpuIndex, jobId);
    await this.removeJobDirAsync(jobId);
  }

  private retireStartedProcess(meta: JobMeta, child: ChildProcess): void {
    const { jobId, gpuIndex, pid } = meta;
    this.retiringJobs.add(jobId);
    this.store.writeMeta({ ...meta, retiring: true });
    child.once("exit", () => {
      this.retiringJobs.delete(jobId);
      this.abandonStart(jobId, gpuIndex);
    });
    if (pid === null) return;
    signalSpawned(child, pid, "SIGTERM");
    const escalation = setTimeout(() => {
      signalSpawned(child, pid, "SIGKILL");
      // Scope cleanup catches descendants that escaped the wrapper process.
      if (meta.scope !== undefined) killJobScope(meta.scope);
    }, KILL_ESCALATION_MS);
    escalation.unref?.();
  }

  private holdCardUntilExit(meta: JobMeta, child: ChildProcess): void {
    const { jobId, gpuIndex } = meta;
    if (gpuIndex === null) return;
    this.cardsHeldByDyingProcess.set(gpuIndex, jobId);
    try {
      this.acquireGpuLock(gpuIndex, jobId);
    } catch {
      // The RAM hold still protects this dying process until its exit callback.
    }
    child.once("exit", () => {
      if (this.cardsHeldByDyingProcess.get(gpuIndex) === jobId) {
        this.cardsHeldByDyingProcess.delete(gpuIndex);
      }
      this.releaseGpuLock(gpuIndex, jobId);
    });
  }

  private countRunningJobs(): number {
    let running = 0;
    for (const jobId of this.store.listJobIds()) {
      if (this.settledJobs.has(jobId)) continue;
      const meta = this.store.readMeta(jobId);
      if (!meta) continue;
      if (this.refresh(meta).status === "running") running++;
    }
    return running;
  }

  list(req: JobListRequest): JobRpcResult {
    this.maybePrune();
    const stored = this.store.listMetas()
      .filter((meta) => !this.retiringJobs.has(meta.jobId))
      .sort((a, b) => b.startedAt - a.startedAt);
    const limit = clampListLimit(req.limit);
    const jobs: JobSummary[] = [];
    let walked = 0;
    for (const entry of stored) {
      if (jobs.length >= limit) break;
      walked++;
      const meta = this.refresh(entry);
      if (req.status && meta.status !== req.status) continue;
      jobs.push(toSummary(this.store, meta, req.includeCommand === true));
    }
    const omitted = stored.length - walked;
    return { ok: true, kind: "jobs", jobs, ...(omitted > 0 ? { omitted } : {}) };
  }

  status(req: JobStatusRequest): JobRpcResult {
    const meta = this.loadForRequest(req.jobId);
    if (!meta) return notFound();
    return { ok: true, kind: "job", job: toSummary(this.store, meta, req.includeCommand === true) };
  }

  logs(req: JobLogsRequest): JobRpcResult {
    const meta = this.loadForRequest(req.jobId);
    if (!meta) return notFound();
    return readJobLogs(this.store, meta, req);
  }

  cancel(req: JobCancelRequest): JobRpcResult {
    const meta = this.loadForRequest(req.jobId);
    if (!meta) return notFound();
    const window = this.startingJobs.get(meta.jobId);
    if (window?.erasing === true) return notFound();
    if (this.retiringJobs.has(meta.jobId)) return notFound();
    if (window) {
      window.abort = "cancelled";
      this.cancelledJobs.add(meta.jobId);
      this.startingJobs.delete(meta.jobId);
      const ended = this.settle(meta, "unknown", null, Date.now(), false, "cancelled");
      return { ok: true, kind: "job", job: toSummary(this.store, ended, false) };
    }
    if (meta.status === "running" && meta.pid !== null) {
      this.signalJob(meta);
    }
    return { ok: true, kind: "job", job: toSummary(this.store, meta, false) };
  }

  private handleChildExit(
    jobId: string,
    code: number | null,
    signal: NodeJS.Signals | null,
  ): void {
    try {
      // Cancellation knowledge outranks a normal-looking shell exit code.
      if (code !== null && signal === null && !this.cancelledJobs.has(jobId)) {
        this.store.recordExitCode(jobId, code);
      }
      // Record signal evidence before refresh consumes it while classifying.
      if (signal !== null) this.signalledJobs.add(jobId);
      const current = this.store.readMeta(jobId);
      if (current) this.refresh(current);
    } catch {
      // Prompt settlement is optional; recovery reaches the same disk state.
    }
  }

  private signalJob(meta: JobMeta): void {
    const pid = meta.pid;
    if (pid === null) return;
    this.cancelledJobs.add(meta.jobId);
    if (meta.cancelRequestedAt === undefined) {
      meta.cancelRequestedAt = Date.now();
      this.store.writeMeta(meta);
    }
    const send = (signal: "SIGTERM" | "SIGKILL") => {
      // Signals require confirmed ownership; inconclusive identity is a hold.
      if (verifyJobProcess(meta) === "ours") signalProcessTree(pid, signal);
    };
    send("SIGTERM");
    const escalation = setTimeout(() => {
      send("SIGKILL");
      // Scope cleanup catches descendants that escaped the wrapper process.
      if (meta.scope !== undefined) killJobScope(meta.scope);
    }, KILL_ESCALATION_MS);
    escalation.unref?.();
  }

  private refresh(meta: JobMeta): JobMeta {
    if (this.retiringJobs.has(meta.jobId)) return meta;
    if (this.startingJobs.has(meta.jobId)) return meta;
    if (meta.status !== "running") {
      if (!this.settledJobs.has(meta.jobId)) this.checkLogCap(meta);
      this.markSettled(meta, false);
      return meta;
    }
    const observed = this.store.readExit(meta.jobId);
    if (observed) return this.settleFromExitMarker(meta, observed);
    // Reads hold the job unless the process is proven gone.
    if (verifyJobProcess(meta) !== "gone") {
      this.checkLogCap(meta);
      return meta;
    }
    // Re-read after proving the pid gone: the wrapper writes the marker first.
    const late = this.store.readExit(meta.jobId);
    if (late) return this.settleFromExitMarker(meta, late);
    return this.settle(
      meta,
      "unknown",
      null,
      this.estimateVanishedEndedAt(meta),
      true,
      this.classifyVanishedJob(meta),
    );
  }

  private settleFromExitMarker(meta: JobMeta, marker: { code: number; at: number }): JobMeta {
    // Both marker reads honor durable cancellation, including after restart.
    if (this.cancelWasRequested(meta)) {
      return this.settle(meta, "unknown", null, marker.at, false, "cancelled");
    }
    return this.settle(meta, "exited", marker.code, marker.at);
  }

  private classifyVanishedJob(meta: JobMeta): JobUnknownReason {
    if (this.cancelWasRequested(meta)) return "cancelled";
    if (this.signalledJobs.has(meta.jobId)) return "killed_by_signal";
    const log = this.store.fileStat(meta.jobId, LOG_FILE);
    if (!log || !Number.isFinite(log.size)) return "undetermined";
    if (isWindows) {
      for (const file of [WRAPPER_FILE, COMMAND_FILE]) {
        const state = this.store.fileExistsState(meta.jobId, file);
        if (state === "unreadable") return "undetermined";
        if (state === "absent") return JOB_SCRIPT_REMOVED_ERROR;
      }
    }
    if (log.size === 0) {
      return isWindows ? "vanished_no_output_windows" : "vanished_no_output_posix";
    }
    return isWindows ? "vanished_with_output_windows" : "vanished_with_output_posix";
  }

  private cancelWasRequested(meta: JobMeta): boolean {
    return meta.cancelRequestedAt !== undefined || this.cancelledJobs.has(meta.jobId);
  }

  private estimateVanishedEndedAt(meta: JobMeta): number {
    const now = Date.now();
    const log = this.store.fileStat(meta.jobId, LOG_FILE);
    if (!log || log.size === 0 || !Number.isFinite(log.mtimeMs)) return now;
    const ended = Math.round(log.mtimeMs);
    if (!Number.isSafeInteger(ended)) return now;
    const floor = Number.isSafeInteger(meta.startedAt) ? meta.startedAt : 0;
    return Math.min(Math.max(ended, floor), now);
  }

  private settle(
    meta: JobMeta,
    status: JobStatus,
    exitCode: number | null,
    endedAt: number,
    approximate = false,
    unknownReason?: JobUnknownReason,
  ): JobMeta {
    if (meta.retiring === true) return this.discardRetired(meta, endedAt);
    const settled: JobMeta = { ...meta, status, exitCode, endedAt, endedAtApproximate: approximate };
    if (unknownReason !== undefined) settled.unknownReason = unknownReason;
    else delete settled.unknownReason;
    this.checkLogCap(settled, false);
    if (settled.gpuIndex !== null) this.releaseGpuLock(settled.gpuIndex, settled.jobId);
    this.store.writeMeta(settled);
    this.markSettled(settled, true);
    this.cancelledJobs.delete(settled.jobId);
    this.signalledJobs.delete(settled.jobId);
    diag("job.exit", {
      jobId: settled.jobId,
      status,
      exitCode,
      ...(approximate ? { endedAtApproximate: true } : {}),
      ...(unknownReason !== undefined ? { unknownReason } : {}),
    });
    return settled;
  }

  private markSettled(meta: JobMeta, transition: boolean): void {
    if (this.settledJobs.has(meta.jobId)) return;
    this.settledJobs.add(meta.jobId);
    if (meta.scope === undefined) return;
    // New transitions kill immediately; recovered terminal records use batched reap.
    if (transition) killJobScope(meta.scope);
    else reapLeftoverJobScope(meta.scope);
  }

  private discardRetired(meta: JobMeta, endedAt: number): JobMeta {
    this.abandonStart(meta.jobId, meta.gpuIndex);
    return { ...meta, status: "unknown", exitCode: null, endedAt };
  }

  private checkLogCap(meta: JobMeta, persist = true): void {
    checkLogCap(this.store, meta, (next) => {
      if (persist) this.store.writeMeta(next);
    });
  }

  private acquireGpuLock(index: number, jobId: string, retried = false): string | null {
    // A dying process can still occupy a card after its record became terminal.
    const dying = this.cardsHeldByDyingProcess.get(index);
    if (dying !== undefined && dying !== jobId) return dying;
    try {
      if (this.store.createGpuLock(index, jobId) === "created") return null;
    } catch (err) {
      throw new JobError(`Could not reserve GPU ${index}: ${errText(err)}`);
    }

    const lock = this.store.readGpuLock(index);
    // An unreadable lock may still name a live job; only evidence permits reaping.
    if (lock.kind === "unreadable") return "unknown";
    if (lock.kind === "holder" && this.gpuHolderState(lock.jobId) !== "gone") {
      return lock.jobId;
    }
    if (retried) {
      return lock.kind === "holder" ? lock.jobId : "unknown";
    }
    if (!this.store.removeGpuLock(index)) {
      return lock.kind === "holder" ? lock.jobId : "unknown";
    }
    return this.acquireGpuLock(index, jobId, true);
  }

  private releaseGpuLock(index: number, jobId: string): void {
    const lock = this.store.readGpuLock(index);
    if (lock.kind !== "holder" || lock.jobId !== jobId) return;
    this.store.removeGpuLock(index);
  }

  private reapGpuLocks(): void {
    for (const lockPath of this.store.listGpuLockPaths()) {
      const lock = this.store.readGpuLockPath(lockPath);
      if (lock.kind === "absent" || lock.kind === "unreadable") continue;
      if (lock.kind === "holder" && this.gpuHolderState(lock.jobId) !== "gone") continue;
      this.store.removeGpuLockPath(lockPath);
    }
  }

  private gpuHolderState(jobId: string): "running" | "gone" | "unknown" {
    const read = this.store.readMetaState(jobId);
    // Absence releases a stale lock; unreadable state holds it and retries later.
    if (read.kind === "absent") return "gone";
    if (read.kind === "unreadable") return "unknown";
    return this.refresh(read.meta).status === "running" ? "running" : "gone";
  }

  private loadForRequest(jobId: unknown): JobMeta | null {
    if (typeof jobId !== "string" || !JOB_ID_PATTERN.test(jobId)) return null;
    if (this.retiringJobs.has(jobId)) return null;
    const meta = this.store.readMeta(jobId);
    if (!meta) return null;
    return this.refresh(meta);
  }

  private removeJobDir(jobId: string): void {
    if (!JOB_ID_PATTERN.test(jobId)) return;
    // Forget first: no in-memory qualifier may outlive its disk record.
    this.forgetJob(jobId);
    this.store.removeJobDir(jobId);
  }

  private async removeJobDirAsync(jobId: string): Promise<void> {
    if (!JOB_ID_PATTERN.test(jobId)) return;
    this.forgetJob(jobId);
    await this.store.removeJobDirAsync(jobId);
  }

  private forgetJob(jobId: string): void {
    this.settledJobs.delete(jobId);
    this.cancelledJobs.delete(jobId);
    this.signalledJobs.delete(jobId);
  }

  private pruneUnreadable(jobId: string, now: number): void {
    const mtime = this.store.jobDirMtime(jobId);
    if (mtime !== null && now - mtime > JOB_RETENTION_MS) this.removeJobDir(jobId);
  }
}

let cached: { root: string; manager: JobManager } | null = null;

export function getJobManager(configDir?: string): JobManager {
  const root = resolveJobsRoot(configDir);
  if (cached && cached.root === root) return cached.manager;
  const manager = new JobManager({ jobsRoot: root });
  manager.recover();
  cached = { root, manager };
  return manager;
}

export function resetJobManagerForTests(): void {
  cached = null;
}
