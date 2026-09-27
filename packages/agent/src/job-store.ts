import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  gpuLockFileName,
  isGpuLockFileName,
  JOB_ID_PATTERN,
} from "@aicommander/protocol";
import { atomicWriteUtf8, ensurePrivateDir, PRIVATE_FILE_MODE } from "./atomic-file.js";
import { envConfigDir } from "./config-dir.js";
import type { JobMeta } from "./job-types.js";

const META_FILE = "meta.json";
export const LOG_FILE = "output.log";
export const EXIT_FILE = "exit";
const WORKSPACE_DIR = "workspace";
export const SHARED_HOME_DIR = "home";

/** Read once at module load so platform-mocked suites can pin behavior before import. */
export const isWindows = process.platform === "win32";

export function isDirectory(target: string): boolean {
  try {
    return fs.statSync(target).isDirectory();
  } catch {
    return false;
  }
}

export type MetaRead =
  | { kind: "ok"; meta: JobMeta }
  | { kind: "absent" }
  | { kind: "unreadable" };

export type LockRead =
  | { kind: "holder"; jobId: string }
  | { kind: "garbage" }
  | { kind: "absent" }
  | { kind: "unreadable" };

export function resolveJobsRoot(configDir?: string): string {
  const base = configDir ?? envConfigDir();
  if (base) return path.join(base, "jobs");
  const isRoot = typeof process.getuid === "function" && process.getuid() === 0;
  if (!isWindows && isRoot) return "/var/lib/aicommander/jobs";
  if (isWindows) {
    const localAppData = process.env["LOCALAPPDATA"];
    const winBase = localAppData && path.isAbsolute(localAppData)
      ? localAppData
      : path.join(os.homedir(), "AppData", "Local");
    return path.join(winBase, "aicommander", "jobs");
  }
  return path.join(os.homedir(), ".local", "share", "aicommander", "jobs");
}

export class JobStore {
  constructor(readonly root: string) {}

  ensureRoot(): void {
    ensurePrivateDir(this.root);
  }

  jobDir(jobId: string): string {
    return path.join(this.root, jobId);
  }

  workspaceDir(jobId: string): string {
    return path.join(this.jobDir(jobId), WORKSPACE_DIR);
  }

  logPath(jobId: string): string {
    return path.join(this.jobDir(jobId), LOG_FILE);
  }

  exitPath(jobId: string): string {
    return path.join(this.jobDir(jobId), EXIT_FILE);
  }

  ensureJobDirs(jobId: string): void {
    ensurePrivateDir(this.jobDir(jobId));
    ensurePrivateDir(this.workspaceDir(jobId));
  }

  listJobIds(): string[] {
    try {
      return fs.readdirSync(this.root).filter((entry) => JOB_ID_PATTERN.test(entry));
    } catch {
      return [];
    }
  }

  listMetas(): JobMeta[] {
    const metas: JobMeta[] = [];
    for (const jobId of this.listJobIds()) {
      const meta = this.readMeta(jobId);
      if (meta) metas.push(meta);
    }
    return metas;
  }

  readMeta(jobId: string): JobMeta | null {
    const read = this.readMetaState(jobId);
    return read.kind === "ok" ? read.meta : null;
  }

  /** Absence is evidence; unreadable data must remain an inconclusive hold. */
  readMetaState(jobId: string): MetaRead {
    if (!JOB_ID_PATTERN.test(jobId)) return { kind: "absent" };
    try {
      const raw = fs.readFileSync(path.join(this.jobDir(jobId), META_FILE), "utf8");
      const parsed: unknown = JSON.parse(raw);
      return isJobMeta(parsed) && parsed.jobId === jobId
        ? { kind: "ok", meta: parsed }
        : { kind: "unreadable" };
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ENOTDIR") return { kind: "absent" };
      return { kind: "unreadable" };
    }
  }

  writeMeta(meta: JobMeta): boolean {
    try {
      atomicWriteUtf8(this.jobDir(meta.jobId), META_FILE, JSON.stringify(meta, null, 2));
      return true;
    } catch {
      return false;
    }
  }

  /** Create-only so a wrapper-written outcome always wins. */
  recordExitCode(jobId: string, code: number): void {
    if (!JOB_ID_PATTERN.test(jobId)) return;
    try {
      fs.writeFileSync(this.exitPath(jobId), String(code), {
        flag: "wx",
        mode: PRIVATE_FILE_MODE,
      });
    } catch {
      // Existing marker or removed directory: disk keeps the authoritative value.
    }
  }

  readExit(jobId: string): { code: number; at: number } | null {
    try {
      const target = this.exitPath(jobId);
      const stat = fs.statSync(target);
      const raw = fs.readFileSync(target, "utf8").trim();
      if (!/^-?\d{1,5}$/.test(raw)) return null;
      const code = Number(raw);
      if (!Number.isInteger(code)) return null;
      return { code, at: Math.round(stat.mtimeMs) };
    } catch {
      return null;
    }
  }

  removeJobDir(jobId: string): void {
    if (!JOB_ID_PATTERN.test(jobId)) return;
    try {
      fs.rmSync(this.jobDir(jobId), {
        recursive: true,
        force: true,
        maxRetries: 3,
        retryDelay: 50,
      });
    } catch {
      // Best effort; recovery retries stale directories.
    }
  }

  async removeJobDirAsync(jobId: string): Promise<void> {
    if (!JOB_ID_PATTERN.test(jobId)) return;
    try {
      await fs.promises.rm(this.jobDir(jobId), {
        recursive: true,
        force: true,
        maxRetries: 3,
        retryDelay: 50,
      });
    } catch {
      // Best effort; recovery retries stale directories.
    }
  }

  jobDirMtime(jobId: string): number | null {
    try {
      return fs.statSync(this.jobDir(jobId)).mtimeMs;
    } catch {
      return null;
    }
  }

  fileStat(jobId: string, file: string): { size: number; mtimeMs: number } | null {
    try {
      const stat = fs.statSync(path.join(this.jobDir(jobId), file));
      return { size: stat.size, mtimeMs: stat.mtimeMs };
    } catch {
      return null;
    }
  }

  fileExistsState(jobId: string, file: string): "exists" | "absent" | "unreadable" {
    try {
      fs.statSync(path.join(this.jobDir(jobId), file));
      return "exists";
    } catch (err) {
      return (err as NodeJS.ErrnoException).code === "ENOENT" ? "absent" : "unreadable";
    }
  }

  gpuLockPath(index: number): string {
    return path.join(this.root, gpuLockFileName(index));
  }

  createGpuLock(index: number, jobId: string): "created" | "exists" {
    const lockPath = this.gpuLockPath(index);
    try {
      const fd = fs.openSync(lockPath, "wx", PRIVATE_FILE_MODE);
      try {
        fs.writeFileSync(fd, jobId);
      } finally {
        fs.closeSync(fd);
      }
      return "created";
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "EEXIST") return "exists";
      throw err;
    }
  }

  readGpuLockPath(lockPath: string): LockRead {
    try {
      const raw = fs.readFileSync(lockPath, "utf8").trim();
      return JOB_ID_PATTERN.test(raw) ? { kind: "holder", jobId: raw } : { kind: "garbage" };
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ENOTDIR") return { kind: "absent" };
      return { kind: "unreadable" };
    }
  }

  readGpuLock(index: number): LockRead {
    return this.readGpuLockPath(this.gpuLockPath(index));
  }

  removeGpuLockPath(lockPath: string): boolean {
    try {
      fs.rmSync(lockPath, { force: true });
      return true;
    } catch {
      return false;
    }
  }

  removeGpuLock(index: number): boolean {
    return this.removeGpuLockPath(this.gpuLockPath(index));
  }

  listGpuLockPaths(): string[] {
    try {
      return fs.readdirSync(this.root)
        .filter(isGpuLockFileName)
        .map((entry) => path.join(this.root, entry));
    } catch {
      return [];
    }
  }
}

function isJobMeta(value: unknown): value is JobMeta {
  if (typeof value !== "object" || value === null) return false;
  const meta = value as Partial<JobMeta>;
  return (
    meta.v === 1 &&
    typeof meta.jobId === "string" &&
    JOB_ID_PATTERN.test(meta.jobId) &&
    typeof meta.name === "string" &&
    typeof meta.command === "string" &&
    typeof meta.cwd === "string" &&
    (meta.status === "running" || meta.status === "exited" || meta.status === "unknown") &&
    (meta.exitCode === null || typeof meta.exitCode === "number") &&
    typeof meta.startedAt === "number" &&
    (meta.endedAt === null || typeof meta.endedAt === "number") &&
    (meta.endedAtApproximate === undefined || typeof meta.endedAtApproximate === "boolean") &&
    (meta.unknownReason === undefined || typeof meta.unknownReason === "string") &&
    (meta.gpuIndex === null || typeof meta.gpuIndex === "number") &&
    (meta.pid === null || typeof meta.pid === "number") &&
    (meta.procIdentity === null || typeof meta.procIdentity === "string") &&
    (meta.retiring === undefined || typeof meta.retiring === "boolean") &&
    (meta.cancelRequestedAt === undefined || typeof meta.cancelRequestedAt === "number") &&
    (meta.scope === undefined || typeof meta.scope === "string") &&
    (meta.truncatedAt === null || typeof meta.truncatedAt === "number")
  );
}
