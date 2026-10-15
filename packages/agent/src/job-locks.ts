import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { ensurePrivateDir } from "./atomic-file.js";
import type { JobStore } from "./job-store.js";

/**
 * Exclusive lock files shared by the GPU lock and named resource locks.
 *
 * A lock is a file created with `wx` that names its holder's jobId. Liveness is
 * never read from the lock itself: the holder's job record decides (see
 * JobManager.gpuHolderState), so a lock whose job is gone is reaped and taken
 * over, an unreadable one is a hold. Named locks are per machine and shared by
 * every account on it; there is no queueing — a held lock is a refusal.
 */
export type LockHolderState = (jobId: string) => "running" | "gone" | "unknown";

const LOCKS_DIR = ".locks";

/**
 * Take one lock file. Returns null on success, else the holder's jobId (or
 * "unknown" when the file cannot be attributed). Throws only on a filesystem
 * failure other than "already exists".
 */
export function acquireLockFile(
  store: JobStore,
  lockPath: string,
  jobId: string,
  content: string,
  holderState: LockHolderState,
  retried = false,
): string | null {
  if (store.createLockFile(lockPath, content) === "created") return null;
  const lock = store.readLockFile(lockPath);
  // An unreadable lock may still name a live job; only evidence permits reaping.
  if (lock.kind === "unreadable") return "unknown";
  if (lock.kind === "holder" && holderState(lock.jobId) !== "gone") return lock.jobId;
  if (retried || !store.removeLockFile(lockPath)) {
    return lock.kind === "holder" ? lock.jobId : "unknown";
  }
  return acquireLockFile(store, lockPath, jobId, content, holderState, true);
}

/** Remove a lock file only while it still names `jobId`. */
export function releaseLockFile(store: JobStore, lockPath: string, jobId: string): void {
  const lock = store.readLockFile(lockPath);
  if (lock.kind !== "holder" || lock.jobId !== jobId) return;
  store.removeLockFile(lockPath);
}

/** Recovery: drop lock files whose holder is proven gone (or that name nobody). */
export function reapLockFiles(store: JobStore, lockPaths: string[], holderState: LockHolderState): void {
  for (const lockPath of lockPaths) {
    const lock = store.readLockFile(lockPath);
    if (lock.kind === "absent" || lock.kind === "unreadable") continue;
    if (lock.kind === "holder" && holderState(lock.jobId) !== "gone") continue;
    store.removeLockFile(lockPath);
  }
}

/** `<jobsRoot>/.locks/<sha256(name)>`: the name never becomes a path component. */
export function namedLockPath(root: string, name: string): string {
  return path.join(root, LOCKS_DIR, createHash("sha256").update(name, "utf8").digest("hex"));
}

export function listNamedLockPaths(root: string): string[] {
  const dir = path.join(root, LOCKS_DIR);
  try {
    return fs.readdirSync(dir)
      .filter((entry) => /^[0-9a-f]{64}$/.test(entry))
      .map((entry) => path.join(dir, entry));
  } catch {
    return [];
  }
}

/**
 * Take every named lock or none, in sorted order. On a conflict every lock this
 * call already took is released before returning the busy one and its holder.
 */
export function acquireNamedLocks(
  store: JobStore,
  locks: readonly string[],
  jobId: string,
  holderState: LockHolderState,
): { lock: string; heldBy: string } | null {
  if (locks.length === 0) return null;
  ensurePrivateDir(path.join(store.root, LOCKS_DIR));
  const taken: string[] = [];
  for (const name of [...locks].sort()) {
    let heldBy: string | null;
    try {
      heldBy = acquireLockFile(
        store,
        namedLockPath(store.root, name),
        jobId,
        JSON.stringify({ name, jobId }),
        holderState,
      );
    } catch (err) {
      releaseNamedLocks(store, taken, jobId);
      throw err;
    }
    if (heldBy !== null) {
      releaseNamedLocks(store, taken, jobId);
      return { lock: name, heldBy };
    }
    taken.push(name);
  }
  return null;
}

export function releaseNamedLocks(store: JobStore, locks: readonly string[] | undefined, jobId: string): void {
  for (const name of locks ?? []) releaseLockFile(store, namedLockPath(store.root, name), jobId);
}
