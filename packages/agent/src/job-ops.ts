import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { isOperationKey, JOB_ID_PATTERN } from "@aicommander/protocol";
import { ensurePrivateDir, PRIVATE_FILE_MODE } from "./atomic-file.js";

/**
 * The operation index behind idempotent job starts.
 *
 * `<jobsRoot>/.ops/<operationKey>` holds `{jobId, fingerprint}` and is created
 * with `wx` BEFORE the job is spawned, so two starts racing on one key cannot
 * both win — within this process and across a restart. The key is already
 * per-principal (the relay hashes it), so one machine's accounts never collide.
 * The index lives exactly as long as its job: abort/retire paths and the 7-day
 * prune remove it, and recovery drops indexes whose job directory is gone.
 */
const OPS_DIR = ".ops";

export interface OpIndexEntry {
  jobId: string;
  fingerprint: string;
}

export type OpIndexRead =
  | { kind: "ok"; entry: OpIndexEntry }
  | { kind: "absent" }
  /** Present but not parseable: a crash between create and write. */
  | { kind: "garbage" }
  | { kind: "unreadable" };

/** What makes two starts "the same work": command, cwd, gpu request and locks. */
export function startFingerprint(req: {
  command: string;
  cwd?: string | undefined;
  gpuIndex?: number | undefined;
  locks?: readonly string[] | undefined;
}): string {
  const canonical = JSON.stringify([
    req.command,
    req.cwd ?? null,
    req.gpuIndex ?? null,
    [...(req.locks ?? [])].sort(),
  ]);
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

function opIndexPath(root: string, opKey: string): string {
  return path.join(root, OPS_DIR, opKey);
}

export function createOpIndex(root: string, opKey: string, entry: OpIndexEntry): "created" | "exists" {
  if (!isOperationKey(opKey)) throw new Error("invalid operation key");
  ensurePrivateDir(path.join(root, OPS_DIR));
  try {
    const fd = fs.openSync(opIndexPath(root, opKey), "wx", PRIVATE_FILE_MODE);
    try {
      fs.writeFileSync(fd, JSON.stringify(entry));
    } finally {
      fs.closeSync(fd);
    }
    return "created";
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "EEXIST") return "exists";
    throw err;
  }
}

export function readOpIndex(root: string, opKey: string): OpIndexRead {
  if (!isOperationKey(opKey)) return { kind: "absent" };
  let raw: string;
  try {
    raw = fs.readFileSync(opIndexPath(root, opKey), "utf8");
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") return { kind: "absent" };
    return { kind: "unreadable" };
  }
  try {
    const parsed = JSON.parse(raw) as Partial<OpIndexEntry> | null;
    if (
      typeof parsed?.jobId === "string" &&
      JOB_ID_PATTERN.test(parsed.jobId) &&
      typeof parsed.fingerprint === "string"
    ) {
      return { kind: "ok", entry: { jobId: parsed.jobId, fingerprint: parsed.fingerprint } };
    }
  } catch {
    // Fall through: a torn write.
  }
  return { kind: "garbage" };
}

/** Remove the index; with `jobId`, only while it still points at that job. */
export function removeOpIndex(root: string, opKey: string | undefined, jobId?: string): void {
  if (opKey === undefined || !isOperationKey(opKey)) return;
  if (jobId !== undefined) {
    const read = readOpIndex(root, opKey);
    if (read.kind !== "ok" || read.entry.jobId !== jobId) return;
  }
  try {
    fs.rmSync(opIndexPath(root, opKey), { force: true });
  } catch {
    // Best effort; recovery reaps orphans.
  }
}

/** Recovery: drop indexes whose job directory is gone or whose content is torn. */
export function reapOpIndexes(root: string, jobExists: (jobId: string) => boolean): void {
  let keys: string[];
  try {
    keys = fs.readdirSync(path.join(root, OPS_DIR)).filter(isOperationKey);
  } catch {
    return;
  }
  for (const key of keys) {
    const read = readOpIndex(root, key);
    if (read.kind === "garbage" || (read.kind === "ok" && !jobExists(read.entry.jobId))) {
      removeOpIndex(root, key);
    }
  }
}
